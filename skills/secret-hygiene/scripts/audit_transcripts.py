#!/usr/bin/env python3
"""Find the secrets that already reached an AI provider through the local agent transcripts.

Claude Code keeps every session in ~/.claude/projects/**/*.jsonl, Codex in
~/.codex/sessions/**/*.jsonl. A value in a prompt, a tool result or a model answer there was
sent to the provider (Anthropic or OpenAI). Deleting the local file does not take it back:
the finding means "rotate it".

Nothing this script prints is a value, a line of a transcript or a hash of a value. A finding
is a per-run id (S1, S2 ...; the same value keeps its id across sessions), a type, the rule,
how sure the match is, where in the session it sat, and the sessions it appears in.

    python3 audit_transcripts.py [--claude] [--codex] [--pii] [--days N] [--out FILE]
    python3 audit_transcripts.py --scrub [--yes] [--days N]

--scrub lists which local transcript files hold a found value; with --yes it replaces each
value in them with ⟦TYPE_n⟧, keeping every line valid JSON. It skips files written to in the
last 10 minutes (a running session). It does not undo what the provider received.

Exit code: 0 nothing found, 1 findings, 2 error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402

SENT = {"prompt", "tool result", "model output"}
ACTIVE_SECONDS = 600
LINES_PER_JOB = 2000


def sources(claude: bool, codex: bool, days: int) -> list[tuple[str, Path]]:
    home = Path.home()
    roots = []
    if claude:
        base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home / ".claude") / "projects"
        roots.append(("claude", base))
    if codex:
        roots.append(("codex", Path(os.environ.get("CODEX_HOME") or home / ".codex") / "sessions"))
    cutoff = time.time() - days * 86400 if days else 0
    out = []
    for client, root in roots:
        if not root.is_dir():
            continue
        for f in root.rglob("*.jsonl"):
            try:
                if f.stat().st_mtime >= cutoff:
                    out.append((client, f))
            except OSError:
                continue
    return sorted(out, key=lambda x: str(x[1]))


def kind_of(client: str, rec: dict) -> str:
    """Where in the session a record sits: prompt, tool result, model output, or local record
    (hook attachments, metadata: not proven to have reached the provider)."""
    if client == "claude":
        t = rec.get("type")
        if t == "user":
            content = (rec.get("message") or {}).get("content")
            if isinstance(content, list) and any(isinstance(x, dict) and x.get("type") == "tool_result"
                                                 for x in content):
                return "tool result"
            return "prompt"
        if t == "assistant":
            return "model output"
        return "local record"
    payload = rec.get("payload") or {}
    if rec.get("type") == "response_item":
        pt, role = payload.get("type"), payload.get("role")
        if pt == "message" and role == "user":
            return "prompt"
        if pt in ("function_call_output", "custom_tool_call_output", "local_shell_call_output"):
            return "tool result"
        return "model output"
    return "local record"


def strings_of(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for x in node:
            yield from strings_of(x)
    elif isinstance(node, dict):
        for v in node.values():
            yield from strings_of(v)


def worker_jsonl(job: tuple) -> tuple:
    """job = (tag, client, lines): scan the decoded strings of each JSON line; return
    (line index, record kind, timestamp, type, rule, value, inner rule) per hit."""
    tag, client, lines = job
    detect, enabled = _detector._W["detect"], _detector._W["enabled"]
    rows = []
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        text = "\n".join(strings_of(rec))
        if not text:
            continue
        hits = _detector.scan_text(detect, text, enabled)
        if not hits:
            continue
        kind = kind_of(client, rec)
        stamp = str(rec.get("timestamp") or "")[:10]
        for m in hits:
            inner = None
            if m.type == "SECRET":
                for x in detect.scan(m.value):
                    if x.type == "SECRET" and x.kind != m.kind:
                        inner = x.kind
                        break
            rows.append((i, kind, stamp, m.type, m.kind, m.value, inner))
    return tag, rows


def jobs_for(files: list[tuple[str, Path]]):
    for client, f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                batch, start = [], 0
                for n, line in enumerate(fh):
                    batch.append(line)
                    if len(batch) >= LINES_PER_JOB:
                        yield (str(f), start), client, batch
                        batch, start = [], n + 1
                if batch:
                    yield (str(f), start), client, batch
        except OSError:
            continue


def run(files, enabled):
    total = sum(f.stat().st_size for _c, f in files if f.exists())
    if total < 1_000_000:
        _detector._worker_init(enabled)
        for job in jobs_for(files):
            yield worker_jsonl(job)
        return
    with _detector.pool(enabled) as ex:
        window = 4 * (os.cpu_count() or 2)
        pending = []
        for job in jobs_for(files):
            pending.append(ex.submit(worker_jsonl, job))
            if len(pending) >= window:
                yield pending.pop(0).result()
        for fut in pending:
            yield fut.result()


def session_label(client: str, path: Path) -> str:
    if client == "claude":
        return f"Claude {path.parent.name.strip('-').replace('-', '/')[-40:]} {path.stem[:8]}"
    return f"Codex {path.stem[-36:][:8]}"


def classify(kind: str, inner: str | None) -> tuple[str, str]:
    guess = kind in ("generic-api-key", "url-query-secret") or kind.startswith("ds-keyword")
    if not guess:
        return kind, "shape"
    if inner and not (inner in ("generic-api-key", "url-query-secret") or inner.startswith("ds-keyword")):
        return inner, "shape"
    return kind, "guess"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Secrets that already reached an AI provider, by location, never by value.")
    ap.add_argument("--claude", action="store_true")
    ap.add_argument("--codex", action="store_true")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--days", type=int, default=0, help="only sessions written to in the last N days (default: all)")
    ap.add_argument("--out", help="write the full report to this file and print only the summary")
    ap.add_argument("--scrub", action="store_true", help="list the local files that hold a found value")
    ap.add_argument("--yes", action="store_true", help="with --scrub: replace the values in those files")
    args = ap.parse_args(argv)
    if not args.claude and not args.codex:
        args.claude = args.codex = True
    detect = _detector.load()
    enabled = None if args.pii else _detector.secret_rules(detect)
    files = sources(args.claude, args.codex, args.days)
    if not files:
        print("No agent transcripts found.")
        return 0
    ids: dict[str, str] = {}
    per_id: dict[str, dict] = {}
    per_file: dict[str, set] = defaultdict(set)
    client_of = {str(f): c for c, f in files}
    for (tag, _start), rows in run(files, enabled):
        for _i, kind, stamp, mtype, rule, value, inner in rows:
            if not args.pii and mtype != "SECRET":
                continue
            sid = ids.setdefault(value, f"S{len(ids) + 1}")
            per_file[tag].add(value)
            name, sure = classify(rule, inner)
            e = per_id.setdefault(sid, {"type": mtype, "rule": name, "sure": sure, "len": len(value),
                                        "sessions": set(), "kinds": Counter(), "first": stamp, "last": stamp,
                                        "clients": set()})
            e["sessions"].add(session_label(client_of[tag], Path(tag)))
            e["kinds"][kind] += 1
            e["clients"].add(client_of[tag])
            if stamp:
                e["first"] = min(e["first"] or stamp, stamp)
                e["last"] = max(e["last"] or stamp, stamp)
    if args.scrub:
        return scrub(per_file, ids, args.yes)
    lines = [f"Scanned {len(files)} transcript file(s)."]
    sent = {k: v for k, v in per_id.items() if SENT & set(v["kinds"])}
    local = {k: v for k, v in per_id.items() if k not in sent}
    lines.append(f"Reached the AI provider: {len(sent)} distinct value(s). Only in local records: {len(local)}.")
    for title, group in (("REACHED THE PROVIDER (rotate these)", sent), ("Only in local records", local)):
        if not group:
            continue
        lines.append(title + ":")
        for sid, e in sorted(group.items(), key=lambda kv: (kv[1]["sure"] != "shape", kv[0])):
            where = ", ".join(f"{n} {k}" for k, n in e["kinds"].most_common())
            prov = "/".join(sorted({"Anthropic" if c == "claude" else "OpenAI" for c in e["clients"]}))
            shown = "; ".join(sorted(e["sessions"])[:3]) + (f"; +{len(e['sessions']) - 3} more"
                                                             if len(e["sessions"]) > 3 else "")
            lines.append(f"  {sid:<5} {e['type']:<7} {e['rule']:<24} {e['sure']:<5} len {e['len']:<4} "
                         f"to {prov:<16} {e['first']}..{e['last']} in {len(e['sessions'])} session(s) "
                         f"[{where}]: {shown}")
    shape = sum(1 for e in sent.values() if e["sure"] == "shape")
    lines.append(f"Summary: {len(sent)} value(s) reached a provider, {shape} of them in a provider's token format "
                 f"(rotate first); {len(sent) - shape} are keyword guesses that can be noise.")
    lines.append("Values are not shown. The same id means the same value. Deleting or scrubbing a local "
                 "transcript does not take back what the provider received.")
    if args.out:
        Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote the full report to {args.out}.")
        print("\n".join(line for line in lines if not line.startswith("  ")))
    else:
        print("\n".join(lines))
    return 1 if per_id else 0


def scrub(per_file: dict[str, set], ids: dict[str, str], yes: bool) -> int:
    now = time.time()
    targets = []
    for tag, values in sorted(per_file.items()):
        path = Path(tag)
        try:
            active = now - path.stat().st_mtime < ACTIVE_SECONDS
        except OSError:
            continue
        targets.append((path, values, active))
    if not targets:
        print("No local transcript holds a found value.")
        return 0
    for path, values, active in targets:
        note = " (skipped: written to in the last 10 minutes)" if active else ""
        print(f"  {len(values)} value(s) in {path}{note}")
    if not yes:
        print(f"{sum(1 for t in targets if not t[2])} file(s) would be changed. Nothing was changed. Run again "
              "with --scrub --yes to replace the values in them. This cleans only this computer; the provider "
              "keeps what it received.")
        return 1
    changed = 0
    for path, values, active in targets:
        if active:
            continue
        tags = {v: f"⟦SCRUBBED_{ids[v]}⟧" for v in values}
        order = sorted(tags, key=len, reverse=True)
        out_lines = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    out_lines.append(line)
                    continue

                def clean(node):
                    if isinstance(node, str):
                        for v in order:
                            if v in node:
                                node = node.replace(v, tags[v])
                        return node
                    if isinstance(node, list):
                        return [clean(x) for x in node]
                    if isinstance(node, dict):
                        return {k: clean(x) for k, x in node.items()}
                    return node
                new = clean(rec)
                compact = json.dumps(new, ensure_ascii=False, separators=(",", ":")) + "\n"
                out_lines.append(compact if new != rec else line)
        tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
        tmp.write_text("".join(out_lines), encoding="utf-8")
        os.replace(tmp, path)
        changed += 1
    print(f"Replaced the values in {changed} file(s). The provider keeps what it received: rotate the values.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
