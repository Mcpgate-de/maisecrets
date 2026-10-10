#!/usr/bin/env python3
"""Measure what ssh consent (#8) would do with the ssh commands an agent really ran: how often it would ask.

    python3 scripts/measure_ssh_consent.py [transcript-dir] [--skip-cwd TEXT]   # default: ~/.claude/projects
        [--last N] [--code ROOT] [--dump FILE] [--excerpts FILE] [--json]

`--last N` reads the N newest transcripts; `--code ROOT` takes the recognizer of another checkout (a release), so
two runs compare old and new on the same transcripts; `--dump FILE` writes a hash, the kind and the reason per
command (no command); `--excerpts FILE` writes a short masked window around the word of each question that cannot
be read, for labelling by hand. Both files stay local; nothing of them goes into the repository. `--json`
prints the same numbers as one JSON object, for a script that compares two runs.

It reads the Bash calls in Claude Code transcripts, classifies each one that names ssh (maisecrets/ssh_consent.py)
and replays the consents per session: a write asks once per host (or group of hosts), a form the hook cannot read
asks every time. It ignores host groups and the 8-hour expiry, so it counts at most the questions of one
session. `--skip-cwd TEXT` leaves out every transcript that ran in a directory whose path contains TEXT. It prints
counts and reasons only: no host, no command, no value. A reality check, not a gate.

Measured on 2026-10-07 over the maintainer's transcripts (this script, default directory: 297 sessions with ssh,
4169 calls): write 82.5 %, unknown 12.7 %, none 4.6 %, read 0.2 %; questions per session median 1, 90th percentile
4, at most 150, 876 in all. The sessions that work on maisecrets itself are in that count; their commands name ssh
in test cases. With `--skip-cwd maisecrets` they are left out; the number is in the README.
Real ops commands almost always use sudo or docker on the remote side, so they are writes by design: the consent
per host carries them, not the read list.
"""
from __future__ import annotations

import collections
import glob
import hashlib
import json
import os
import re
import statistics
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# --code ROOT: the recognizer of another checkout (a release), to compare it with this one on the same transcripts
if "--code" in sys.argv:
    ROOT = Path(sys.argv[sys.argv.index("--code") + 1]).resolve()
os.environ["MAISECRETS_HOME"] = tempfile.mkdtemp(prefix="maisecrets-measure-")   # never the real store
sys.path.insert(0, str(ROOT))
from maisecrets import detect, hooks, ssh_consent  # noqa: E402


def parse(text: str):
    ctxs = hooks._shell_contexts(text)
    return hooks._segments(text, ctxs), ctxs


def commands(path: str, skip_cwd: str = "") -> list[str]:
    out = []
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            if '"Bash"' not in line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if skip_cwd and skip_cwd in (rec.get("cwd") or ""):
                return []
            for block in (rec.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Bash":
                    cmd = (block.get("input") or {}).get("command", "")
                    if isinstance(cmd, str) and ssh_consent._TOKEN_RE.search(cmd):
                        out.append(cmd)
    except OSError:
        pass
    return out


def _option(argv: list[str], name: str) -> tuple[str, list[str]]:
    if name not in argv:
        return "", argv
    k = argv.index(name)
    return (argv[k + 1] if k + 1 < len(argv) else ""), argv[:k] + argv[k + 2:]


def _excerpt(cmd: str, why: str) -> str:
    """A short window around the word the verdict names, with every detected value masked: for a person who labels
    the questions by hand. Written only to a local file the caller names, never printed."""
    word = re.search(r"'([^']*)'", why)
    m = re.search(re.escape(word.group(1)), cmd) if word else ssh_consent._TOKEN_RE.search(cmd)
    lo, hi = (max(0, m.start() - 60), min(len(cmd), m.end() + 60)) if m else (0, 120)
    text = cmd[lo:hi]
    for hit in sorted(detect.scan(text), key=lambda h: -len(h.value)):
        text = text.replace(hit.value, "<value>")
    return text.replace("\n", "\\n")


def main(argv: list[str]) -> int:
    skip, argv = _option(argv, "--skip-cwd")
    _code, argv = _option(argv, "--code")
    last, argv = _option(argv, "--last")
    dump, argv = _option(argv, "--dump")
    excerpts, argv = _option(argv, "--excerpts")
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    base = Path(argv[0]).expanduser() if argv else Path.home() / ".claude" / "projects"
    kinds, why, asks = collections.Counter(), collections.Counter(), []
    total = 0
    paths = sorted(glob.glob(str(base / "*" / "*.jsonl")), key=os.path.getmtime)
    if last:
        paths = paths[-int(last):]          # the newest sessions
    rows = []
    for path in paths:
        cmds = commands(path, skip)
        if not cmds:
            continue
        granted: set[str] = set()
        n = 0
        for cmd in cmds:
            total += 1
            v = ssh_consent.classify(cmd, parse)
            kinds[v.kind] += 1
            if dump or excerpts:
                rows.append((hashlib.sha256(cmd.encode()).hexdigest()[:16], v.kind,
                             re.sub(r"'[^']*'", "'…'", v.why or ""), cmd, v.why or ""))
            if v.kind in ("write", "unknown", "deny"):
                why[(v.kind, re.sub(r"'[^']*'", "'…'", v.why))] += 1
            if v.kind == "unknown":
                n += 1
            elif v.kind == "write" and not set(v.hosts) <= granted:
                n += 1
                granted |= set(v.hosts)
        asks.append(n)
    if not total:
        print("no ssh command found")
        return 0
    asks.sort()
    if as_json:                          # the same numbers for a script that compares two runs
        print(json.dumps({"sessions": len(asks), "calls": total, "kinds": dict(kinds), "questions": sum(asks),
                          "median": statistics.median(asks), "p90": asks[int(0.9 * len(asks))], "max": asks[-1],
                          "reasons": [{"kind": k, "why": w, "n": n} for (k, w), n in why.most_common()]}))
    else:
        _print_summary(kinds, why, asks, total)
    _write_files(rows, dump, excerpts)
    return 0


def _print_summary(kinds, why, asks, total) -> None:
    print(f"sessions with ssh: {len(asks)}, calls: {total}")
    for k, n in kinds.most_common():
        print(f"  {k:8} {n:6}  {100 * n / total:5.1f} %")
    print(f"questions per session: median {statistics.median(asks)}, 90th percentile {asks[int(0.9 * len(asks))]}, "
          f"at most {asks[-1]}, {sum(asks)} in all")
    for (k, w), n in why.most_common(10):
        print(f"  {n:6}  {k:8} {w}")


def _write_files(rows, dump, excerpts) -> None:
    if dump:
        # per command: a hash, the kind and the reason, never the command: two runs on the same transcripts (this
        # checkout and --code of a release) compare command by command
        with open(dump, "w", encoding="utf-8") as f:
            for h, kind, reason, _cmd, _why in rows:
                f.write(json.dumps({"h": h, "kind": kind, "why": reason}) + "\n")
    if excerpts:
        with open(excerpts, "w", encoding="utf-8") as f:
            for h, kind, reason, cmd, raw in rows:
                if kind == "unknown":
                    f.write(json.dumps({"h": h, "why": reason, "excerpt": _excerpt(cmd, raw)}) + "\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
