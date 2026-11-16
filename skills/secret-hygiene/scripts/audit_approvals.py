#!/usr/bin/env python3
"""Find credentials in the approvals and settings that Claude Code and Codex keep outside the repository.

A command that a person approves is stored as text. A token in that command stays in the file, and the
client sends the rule back to the model with each later session. The working tree scan (scan_secrets.py)
sees only the files of one repository; this script reads the files of this user:

  Claude Code  <config dir>/settings.json, settings.local.json            (the whole file: permissions, env ...)
               <config dir>/.claude.json, its backups, .config.json      (projects[<path>].allowedTools)
               <project>/.claude/settings.json, settings.local.json     (each project of .claude.json)
  Codex        <codex home>/config.toml                                  (the whole file)
               <codex home>/rules/*.rules                                (prefix_rule lines, the approvals)
               <project>/.codex/config.toml, .codex/rules/*.rules       (each [projects."<path>"] of config.toml)

<config dir> is CLAUDE_CONFIG_DIR or ~/.claude; .claude.json sits in CLAUDE_CONFIG_DIR, else in the home.
<codex home> is CODEX_HOME or ~/.codex.

Nothing this script prints is a value, a line of a file or a hash of a value. A finding is a per-run id
(S1, S2 ...; the same value keeps its id across files), the file, the place in it, the type, the rule, how
sure the match is and the length. The script never changes a file.

Every path the report prints (a project folder, a file name) is scanned too, and a key that does not look like
a plain name is printed as [key].

    python3 audit_approvals.py [--pii] [--out FILE] [--max-mb N]

--out must not name a file this script reads. --max-mb (default 50) skips a larger file; the report names it.

Exit code: 0 nothing found, 1 findings, 2 error (a file could not be read: not a regular file, too large, or not
parsable; so "nothing found" is not proven).
"""
from __future__ import annotations

import argparse
import json
import os
import math
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402

ROTATION = "references/rotation.md"
WITHHELD = "[withheld]"


# ------------------------------------------------------------------------------------------- files --
def claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def claude_client_files() -> list[Path]:
    """The client config of Claude Code: `.claude.json` in CLAUDE_CONFIG_DIR, else in the home (the rule of
    maisecrets/vault_refs.py global_file, copied: the standalone skill zip has no vault_refs), its
    `-custom-oauth` form, the legacy `.config.json` of the config dir, and the copies the client keeps in
    `backups/`. Each holds `projects[<path>].allowedTools`."""
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    home = Path(base) if base else Path.home()
    out = [home / ".claude.json"]
    if os.environ.get("CLAUDE_CODE_CUSTOM_OAUTH_URL"):
        out.append(home / ".claude-custom-oauth.json")
    for extra in [claude_dir() / ".config.json", *sorted((claude_dir() / "backups").glob(".claude*.json*"))]:
        if extra.is_file():
            out.append(extra)
    return out


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")


def rules_in(folder: Path) -> list[Path]:
    """`*.rules` in a rules folder, as Codex loads them (codex-rs/core/src/exec_policy.rs collect_policy_files)."""
    try:
        return sorted(p for p in folder.iterdir() if p.suffix == ".rules" and p.is_file())
    except OSError:
        return []


MAX_MB = 50.0     # a settings file is kilobytes; a 100 MB file took 214 s and 511 MB (Gate A M3)


class Unreadable(OSError):
    """A file this script does not read: not a regular file, or larger than --max-mb."""


def _read(path: Path) -> str:
    """The text of a regular file, read only (this script never writes a source). Opened without blocking and
    checked on the open descriptor: a FIFO or a link to /dev/stdin made a plain open() wait forever (Gate A M2)."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Unreadable("not a regular file")
        if st.st_size > MAX_MB * 1_000_000:
            raise Unreadable(f"too large ({st.st_size // 1_000_000} MB, --max-mb {MAX_MB:g})")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read().decode("utf-8", errors="replace")
    finally:
        if fd >= 0:
            os.close(fd)


def _claude_projects(files: list[Path]) -> list[str]:
    out: list[str] = []
    for f in files:
        try:
            data = json.loads(_read(f))
        except Exception:   # main() reports the file; a deep nesting raised RecursionError here
            continue
        projects = data.get("projects") if isinstance(data, dict) else None
        if isinstance(projects, dict):
            out += [p for p in projects if isinstance(p, str) and p not in out]
    return out


PROJECT_HEADER = re.compile(r"""^\s*\[\s*projects\s*\.\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)')\s*\]""")


def _codex_projects(config: Path) -> list[str]:
    try:
        text = _read(config)
    except (OSError, ValueError):
        return []
    out: list[str] = []
    for line in text.splitlines():
        m = PROJECT_HEADER.match(line)
        if m:
            path = m.group(1).replace("\\\\", "\\").replace('\\"', '"') if m.group(1) is not None else m.group(2)
            if path not in out:
                out.append(path)
    return out


def sources() -> list[tuple[Path, str, str]]:
    """(file, client, what it is) for every file this script looks for, present or not."""
    cdir, chome = claude_dir(), codex_home()
    out = [(cdir / "settings.json", "Claude Code", "user settings"),
           (cdir / "settings.local.json", "Claude Code", "user settings")]
    client = claude_client_files()
    out += [(f, "Claude Code", "client config") for f in client]
    for p in _claude_projects(client):
        for name in ("settings.json", "settings.local.json"):
            out.append((Path(p) / ".claude" / name, "Claude Code", "project settings"))
    out.append((chome / "config.toml", "Codex", "config"))
    user_rules = rules_in(chome / "rules")
    out += [(f, "Codex", "approval rules") for f in user_rules] or [(chome / "rules" / "*.rules", "Codex",
                                                                        "approval rules")]
    for p in _codex_projects(chome / "config.toml"):
        folder = Path(p) / ".codex"
        out.append((folder / "config.toml", "Codex", "project config"))
        out += [(f, "Codex", "project approval rules") for f in rules_in(folder / "rules")]
    seen, unique = set(), []
    for f, c, w in out:
        key = os.path.normcase(os.path.abspath(str(f)))
        if key not in seen:
            seen.add(key)
            unique.append((f, c, w))
    return unique


# ------------------------------------------------------------------------------------------ places --
SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _high_entropy(s: str) -> bool:
    """A name of 16 or more characters with letters and digits and more than 3.5 bits per character: a key of
    random characters, not a word such as GITHUB_TOKEN."""
    if len(s) < 16 or not re.search(r"\d", s) or not re.search(r"[A-Za-z]", s):
        return False
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(x) for x in set(s))) > 3.5


def safe_name(name: str) -> bool:
    """A JSON key or a TOML name is printed only when it looks like a name: a key can itself be a credential
    that no rule matches (Gate A L1)."""
    return bool(SAFE_NAME.fullmatch(name)) and not _high_entropy(name)


def _key(k: str) -> str:
    return f".{k}" if safe_name(k) else "[key]"


def json_strings(node, path: str = ""):
    """(JSON path, string) for each string in the document, keys included (a key can hold a command)."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, list):
        for i, x in enumerate(node):
            yield from json_strings(x, f"{path}[{i}]")
    elif isinstance(node, dict):
        for k, v in node.items():
            sub = f"{path}{_key(str(k))}"
            yield sub + " (key)", str(k)
            yield from json_strings(v, sub)


def is_approval(what: str, place: str) -> bool:
    return (what.endswith("approval rules") or ".allowedTools[" in place
            or place.startswith(("permissions.allow[", "permissions.ask[", "permissions.deny[")))


def fix_for(what: str, place: str) -> str:
    if place == "(path)":
        return (f"a file or folder name holds the credential: rotate the credential ({ROTATION}), then rename "
                "the file or folder")
    if place.endswith("(project path)"):
        return (f"a project folder name holds the credential: rotate the credential ({ROTATION}), then remove "
                "that project entry")
    if what.endswith("approval rules"):
        return f"remove this prefix_rule from the file, then rotate the credential ({ROTATION})"
    if is_approval(what, place):
        return f"remove this approval entry from the file, then rotate the credential ({ROTATION})"
    return (f"take the value out of this setting (an environment variable or a placeholder), then rotate the "
            f"credential ({ROTATION})")


TOML_SECTION = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
TOML_KEY = re.compile(r"""^\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.-]+)\s*=""")


def line_places(text: str, toml: bool) -> list[str]:
    """For each line (index 0 = line 1) its place: the line number, and in a TOML file the table and key
    that the line belongs to (names only)."""
    out, section, key = [], "", ""
    for n, line in enumerate(text.split("\n"), 1):
        if toml:
            s, k = TOML_SECTION.match(line), TOML_KEY.match(line)
            if s:
                section, key = s.group(1), ""
            elif k:
                key = k.group(1)
            parts = [x if safe_name(x) else f"[{label}]" for x, label in ((section, "section"), (key, "key")) if x]
            name = ".".join(parts)
            out.append(f"line {n} ({name})" if name else f"line {n}")
        else:
            out.append(f"line {n}")
    return out


# -------------------------------------------------------------------------------------------- scan --
def scan_file(detect, enabled, path: Path, what: str) -> list[tuple[str, object]]:
    """(place, match) for each hit. A JSON file is scanned string by string with its JSON path; the client
    config only in `projects.*.allowedTools` (the rest is account state and MCP servers, which the plugin
    handles elsewhere). A file that is not valid JSON, a rules file and a TOML file are scanned as text with
    line numbers."""
    text = _read(path)
    hits: list[tuple[str, object]] = []
    if path.name.endswith(".rules") or path.suffix == ".toml" or what.endswith("approval rules"):
        doc = None
    else:
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
    if doc is not None:
        if what == "client config":
            projects = doc.get("projects") if isinstance(doc, dict) else None
            items = []
            for name, entry in (projects.items() if isinstance(projects, dict) else []):
                # the project path is a key of this file and is printed as the folder of its settings: scanned
                # here, so a token in it is a finding and the guard withholds it (Gate A B1)
                shown_name = json.dumps(name, ensure_ascii=False)
                items.append((f"projects[{shown_name}] (project path)", name))
                tools = entry.get("allowedTools") if isinstance(entry, dict) else None
                if isinstance(tools, list):
                    items += [(f"projects[{shown_name}].allowedTools[{i}]", t)
                              for i, t in enumerate(tools) if isinstance(t, str)]
        else:
            items = list(json_strings(doc))
        for place, s in items:
            hits += [(place.lstrip("."), m) for m in detect.scan(s, enabled, "tool")]
        return hits
    places = line_places(text, path.suffix == ".toml")
    starts = _detector.line_starts(text)
    for m in _detector.scan_text(detect, text, enabled, "tool"):
        place = places[_detector.line_of(starts, m.start) - 1]
        if what.endswith("approval rules"):
            place = f"rules/{path.name} {place}"
        hits.append((place, m))
    return hits


def inner_rule(detect, m) -> str | None:
    if m.type != "SECRET":
        return None
    for x in detect.scan(m.value):
        if x.type == "SECRET" and x.kind != m.kind:
            return x.kind
    return None


def classify(kind: str, inner: str | None) -> tuple[str, str]:
    def guess(k: str) -> bool:
        return k in ("generic-api-key", "url-query-secret") or k.startswith("ds-keyword")
    if not guess(kind):
        return kind, "shape"
    if inner and not guess(inner):
        return inner, "shape"
    return kind, "guess"


def shown(text: str) -> str:
    """A path or a place as printed: a control character (a NUL or an escape in a project key) as \\xNN."""
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", text)


def guard(lines: list[str], values) -> list[str]:
    """The last check before any output: a line that holds a found value (a project path or a TOML key that
    contains it, for example) loses that part, also in the forms the report writes it: JSON-escaped (a project
    key) and with control characters escaped (Gate A M1). No value leaves this script, whatever the report
    builds."""
    forms = set()
    for v in values:
        if v:
            forms |= {v, json.dumps(v)[1:-1], json.dumps(v, ensure_ascii=False)[1:-1], shown(v)}
    order = sorted((f for f in forms if f), key=len, reverse=True)
    out = []
    for line in lines:
        for v in order:
            if v in line:
                line = line.replace(v, WITHHELD)
        out.append(line)
    return out


def main(argv: list[str]) -> int:
    global MAX_MB
    ap = argparse.ArgumentParser(
        description="Credentials in the approvals and settings of Claude Code and Codex, by place, never by value.")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--out", help="write the full report to this file and print only the summary")
    ap.add_argument("--max-mb", type=float, default=MAX_MB,
                    help=f"do not read a file larger than this (default {MAX_MB:g}); the report names it")
    args = ap.parse_args(argv)
    MAX_MB = args.max_mb
    try:
        detect = _detector.load()
    except SystemExit as exc:
        print(exc)
        return 2
    enabled = None if args.pii else _detector.secret_rules(detect)
    files = sources()
    if args.out:
        def real(f) -> str:
            try:
                return os.path.realpath(str(f))
            except ValueError:   # a NUL in a project path: no file can have that name
                return ""
        out_real = real(args.out)
        if out_real and any(real(f) == out_real for f, _c, _w in files):
            print("secret-hygiene: --out names a file this script reads; it writes no source file. "
                  "Choose another --out file.")
            return 2
    ids: dict[str, str] = {}
    findings, read, missing, failed = [], [], [], []

    def add(m, path: Path, place: str, client: str, what: str) -> None:
        if not args.pii and m.type != "SECRET":
            return
        sid = ids.setdefault(m.value, f"S{len(ids) + 1}")
        rule, sure = classify(m.kind, inner_rule(detect, m))
        findings.append((sid, m.type, rule, sure, len(m.value), path, place, client, what))

    for path, client, what in files:
        label = f"{shown(str(path))} ({client} {what})"
        try:
            if "*" in path.name:
                raise FileNotFoundError
            os.stat(str(path))
        except (FileNotFoundError, NotADirectoryError, ValueError):   # ValueError: a NUL in a project path
            missing.append(label)
            continue
        except OSError as exc:
            failed.append(f"{label}: {exc.__class__.__name__}")
            continue
        try:
            hits = scan_file(detect, enabled, path, what)
        except Unreadable as exc:
            failed.append(f"{label}: {exc}")
            continue
        except Exception as exc:   # a deep nesting raised RecursionError and read as "findings" (Gate A M4)
            failed.append(f"{label}: {exc.__class__.__name__}")
            continue
        read.append(label)
        for place, m in hits:
            add(m, path, shown(place), client, what)
    # every path this report prints is scanned too: a project key or a file name can hold a token, and the
    # guard withholds only values it knows (Gate A B1; scan_secrets.py _safe_author is the model)
    for path, client, what in files:
        for m in detect.scan(str(path), enabled, "tool"):
            if m.value not in ids:
                add(m, path, "(path)", client, what)
    lines = ["Approvals and settings that Claude Code and Codex keep outside the repository.",
             f"Read {len(read)} file(s); {len(missing)} known file(s) do not exist"
             + (f"; {len(failed)} could NOT be read" if failed else "") + "."]
    lines.append(f"Findings: {len(ids)} distinct value(s) in {len(findings)} place(s).")
    for sid, mtype, rule, sure, n, path, place, client, what in sorted(
            findings, key=lambda f: (f[3] != "shape", int(f[0][1:]), str(f[5]), f[6])):
        lines.append(f"  {sid:<4} {mtype:<7} {rule:<24} {sure:<5} len {n:<4} {shown(str(path))}  {place}  "
                     f"({client} {what})")
        lines.append(f"       fix: {fix_for(what, place)}")
    if failed:
        lines.append("Could NOT be read (nothing found there is not proven):")
        lines += [f"  {x}" for x in failed]
    lines.append("Files read:")
    lines += [f"  {x}" for x in read] or ["  (none)"]
    lines.append("Files that do not exist:")
    lines += [f"  {x}" for x in missing] or ["  (none)"]
    shape = len({f[0] for f in findings if f[3] == "shape"})
    lines.append(f"Summary: {len(ids)} value(s); {shape} match a provider's token format (rotate first). "
                 "Removing an entry does not revoke the credential: the command ran with it, and copies of the "
                 f"file (backups, transcripts) can still hold it. Rotate it ({ROTATION}), then remove the entry.")
    lines.append("Values are not shown. The same id means the same value. This script changed no file.")
    lines = guard(lines, ids)
    if args.out:
        try:
            Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"secret-hygiene: cannot write the --out file: {exc.__class__.__name__}")
            return 2
        print(guard([f"Wrote the full report to {shown(args.out)}."], ids)[0])
        print("\n".join(line for line in lines if not line.startswith("  ")))
    else:
        print("\n".join(lines))
    if findings:
        return 1
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
