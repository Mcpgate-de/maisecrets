#!/usr/bin/env python3
"""List the secrets in a working tree and, with --history, in the git history.

The output never contains a value, a line of the file, or a hash of a value: it goes to a
cloud model. A finding is a location, a type, the rule that matched, the length, and an id
(S1, S2 ...). The same value gets the same id within one run, so a value found in the tree
and in the history carries one id. A hash would let a model test guesses against a weak
password; a per-run id cannot.

    python3 scan_secrets.py [PATH ...] [--history] [--pii] [--max-commits N]

Exit code: 0 nothing found, 1 findings, 2 error.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", ".next",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor", "target"}
MAX_BYTES = 2_000_000


class Ids:
    def __init__(self) -> None:
        self._ids: dict[str, str] = {}

    def of(self, value: str) -> str:
        if value not in self._ids:
            self._ids[value] = f"S{len(self._ids) + 1}"
        return self._ids[value]


def _wanted(match, pii: bool) -> bool:
    return pii or match.type == "SECRET"


def _files(paths: list[Path]):
    for root in paths:
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                yield Path(dirpath) / name


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _tracked(cwd: Path) -> set[str] | None:
    r = subprocess.run(["git", "ls-files", "-z", "--full-name"], cwd=cwd, capture_output=True)
    if r.returncode != 0:
        return None
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True)
    root = Path(top.stdout.strip())
    return {str((root / p).resolve()) for p in r.stdout.decode(errors="replace").split("\0") if p}


def scan_tree(detect, paths: list[Path], ids: Ids, pii: bool) -> list[dict]:
    tracked = _tracked(paths[0] if paths[0].is_dir() else paths[0].parent)
    out = []
    for path in _files(paths):
        text = _read(path)
        if not text:
            continue
        starts = _detector.line_starts(text)
        for m in detect.scan(text):
            if not _wanted(m, pii):
                continue
            state = "untracked" if tracked is not None and str(path.resolve()) not in tracked else "tracked"
            if tracked is None:
                state = "no git"
            out.append({"id": ids.of(m.value), "where": f"{path}:{_detector.line_of(starts, m.start)}",
                        "type": m.type, "rule": m.kind, "len": len(m.value), "git": state})
    return out


def scan_history(detect, cwd: Path, ids: Ids, pii: bool, max_commits: int) -> list[dict]:
    """Added lines of every commit on every ref, newest first. One row per value and file:
    the newest commit that added it and how many commits added it."""
    r = subprocess.run(["git", "log", "-p", "--all", "--no-color", "--no-ext-diff", "-U0",
                        f"--max-count={max_commits}", "--format=commit %h"],
                       cwd=cwd, capture_output=True)
    if r.returncode != 0:
        raise SystemExit("secret-hygiene: not a git repository, or git log failed.")
    seen: dict[tuple[str, str], dict] = {}
    commit, path, lines = "", "", []

    def flush():
        if not lines:
            return
        text = "\n".join(t for _, t in lines)
        starts = _detector.line_starts(text)
        for m in detect.scan(text):
            if not _wanted(m, pii):
                continue
            key = (ids.of(m.value), path)
            if key in seen:
                seen[key]["commits"] += 1
                continue
            lineno = lines[_detector.line_of(starts, m.start) - 1][0]
            seen[key] = {"id": key[0], "where": f"{path}:{lineno}", "commit": commit, "type": m.type,
                         "rule": m.kind, "len": len(m.value), "commits": 1}
        lines.clear()

    new_line = 0
    for raw in r.stdout.decode("utf-8", errors="replace").splitlines():
        if raw.startswith("commit "):
            flush()
            commit = raw.split(" ", 1)[1]
        elif raw.startswith("+++ "):
            flush()
            path = raw[6:] if raw.startswith("+++ b/") else raw[4:]
        elif raw.startswith("@@"):
            try:
                new_line = int(raw.split("+", 1)[1].split(",")[0].split(" ")[0])
            except (IndexError, ValueError):
                new_line = 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            lines.append((new_line, raw[1:]))
            new_line += 1
    flush()
    return list(seen.values())


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="List secrets by location, never by value.")
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--history", action="store_true", help="also scan every commit on every ref")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--max-commits", type=int, default=5000)
    args = ap.parse_args(argv)
    detect = _detector.load()
    paths = [Path(p) for p in args.paths]
    for p in paths:
        if not p.exists():
            print(f"secret-hygiene: {p} does not exist")
            return 2
    ids = Ids()
    tree = scan_tree(detect, paths, ids, args.pii)
    hist = scan_history(detect, paths[0] if paths[0].is_dir() else paths[0].parent, ids, args.pii,
                        args.max_commits) if args.history else []
    print(f"Working tree: {len(tree)} finding(s)")
    for f in tree:
        print(f"  {f['id']:<4} {f['type']:<7} {f['rule']:<24} len {f['len']:<4} {f['git']:<9} {f['where']}")
    if args.history:
        in_tree = {f["id"] for f in tree}
        print(f"Git history: {len(hist)} finding(s)")
        for f in hist:
            now = "still in tree" if f["id"] in in_tree else "only in history"
            print(f"  {f['id']:<4} {f['type']:<7} {f['rule']:<24} len {f['len']:<4} "
                  f"commit {f['commit']} (+{f['commits'] - 1} more) {now:<15} {f['where']}")
    print("Values are not shown. The same id means the same value.")
    return 1 if tree or hist else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
