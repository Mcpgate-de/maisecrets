#!/usr/bin/env python3
"""List the secrets in a working tree and, with --history, in the git history.

The output never contains a value, a line of the file, or a hash of a value: it goes to a
cloud model. A finding is a location, a type, the rule, how sure the match is, the length,
and an id (S1, S2 ...). The same value gets the same id within one run, so a value found in
the tree and in the history carries one id. A hash would let a model test guesses against a
weak password; a per-run id cannot.

    python3 scan_secrets.py [PATH ...] [--history] [--pii] [--max-commits N] [--max-mb N] [--out FILE]

--out writes the full report to FILE and prints only the summary.

Exit code: 0 nothing found and the scan was complete, 1 findings, 2 error, 3 nothing found
but the history scan stopped early (--max-commits), so "nothing found" is not proven.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", ".next",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor", "target"}
# generated files: large, rarely hand-written, full of hashes that look like keys
SKIP_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock", "*.min.js",
              "*.min.css", "*.map", "*.svg")
MAX_BYTES = 2_000_000
# rules that match a keyword next to a value, not a provider's token format: they can be noise
GUESS_RULES = {"generic-api-key", "url-query-secret"}


def _is_guess(rule: str) -> bool:
    return rule in GUESS_RULES or rule.startswith("ds-keyword")


def _skipped(name: str) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in SKIP_FILES)


class Ids:
    def __init__(self) -> None:
        self._ids: dict[str, str] = {}

    def of(self, value: str) -> str:
        if value not in self._ids:
            self._ids[value] = f"S{len(self._ids) + 1}"
        return self._ids[value]


def _wanted(match, pii: bool) -> bool:
    return pii or match.type == "SECRET"


def _classify(detect, match) -> tuple[str, str]:
    """(rule, sure) where sure is 'shape' for a provider's token format and 'guess' for a keyword
    match. A keyword match whose value is itself a provider token (`TOKEN=ghp_…`) is named by the
    provider: the report then says which service to rotate (ops review, 2026-09-27)."""
    if not _is_guess(match.kind):
        return match.kind, "shape"
    for inner in detect.scan(match.value):
        if inner.type == "SECRET" and not _is_guess(inner.kind):
            return inner.kind, "shape"
    return match.kind, "guess"


def _files(paths: list[Path]):
    for root in paths:
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if not _skipped(name):
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


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True)


def _repo_root(cwd: Path) -> Path | None:
    r = _git(cwd, "rev-parse", "--show-toplevel")
    return Path(r.stdout.decode().strip()) if r.returncode == 0 else None


def _tracked(cwd: Path) -> set[str] | None:
    root = _repo_root(cwd)
    if root is None:
        return None
    r = _git(cwd, "ls-files", "-z", "--full-name")
    return {str((root / p).resolve()) for p in r.stdout.decode(errors="replace").split("\0") if p}


SKIPPED: list[str] = []      # files and file changes over MAX_BYTES; the report names them


def scan_tree(detect, paths: list[Path], ids: Ids, pii: bool) -> list[dict]:
    tracked = _tracked(paths[0] if paths[0].is_dir() else paths[0].parent)
    out = []
    for path in _files(paths):
        try:
            if path.stat().st_size > MAX_BYTES:
                SKIPPED.append(str(path))
                continue
        except OSError:
            continue
        text = _read(path)
        if not text:
            continue
        starts = _detector.line_starts(text)
        for m in detect.scan(text):
            if not _wanted(m, pii):
                continue
            if tracked is None:
                state = "no git"
            else:
                state = "tracked" if str(path.resolve()) in tracked else "untracked"
            rule, sure = _classify(detect, m)
            out.append({"id": ids.of(m.value), "where": f"{path}:{_detector.line_of(starts, m.start)}",
                        "type": m.type, "rule": rule, "sure": sure, "len": len(m.value), "git": state})
    return out


class Pushed:
    """Whether a commit is on a remote-tracking branch: pushed, local only, or no remote at all.
    As fresh as the last `git fetch`, which the report says."""

    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd
        self.has_remote = bool(_git(cwd, "remote").stdout.strip())
        self._cache: dict[str, str] = {}

    def of(self, commit: str) -> str:
        if not self.has_remote:
            return "no remote"
        if commit not in self._cache:
            r = _git(self.cwd, "branch", "-r", "--contains", commit)
            self._cache[commit] = "pushed" if r.returncode == 0 and r.stdout.strip() else "local only"
        return self._cache[commit]


def scan_history(detect, cwd: Path, ids: Ids, pii: bool, max_commits: int) -> tuple[list[dict], int, int]:
    """Added lines of every commit on every ref, newest first. One row per value and file: the
    newest commit that added it, its date and author, whether it was pushed, and how many commits
    added it. Returns (rows, commits scanned, commits in total)."""
    total = int(_git(cwd, "rev-list", "--all", "--count").stdout.decode().strip() or 0)
    r = _git(cwd, "log", "-p", "--all", "--no-color", "--no-ext-diff", "-U0", f"--max-count={max_commits}",
             "--date=short", "--format=commit %h %ad %an")
    if r.returncode != 0:
        raise RuntimeError("git log failed")
    pushed = Pushed(cwd)
    seen: dict[tuple[str, str], dict] = {}
    commit, date, author, path, lines = "", "", "", "", []
    scanned = 0

    def flush():
        if not lines or _skipped(os.path.basename(path)):
            lines.clear()
            return
        text = "\n".join(t for _, t in lines)
        if len(text) > MAX_BYTES:
            # a data dump in one commit made a 217-commit history take 71 s (2026-09-27); the
            # same size limit as for a file in the tree, and the report names what it skipped
            SKIPPED.append(f"{path} in commit {commit}")
            lines.clear()
            return
        starts = _detector.line_starts(text)
        for m in detect.scan(text):
            if not _wanted(m, pii):
                continue
            key = (ids.of(m.value), path)
            if key in seen:
                seen[key]["commits"] += 1
                seen[key]["first"] = date
                continue
            lineno = lines[_detector.line_of(starts, m.start) - 1][0]
            rule, sure = _classify(detect, m)
            seen[key] = {"id": key[0], "where": f"{path}:{lineno}", "commit": commit, "date": date,
                         "first": date, "author": author, "pushed": pushed.of(commit), "type": m.type,
                         "rule": rule, "sure": sure, "len": len(m.value), "commits": 1}
        lines.clear()

    new_line = 0
    for raw in r.stdout.decode("utf-8", errors="replace").splitlines():
        if raw.startswith("commit "):
            flush()
            scanned += 1
            parts = raw.split(" ", 3)
            commit, date, author = parts[1], parts[2] if len(parts) > 2 else "", parts[3] if len(parts) > 3 else ""
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
    return list(seen.values()), scanned, total


def report(tree: list[dict], hist: list[dict] | None, history_note: str) -> list[str]:
    out = [f"Working tree: {len(tree)} finding(s)"]
    for f in tree:
        out.append(f"  {f['id']:<4} {f['type']:<7} {f['rule']:<24} {f['sure']:<5} len {f['len']:<4} "
                   f"{f['git']:<9} {f['where']}")
    if hist is not None:
        in_tree = {}
        for f in tree:
            in_tree.setdefault(f["id"], f["where"])
        out.append(f"Git history: {len(hist)} finding(s)")
        for f in hist:
            more = f" (added in {f['commits']} commits, first {f['first']})" if f["commits"] > 1 else ""
            now = f"value also at {in_tree[f['id']]}" if f["id"] in in_tree else "only in history"
            out.append(f"  {f['id']:<4} {f['type']:<7} {f['rule']:<24} {f['sure']:<5} len {f['len']:<4} "
                       f"{f['pushed']:<10} commit {f['commit']} {f['date']} by {f['author']}{more}; "
                       f"{now}; {f['where']}")
    if history_note:
        out.append(history_note)
    if SKIPPED:
        mb = f"{MAX_BYTES / 1_000_000:g}"
        shown = "; ".join(SKIPPED[:5]) + (f"; and {len(SKIPPED) - 5} more" if len(SKIPPED) > 5 else "")
        out.append(f"NOT scanned, larger than {mb} MB (raise with --max-mb): {shown}.")
    rows = tree + (hist or [])
    ids = {f["id"] for f in rows}
    sure = Counter(f["sure"] for f in {f["id"]: f for f in rows}.values())
    out.append(f"Summary: {len(ids)} distinct value(s); {sure.get('shape', 0)} match a provider's token format, "
               f"{sure.get('guess', 0)} are keyword guesses that can be noise.")
    if hist:
        out.append("'pushed' is as fresh as the last git fetch.")
    out.append("Values are not shown. The same id means the same value. To see a value, open the file at the "
               "line yourself; do not paste it into the chat.")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="List secrets by location, never by value.")
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--history", action="store_true", help="also scan every commit on every ref")
    ap.add_argument("--pii", action="store_true", help="also list personal data (e-mail, IBAN, phone ...)")
    ap.add_argument("--max-commits", type=int, default=5000)
    ap.add_argument("--out", help="write the full report to this file and print only the summary")
    ap.add_argument("--max-mb", type=float, default=2.0,
                    help="skip a file, or a file change in one commit, larger than this (default 2); "
                         "the report names every skip")
    args = ap.parse_args(argv)
    global MAX_BYTES
    MAX_BYTES = int(args.max_mb * 1_000_000)
    detect = _detector.load()
    paths = [Path(p) for p in args.paths]
    for p in paths:
        if not p.exists():
            print(f"secret-hygiene: {p} does not exist")
            return 2
    ids = Ids()
    tree = scan_tree(detect, paths, ids, args.pii)
    hist, note, incomplete = None, "", False
    if args.history:
        cwd = paths[0] if paths[0].is_dir() else paths[0].parent
        if _repo_root(cwd) is None:
            note = "Git history: not scanned, this is not a git repository."
        else:
            try:
                hist, scanned, total = scan_history(detect, cwd, ids, args.pii, args.max_commits)
            except RuntimeError:
                print("secret-hygiene: git log failed; the history was not scanned")
                return 2
            if scanned < total:
                incomplete = True
                note = (f"WARNING: the history scan stopped after {scanned} of {total} commits "
                        f"(--max-commits). The older commits were NOT scanned.")
    lines = report(tree, hist, note)
    if args.out:
        Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote the full report to {args.out}.")
        print("\n".join(line for line in lines if not line.startswith("  ")))
    else:
        print("\n".join(lines))
    if tree or hist:
        return 1
    return 3 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
