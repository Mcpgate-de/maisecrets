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
# no size limit and no list of "generated" files: a data dump, a log and a bundled script are
# where leaks sit (a 2 MB limit dropped a JWT in a SQL dump; review, 2026-09-27). Only a file
# that is binary (a NUL byte in its first 4 KiB) is passed over, and the report names it.
SKIP_FILES: tuple = ()
MAX_BYTES = 0      # 0: no limit; --max-mb sets one for a quick first look
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


def _wanted_type(mtype: str, pii: bool) -> bool:
    return pii or mtype == "SECRET"


def _classify(kind: str, inner: str | None) -> tuple[str, str]:
    """(rule, sure) where sure is 'shape' for a provider's token format and 'guess' for a keyword
    match. A keyword match whose value is itself a provider token (`TOKEN=ghp_…`) is named by the
    provider: the report then says which service to rotate (ops review, 2026-09-27)."""
    if not _is_guess(kind):
        return kind, "shape"
    if inner and not _is_guess(inner):
        return inner, "shape"
    return kind, "guess"


PARALLEL_BYTES = 1_000_000   # below this the scan stays in one process: starting workers costs more
SPLIT_BYTES = 2_000_000      # a file above this is scanned in pieces on several cores (no content is skipped)


def run_jobs(jobs, total_bytes: int):
    """Yield (tag, matches) for every job (tag, text), in job order, on every core when there is
    enough text to be worth it."""
    if total_bytes < PARALLEL_BYTES:
        _detector._worker_init(ENABLED)
        for job in jobs:
            yield _detector.worker_scan(job)
        return
    import os
    with _detector.pool(ENABLED) as ex:
        window = 4 * (os.cpu_count() or 2)
        pending = []
        for job in jobs:
            pending.append(ex.submit(_detector.worker_scan, job))
            if len(pending) >= window:
                yield pending.pop(0).result()
        for f in pending:
            yield f.result()


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
    """The text of a file, "" when it cannot be read, None when it is binary."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
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


ENABLED: set | None = None   # the rule ids that run; None runs every rule (--pii)
SKIPPED: list[str] = []      # files and file changes over --max-mb; the report names them
BINARY: list[str] = []       # binary files, passed over; the report counts them


def scan_tree(detect, paths: list[Path], ids: Ids, pii: bool) -> list[dict]:
    tracked = _tracked(paths[0] if paths[0].is_dir() else paths[0].parent)
    files, total = [], 0
    for path in _files(paths):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if MAX_BYTES and size > MAX_BYTES:
            SKIPPED.append(str(path))
            continue
        files.append(path)
        total += size

    def jobs():
        for path in files:
            text = _read(path)
            if text is None:
                BINARY.append(str(path))
                continue
            if not text:
                continue
            if len(text) <= SPLIT_BYTES:
                yield (str(path), 0), text
                continue
            # a large file goes to several cores in overlapping line pieces
            lines = text.split("\n")
            offs = [0]
            for line in lines:
                offs.append(offs[-1] + len(line) + 1)
            step = max(1, len(lines) * SPLIT_BYTES // len(text))
            i = 0
            while i < len(lines):
                j = min(len(lines), i + step)
                yield (str(path), offs[i]), text[offs[i]:offs[j] - 1 if j < len(lines) else len(text)]
                if j >= len(lines):
                    break
                i = j - _detector.CHUNK_OVERLAP
    out = []
    by_path: dict[str, dict] = {}
    for (tag, base), found in run_jobs(jobs(), total):
        for start, end, mtype, kind, value, inner in found:
            by_path.setdefault(tag, {})[(start + base, end + base)] = (mtype, kind, value, inner)
    for tag in [str(p) for p in files if str(p) in by_path]:
        path = Path(tag)
        text = _read(path) or ""
        starts = _detector.line_starts(text)
        for (start, _end), (mtype, kind, value, inner) in sorted(by_path[tag].items()):
            if not _wanted_type(mtype, pii):
                continue
            if tracked is None:
                state = "no git"
            else:
                state = "tracked" if str(path.resolve()) in tracked else "untracked"
            rule, sure = _classify(kind, inner)
            out.append({"id": ids.of(value), "where": f"{path}:{_detector.line_of(starts, start)}",
                        "type": mtype, "rule": rule, "sure": sure, "len": len(value), "git": state})
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


def _safe_author(detect, name: str) -> str:
    """A git author name is text anybody can set: one that looks like a secret is not printed."""
    if any(m.type == "SECRET" for m in detect.scan(name)):
        return "(an author name that looks like a secret)"
    return name


BATCH = 150   # commits per worker job


def scan_history(detect, cwd: Path, ids: Ids, pii: bool, max_commits: int) -> tuple[list[dict], int, int]:
    """Added lines of every commit on every ref, newest first. One row per value and file: the
    newest commit that added it, its date and author, whether it was pushed, and how many commits
    added it. Each worker runs git log for its own batch of commits. Returns (rows, commits
    scanned, commits in total)."""
    listed = _git(cwd, "rev-list", "--all")
    if listed.returncode != 0:
        raise RuntimeError("git rev-list failed")
    shas = listed.stdout.decode().split()
    total = len(shas)
    if max_commits:
        shas = shas[:max_commits]
    pushed = Pushed(cwd)
    seen: dict[tuple[str, str], dict] = {}
    # small batches on a short history: one commit with a data dump must not hold a whole
    # batch on one core while the others wait (217 commits took 50 s in two batches of 150)
    batch = max(1, min(BATCH, len(shas) // (8 * (os.cpu_count() or 2)) or 1))
    jobs = [(i, str(cwd), shas[i:i + batch], MAX_BYTES) for i in range(0, len(shas), batch)]

    def results():
        if len(shas) <= 20:
            _detector._worker_init(ENABLED)
            for job in jobs:
                yield _detector.worker_history(job)
            return
        import os
        with _detector.pool(ENABLED) as ex:
            window = 2 * (os.cpu_count() or 2)
            pending = []
            for job in jobs:
                pending.append(ex.submit(_detector.worker_history, job))
                if len(pending) >= window:
                    yield pending.pop(0).result()
            for f in pending:
                yield f.result()
    for _idx, rows, skipped, rc in results():
        if rc != 0:
            raise RuntimeError("git log failed")
        SKIPPED.extend(skipped)
        for c, d, a, p, lineno, mtype, kind, value, inner in rows:
            if not _wanted_type(mtype, pii):
                continue
            key = (ids.of(value), p)
            if key in seen:
                seen[key]["commits"] += 1
                seen[key]["first"] = d
                continue
            rule, sure = _classify(kind, inner)
            seen[key] = {"id": key[0], "where": f"{p}:{lineno}", "commit": c, "date": d,
                         "first": d, "author": _safe_author(detect, a), "pushed": pushed.of(c), "type": mtype,
                         "rule": rule, "sure": sure, "len": len(value), "commits": 1}
    return list(seen.values()), len(shas), total


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
        out.append(f"NOT scanned, larger than {mb} MB (--max-mb): {shown}.")
    if BINARY:
        out.append(f"Passed over {len(BINARY)} binary file(s) in the working tree.")
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
    ap.add_argument("--max-commits", type=int, default=0, help="scan only the newest N commits (default: all)")
    ap.add_argument("--out", help="write the full report to this file and print only the summary")
    ap.add_argument("--max-mb", type=float, default=0,
                    help="skip a file, or a file change in one commit, larger than this, for a quick first "
                         "look (default: no limit); the report names every skip")
    args = ap.parse_args(argv)
    global MAX_BYTES
    MAX_BYTES = int(args.max_mb * 1_000_000)
    detect = _detector.load()
    global ENABLED
    ENABLED = None if args.pii else _detector.secret_rules(detect)
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
            except RuntimeError as exc:
                print(f"secret-hygiene: {exc}; the history was not scanned")
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
