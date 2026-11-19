#!/usr/bin/env python3
"""The scope of a merge request into next: does it need the test suites (.gitlab-ci.yml)?

    results  every changed entry is a measurement result or the format-watch snapshot, a regular file of a known
             type: the job baseline_only runs the tests that read those files, and the other test jobs do not run
    code     anything else, .gitlab-ci.yml included: every test job runs

GitLab cannot say "only these paths changed", so the rules in .gitlab-ci.yml name every other path
(`code_globs()`, written into the list .code_paths). A merge request that changes none of them runs only
baseline_only, and its guard (`check`) reads the diff again: the names, the file modes and the binary files. A change
that is not of the class results turns the job red, so no path skips the tests unseen.

    python3 scripts/mr_scope.py classify BASE   # prints results or code for BASE..HEAD
    python3 scripts/mr_scope.py check BASE      # exit 1 and the refused entries when BASE..HEAD is not results
    python3 scripts/mr_scope.py tests           # the test modules that read the result files
    python3 scripts/mr_scope.py globs           # the patterns of .code_paths in .gitlab-ci.yml
"""
from __future__ import annotations

import functools
import re
import subprocess
import sys
from collections import defaultdict
from typing import NamedTuple

# what scripts/release_gate.py --keep writes, the other measurement runs, and the snapshot of scripts/watch_formats.py
RESULT_DIRS = ("bench/results",)
RESULT_FILES = ("bench/HOLDOUT-LOG.md", "docs/coverage.json", "docs/format-watch.txt", "docs/format-watch-fp.txt")
# the file types of the runs in bench/results that a baseline merge request adds (2026-11: .json.gz, .json.log,
# .json, .jsonl, .md, .txt, SHA256SUMS); an older run also holds .csv, .diff and .jsonl.gz, which go through the suites
RESULT_SUFFIXES = (".json.gz", ".json", ".jsonl", ".log", ".md", ".txt")
RESULT_NAMES = ("SHA256SUMS",)
GZIP = b"\x1f\x8b"

# the modules that read the result files, or run a script that reads them (tests/test_mr_scope.py finds them with grep
# and fails when one is missing here)
TESTS = ("tests.test_mr_scope", "tests.test_baseline_only", "tests.test_extended_baseline", "tests.test_format_intake",
         "tests.test_readme_moved_sections", "tests.test_release_gate", "tests.test_release_tools",
         "tests.test_release_tree", "tests.test_tree_size", "tests.test_tree_types", "tests.test_watch_formats")


class Entry(NamedTuple):
    path: str
    mode: str            # the new mode; 000000 for a deleted entry
    binary: bool         # git diff --numstat shows "-"
    head: bytes = b""    # the first bytes of the new blob of a binary entry


def _plain(path: str) -> bool:
    parts = path.split("/")
    return bool(path) and "\\" not in path and all(p not in ("", ".", "..") for p in parts)


def is_result(path: str) -> bool:
    return _plain(path) and (path in RESULT_FILES or any(path.startswith(d + "/") for d in RESULT_DIRS))


def classify(paths: list[str]) -> str:
    """results or code. No path or an odd path is code: every test job runs."""
    if paths and all(is_result(p) for p in paths):
        return "results"
    return "code"


def refused(entries: list[Entry]) -> list[str]:
    """The entries a results merge request may not hold, each with the reason. A deleted result is allowed."""
    out = []
    for e in entries:
        if not is_result(e.path):
            out.append(f"{e.path}: no measurement result")
        elif e.mode == "000000":
            continue
        elif e.mode != "100644":
            out.append(f"{e.path}: mode {e.mode}, only a regular file (no symlink, no submodule, no executable)")
        elif e.path.startswith(tuple(d + "/" for d in RESULT_DIRS)) and not (
                e.path.endswith(RESULT_SUFFIXES) or e.path.rsplit("/", 1)[-1] in RESULT_NAMES):
            out.append(f"{e.path}: a file type that no baseline holds ({', '.join(RESULT_SUFFIXES + RESULT_NAMES)})")
        elif e.binary and not (e.path.endswith(".gz") and e.head.startswith(GZIP)):
            out.append(f"{e.path}: a binary file that is no gzip result")
    return out


def _git(*args: str) -> bytes:
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def entries(base: str, head: str = "HEAD") -> list[Entry]:
    """The changed entries of BASE..HEAD with their new mode, from git diff --raw and --numstat."""
    raw = _git("diff", "--raw", "-z", "--no-renames", "--no-abbrev", base, head).split(b"\0")
    binary = set()
    for rec in _git("diff", "--numstat", "-z", "--no-renames", base, head).split(b"\0"):
        added, _, rest = rec.partition(b"\t")
        if added == b"-":
            binary.add(rest.partition(b"\t")[2].decode("utf-8", "replace"))
    out = []
    for meta, path in zip(raw[0::2], raw[1::2]):
        if not meta.startswith(b":"):
            continue
        _, new_mode, _, new_sha, _ = meta[1:].decode().split(" ")
        name = path.decode("utf-8", "replace")
        blob = b""
        if name in binary and new_mode != "000000":
            blob = _git("cat-file", "blob", new_sha)[:4]
        out.append(Entry(name, new_mode, name in binary, blob))
    return out


# --- the patterns of .code_paths -------------------------------------------------------------------------------

def _bracket(chars: list[str]) -> str:
    # a "-" is literal only as the last character of a bracket (Ruby File.fnmatch, which GitLab uses)
    return "[!" + "".join(sorted(c for c in chars if c != "-")) + ("-" if "-" in chars else "") + "]"


def _others(names: set[str]) -> list[str]:
    """Glob alternatives that match one path segment exactly when it is not one of `names`."""
    alts: list[str] = []

    def walk(prefix: str) -> None:
        nxt = sorted({n[len(prefix)] for n in names if n.startswith(prefix) and len(n) > len(prefix)})
        if prefix and prefix not in names:
            alts.append(prefix)
        alts.append(prefix + (_bracket(nxt) + "*" if nxt else "?*"))
        for c in nxt:
            walk(prefix + c)

    walk("")
    return alts


def _brace(alts: list[str]) -> str:
    return alts[0] if len(alts) == 1 else "{" + ",".join(alts) + "}"


def code_globs() -> list[str]:
    """Patterns for GitLab rules:changes that match every path outside RESULT_DIRS and RESULT_FILES."""
    spec: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"files": set(), "dirs": set(), "via": set()})
    for path, kind in [(f, "files") for f in RESULT_FILES] + [(d, "dirs") for d in RESULT_DIRS]:
        parts = path.split("/")
        for i in range(len(parts) - 1):
            spec["/".join(parts[:i])]["via"].add(parts[i])
        spec["/".join(parts[:-1])][kind].add(parts[-1])
    out = []
    for folder in sorted(spec):
        s, pre = spec[folder], folder + "/" if folder else ""
        other = _brace(_others(s["files"] | s["dirs"] | s["via"]))
        out.append(pre + other)                   # a file of another name
        out.append(pre + other + "/**/*")         # a file in a folder of another name
        # a folder named like a light file, a file named like a light folder
        out.append(pre + _brace(sorted([f + "/**/*" for f in s["files"]] + sorted(s["dirs"] | s["via"]))))
    return out


def _expand(pattern: str) -> list[str]:
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    return [x for alt in m.group(1).split(",") for x in _expand(pattern[:m.start()] + alt + pattern[m.end():])]


def _regex(pattern: str) -> str:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:[^/]*/)*", i + 3
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        elif pattern[i] == "[":
            end = pattern.index("]", i + 2)
            body = pattern[i + 1:end]
            neg = body[:1] in ("!", "^")
            chars = body[1:] if neg else body
            out += "[" + ("^/" if neg else "") + "".join(re.escape(c) for c in chars) + "]"
            i = end + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return out


@functools.lru_cache(maxsize=None)
def _compiled(pattern: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{_regex(p)})" for p in _expand(pattern)))


def glob_match(pattern: str, path: str) -> bool:
    """GitLab rules:changes: File.fnmatch? with FNM_PATHNAME | FNM_DOTMATCH | FNM_EXTGLOB, for the forms used here
    (braces, *, ?, [!...] without ranges, **/)."""
    return bool(_compiled(pattern).fullmatch(path))


def main(argv: list[str]) -> int:
    if argv == ["globs"]:
        for g in code_globs():
            print(g)
        return 0
    if argv == ["tests"]:
        print(" ".join(TESTS))
        return 0
    if len(argv) == 2 and argv[0] == "classify" and argv[1]:
        print(classify([e.path for e in entries(argv[1])]))
        return 0
    if len(argv) == 2 and argv[0] == "check" and argv[1]:
        found = entries(argv[1])
        bad = refused(found) if found else ["(no change)"]
        if not bad:
            print(f"mr_scope: {len(found)} changed entries, all measurement results")
            return 0
        print("mr_scope: the pipeline rules (.code_paths) ran baseline_only alone, but this merge request holds more "
              "than measurement results. Refused:")
        for line in bad:
            print(f"  {line}")
        print("Split the merge request, or fix .code_paths (python3 scripts/mr_scope.py globs).")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
