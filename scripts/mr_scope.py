#!/usr/bin/env python3
"""The scope of a merge request into next: which test jobs its changed paths need (.gitlab-ci.yml).

    results  every path is a measurement result or the format-watch snapshot: the job baseline_only runs the tests
             that read those files, and the other test jobs do not run
    ci       .gitlab-ci.yml changed, and at most docs/REPO-STANDARDS.md beside it: the job ci_only runs the tests
             that read those files, and one smoke job per runner image shows that the image starts. A changed line
             with a pinned version or image (PIN) makes it code: ci_only fails and asks for the label full-ci
    code     anything else, and a mix of two classes: every test job runs (the label full-ci runs them always)

GitLab cannot say "only these paths changed", so the rules in .gitlab-ci.yml name every other path
(`code_globs()`, written into the list .code_paths). The light jobs check the class again with `check`; a path set
that the rules let through but that is not of their class turns the job red, so no path skips the tests unseen.

    python3 scripts/mr_scope.py classify BASE      # prints results, ci or code for BASE..HEAD
    python3 scripts/mr_scope.py check CLASS BASE   # exit 1 and the other paths when BASE..HEAD is not CLASS
    python3 scripts/mr_scope.py tests CLASS        # the test modules that read the files of CLASS
    python3 scripts/mr_scope.py globs              # the patterns of .code_paths in .gitlab-ci.yml
"""
from __future__ import annotations

import functools
import re
import subprocess
import sys
from collections import defaultdict

# what scripts/release_gate.py --keep writes, the other measurement runs, and the snapshot of scripts/watch_formats.py
RESULT_DIRS = ("bench/results",)
RESULT_FILES = ("bench/HOLDOUT-LOG.md", "docs/coverage.json", "docs/format-watch.txt", "docs/format-watch-fp.txt")
CI_FILE = ".gitlab-ci.yml"
CI_FILES = (CI_FILE, "docs/REPO-STANDARDS.md")

# the modules that read the files of a class, or run a script that reads them (tests/test_mr_scope.py finds them
# with grep and fails when one is missing here)
TESTS = {
    "results": ("tests.test_mr_scope", "tests.test_baseline_only", "tests.test_extended_baseline",
                "tests.test_format_intake", "tests.test_readme_moved_sections", "tests.test_release_gate",
                "tests.test_release_tools", "tests.test_release_tree", "tests.test_tree_size",
                "tests.test_watch_formats"),
    "ci": ("tests.test_mr_scope", "tests.test_baseline_only", "tests.test_readme_moved_sections",
           "tests.test_release_gate", "tests.test_release_tools", "tests.test_release_tree", "tests.test_tree_size",
           "tests.test_user_rules"),
}


def _plain(path: str) -> bool:
    parts = path.split("/")
    return bool(path) and "\\" not in path and all(p not in ("", ".", "..") for p in parts)


def is_result(path: str) -> bool:
    return _plain(path) and (path in RESULT_FILES or any(path.startswith(d + "/") for d in RESULT_DIRS))


# a changed line of .gitlab-ci.yml with a pinned version or image: a test job uses it, so the merge request is code
# (a new client version is what the harness tests). GitLab rules cannot read diff lines; the guard of ci_only fails
# and asks for the label full-ci
PIN = re.compile(r"CLAUDE_CODE_VERSION|CODEX_VERSION|\bimage:|@sha256:|[A-Za-z0-9_.-]==\d")


def pinned(ci_lines: list[str]) -> list[str]:
    """The added or removed lines of a diff of .gitlab-ci.yml that hold a pinned version or image."""
    return [line for line in ci_lines if line[:1] in "+-" and not line.startswith(("+++", "---"))
            and PIN.search(line)]


def classify(paths: list[str], ci_lines: list[str] = ()) -> str:
    """results, ci or code. No path, an odd path, a mix of classes or a changed pin in .gitlab-ci.yml (`ci_lines`:
    the diff of that file) is code: every test job runs."""
    if not paths or not all(_plain(p) for p in paths):
        return "code"
    if all(is_result(p) for p in paths):
        return "results"
    if set(paths) <= set(CI_FILES) and CI_FILE in paths and not pinned(list(ci_lines)):
        return "ci"
    return "code"


def ci_diff(base: str, head: str = "HEAD") -> list[str]:
    return subprocess.run(["git", "diff", "-U0", "--no-renames", base, head, "--", CI_FILE], capture_output=True,
                          text=True, check=True).stdout.splitlines()


def changed(base: str, head: str = "HEAD") -> list[str]:
    out = subprocess.run(["git", "diff", "--name-only", "--no-renames", base, head], capture_output=True,
                         text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


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
    """Patterns for GitLab rules:changes that match every path outside RESULT_* and CI_FILES."""
    spec: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"files": set(), "dirs": set(), "via": set()})
    for path, kind in [(f, "files") for f in RESULT_FILES + CI_FILES] + [(d, "dirs") for d in RESULT_DIRS]:
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
    if argv[:1] == ["globs"] and len(argv) == 1:
        for g in code_globs():
            print(g)
        return 0
    if argv[:1] == ["tests"] and len(argv) == 2 and argv[1] in TESTS:
        print(" ".join(TESTS[argv[1]]))
        return 0
    if argv[:1] == ["classify"] and len(argv) == 2 and argv[1]:
        print(classify(changed(argv[1]), ci_diff(argv[1])))
        return 0
    if argv[:1] == ["check"] and len(argv) == 3 and argv[1] in TESTS and argv[2]:
        paths, lines = changed(argv[2]), ci_diff(argv[2])
        got = classify(paths, lines)
        if got == argv[1]:
            print(f"mr_scope: {len(paths)} changed paths, class {got}")
            return 0
        if pins := pinned(lines):
            print("mr_scope: a pinned version or image changed in .gitlab-ci.yml. A test job uses it, so this merge "
                  "request needs the full pipeline. Add the label full-ci and run a new pipeline. Changed lines:")
            for line in pins:
                print(f"  {line}")
            return 1
        print(f"mr_scope: this job tests the class {argv[1]}, but the merge request is of the class {got}. "
              f"The pipeline rules (.code_paths) ran the short jobs only. Changed paths:")
        for p in paths or ["(none)"]:
            print(f"  {p}")
        print("Split the merge request, or fix .code_paths (python3 scripts/mr_scope.py globs).")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
