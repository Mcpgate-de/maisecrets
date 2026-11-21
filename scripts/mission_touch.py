#!/usr/bin/env python3
"""The mission parts a change touches: which promises to keep in mind, which beliefs to check.

Each belief of beliefs/*.toml names the code its mutation breaks (`[proof]`: `file` and the `find` text), the tests
that must go red (`runner`) and the mission parts it serves (`serves`). This script reads the diff from BASE and
joins it with them:

- guarded code changed: a changed line of the diff lies in the `find` text of a proof. The mutation may no longer
  apply, or the line may no longer keep the part: check the belief, and the sentence of the part.
- test changed: a test file that a runner names changed.
- the other beliefs on a changed file, whose guarded lines did not change, are only counted.
- changed code that no proof names: no belief proves anything about this file.
- the controls that mission/code.toml declares for each changed program file, and a changed program file that it does
  not declare: keep each control of the file, and declare a new file (mission_coverage.py --strict goes red without).

It only reports and exits 0; scripts/replay_can_fail.py and scripts/mission_coverage.py are the gates.

    python3 scripts/mission_touch.py                    # from the merge base with origin/next to the work tree
    python3 scripts/mission_touch.py BASE               # from the merge base with BASE to the work tree
    python3 scripts/mission_touch.py BASE HEAD          # from the merge base with BASE to HEAD (CI)

Python 3.11+ (tomllib); with an older Python it says so and exits 0.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")
# the code that a belief can guard: the program files of the plugin (mission_coverage.py reads this one pattern)
CODE = re.compile(r"^(maisecrets/.*\.py|hooks/[^/]+\.(?:py|sh|cmd)|claude-mod/.*\.mjs|skills/[^/]+/scripts/.*\.py)$")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True).stdout


def changed_lines(base: str, head: str | None) -> dict[str, list[tuple[int, int]]]:
    """For each changed file: the line ranges of BASE that the diff touches, as (first, last). A pure insertion
    after line n is (n, n), so a line added inside a guarded block counts; a new file has no range."""
    diff = git("diff", "-U0", "--no-renames", "--no-color", base, *([head] if head else []))
    out: dict[str, list[tuple[int, int]]] = {}
    path = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path = line.split(" b/", 1)[1] if " b/" in line else None
            if path is not None:
                out.setdefault(path, [])
        elif path is not None and (m := HUNK.match(line)):
            start, count = int(m.group(1)), int(m.group(2) or "1")
            out[path].append((start, start + count - 1) if count else (start, start))
    return out


def proofs(belief: dict) -> list[dict]:
    p = belief.get("proof", [])
    return [x for x in ([p] if isinstance(p, dict) else p) if isinstance(x, dict) and isinstance(x.get("file"), str)]


def tests_of(belief: dict) -> list[tuple[str, str]]:
    """(file, test name) for each runner entry; the name is empty when the entry names a whole file."""
    runner = belief.get("runner", [])
    out = []
    for r in (runner if isinstance(runner, list) else [runner]):
        if isinstance(r, str) and r.split("::", 1)[0].endswith((".py", ".ts", ".mjs")):
            bits = r.split("::")
            out.append((bits[0], bits[-1] if len(bits) > 1 else ""))
    return out


def function_lines(text: str, name: str) -> tuple[int, int] | None:
    """The lines of `def name(` up to the next line at the same or a lower indent; None when absent or when the runner
    names a whole file (name empty): an edit somewhere in that file does not change this belief's test."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(rf"(\s*)(?:async\s+)?def {re.escape(name)}\(", line) if name else None
        if m:
            indent = len(m.group(1))
            end = next((j for j in range(i + 1, len(lines))
                        if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) <= indent), len(lines))
            return i + 1, end
    return None


def block(base: str, path: str, find: str, cache: dict) -> tuple[int, int] | None:
    """The lines of BASE:path that hold the find text, or None when BASE does not hold it."""
    if path not in cache:
        try:
            cache[path] = git("show", f"{base}:{path}")
        except subprocess.CalledProcessError:
            cache[path] = ""
    at = cache[path].find(find) if find else -1
    if at < 0:
        return None
    first = cache[path].count("\n", 0, at) + 1
    return first, first + find.rstrip("\n").count("\n")


def tomls(rev: str, prefix: str) -> list[tuple[str, dict]]:
    """Each .toml under prefix at rev, parsed: the beliefs of the merge base name the lines of the merge base."""
    import tomllib
    paths = [p for p in git("ls-tree", "-r", "--name-only", rev, "--", prefix).splitlines() if p.endswith(".toml")]
    raw = subprocess.run(["git", "-C", str(ROOT), "cat-file", "--batch"],
                         input="".join(f"{rev}:{p}\n" for p in paths).encode(), check=True, capture_output=True).stdout
    out, at = [], 0
    for p in paths:
        header_end = raw.index(b"\n", at)
        size = int(raw[at:header_end].split()[2])
        out.append((p, tomllib.loads(raw[header_end + 1:header_end + 1 + size].decode("utf-8"))))
        at = header_end + 1 + size + 1
    return out


def parts_of(rev: str) -> dict[str, str]:
    says: dict[str, str] = {}
    for _, mission in tomls(rev, "mission/"):
        for part in mission.get("part", []):
            if isinstance(part, dict) and isinstance(part.get("id"), str):
                says[part["id"]] = str(part.get("says", ""))
    return says


def declared_controls(head: str | None, paths: list[str]) -> tuple[list[str], list[str]]:
    """(lines "file: C1, C2" or "file: none", files the register does not declare) for the changed program files,
    from mission/code.toml of HEAD, or of the work tree when HEAD is None."""
    import tomllib
    try:
        text = git("show", f"{head}:mission/code.toml") if head else (ROOT / "mission" / "code.toml").read_text(
            encoding="utf-8")
        register = tomllib.loads(text).get("file", {})
    except (subprocess.CalledProcessError, OSError, ValueError):
        register = {}
    lines, missing = [], []
    for p in paths:
        entry = register.get(p)
        if not isinstance(entry, dict):
            missing.append(p)
        else:
            controls = entry.get("controls")
            lines.append(f"{p}: {', '.join(controls)}" if isinstance(controls, list) else f"{p}: none")
    return lines, missing


def report(base: str, head: str | None) -> str:
    merge_base = git("merge-base", base, head or "HEAD").strip()
    changed = changed_lines(merge_base, head)
    says = parts_of(merge_base)
    cache: dict[str, str] = {}
    guarded: dict[str, list[str]] = {}      # part -> lines of the report
    tested: dict[str, list[str]] = {}
    same_file: dict[str, int] = {}
    named: set[str] = set()
    for path, b in tomls(merge_base, "beliefs/"):
        name = str(b.get("belief", Path(path).stem))
        serves = [s for s in b.get("serves", []) if isinstance(s, str)] or ["(no part)"]
        hit, near = [], False
        for p in proofs(b):
            named.add(p["file"])
            if p["file"] not in changed:
                continue
            lines = block(merge_base, p["file"], p.get("find", ""), cache)
            if lines and any(a <= lines[1] and b_ >= lines[0] for a, b_ in changed[p["file"]]):
                hit.append(f"{p['file']}:{lines[0]}-{lines[1]}")
            else:
                near = True
        tests = []
        for file, test in tests_of(b):
            if file not in changed:
                continue
            if file not in cache:
                block(merge_base, file, "", cache)
            lines = function_lines(cache[file], test)
            if lines and any(a <= lines[1] and b_ >= lines[0] for a, b_ in changed[file]):
                tests.append(f"{file}::{test}")
        tests = sorted(set(tests))
        near = near or (not hit and not tests and any(f in changed for f, _ in tests_of(b)))
        for part in serves:
            if hit:
                guarded.setdefault(part, []).append(f"{name} ({', '.join(hit)})")
            elif tests:
                tested.setdefault(part, []).append(f"{name} ({', '.join(tests)})")
            elif near:
                same_file[part] = same_file.get(part, 0) + 1
    new = git("ls-files", "--others", "--exclude-standard").splitlines() if head is None else []
    unguarded = sorted(p for p in set(changed) | set(new) if CODE.match(p) and p not in named)
    touched = sorted(set(guarded) | set(tested),
                     key=lambda s: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s)])
    out = [f"mission_touch: {merge_base[:8]}..{(head or 'work tree')[:12]}: {len(changed)} files changed, "
           f"{len(touched)} mission parts touched"]
    for part in touched:
        out.append(f"{part}  {says.get(part, '')}".rstrip())
        out += [f"  guarded code changed: {x}" for x in guarded.get(part, [])]
        out += [f"  test changed: {x}" for x in tested.get(part, [])]
    if same_file:
        out.append("Beliefs on a changed file whose guarded lines did not change: "
                   + ", ".join(f"{k} {v}" for k, v in sorted(same_file.items())))
    if unguarded:
        out.append("Changed code that no belief guards: " + ", ".join(unguarded))
    program = sorted(p for p in set(changed) | set(new) if CODE.match(p) and (ROOT / p).exists())
    lines, missing = declared_controls(head, program)
    if lines:
        out.append("Controls of the changed program files (mission/code.toml): " + "; ".join(lines))
    if missing:
        out.append("Changed program files that mission/code.toml does not declare: " + ", ".join(missing))
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if sys.version_info < (3, 11):
        print("mission_touch: needs Python 3.11+ (tomllib); skipped")
        return 0
    base = argv[0] if argv else "origin/next"
    print(report(base, argv[1] if len(argv) > 1 else None))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
