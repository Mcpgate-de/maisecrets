#!/usr/bin/env python3
"""Re-derive the numbers the docs state, so a stale count fails CI instead of a reader.

The first public review found the test count wrong in two files and the scenario count wrong
in one; each had been true once. A number in prose inherits the reference point of whoever
typed it. This script measures each declared number again and refuses a mismatch.

    python3 scripts/derived_counts.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def count_tests() -> int:
    """The tests `unittest discover -s tests` loads, counted without running them: running the
    suite to read "Ran N" took 59 s in CI and ran the suite a second time in the pre-push hook
    (2026-09-28). A module that fails to import is a _FailedTest, so it cannot shrink the count
    silently; it fails the run instead."""
    code = ("import sys, unittest\n"
            "suite = unittest.defaultTestLoader.discover('tests')\n"
            "def walk(s):\n"
            "    for t in s:\n"
            "        yield from (walk(t) if isinstance(t, unittest.TestSuite) else [t])\n"
            "tests = list(walk(suite))\n"
            "broken = [t.id() for t in tests if type(t).__name__ == '_FailedTest']\n"
            "print(-1 if broken else len(tests))\n"
            "print(*broken, sep='\\n', file=sys.stderr)\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=120)
    try:
        return int(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return -1


def count_scenarios(path: str, marker: str) -> int:
    """Top-level entries of the SCENARIOS dict: four spaces, a name, an opening brace."""
    text = (ROOT / path).read_text(encoding="utf-8")
    return len(re.findall(marker, text, re.M))


def declared(path: str, pattern: str) -> int | None:
    m = re.search(pattern, (ROOT / path).read_text(encoding="utf-8"), re.M)
    return int(m.group(1)) if m else None


def main() -> int:
    checks = [
        ("docs/TESTING.md tests", declared("docs/TESTING.md", r"^(\d+) tests \(`tests/"), count_tests()),
        ("README Claude scenarios", declared("README.md", r"harness/run.py\s+# (\d+) scenarios"),
         count_scenarios("harness/run.py", r'^    "[a-z_]+": \{$')),
        ("README Codex scenarios", declared("README.md", r"harness/codex.py \[--real\]\s+# (\d+) scenarios"),
         count_scenarios("harness/codex.py", r'^    "[a-z_]+": \{$')),
        ("README beliefs", declared("README.md", r"replay_can_fail.py\s+# (\d+) proofs"),
         len(list((ROOT / "beliefs").glob("*.toml")))),
    ]
    rc = 0
    for name, stated, measured in checks:
        ok = stated == measured
        rc |= not ok
        print(f"[{'ok ' if ok else 'BAD'}] {name}: stated {stated}, measured {measured}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
