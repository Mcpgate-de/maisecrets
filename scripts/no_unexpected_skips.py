#!/usr/bin/env python3
"""Fail when the unit suite skipped a test that CI must run.

A skipped test reads as green: without git in the image the skill's history tests were all
skipped and nothing noticed (2026-09-27). CI accepts two skips: the native-store test, which
needs a real keychain or Credential Locker, and the native clipboard test, which overwrites the
clipboard and runs in its own step on the macOS and Windows runners.

    python scripts/no_unexpected_skips.py unit.log [allowed reason ...]

The job on the oldest Python adds "tomllib is Python 3.11+": two checks of tooling files need
tomllib and run on the other Pythons.
"""
import re
import sys

ALLOWED = ("MAISECRETS_NATIVE_BACKEND_TEST", "MAISECRETS_NATIVE_CLIPBOARD_TEST",
           # the PowerShell part of hooks.json: the GitHub Windows and macOS runners have pwsh, the Linux
           # images of GitLab do not
           "pwsh is not installed")


def main(path: str, *extra: str) -> int:
    text = open(path, encoding="utf-8", errors="replace").read()
    allowed = ALLOWED + extra
    bad = [line.strip() for line in text.splitlines()
           if re.search(r"\.\.\. skipped ", line) and not any(a in line for a in allowed)]
    if not re.search(r"^Ran \d+ tests?", text, re.M):
        print("no unittest summary in the log: the suite did not run")
        return 1
    for line in bad:
        print("unexpected skip:", line)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
