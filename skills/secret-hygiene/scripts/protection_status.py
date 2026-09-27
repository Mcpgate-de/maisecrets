#!/usr/bin/env python3
"""Is the maisecrets protection (the hooks) active for this agent right now?

The hooks write one line per run to ~/.maisecrets/hooks.log. When they are active, the prompt
that loaded this skill went through them a moment ago, so a line from the last few minutes is
there. This script prints only a verdict, the client and the age of the last line: never a
line of the log, a path of the user's project or a value.

    python3 protection_status.py

Exit code: 0 active, 1 not active (the protection is not installed, not trusted, or not
running in this session).
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import sys
from pathlib import Path

RECENT_SECONDS = 300
REPO = "https://github.com/Mcpgate-de/maisecrets.git"


def home() -> Path:
    return Path(os.environ.get("MAISECRETS_HOME") or Path.home() / ".maisecrets")


def last_run() -> tuple[float | None, str]:
    """Seconds since the last hook run and its client, from the run log's last line."""
    log = home() / "hooks.log"
    try:
        with open(log, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 4096))
            tail = fh.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return None, ""
    for line in reversed(tail):
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            when = dt.datetime.fromisoformat(parts[0])
        except ValueError:
            continue
        return (dt.datetime.now() - when).total_seconds(), parts[2]
    return None, ""


def installed(cli: str) -> bool | None:
    """Whether `cli plugin list` names maisecrets; None when the CLI is not on this machine."""
    if not shutil.which(cli):
        return None
    try:
        r = subprocess.run([cli, "plugin", "list"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return "maisecrets" in (r.stdout + r.stderr)


def main() -> int:
    age, client = last_run()
    active = age is not None and 0 <= age <= RECENT_SECONDS
    codex, claude = installed("codex"), installed("claude")
    py_ok = sys.version_info >= (3, 11)
    if active:
        print(f"maisecrets protection: ACTIVE ({client or 'agent'} hooks ran {int(age)} s ago).")
        return 0
    print("maisecrets protection: NOT ACTIVE. A secret typed or pasted into a prompt reaches the AI provider.")
    if age is None:
        print("No maisecrets hook has run on this machine.")
    else:
        print(f"The last maisecrets hook ran {int(age // 60)} min ago ({client or 'agent'}), not for this prompt.")
    for name, state in (("Codex", codex), ("Claude Code", claude)):
        if state is not None:
            print(f"{name}: plugin {'installed' if state else 'not installed'}.")
    if not py_ok:
        print("Python 3.11 or newer is needed for the hooks; this is " + sys.version.split()[0] + ".")
    print("To install (after the user's yes):")
    if codex is not None or claude is None:
        print(f"  Codex:       codex plugin marketplace add {REPO}")
        print("               codex plugin add maisecrets@maisecrets")
        print("               then open /hooks once and trust the maisecrets hooks, and start a new session")
    if claude is not None:
        print("  Claude Code: claude plugin marketplace add Mcpgate-de/maisecrets")
        print("               claude plugin install maisecrets@maisecrets")
        print("               then start a new session")
    if codex:
        print("The plugin is installed in Codex but its hooks did not run: trust them in /hooks, then start "
              "a new session.")
    if claude:
        print("The plugin is installed in Claude Code but its hooks did not run: start a new session "
              "(or /reload-plugins).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
