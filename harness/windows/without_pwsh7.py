"""Run a command on a Windows machine as if PowerShell 7 were not installed, the state of a stock Windows 11.

Claude Code 2.1.284 looks for pwsh on PATH and then at %ProgramFiles%\\PowerShell\\7\\pwsh.exe before it falls
back to Windows PowerShell 5.1. This wrapper takes PowerShell 7 off the PATH of the command. It cannot move
ProgramFiles: Windows sets that variable itself in every new process (measured: a child saw C:\\Program Files
after the job and this wrapper had set another value), so the CI job renames the PowerShell 7 folder.

Usage: python harness/windows/without_pwsh7.py <command> [args ...]
"""
from __future__ import annotations

import os
import subprocess
import sys

env = dict(os.environ)
env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if "PowerShell\\7" not in p)
code = ("import os, shutil; "
        "print('pwsh on the PATH of a child:', shutil.which('pwsh'))")
subprocess.run([sys.executable, "-c", code], env=env)
sys.exit(subprocess.run(sys.argv[1:], env=env).returncode)
