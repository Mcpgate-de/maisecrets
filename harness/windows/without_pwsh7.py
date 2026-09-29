"""Run a command on a Windows machine as if PowerShell 7 were not installed, the state of a stock Windows 11.

Claude Code 2.1.284 looks for pwsh on PATH and then at %ProgramFiles%\\PowerShell\\7\\pwsh.exe before it falls
back to Windows PowerShell 5.1. The CI job itself runs in pwsh 7, which hands every native child the real
ProgramFiles whatever the job sets (measured: `$env:ProgramFiles` and a process-level
SetEnvironmentVariable both left a child on C:\\Program Files). Python passes its own environment on, so
the change is made here.

Usage: python harness/windows/without_pwsh7.py <command> [args ...]
"""
from __future__ import annotations

import os
import subprocess
import sys

env = dict(os.environ)
env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if "PowerShell\\7" not in p)
for name in ("ProgramFiles", "PROGRAMFILES"):
    env.pop(name, None)
env["ProgramFiles"] = r"C:\no-program-files"
code = ("import os, shutil; "
        "print('ProgramFiles seen by a child:', os.environ.get('ProgramFiles'), '| pwsh:', shutil.which('pwsh'))")
subprocess.run([sys.executable, "-c", code], env=env)
sys.exit(subprocess.run(sys.argv[1:], env=env).returncode)
