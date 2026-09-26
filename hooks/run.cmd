@echo off
rem Hook launcher for Windows without Git Bash. Codex runs the commandWindows entry of
rem hooks/hooks.json as   cmd.exe /C "<command>"   with the payload on stdin (codex-rs,
rem hooks/src/engine/command_runner.rs, read 2026-09-26). A batch file hands stdin to its
rem child untouched; a PowerShell launcher lost it (the host consumed the stream, measured
rem in the Windows matrix job). Same job as run.sh: find a Python 3.11+, run dispatch.py.
rem Fails closed: without Python exit 2 (a block in Claude Code; Codex runs the tool anyway
rem on a failed hook, so the message names the missing piece).
rem Usage: run.cmd <user-prompt|pre-tool|post-tool|session-start>
set PYTHONUTF8=1
set "HERE=%~dp0"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 (
  py -3 "%HERE%dispatch.py" %*
  goto :done
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 (
  python "%HERE%dispatch.py" %*
  goto :done
)
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 (
  python3 "%HERE%dispatch.py" %*
  goto :done
)
if "%~1"=="post-tool" (
  rem both shapes: updatedToolOutput for Claude Code, decision/reason for Codex
  echo {"decision":"block","reason":"[maisecrets needs Python 3.11 or newer. Install it with: winget install Python.Python.3.12 - then restart the client. Tool output withheld; the tool ran and finished, do not run it again.]","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"[maisecrets needs Python 3.11 or newer. Install it with: winget install Python.Python.3.12 - then restart the client. Tool output withheld; the tool ran and finished, do not run it again.]"}}
  exit /b 0
)
echo maisecrets needs Python 3.11 or newer (tried py -3, python, python3). Install it with: winget install Python.Python.3.12 - then restart the client. Until then every prompt and command is blocked; the command did not run. 1>&2
exit /b 2
:done
exit /b %errorlevel%
