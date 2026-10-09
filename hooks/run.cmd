@echo off
rem the detached marker child of :mark (below): only it touches the home, so a stalled home cannot hold the hook
if "%~1"=="__mark" goto :mark_now
set "MS_SELF=%~f0"
rem Hook launcher for Windows without Git Bash. Codex runs the commandWindows entry of
rem hooks/hooks.json as   cmd.exe /C "<command>"   with the payload on stdin (codex-rs,
rem hooks/src/engine/command_runner.rs, read 2026-09-26). A batch file hands stdin to its
rem child untouched; a PowerShell launcher lost it (the host consumed the stream, measured
rem in the Windows matrix job). Same job as run.sh: find a Python 3.9+, run dispatch.py.
rem Fails closed: without Python exit 2 (a block in Claude Code; Codex runs the tool anyway
rem on a failed hook, so the message names the missing piece).
rem Usage: run.cmd <user-prompt|pre-tool|post-tool|session-start>
set PYTHONUTF8=1
set "HERE=%~dp0"
rem One line per start, overwritten: when a hook does not act, this says whether the client started it and with
rem which environment. Codex clears the environment of a hook and replays a snapshot (codex-rs command_runner.rs);
rem on one Windows machine no hook acted with Python installed (2026-09-30). Names and paths only, never a payload.
set "MS_PATH=no"
if defined PATH set "MS_PATH=yes"
>"%HERE%last-start.txt" echo %DATE% %TIME% event=%~1 user=%USERNAME% profile=%USERPROFILE% localappdata=%LOCALAPPDATA% programfiles=%ProgramFiles% path=%MS_PATH%
rem Codex clears the environment of a hook and replays a snapshot (codex-rs command_runner.rs). Without these
rem variables Python finds no home directory and run.cmd no Python (measured on windows-latest, 2026-09-30).
if not defined SystemRoot set "SystemRoot=C:\Windows"
if not defined ProgramFiles set "ProgramFiles=C:\Program Files"
if not defined PATH set "PATH=%SystemRoot%\System32;%SystemRoot%"
if defined USERPROFILE goto :profile_set
rem the plugin sits in <profile>\.codex\...: the part before \.codex\ is the profile
set "MS_UP=%HERE:\.codex\=|%"
if "%MS_UP%"=="%HERE%" goto :profile_set
for /f "tokens=1 delims=|" %%A in ("%MS_UP%") do set "USERPROFILE=%%A"
:profile_set
if not defined LOCALAPPDATA if defined USERPROFILE set "LOCALAPPDATA=%USERPROFILE%\AppData\Local"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
  py -3 "%HERE%dispatch.py" %*
  goto :done
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
  python "%HERE%dispatch.py" %*
  goto :done
)
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
  python3 "%HERE%dispatch.py" %*
  goto :done
)
rem Not on PATH: the python.org installer (also through winget) leaves PATH alone unless asked, and an
rem open client keeps the PATH it started with (reported 2026-09-30: Python 3.12 installed, not found).
rem Look where that installer puts Python, for one user and for all users.
for %%P in ("%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" "%SystemRoot%\py.exe") do (
  if exist %%P (
    %%P -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if not errorlevel 1 (
      %%P -3 "%HERE%dispatch.py" %*
      goto :done
    )
  )
)
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "%ProgramFiles%\Python3*") do (
  if exist "%%~D\python.exe" (
    "%%~D\python.exe" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if not errorlevel 1 (
      "%%~D\python.exe" "%HERE%dispatch.py" %*
      goto :done
    )
  )
)
>>"%HERE%last-start.txt" echo no Python 3.9 or newer found
if "%~1"=="post-tool-failure" (
  echo {"systemMessage": "maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine. Then restart the client."}
  call :mark
  exit /b 0
)
if "%~1"=="post-tool" (
  rem both shapes: updatedToolOutput for Claude Code, decision/reason for Codex
  echo {"decision":"block","reason":"[maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Tool output withheld; the tool ran and finished, do not run it again.]","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"[maisecrets needs Python 3.9 or newer. Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Tool output withheld; the tool ran and finished, do not run it again.]"}}
  call :mark
  exit /b 0
)
echo maisecrets needs Python 3.9 or newer (tried py -3, python, python3 and the install folders of python.org). Install it for all users, as an administrator: winget install --id Python.Python.3.12 --exact --scope machine - a Python for one user only cannot run in the Codex sandbox. Then restart the client. Until then every prompt and command is blocked; the command did not run. 1>&2
call :mark
exit /b 2
:done
exit /b %errorlevel%

rem an incident marker for /maisecrets:report incident (docs/DIAGNOSTICS.md, section 3): after the answer, this file
rem starts itself again as a detached child with no window and no stream of the hook (start /b, every stream on nul),
rem so the client's pipe closes when the hook ends, and a stalled home cannot hold it (codex code review, round 2)
:mark
start "" /b cmd /d /c call "%MS_SELF%" __mark <nul >nul 2>&1
exit /b 0

rem the child: one md in a home that exists and is no reparse point (a junction), so md creates no parent and
rem follows nothing
:mark_now
set "MS_HOME=%MAISECRETS_HOME%"
if "%MS_HOME%"=="" set "MS_HOME=%USERPROFILE%\.maisecrets"
if not exist "%MS_HOME%\" exit /b 0
for %%A in ("%MS_HOME%") do set "MS_ATTR=%%~aA"
if /i "%MS_ATTR:~8,1%"=="l" exit /b 0
md "%MS_HOME%\incident-marker.launcher.no-python" >nul 2>&1
exit /b 0
