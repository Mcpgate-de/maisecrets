#!/usr/bin/env bash
# Hook launcher: picks the Python interpreter this machine has.
#   macOS / Linux: python3 (always present or one package away)
#   Windows: Claude Code requires Git Bash, so this script runs there too; Python
#            installs as python.exe or the py launcher (winget install Python.Python.3.12)
# Usage: run.sh <user-prompt|pre-tool|post-tool|session-start> | run.sh report [last|n] [note]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
for PY in python3 python "py -3"; do
  if $PY -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >/dev/null 2>&1; then
    exec $PY "$HERE/dispatch.py" "$@"
  fi
done
echo "maisecrets: no Python 3.11+ found (tried python3, python, py -3); prompt blocked" >&2
exit 2   # fail closed: without the detector nothing may pass
