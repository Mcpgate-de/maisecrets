#!/usr/bin/env bash
# Hook launcher: picks the Python interpreter this machine has.
#   macOS / Linux: python3 (a stock Mac ships 3.9 in /usr/bin; Homebrew and python.org put
#                  a newer one in /opt/homebrew/bin, /usr/local/bin or /Library/Frameworks)
#   Windows: Claude Code requires Git Bash, so this script runs there too; Python
#            installs as python.exe or the py launcher (winget install Python.Python.3.12)
# Usage: run.sh <user-prompt|pre-tool|post-tool|session-start> | run.sh <cli command…>
set -u
# the payload is UTF-8 JSON; on Windows python.exe would otherwise decode a pipe with the
# console code page and a prompt with umlauts fails the hook (fail closed, but for no reason)
export PYTHONUTF8=1
HERE="$(cd "$(dirname "$0")" && pwd)"
FOUND=""
for PY in python3 python "py -3" python3.14 python3.13 python3.12 python3.11 \
          /opt/homebrew/bin/python3 /usr/local/bin/python3 \
          /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
  if $PY -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >/dev/null 2>&1; then
    exec $PY "$HERE/dispatch.py" "$@"
  fi
  V="$($PY -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null)" && FOUND="${FOUND:+$FOUND, }$PY is $V"
done
MSG="maisecrets needs Python 3.11 or newer on the PATH of the client (found: ${FOUND:-none}). Install it: macOS 'brew install python' or python.org, Windows 'winget install Python.Python.3.12', Linux your package manager; then restart the client."
case "${1:-}" in
  post-tool)
    # Claude Code ignores exit 2 here and would show the raw output to the model: answer
    # fail-closed with the JSON the hook itself would give (review, 2026-09-26)
    printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"[%s Tool output withheld; the tool ran and finished, do not run it again.]"}}' "$MSG"
    exit 0 ;;
  session-start)
    printf '{"systemMessage":"%s Until then every prompt is blocked."}' "$MSG"
    exit 0 ;;
esac
echo "$MSG Until then every prompt is blocked." >&2
exit 2   # fail closed: without the detector nothing may pass
