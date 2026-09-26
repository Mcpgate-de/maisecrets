#!/bin/bash
# Installs the repo's git hooks WITHOUT touching core.hooksPath.
#
# This machine runs a global hooks directory (core.hooksPath=~/.git-hooks)
# whose universal pre-commit delegates to `.git/hooks/pre-commit.local` when
# that file exists. So the repo's pre-commit is installed under that name.
# The global directory has no pre-push, so a repo pre-push cannot run under
# it; it is installed as `pre-push.local` for a delegating global pre-push.
#
# Never write core.hooksPath here: on 2026-09-26 an earlier version of this
# script resolved `git rev-parse --git-path hooks` to the GLOBAL directory and
# overwrote the universal hook. Restored from a transcript copy, 1867 bytes.
set -eu
ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$ROOT/.git/hooks"
mkdir -p "$HOOKS_DIR"
cp "$ROOT/.githooks/pre-commit" "$HOOKS_DIR/pre-commit.local"
cp "$ROOT/.githooks/pre-push"   "$HOOKS_DIR/pre-push.local"
cp "$ROOT/.githooks/pre-commit" "$HOOKS_DIR/pre-commit"
cp "$ROOT/.githooks/pre-push"   "$HOOKS_DIR/pre-push"
cp "$ROOT/.githooks/commit-msg" "$HOOKS_DIR/commit-msg"
cp "$ROOT/.githooks/commit-msg" "$HOOKS_DIR/commit-msg.local"
chmod +x "$HOOKS_DIR"/pre-commit "$HOOKS_DIR"/pre-push "$HOOKS_DIR"/commit-msg "$HOOKS_DIR"/*.local
echo "installed into $HOOKS_DIR: pre-commit, pre-push, commit-msg (+ .local copies for a delegating global hooks dir)"
GLOBAL="$(git config --global --get core.hooksPath || true)"
if [ -n "$GLOBAL" ]; then
  echo "note: global core.hooksPath=$GLOBAL is active."
  echo "      pre-commit runs via its delegation to pre-commit.local."
  for h in pre-push commit-msg; do
    if [ ! -x "$GLOBAL/$h" ]; then
      echo "      $h will NOT run until $GLOBAL/$h delegates to .git/hooks/$h.local (CI checks the same rule)."
    fi
  done
fi
