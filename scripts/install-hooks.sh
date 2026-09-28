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
#
# Each installed hook is a two-line wrapper that runs the hook of the tree that is checked out:
# a copy went stale when .githooks changed (2026-09-28: the installed pre-push lacked the scan
# that .githooks/pre-push had), and all worktrees share this one hooks directory, so the wrapper
# runs the version of the worktree that commits or pushes.
set -eu
# the common git directory: in a worktree `.git` is a file, and `$ROOT/.git/hooks` does not exist
HOOKS_DIR="$(git rev-parse --path-format=absolute --git-common-dir)/hooks"
mkdir -p "$HOOKS_DIR"
for h in pre-commit pre-push commit-msg; do
  for name in "$h" "$h.local"; do
    printf '#!/bin/bash\n# installed by scripts/install-hooks.sh: runs the hook of the checked-out tree\nexec "$(git rev-parse --show-toplevel)/.githooks/%s" "$@"\n' "$h" > "$HOOKS_DIR/$name"
    chmod +x "$HOOKS_DIR/$name"
  done
done
echo "installed into $HOOKS_DIR: pre-commit, pre-push, commit-msg (+ .local for a delegating global hooks dir), each running .githooks/<hook> of the checked-out tree"
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
