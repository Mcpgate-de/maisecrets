#!/usr/bin/env bash
# Stable entry point for a personal /ms command (installed by `/maisecrets:shortcut` to
# ~/.maisecrets/bin/ms.sh). The plugin folder moves with every version (cache/<v>/,
# synced/<id>/maisecrets~gN/), so a personal command cannot name it; this wrapper finds the
# newest installed copy and runs its `pending` (send the last blocked prompt). A `$(…)` in a
# command's `!` line fails Claude Code's permission check (field report, 2026-09-26), so the
# command line is this fixed path and nothing else.
set -u
ROOT="$(python3 - <<'PY'
import glob, json, os
home = os.environ.get("HOME") or os.path.expanduser("~")   # Git Bash sets HOME; python.exe prefers USERPROFILE
best, best_v = None, ()
for pat in ("/.claude/plugins/cache/*/maisecrets/*/", "/.claude/plugins/synced/*/maisecrets*/"):
    for d in glob.glob(home + pat):
        try:
            with open(os.path.join(d, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
                v = tuple(int(x) for x in json.load(f)["version"].split("."))
        except (OSError, ValueError, KeyError):
            continue
        if v > best_v and os.path.isfile(os.path.join(d, "hooks", "run.sh")):
            best, best_v = d.rstrip("/"), v
print(best or "")
PY
)"
if [ -z "$ROOT" ]; then
  echo "(maisecrets: no installed plugin copy found; run /maisecrets:shortcut again after installing)"
  exit 0
fi
exec bash "$ROOT/hooks/run.sh" pending
