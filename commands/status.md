---
description: Show what maisecrets is and does on this machine - version, plugin folder, Python, store, policy, counts. No value is printed.
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status)
---

Run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`.
