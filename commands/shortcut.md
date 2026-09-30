---
description: Install a short personal /ms command for /maisecrets:send (works over SSH and in Remote Control).
argument-hint: "[name | --remove]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" shortcut *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" shortcut *)
---

Run exactly this command and show the user its output, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" shortcut --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" shortcut --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

It writes `~/.claude/commands/ms.md` (or the name given) and a small wrapper in
`~/.maisecrets/bin/` that finds the installed plugin at run time, so the shortcut survives
plugin updates. The user then types `/ms` after a blocked prompt. `--remove` takes it away
again and keeps it away.
