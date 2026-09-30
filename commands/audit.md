---
description: The last resolves - when, which session, which key, which tool, the command with its placeholders. Values are never in this log.
argument-hint: "[n]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" audit *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" audit *)
---

Run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" audit --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" audit --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.
