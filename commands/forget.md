---
description: Delete stored values by key, for example /maisecrets:forget SECRET_c3. A placeholder for a deleted key no longer resolves.
argument-hint: <key> [key ...]
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" forget:*), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" forget:*)
---

The user wants to delete these stored values: $ARGUMENTS

If no key is given, tell the user to run /maisecrets:list and name the keys, then stop.
Otherwise run exactly this command with the keys the user gave, and show its output as is:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" forget --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" forget --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.
