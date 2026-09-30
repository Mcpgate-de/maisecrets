---
description: Install a guard outside the plugin folder that blocks the session when an update left maisecrets not running.
argument-hint: "[install | remove | status]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" guard *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" guard *)
---

Run exactly this command and show the user its output, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" guard --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" guard --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes. With no argument it shows the status.

For a plugin that the organisation syncs from claude.ai, an update rewrites the plugin folder, and a
session loaded from it then runs no maisecrets hook, silently. `install` copies a small guard to
`~/.claude/maisecrets-guard.py` and registers it in `~/.claude/settings.json` (a backup is made
first). When maisecrets did not run for a prompt or a tool call, the guard blocks it and names
`/reload-plugins`, and `claude --resume` with the session id for when the reload does not help. It stays silent for an account without maisecrets and for Codex. `remove` takes it
away again.
