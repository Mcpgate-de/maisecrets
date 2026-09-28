---
description: Install a short personal /ms command for /maisecrets:send (works over SSH and in Remote Control).
argument-hint: "[name | --remove]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" shortcut *)
---

Run exactly this command and show the user its output, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" shortcut --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

It writes `~/.claude/commands/ms.md` (or the name given) and a small wrapper in
`~/.maisecrets/bin/` that finds the installed plugin at run time, so the shortcut survives
plugin updates. The user then types `/ms` after a blocked prompt. `--remove` takes it away
again and keeps it away.
