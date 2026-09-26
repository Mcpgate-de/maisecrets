---
description: Install a short personal /ms command for /maisecrets:send (works over SSH and in Remote Control).
argument-hint: [name]
allowed-tools: Bash(bash *maisecrets*shortcut*)
---

Run exactly this command and show the user its output, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" shortcut $ARGUMENTS
```

It writes `~/.claude/commands/ms.md` (or the name given) and a small wrapper in
`~/.maisecrets/bin/` that finds the installed plugin at run time, so the shortcut survives
plugin updates. The user then types `/ms` after a blocked prompt.
