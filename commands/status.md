---
description: Show whether maisecrets protects this session (a verdict per check, with the next step), then the details - version, plugin folder, Python, store, policy, counts. /maisecrets:status test proves both protection paths. No stored value is printed.
argument-hint: "[test]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status test), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status test)
---

The arguments are: `$ARGUMENTS`

If the arguments are `test`, run exactly this command, show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status test
```

Its output holds a self-test value that maisecrets replaces with ⟦SELFTEST⟧ before you read it. The value is no secret; do not try to get it. The user sees it and sends it as the next prompt.

Otherwise run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead (with `test` after `status` for the self-test):

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user".
