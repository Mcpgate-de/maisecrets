---
description: "maisecrets keeps secrets and personal data out of the AI. Commands: status, list, term, forget, settings, ner, sref, send, put, report, rules, audit, guard, shortcut, demo, not-a-secret"
argument-hint: "[status [all|test] | list | term [add NAME] | forget KEY | settings | ner | sref login | send | ...]"
disable-model-invocation: true
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" entry *), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status test), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" entry *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status test)
---

The maisecrets prompt hook has already answered a command that only the person may give (term add, not-a-secret, demo on, a settings change, forget import:ID, report incident), before this command runs. Do not make such a change in another way, and do not write maisecrets files.

If the arguments are exactly `status test`, run exactly `bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" status test` (on Windows: `& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" status test`), show the user its output as is, then stop. Its output holds a self-test value that maisecrets replaces with ⟦SELFTEST⟧ before you read it. The value is no secret; do not try to get it.

Otherwise run exactly this command:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" entry --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" entry --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. If that is empty too (Codex on Windows), use the folder of the newest version: `Split-Path (Split-Path (Get-ChildItem "$HOME\.codex\plugins\cache\*\maisecrets\*\hooks\run.cmd" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName)`. Codex on Windows runs the command in its sandbox as another user, who may not write this user's maisecrets folder or read its vault. If the command fails there (`no write access`, access denied, or the message that Python is missing), run the same command once more outside the sandbox, with escalated permissions, and give the reason "maisecrets reads the store of this user". The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does. The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

If the first line of the output is exactly `(maisecrets: the blocked prompt follows)`, the lines after it are the prompt the user sent through maisecrets, with placeholders instead of values. Begin your reply with one line `Sent: ` followed by that text as it is, then answer it.

Otherwise show the user the output as is, then stop. If the first word of the arguments is `settings`, the output is Markdown (a table): show it as your whole answer, not in a code block. If the first word is `ner` and the command exits with code 3 or 4, run the `maisecrets:ner` command with the same arguments: it knows the next step.
