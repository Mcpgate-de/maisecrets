---
description: The last resolves - when, which session, which key, which tool, the command with its placeholders. Values are never in this log.
argument-hint: [n]
allowed-tools: Bash(bash *maisecrets*audit*)
---

Run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" audit $ARGUMENTS
```
