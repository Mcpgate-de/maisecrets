---
description: The last resolves - when, which session, which key, which tool, the command with its placeholders. Values are never in this log.
argument-hint: "[n]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" audit *)
---

Run exactly this command and show the user its output as is, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" audit --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.
