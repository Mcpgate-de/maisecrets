---
description: Report to the maisecrets maintainers - a false positive (last detection), a bug, or a feature request. Prints the issue text and a prefilled link; --create files it with the GitHub CLI. Carries no value.
argument-hint: "[last | bug <text> | feature <text>] [--create]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" report *)
---

Run exactly this command and show the user its output (the issue text and the link), then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report --args-stdin <<'MAISECRETS_ARGS_END'
$ARGUMENTS
MAISECRETS_ARGS_END
```

On Windows without bash (PowerShell: the ChatGPT app, Codex on Windows, Claude Code without Git Bash), run this instead:

```
@'
$ARGUMENTS
'@ | & "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" report --args-stdin
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place. The single-quoted here-string keeps the arguments as they are, as the quoted heredoc does.

The arguments go in the quoted heredoc as they are, so the shell never reads them as code. Do not move them onto the command line, and do not add quotes.

Forms: `/maisecrets:report` lists the last detections; `/maisecrets:report last <why it is wrong>`
prepares a false-positive issue from the last one and names the `/maisecrets:forget` command that
deletes its stored value, so the text is not redacted or blocked again; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` prepare an issue without a detection.
With `--create` among the arguments, the command files the issue at once through the GitHub CLI
(`gh`, logged in). Use it only when the user wrote `--create`: it publishes the text.

The link opens a GitHub issue prefilled with the plugin version and platform, plus the rule name
and type for a false positive. It carries no value. Do not add detected text to the issue; the
user describes its shape in words.
