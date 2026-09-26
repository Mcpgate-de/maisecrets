---
description: Report to the maisecrets maintainers as a prefilled GitHub issue - a false positive (last detection), a bug, or a feature request. Carries no value.
argument-hint: [last | bug <text> | feature <text>]
allowed-tools: Bash(bash *maisecrets*report*)
---

Run exactly this command and show the user the URL it prints, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report $ARGUMENTS
```

Forms: `/maisecrets:report` lists the last detections; `/maisecrets:report last <why it is wrong>`
prepares a false-positive issue from the last one; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` prepare an issue without a detection.

The link opens a GitHub issue prefilled with the plugin version and platform, plus the rule name
and type for a false positive. It carries no value. Do not add detected text to the issue; the
user describes its shape in words.
