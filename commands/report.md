---
description: Report the last maisecrets detection as a false positive (prefilled GitHub issue, carries no value)
argument-hint: [note about why it is wrong]
allowed-tools: Bash(bash *maisecrets*report*)
---

Run exactly this command and show the user the URL it prints, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report $ARGUMENTS
```

The link opens a GitHub issue prefilled with the rule name, the type, the hook and the plugin
version. It carries no value. Do not add the detected text to the issue; the user describes its
shape in words.
