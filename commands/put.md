---
description: Store the value in your clipboard in the maisecrets vault and get a placeholder back (for a password without a recognisable shape). The value never reaches the model.
allowed-tools: Bash(bash *maisecrets*put*)
---

The user has copied a secret to the clipboard. Run exactly this command and show the user its
output, then stop:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" put --clipboard $ARGUMENTS
```

The output names the placeholder (such as ⟦SECRET_c4⟧) and tells the user it is now in the
clipboard in place of the value. Ask the user to paste that placeholder into their next message
where the value is needed; a placeholder resolves only after a human typed it into this session.
Never ask for the value itself.
