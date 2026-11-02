---
description: Sensitive References of your gateway - status (the default) shows which MCP server offers them and whether maisecrets is logged in, login [NAME] logs in once in the browser, logout [NAME] forgets the login. No value is printed.
argument-hint: "[status | login [NAME] | logout [NAME]]"
allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref *), Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref *), PowerShell(& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref)
---

Run exactly this command with the arguments the user gave (`$ARGUMENTS`, none for the status), and show the user its output as is:

```
bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" sref $ARGUMENTS
```

On Windows without bash (PowerShell), run this instead:

```
& "${CLAUDE_PLUGIN_ROOT}/hooks/run.cmd" sref $ARGUMENTS
```

If `${CLAUDE_PLUGIN_ROOT}` is still written like that when the command runs, put `$env:CLAUDE_PLUGIN_ROOT` in its place.

`login` opens the browser and waits up to 110 seconds: the user logs in there and gives the consent. If no browser opens, the output names the URL; tell the user to open it. Start a login only when the user asked for it with this command. Do not open the URL yourself, and do not run the command again on your own if it ends without a login.
