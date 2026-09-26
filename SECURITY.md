# Security

## Reporting

Report a weakness by e-mail to the maintainer named in `.claude-plugin/plugin.json`
(organisation on GitHub: Mcpgate-de). Do not open a public issue for a
weakness that lets a value leave the machine. You get an answer within 7 days
and a fix or a documented decision within 30 days. A report that contains a
real value is not needed: name the shape and the path.

## What the plugin protects, and what it does not

The full threat model is in `docs/THREAT-MODEL.md`. The short form:

- **Protected:** a secret or PII value in a prompt, a tool result, or a
  transcript never reaches the cloud model. A value reaches only the command
  or the tool call that a human approved, in the session where a human typed
  its reference.
- **Not protected:** a process running as the same user. Every store the
  plugin uses (macOS login keychain, Windows Credential Locker, an encrypted
  file with its key next to it) is readable by the user's own processes
  without a dialog. The plugin does not change that; it adds gates in front
  of the agent, not in front of the user.
- **Not protected:** a machine that is already compromised, or an agent that
  runs with hooks disabled.

## Reviews

Three defensive reviews (macOS store, Windows and Linux stores, the agent
channel) of 2026-09-26 are in `docs/reviews/`. Each finding lists what was
verified and what was assumed. The items they closed are in `CHANGELOG.md`.
