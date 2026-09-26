# Security

## Reporting

Report a weakness privately through "Report a vulnerability" on the Security
tab of github.com/Mcpgate-de/maisecrets (private vulnerability reporting is
enabled). Do not open a public issue for a weakness that lets a value leave
the machine. You get an answer within 7 days and a fix or a documented
decision within 30 days. A report that contains a real value is not needed:
name the shape and the path.

## What the plugin protects, and what it does not

The full threat model is in `docs/THREAT-MODEL.md`. The short form:

- **Protected:** a secret or PII value that the plugin detects in a prompt, a
  tool result or a transcript does not reach the cloud model as text.
- **Limited:** a placeholder resolves only in a session where a human typed
  it, where it was created, or where its value appeared in a tool result. On
  Claude Code the normal permission rules apply to the rewritten command. On
  Codex a rewritten command runs without an approval prompt.
- **Not protected:** a process running as the same user. Every store the
  plugin uses (macOS login keychain, Windows Credential Locker, an encrypted
  file with its key next to it) and the FIFO a value waits in are readable by
  the user's own processes without a dialog. The plugin does not change that;
  it adds gates in front of the agent, not in front of the user.
- **Not protected:** a machine that is already compromised, or an agent that
  runs with hooks disabled or untrusted.

## Reviews

Five defensive reviews of 2026-09-26 (macOS store, Windows and Linux stores,
the agent channel, the Codex adapter, failure modes) are in `docs/reviews/`,
and a second round of four (repository visitor, operator, code, agent and
tool) was applied the same day. Each finding lists what was verified and what
was assumed. The items they closed are in `CHANGELOG.md`.
