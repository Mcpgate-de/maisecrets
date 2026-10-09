# Privacy

maisecrets runs on your machine and sends nothing anywhere. This page states what it
reads, what it stores, for how long, and what leaves the machine, so that a person or a
data-protection officer can check it against the source.

## What it reads

The hooks read the text of your prompts, the input of tool calls and the results of tool
calls that the client hands them, and scan that text for secrets and personal data
(e-mail addresses, phone numbers, IBANs, card numbers, IP addresses and national
identifiers where enabled). No other file on your machine is read unless a tool call
reads it.

## What it stores, and where

- Detected values go into the store of your operating system: the macOS login keychain,
  the Windows Credential Locker, or an encrypted file with a 0600 key file on Linux.
- `~/.maisecrets/index.json` holds metadata: a keyed fingerprint of each value, a masked
  display for personal data (never for a secret), timestamps, and the session ids that may
  resolve it. It never holds a value.
- `~/.maisecrets/audit.log` holds one line per resolve (time, session, key, tool, the
  command with placeholders). `events.log` holds the last detections (rule and type).
  `hooks.log` holds one line per hook run. `pending/` holds a blocked prompt with
  placeholders for 15 minutes. `incidents.json` and the `incident-marker.*` folders hold
  maisecrets' own internal failures as closed codes (code, cause, client, tool class, a
  count, the number of days, the plugin version); never an error text, a path, a prompt, a
  command, a session id or a value. None of them holds a value.
- With `scrub_transcript` on (the default), the plugin masks a detected value inside the
  client's own transcript file on your disk, in place.

## For how long

A value expires after its TTL (24 hours by default, one hour for card numbers, at most 30
days; renewed on use up to the cap) and is then deleted from the store. Metadata of an
expired value is deleted 30 days later. The logs are capped (2 000 lines). `wipe` deletes
everything at once.

## What leaves the machine

No telemetry and no download. The hooks and the mod send nothing to a server of their own.
Connections start only from a command you run:

- Your own ssh command inside the Claude Code sandbox goes through Claude Code's local
  sandbox proxy to the host you named, with the proxy login Claude Code sets for that
  sandbox. Before an ssh command that carries a value, a check tries a few direct
  connections that the sandbox must refuse; it sends no data.
- `/maisecrets:report` prints the issue text and a prefilled link to the configured
  `report_url`. It opens no browser and files nothing: the connection starts when you open
  the link, and you decide in GitHub's form. The link carries the issue text, the plugin
  version, your platform and the rule name of a detection or the closed codes of an internal
  failure, never a value. Set `report_url` to your own tracker or to `null`.
- The Windows Credential Locker may roam through a Microsoft account on a machine that is
  not domain-joined. Choose the `encrypted-file` store there if that matters.

## Who processes what

The plugin has no server and no telemetry. mcpgate (the publisher) receives no data from
it. The source is public at https://github.com/Mcpgate-de/maisecrets under Apache-2.0.
