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
  placeholders for 15 minutes. None of them holds a value.
- With `scrub_transcript` on (the default), the plugin masks a detected value inside the
  client's own transcript file on your disk, in place.

## For how long

A value expires after its TTL (24 hours by default, one hour for card numbers, at most 30
days; renewed on use up to the cap) and is then deleted from the store. Metadata of an
expired value is deleted 30 days later. The logs are capped (2 000 lines). `wipe` deletes
everything at once.

## What leaves the machine

Nothing. No hook opens a network connection. Two things to know:

- `/maisecrets:report` opens your browser on a prefilled issue page at the configured
  `report_url`; the page carries the plugin version, your platform and the rule name of a
  detection, never a value. Set `report_url` to your own tracker or to `null`.
- The Windows Credential Locker may roam through a Microsoft account on a machine that is
  not domain-joined. Choose the `encrypted-file` store there if that matters.

## Who processes what

The plugin has no server and no telemetry. mcpgate (the publisher) receives no data from
it. The source is public at https://github.com/Mcpgate-de/maisecrets under Apache-2.0.
