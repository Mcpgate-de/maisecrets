# Threat model

What the plugin defends, against whom, with which control, and where the
control ends. Written from the three reviews of 2026-09-26 in
`docs/reviews/`. Every control named here has a test or a harness scenario
that goes red when the control is removed (`docs/TESTING.md`).

## Assets

- A secret (token, password, key) or a PII value (e-mail, IBAN, card, phone,
  national identifier) that a person types, that a file holds, or that a
  command prints.
- The mapping reference → value, kept in the local store and the index.

## Actors

| actor | capability | intent |
|---|---|---|
| A1 cloud model | sees prompts, tool results, transcripts | none; the leak is the exposure itself |
| A2 the agent under injection | writes commands and tool calls from text it read | send a value somewhere, or read the store |
| A3 another process of the same user | reads files, runs `security`, PowerShell, openssl | read values |
| A4 another user or a copy of the disk | reads files it can reach | read values |
| A5 the person | everything | none; needs to see and control |

## Controls

| # | control | defends against | ends where |
|---|---|---|---|
| C1 | `UserPromptSubmit` blocks a prompt with a hit, stores the value, hands back the rewritten prompt | A1 | a value with no known shape in a prompt (use `put`) |
| C2 | `PostToolUse` redacts tool results by shape and by exact match of every live value (keyed fingerprint of each token) | A1 | a value transformed by the command (base64, split); output above 50K chars spilled by Claude Code |
| C3 | transcript scrub: after C1 (a detached child waits for the record Claude Code writes after the hook), after a Codex redaction, and after an MCP resolve (the client logs the hook's stdout with the inserted value) | A1, A4 | a transcript written by a client we do not scrub; a record written later than 15 s after the block |
| C4 | session rule: a reference resolves only in a session where a human typed it or where it was minted | A2 | the human pastes a reference into a session the injection controls |
| C5 | one-time grant for Bash: the command carries `$(resolve KEY --grant NONCE)`, never the value; the nonce dies after one read or 120 s | A2, A5's screen, transcript | MCP arguments (the value must be inline; the client's permission prompt shows it) |
| C6 | quoting-aware rewrite: the resolver call is placed in the quoting context of the placeholder, so no value is spliced into shell syntax | injection through a value with shell characters | a shell other than bash (PowerShell on Codex for Windows: not covered yet) |
| C7 | limiter: distinct keys per session and resolves per hour, deny above the cap | A2 in bulk | caps are per hook process; a direct store read by A2 is C8's job |
| C8 | store-read backstop: Bash commands that read the store (`maisecrets get`, `security … maisecrets`, vault files) are denied | A2 | text matching; an obfuscated command passes. This is a backstop, not a boundary |
| C9 | audit line per resolve: time, session, key, tool, command with placeholders | A5 sees what left | the log is on the same disk |
| C10 | keyed fingerprints: the index holds HMAC(key, value); the key lives in the store, never in the index | A4 guessing short PII from `index.json` | A3 can read the key |
| C11 | TTL with renewal cap; expiry deletes the value and keeps metadata | A4, stale mappings | the person can set 30 days |
| C12 | store choice: keychain (macOS), Credential Locker (Windows), encrypted file with 0600 key (Linux) | A4 | **not A3**: every store hands the value to any process of the same user without a dialog |

## What is knowingly not defended

- **A3, a process of the same user.** The macOS keychain item's ACL trusts
  `/usr/bin/security`, so any `security find-generic-password` reads it. The
  Windows PasswordVault cannot be locked and roams through the Microsoft
  account on a non-domain machine. The Linux key file is readable by its
  owner, as it must be. A user-presence gate (Touch ID) needs a signed helper
  application on the data-protection keychain; it is not built.
- **A2 through a path the hooks do not see:** `cat .env`, `printenv`, a copy
  of `~/.maisecrets`. The Claude Code sandbox closes these
  (`sandbox.credentials` deny for the files, `injectHosts` for allowed
  destinations); it lives in the user's settings, not in the plugin, and does
  not exist on native Windows. The README recommends the settings.
- **The client's permission prompt for an MCP tool** shows the resolved
  argument. It is the person's own value at the point of the real call.

## Decisions taken from the reviews

- Persistent pointers to `.env` values are an opt-in mode with random ids,
  keyed fingerprints and the C4–C9 gates, not yet built. Value import and a
  transfer of all keys to a gateway are not built: both create a second or a
  central copy of long-lived secrets.
- PBKDF2 over the random key file adds no security (the key is random); it
  is kept only because the file format has no version field yet.
