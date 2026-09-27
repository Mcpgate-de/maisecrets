# Threat model

What the plugin defends, against whom, with which control, and where the
control ends. Written from the reviews of 2026-09-26 in `docs/reviews/` and
the second round applied the same day. Every control named here has a test or
a harness scenario that goes red when the control is removed
(`docs/TESTING.md`).

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
| C4 | session rule: a reference resolves only in a session where a human typed it, where it was minted, or where the value appeared in a tool result (redaction admits it) | A2 naming a key it never saw | the human pastes a reference into a session the injection controls; a headless prompt built from untrusted text admits what it names; a value read from a file is resolvable in that session (no worse than without the plugin) |
| C5 | up-front read for Bash: the command starts with `__ms_1="$(cat <fifo>)" \|\| exit 97`; every key is checked before a detached child serves the value once through a FIFO in a directory only this user can enter (`$XDG_RUNTIME_DIR/maisecrets` or `maisecrets-<uid>` in the temp directory; owner and mode checked, no symlink), never in the command text; Windows Git Bash reads it under a grant | A2, A4, A5's screen, transcript | A3: another process of the same user can read the FIFO while the command waits to start (up to 120 s); MCP arguments (the value must be inline; the client's permission prompt shows it); on Codex `allow` skips its approval prompt; the grant is a boundary on Windows only |
| C6 | context-aware rewrite: a scanner tracks `'…'`, `"…"`, `$(…)`, heredocs, comments; the variable is placed in the placeholder's context; a nested shell (`bash -c`, `ssh`, `eval`, `su -c`, an interpreter with inline code), a quoted heredoc, `$'…'`, backticks, arithmetic, `awk -v` and a command word that encodes, slices or traces the value are refused with the reason; a failed read ends the whole command before it runs | injection through a value with shell characters; a command running with ""; the value leaving as base64/hex/xtrace | a transform applied in a later command that carries no placeholder (C2 catches the plain and encoded forms of values this session resolved); PowerShell (Codex on Windows is denied) |
| C7 | limiter: distinct keys per session and resolves per hour, deny above the cap | A2 in bulk | the caps count every hook process of this user in the last hour (the records live in the index); a direct store read by A2 is C8's job |
| C13 | fail-closed on the plugin's own failure: a 7 s watchdog answers block/deny/withhold before the client's timeout, a crashing hook answers the same, error texts carry types only, a damaged index is refused | the plugin's own faults turning into fail-open | a client that kills the hook earlier than 7 s |
| C8 | store backstop: Bash commands that read or change the store (`maisecrets get`, `security … maisecrets`, `~/.maisecrets`, a delivery path) and Write/Edit under `~/.maisecrets` are denied, the reason names the pattern | A2 | text matching; an obfuscated command passes. This is a backstop, not a boundary |
| C9 | audit line per resolve: time, session, key, tool, command with placeholders | A5 sees what left | the log is on the same disk |
| C10 | keyed fingerprints: the index holds HMAC(key, value); the key lives in the store, never in the index | A4 guessing short PII from `index.json` | A3 can read the key |
| C11 | TTL with renewal cap; expiry deletes the value and keeps metadata | A4, stale mappings | the person can set 30 days |
| C12 | store choice: keychain (macOS, value on stdin of `security -i`, base64-marked), Credential Locker (Windows, base64 on stdin), encrypted file with 0600 key (Linux); a damaged index or store file is never overwritten | A4 | **not A3**: every store hands the value to any process of the same user without a dialog; the Credential Locker may roam through a Microsoft account |
| C14 | file tools resolve inline like MCP (session rule, limiter, audit line with the file name, transcript scrub); `resolve_in_files: false` makes them refuse instead; MCP dict keys are refused; the maisecrets home is never written by the agent | the workflow silently writing a placeholder or destroying a redacted file; an injected config change | the value is on disk in plaintext where the user asked for it, and in the client's permission prompt |
| C15 | machine policy: keys in the administrator's policy file win over the user file; the plaintext store needs an explicit opt-in; the model is told never to change settings | A2 or a user loosening the caps | a user with administrator rights |
| C16 | an MCP call that gets a real value returns `ask` with the rewritten input (Claude Code), with a warning for a published-text field; Codex, which cannot ask, refuses a value in such a field | A1 steering a value into a message, a post or a comment | a user who allows the prompt without reading it; a text field whose name is not on the list (Codex); Bash and Write/Edit, which follow the client's own permission rules |
| C17 | skill output: the secret-hygiene scripts print locations, types, lengths and per-run ids, never a value, a line or a hash of a value; the redacted copy is a new file | the model reading a leaked value while it cleans up a leak | a user who opens the original file |

## What is knowingly not defended

- **A3, a process of the same user.** The macOS keychain item's ACL trusts
  `/usr/bin/security`, so any `security find-generic-password` reads it. The
  Windows PasswordVault cannot be locked and roams through the Microsoft
  account on a non-domain machine. The Linux key file is readable by its
  owner, as it must be. A user-presence gate (Touch ID) needs a signed helper
  application on the data-protection keychain; it is not built.
- **A3 reading a waiting FIFO.** The same class as `security
  find-generic-password`; the run directory keeps other users out, not the
  user's own processes.
- **A2 through a path the hooks do not see:** a command that pipes `.env` into an upload, a
  copy of `~/.maisecrets` by a tool that is not Bash, Write or Edit. The Claude Code sandbox closes these
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
