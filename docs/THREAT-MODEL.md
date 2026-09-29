# Threat model

What the plugin defends, against whom, with which control, and where the
control ends. Every control named here has a test or
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

## Core protection and rehydration policy

Two layers, kept apart on purpose (`maisecrets/rehydration.py`).

- **Core protection** keeps a value out of the model: C1 to C3 on the way in and back, C4 to C9 around
  every resolve, and the capability checks of C6, C14 and C18. A form where the value could turn into
  code, or a path a client cannot take, is refused on every setting. Nothing below loosens it.
- **The rehydration policy** decides only whether maisecrets adds its own confirm where a value is put
  into a call that can take it. `automatic`, the default, adds none: the client's permission rules
  decide, as without the plugin, but the model sees the placeholder. `confirm` asks on Claude Code and
  refuses on Codex. `block` refuses. C16 holds it; the matrix per path and client is
  `tests/test_rehydration_matrix.py`.

The policy is not a boundary against A2. With `automatic`, an agent under injection that holds a
placeholder of its session can put the value into a call that the client's rules allow, like any
command the user lets it run. C4 (only placeholders a human gave this session), C7 (the caps) and C9
(the audit line) still apply; a stricter control is `confirm` or the client's own rules.

## Controls

| # | control | defends against | ends where |
|---|---|---|---|
| C1 | `UserPromptSubmit` blocks a prompt with a hit (a detector shape, or a value the store holds, by keyed fingerprint of each token and, for a value this session resolved, as a substring), stores the value, hands back the rewritten prompt | A1 | a value with no known shape that is not stored (use `put`); a stored value with spaces that this session did not resolve; a resolved value shorter than 8 characters. A stored ordinary word of 8 characters or more blocks every prompt that contains it |
| C2 | `PostToolUse` redacts tool results by shape and by exact match of every live value (keyed fingerprint of each token, and of the text a hex or base64 token decodes to) | A1 | a value of another session that the command transformed inside a longer token or split (a value this session resolved is matched in every encoding as a substring); output above 50K chars spilled by Claude Code |
| C3 | transcript scrub: after C1 (a detached child waits for the record Claude Code writes after the hook), after a Codex redaction, and after an MCP resolve (the client logs the hook's stdout with the inserted value) | A1, A4 | a transcript written by a client we do not scrub; a record written later than 15 s after the block |
| C4 | session rule: a reference resolves only in a session where a human typed it, where it was minted, or where the value appeared in a tool result (redaction admits it) | A2 naming a key it never saw | the human pastes a reference into a session the injection controls; a headless prompt built from untrusted text admits what it names; a value read from a file is resolvable in that session (no worse than without the plugin) |
| C5 | up-front read for Bash: the command starts with `__ms_1="$(cat <fifo>)" \|\| exit 97`; every key is checked before a detached child serves the value once through a FIFO in a directory only this user can enter (`$XDG_RUNTIME_DIR/maisecrets` or `maisecrets-<uid>` in the temp directory; owner and mode checked, no symlink), never in the command text; Windows Git Bash reads it under a grant | A2, A4, A5's screen, transcript | A3: another process of the same user can read the FIFO while the command waits to start (up to 120 s); MCP arguments (the value must be inline; the client's permission prompt shows it); on Codex `allow` may skip its approval of a shell command (documented for 0.155.1; the sandbox and the MCP tool approval stay, measured on 0.158.0); the grant is a boundary on Windows only |
| C6 | context-aware rewrite: a scanner tracks `'…'`, `"…"`, `$(…)`, heredocs, comments; the variable is placed in the placeholder's context; a nested shell (`bash -c`, `ssh`, `eval`, `su -c`, an interpreter with inline code), a quoted heredoc, `$'…'`, backticks, arithmetic, `awk -v` and a command word that encodes, slices or traces the value are refused with the reason; a failed read ends the whole command before it runs | injection through a value with shell characters; a command running with ""; the value leaving as base64/hex/xtrace | a transform applied in a later command that carries no placeholder (C2 catches the plain and encoded forms of values this session resolved); PowerShell (Codex on Windows is denied); a command word the hook cannot read (a variable such as `$S`, a script file), whose command the client's permission prompt shows |
| C7 | limiter: distinct keys per session and resolves per hour, deny above the cap | A2 in bulk | the caps count every hook process of this user in the last hour (the records live in the index); a direct store read by A2 is C8's job |
| C13 | the guard outside the plugin folder (`hooks/guard.py`, placed at `~/.claude/maisecrets-guard.py`): every maisecrets hook of Claude Code writes a heartbeat named by session, event and call id; the guard blocks, denies or withholds a call for which none came within 5 s, where maisecrets is meant to run (a synced or installed copy for the active account, not switched off); fail-closed on the plugin's own failure: a 7 s watchdog answers block/deny/withhold before the client's timeout, a crashing hook answers the same, and so does an entry point that cannot import the plugin's code, error texts carry types only, a damaged index is refused | the plugin's own faults turning into fail-open | a client that kills the hook earlier than 7 s; a client that runs no hook at all: Claude Code for a plugin whose folder moved while the session was open, or during its start (anthropics/claude-code#97847, measured by the harness scenario `plugin_folder_moved`), unless the guard is registered (`plugin_folder_moved_guarded`); a synced install registers it at its session start, so the first session of a first install is not covered, nor one where the person removed it or `guard` is false; Claude Code may rewrite `settings.json` and drop the entry until the next session start |
| C8 | store backstop: Bash commands that read or change the store (`maisecrets get`, `security … maisecrets`, `~/.maisecrets`, a delivery path) and Write/Edit under `~/.maisecrets` are denied, the reason names the pattern; Read, Grep, Glob, LS, NotebookRead, the editing tools, an MCP path argument (also a `file:` URI) and an MCP resource read (`ReadMcpResourceTool`, `ReadMcpResourceDirTool`) under the vault home or the value directory are denied by file identity (symlink, relative path, another case and a hard link to a store file resolved); Bash names the default and the configured home | A2 | Bash: text matching, so an obfuscated command passes. The agent runs as the same user: a command that builds the path at run time can still read the file store (key and ciphertext side by side) or ask the keychain. This is a backstop, not a boundary; a hard boundary needs a broker process, and the Claude Code sandbox rule that denies reads of `~/.maisecrets` (README) is the strongest step today |
| C9 | audit line per resolve: time, session, key, tool, command with placeholders | A5 sees what left | the log is on the same disk |
| C10 | keyed fingerprints: the index holds HMAC(key, value); the key lives in the store, never in the index | A4 guessing short PII from `index.json` | A3 can read the key |
| C11 | TTL with renewal cap; expiry deletes the value and keeps metadata | A4, stale mappings | the person can set 30 days |
| C12 | store choice: keychain (macOS, value on stdin of `security -i`, base64-marked), Credential Locker (Windows, base64 on stdin), encrypted file with 0600 key (Linux); a damaged index or store file is never overwritten | A4 | **not A3**: every store hands the value to any process of the same user without a dialog; the Credential Locker may roam through a Microsoft account |
| C14 | file tools resolve inline like MCP (session rule, limiter, audit line with the file name, transcript scrub), Codex `apply_patch` in its content lines (a placeholder in a file name of the patch is refused); `resolve_in_files: false` blocks them (C16); MCP dict keys are refused; the maisecrets home is never written by the agent | the workflow silently writing a placeholder or destroying a redacted file; an injected config change | the value is on disk in plaintext where the user asked for it, and in the client's permission prompt when the client's rules show one |
| C15 | machine policy: keys in the administrator's policy file win over the user file; the plaintext store needs an explicit opt-in; the model is told never to change settings | A2 or a user loosening the caps | a user with administrator rights |
| C16 | rehydration policy, one decision per path (Bash, ssh, MCP, file tools): `automatic` (default) gives no decision on Claude Code, so its permission rules apply, and `allow` on Codex, the only decision that carries a rewritten input there; `confirm` returns `ask` with the rewritten input on Claude Code (also in auto and bypass mode; a warning for a published-text field) and refuses on Codex before anything is resolved; `block`, a value that is none of the three, and `resolve_in_files: false` for the file tools refuse before anything is resolved; a user file that is not valid JSON or no object blocks, one ignored for a wrong type keeps what it made stricter (a non-string value there blocks); every rewrite is decided by the policy: `_rehydrated`, and the ssh branch of `_pre_bash` under the same policy (a test names every call site and every function that builds a rewrite) | the person who wants a second look before a value leaves; a typo in the setting granting more | with `automatic`, nothing of ours between an allowed call and its destination (see "Core protection and rehydration policy"); a user who allows a `confirm` prompt without reading it; on Codex `allow` keeps Codex's sandbox and its MCP tool approval (codex-cli 0.158.0), whether it skips the approval of an escalated shell command is not measured (0.155.1 documented that it does) |
| C18 | ssh gets a value only on stdin, inside the Claude Code sandbox (with `rehydration: confirm`, after the user confirms): the command starts with a guard, `hooks/sandbox_probe.py` (`SANDBOX_RUNTIME=1`, the sandbox proxy's `srt.` login, no direct network, and a proxy that refuses a wrong login with 407; else exit 97 before the value is read), ssh gets `hooks/proxy_connect.py` as its first `ProxyCommand`, and under `confirm` the hook asks with the host and the remote command; a value in ssh's arguments, a remote shell, an own proxy or jump host are refused; Codex keeps the refusal. Opt-in `ssh_approval: per-session`, under `confirm`: one ask per value and session, recorded only when the allowed command reads the value from its FIFO, which sits in a directory nobody can list (mode 0300) so only the command that holds its name can read it; the store keeps only token hashes; for read-only remote commands only, each a bare command word (`maisecrets/ssh_approval.py`) | A2 sending a value to a host of its choice over ssh | the remote command, which may pass the value on (with `automatic` nothing of ours reads it; under `confirm` the user reads it at the prompt, with the session approval only the first one, and later ones are limited to commands that read and print); the hosts in `sandbox.network.allowedDomains`, which the user chose; with the session approval, a program that runs as the user outside the sandbox, which can write the approval store like any file of the user; A3, a local process that fakes the sandbox environment and its proxy on a machine with no direct network |
| C17 | skill output: the secret-hygiene scripts print locations, types, lengths and per-run ids, never a value, a line or a hash of a value; the redacted copy is a new file | the model reading a leaked value while it cleans up a leak | a user who opens the original file |

## Invariants

Four goals hold over every path, each with its own tests and a mutation per path
(`docs/TESTING.md`, `beliefs/inv-*.toml`):

- **I1** A stored value never reaches a hook output the model or the person reads, within the
  ends of C1 and C2 (a short or spaced value in a prompt, another session's value transformed
  inside a longer token). The one exception is `updatedInput` of a resolving PreToolUse answer,
  the delivery the user allows.
- **I3** No tool of the agent reads a file of the vault home or the value run directory, within
  the end of C8 (Bash is a text match). Codex `apply_patch` reaches the matcher through its aliases
  `Write` and `Edit`; a patch whose header names the home is refused (measured on codex-cli 0.158.0).
- **I4** Every value the detector finds can be masked in a transcript in every record shape the
  clients write.

- **I2** On Claude Code a rewrite never grants more than the call the model wrote: no `allow`, the
  original input back when each value becomes its placeholder again, and in Bash only the reads of
  the values and, for ssh, the guard and the options that narrow it. On Codex a rewrite carries
  `allow` (C5); a test records that exception and fails when it changes.

## What is knowingly not defended

- **A3, a process of the same user.** The macOS keychain item's ACL trusts
  `/usr/bin/security`, so any `security find-generic-password` reads it. The
  Windows PasswordVault cannot be locked and roams through the Microsoft
  account on a non-domain machine. The Linux key file is readable by its
  owner, as it must be. A user-presence gate (Touch ID) needs a signed helper
  application on the data-protection keychain; it is not built.
- **A2 taking another session's blocked prompt.** `/ms` reads the prompt of the session the client
  names; a command that sets or clears that id is refused by text match, so an obfuscated one
  passes (the C8 class). The prompt holds placeholders, never a value.
- **A compromised release.** A hook runs as the user and sees every value, like any plugin or
  package with that access; a pinned, reviewed version is the admin's control.
- **A3 reading a waiting FIFO.** The same class as `security
  find-generic-password`; the run directory keeps other users out, not the
  user's own processes.
- **A2 through a path the hooks do not see:** a command that pipes `.env` into an upload, a
  copy of `~/.maisecrets` by a tool that is not Bash, Write or Edit. The Claude Code sandbox closes these
  (`sandbox.credentials` deny for the files, `injectHosts` for allowed
  destinations); it lives in the user's settings, not in the plugin, and does
  not exist on native Windows. The README recommends the settings.
- **The client's permission prompt for an MCP tool**, when the client shows
  one, shows the resolved argument. It is the person's own value at the point
  of the real call.
- **Where a value goes after an allowed call.** With `rehydration: automatic`
  maisecrets does not judge the destination: a value the person asked to send
  over Slack goes to Slack. A per-destination policy (a public sink, an unknown
  host) is a later layer on top of C16, not part of the core.

## Decisions

- Persistent pointers to `.env` values are an opt-in mode with random ids,
  keyed fingerprints and the C4–C9 gates, not yet built. Value import and a
  transfer of all keys to a gateway are not built: both create a second or a
  central copy of long-lived secrets.
- PBKDF2 over the random key file adds no security (the key is random); it
  is kept only because the file format has no version field yet.
