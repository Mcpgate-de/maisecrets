# maisecrets review: the agent channel and the product surface

Reference point: the working tree `/Users/akruse/maisecrets`, read on 2026-09-26. I changed nothing in the repo. The probes ran in a scratchpad vault home (`jsonfile`) and on a dummy keychain item; I deleted both.

## 1. Exfiltration through rehydration

**Threat.** Actor: text that the agent reads (file, web page, tool result). Capability: it steers the model to write a Bash command. Asset: every live vault value. Path: the command carries a placeholder, PreToolUse inserts the value, and the command sends it where the actor chooses.

**What the current design defends.**
- The model never sees a value that it types or reads in a detectable shape. VERIFIED: `docs/TESTING.md:9-12` (harness, 4 scenarios); `hooks.py:221-269`.
- A placeholder in a non-gateway MCP tool goes out unresolved. Only the placeholder leaks, never the value. VERIFIED: `hooks.py:187-188`.
- An unknown or expired key denies the whole call. VERIFIED: `hooks.py:202-209`.
- In Claude Code, the normal permission rules apply to the resolved command. VERIFIED: `hooks.py:216-217`. The docs say rules are evaluated "against the input your hook returns, not the input Claude sent" (code.claude.com/docs/en/hooks, PreToolUse decision control).

**What it does not defend. Three gaps, measured.**
1. **No session binding.** A key from session A resolves in session B. VERIFIED by probe: `other-session resolves: True`. The `session` field is stored (`vault.py:105`) but `Vault.get` never checks it (`vault.py:359-372`).
2. **Keys are guessable.** Keys are per-type counters (`vault.py:338-340`, `docs/PROTOCOL.md:18`). An injected instruction can name `SECRET_c1` without the session ever having seen it. VERIFIED by probe: `guessed SECRET_c1 resolves: True`.
3. **The output net does not know the values it inserted.** PostToolUse redacts only by shape (`detect.scan`, `hooks.py:232-243`). A value without a known shape (for example one stored with `maisecrets put`) comes back to the model in plaintext when a command prints it. VERIFIED by probe: `post_tool redacts known shapeless value: False`. A value that a command transforms before it prints it also escapes. This is a property of any output filter. Thus the only real boundary is the gate *before* the resolve.

Two more gaps, not measured:
- **The vault is readable from the agent's own shell.** A macOS keychain item that `security` created is readable by a second `security` call without a prompt. VERIFIED by probe on a dummy item (read rc=0, no dialog). `maisecrets get` prints the value (`cli.py:37-46`). Thus the agent's Bash tool reaches the store directly, around the PreToolUse hook. The encrypted-file backend states the same limit (`vault.py:184-186`).
- **The resolved command can leave the machine through the permission layer.** If auto mode sends the tool input to its classifier, and if that input is the hook's `updatedInput`, the classifier receives the plaintext value. ASSUMED. The docs say permission evaluation uses the returned input; they do not say what the classifier receives. Measure this with the fake upstream before any release.

**Comparison with established tools.** They defend against automated outflow mostly with *human presence* and *scope*, not with output filters.

| tool | how a process gets the value | control against unattended use |
|---|---|---|
| 1Password CLI `op run` / `op read` | values as env vars of one subprocess | biometric prompt per new terminal; expires after 10 min idle, hard limit 12 h. VERIFIED: 1password.dev/cli/app-integration-security. `op run` masks output unless `--no-masking` (ASSUMED from the flag name). |
| Doppler / Infisical `run` | env injection from a service token | none per call; scope by token and environment. ASSUMED. |
| direnv | `.envrc` exports into the shell | `direnv allow` per file content hash; any edit needs a new allow. ASSUMED (well known behaviour). |
| HashiCorp Vault Agent | auto-auth, template renders a file | policies and short leases; no human in the loop. ASSUMED. |
| git credential helpers | git asks per protocol and host | the value goes only to the host git contacts; keychain ACL. ASSUMED. |

Lesson: bind a grant to (key, scope, time window), and require a human act that the agent cannot perform.

## 2. "Ask before rehydrate"

**Claude Code.** VERIFIED from code.claude.com/docs/en/hooks (PreToolUse decision control):
- `"ask"` "prompts the user to confirm".
- `permissionDecisionReason`: "For `"allow"` and `"ask"`, shown to the user but not Claude."
- The prompt carries a source label, `[plugin:<name>]`.
- `"ask"` also forces a prompt in auto mode; the classifier "can't approve the call silently".
- With several hooks, precedence is `deny` > `defer` > `ask` > `allow`.
- **Trap:** `updatedInput` combined with `"ask"` is documented "to show the modified input to the user". Thus an ask that carries the resolved command puts the plaintext value on the screen (screen share, recording).

**Codex.** VERIFIED from learn.chatgpt.com/docs/hooks: `permissionDecision: "ask"` is "parsed but not supported yet"; `updatedInput` only with `"allow"`. A `PermissionRequest` event exists. A third-party report says an unsupported decision fails open (github.com/i9wa4/dotfiles/issues/378; ASSUMED, not reproduced). Thus on Codex, "ask" must be built as `deny` plus an out-of-band grant.

**Design that keeps the value off the screen.** Do not put the value into the command line. Rewrite the placeholder into an indirection, for example a call to a resolver with a one-time grant id that the hook mints for (key, SHA-256 of the command, session, 60 s). The prompt then shows the indirection and the reason text ("inserts SECRET_c7, source .env:STRIPE_KEY, first use in this session"). The resolver redeems the grant once. This also removes the value from the process list. Proposal, not measured.

**How to keep the UX cost small.**
- Ask once per session per key. After an approval, the grant covers that key for the session.
- Ask only for persistent entries (pointers, manual puts). Keep the current flow for values that the user typed in this session.
- Never ask for gateway MCP tools. They receive only the placeholder (`hooks.py:184-185`).
- A network-verb filter (curl, wget, ssh, git push, …) is a UX reducer, not a boundary. An agent can write a script and then run it. Use it to *skip* asks for clearly local commands at most, never as the only gate for persistent entries.
- In `-p` runs without a permission host, treat ask as deny (ASSUMED).

## 3. Limiter

- **Per-session cap:** at most N distinct keys resolved (proposal: 5). Above that, deny with a reason that names the count.
- **Per-hour cap:** at most M distinct keys per hour over all sessions (proposal: 10). This stops a loop that starts new sessions.
- **Cool-down:** after a user denies an ask for key K, deny K for 10 minutes without a new prompt. This stops prompt fatigue ("click until yes").
- **Audit line per resolve**, append-only, mode 0600, `~/.maisecrets/audit.jsonl`: time, session, key, kind, source (file:var for a pointer), tool, decision (auto/asked/approved/denied/capped), the first 40 characters of the command *before* resolution. The pre-resolution command holds placeholders, not values, so it is safe by construction; still run `detect.scan` on it. Also log the parsed destination host, because 40 characters often cut the host off.
- **State:** keep counters in a locked file under `~/.maisecrets/`; if it is unreadable, deny (`docs/PROTOCOL.md:73`).
- **What the OS stores contribute:** today nothing. VERIFIED: the keychain read in the probe gave no dialog. A keychain item with an empty trusted-application list would show a macOS dialog on each read (ASSUMED). That dialog is a human act that a shell agent cannot perform, so it can carry the out-of-band grant on macOS. On Windows and Linux there is no equivalent in the current backends.

## 4. `.env` handling modes

| mode | verdict | reason |
|---|---|---|
| Scan-and-redact | keep, default | exists (`hooks.py:221-269`, harness `read_env`); no new asset |
| Pointer registration | offer, opt-in, with gates | the file stays the one source of truth; no copy. But a pointer never expires, so it makes the standing exposure longer. Require: random key id (not `ENV_STRIPE_KEY`), keyed HMAC fingerprint, binding to the project path, ask once per session, limiter |
| Value import | do not offer | a second copy of a long-lived secret in a store that the agent's shell can read (gap above); `CONCEPT.md:123-124` already says long-lived secrets belong in the password manager |
| Gateway transfer | do not offer | makes one central store of all developer secrets, a high-value target; the local stack must fetch at start; this adds capability, not security, against the owner's stated principle |

The hash-every-token detection for pointers is sound only with a keyed HMAC. The current fingerprint is unsalted `sha256(value)[:12]` (`vault.py:90-91`). For a low-entropy value (phone, email, PIN) an enumeration reverses it. VERIFIED from the code; the enumeration is not run.

## 5. Transparency

**Show:** the list of protected keys; type and kind; source (`file:var`, never the line); created, expires, uses; last resolve (time, session, tool, destination host, decision); the counts against the caps; the active backend (exists, `vault.py:76-87`).

**Never show to the model:** values, prefixes or suffixes of secrets, fingerprints, the list of *other* live keys (it makes enumeration easy). The status and list commands are for the human terminal. The PreToolUse hook should deny agent Bash commands that call `maisecrets get` or read the store, and say why.

**Never show anywhere:** a value in an ask prompt, an audit line, or a block reason (`docs/PROTOCOL.md:76`).

## 6. Recommendations (ranked)

1. **Bind resolution to the session** (S). A key resolves only in the session that minted it or that received it in a model-visible result; otherwise ask. Defends against guessed keys and cross-session reuse by injection.
2. **Redact inserted values by exact match in PostToolUse** (S). The hook knows which keys it resolved for the call. Defends against the plain echo of a shapeless value. It does not stop a transformed value; name that residual.
3. **Deny agent access to the store itself** (S). PreToolUse denies Bash commands that call `maisecrets get`, `security find-generic-password` for the service, or read the vault files. Defends against the direct read around the hook. It is a heuristic; the OS dialog (item 6) is the boundary.
4. **Measure what the classifier and the transcript receive** (S). Harness scenario in auto mode and a transcript check after a resolve. Defends against the value leaving the machine through the permission layer (ASSUMED risk).
5. **Limiter plus audit line** (M). Per-session and per-hour caps on distinct keys, cool-down after a deny, one audit line per resolve with the destination host. Defends against mass outflow and gives the record for "where did the value go".
6. **Ask once per session per persistent key, without the value on screen** (M). Claude Code: `"ask"` with an indirection and a one-time grant, never `updatedInput` with the value. Codex: deny plus an out-of-band grant; on macOS a keychain dialog carries the human act. Defends against unattended use of long-lived secrets.
7. **Pointer mode as opt-in with random ids and keyed HMAC** (M). Replace unsalted fingerprints everywhere. Defends against name-based addressing and fingerprint reversal of low-entropy values.
8. **Do not build value import or gateway transfer** (S, a decision). Defends against a second and a central copy of long-lived secrets.
