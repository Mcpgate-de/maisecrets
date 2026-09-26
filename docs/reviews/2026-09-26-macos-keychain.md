# maisecrets: macOS threat review (persistent pointers, ask-before-rehydrate)

Reference point: working copy `/Users/akruse/maisecrets` read on 2026-09-26 (not a git repository, so no SHA). Host: macOS 27.0, build 26A428. Sources: `security(1)` man page on this host, Apple documentation JSON (TN3137, `kSecAttrSynchronizable`, `kSecUseDataProtectionKeychain`, `SecAccessControlCreateFlags.userPresence`), cached Claude Code docs (hooks, permissions, sandboxing, env-vars), the macOS 27.0 SDK header `ESTypes.h`.

Threat actor for all sections: a prompt-injected agent that runs Bash as the user, plus any other process that runs as the same user.

## 1. What a same-user process can read from the login keychain

- **The trusted application is `/usr/bin/security`, not maisecrets.** VERIFIED by experiment. I created a throwaway keychain file in the scratchpad (not the login keychain) and added an item with the same flags as `KeychainBackend.put` (`vault.py:159`). `security dump-keychain -a` showed the decrypt ACL entry `applications (1): /usr/bin/security`, requirement `identifier "com.apple.security" and anchor apple`. A separate Python child process then ran `security find-generic-password -w` and got the value, exit 0, no prompt.
- **Consequence.** Any same-user process that calls `security find-generic-password -s maisecrets -a SECRET_c7 -w` gets the value silently. This includes a Bash command the agent writes. The comment at `vault.py:157` ("the creating tool may read it, others are asked") is therefore misleading: the "creating tool" is a binary every process can run. ASSUMED: the result is the same in an unlocked login keychain (the ACL model is per item, not per keychain file).
- **Metadata is free.** VERIFIED in the same experiment: `find-generic-password` without `-w` returns the attributes. The label and comment (`vault.py:350-352`) disclose type, kind and fingerprint to any enumerator.
- **`-A` / `-T`.** VERIFIED (`security(1)`): `-A` allows any application "without warning (insecure, not recommended!)"; `-T appPath` names an application that may access the item. The code sets neither, so the default applies, which is shown above.
- **Value on the command line.** VERIFIED (`security(1)`): for `-w` the man page says "Put at end of command to be prompted (recommended)". The code passes the value as an argument (`vault.py:160`), so it sits in the argv of a short-lived process. ASSUMED: same-user processes can read it with `ps` during that window.
- **iCloud sync is off.** VERIFIED (TN3137): iCloud Keychain requires the data-protection keychain; the `security` tool "is primarily focused on the file-based keychain"; the `kSecAttrSynchronizable` page says items are not synchronizable unless the key is set to true. The README claim holds.

## 2. User presence on read

- VERIFIED (TN3137): biometric protection (Touch ID) "require[s] the data protection keychain". Access to it comes from keychain-access-group entitlements that "must be authorized by a provisioning profile", which needs an app-like bundle; a plain command-line tool does not qualify. The `security` CLI therefore cannot create an item with `kSecAccessControlUserPresence`.
- VERIFIED (Apple docs): `.userPresence` means "biometry or passcode", equivalent to `biometryAny` or `devicePasscode`.
- Options that remain for the plugin:
  1. **File-based ACL with no trusted application** (`-T ""`). ASSUMED: every read then shows a keychain dialog. Weakness: if the user clicks "Always Allow", `/usr/bin/security` joins the list and the gate is gone for every caller. Needs a live test.
  2. **A signed helper app** (Developer ID, provisioning profile) as the only trusted application, which stores persistent entries in the data-protection keychain with `SecAccessControl(.userPresence)`. This is the only option with a cryptographic binding to presence. Effort L.
  3. **`LAContext` gate in a helper without moving the value.** ASSUMED: works without entitlements, but it is only a UI gate; the value stays readable through route 1 above. It adds nothing alone.

## 3. Rate limit and audit trail

- VERIFIED: the macOS 27.0 SDK `ESTypes.h` defines 167 `ES_EVENT_TYPE_` symbols and none refers to the keychain. Endpoint Security gives no keychain-read event.
- ASSUMED: `securityd` writes unified-log lines, but Apple does not document them as an audit trail, and the OS has no documented rate limit on item reads.
- Conclusion: rate limit and audit are the plugin's job. **Warning:** a plugin counter meters only reads through the hook. A direct `security` call bypasses it. The limiter is useful only together with a control that closes the direct path (sections 5 and 6).

## 4. Pointer model versus stored values

- **At rest, the two are equal against a same-user process.** The `.env` file is plaintext; the keychain copy is readable silently (section 1). Neither form adds confidentiality against the actor.
- **Pointer advantages.** One source of truth (rotation needs no re-registration), no second copy that outlives the file, and a precise list of the files that hold secrets. That list is the main value: it lets the plugin and the sandbox deny reads of exactly those paths.
- **Pointer disadvantages.** (a) Persistent scope: every registered secret is resolvable in every session, so the blast radius grows from "what the user typed today" to "every `.env` ever registered". (b) Detection by whitespace-delimited tokens misses `KEY=value`, `"value"`, `user:value@host` and any encoded form (base64, hex, split strings). (c) The HMAC key in the keychain is readable silently; this matters only for offline brute force, not for exfiltration.
- **Side finding.** `index.json` stores `sha256(value)[:12]` without a key (`vault.py:90-91`). For low-entropy PII (phone, IBAN) an attacker with the file can recover the value by enumeration. Use the keyed HMAC for all entries.

## 5. The "ask before rehydrate" control

What it defends: a silent resolution of a persistent pointer inside a command that the user did not see.

What it does not defend:
- **The value appears on screen.** VERIFIED (hooks reference): `updatedInput` combined with `"ask"` shows "the modified input to the user". The dialog therefore displays the plaintext secret (screen share, recording, shoulder view).
- **Permission modes.** VERIFIED (permissions doc): `bypassPermissions` "skips permission prompts"; `dontAsk` "auto-denies every call that would otherwise prompt". ASSUMED: a hook `"ask"` is skipped in bypass mode. VERIFIED: in auto mode a hook `"ask"` forces a prompt (since v2.1.211).
- **Direct reads.** `cat .env`, the Read tool, `env`/`printenv` when the variables are exported, `security find-generic-password -w`. None of these contains a placeholder, so the hook never fires.
- **Egress without output.** A command can send a value to a network host; PostToolUse redaction never sees it.
- **Approval fatigue.** Users approve repeated dialogs without reading.

Controls that close these gaps are in section 6. The strongest one is VERIFIED to exist: the Claude Code Bash sandbox (Seatbelt on macOS) enforces `denyRead` paths and a network domain allowlist at the OS level for Bash and its children, and `sandbox.credentials` can deny files and unset or mask environment variables. On macOS a file `mask` behaves like `deny` (no sentinel copy); environment `mask` with `injectHosts` substitutes the real value only on egress to named hosts (requires `network.tlsTerminate`). `allowUnsandboxedCommands: false` removes the `dangerouslyDisableSandbox` retry. The sandbox does not cover the Read/Edit/Write tools; those need `permissions.deny` rules.

## 6. Ranked recommendations

1. **Turn on the Bash sandbox with a domain allowlist, strict mode, and `credentials` deny for every registered `.env`; mask exported secrets with `injectHosts`.** Effort M. Defends: exfiltration of any value (resolved or read directly) to unlisted hosts; `cat` of source files; `env` dumps. The plugin can generate these entries from its pointer list.
2. **Deny the Read tool and Bash access to registered source files and to the vault**: `permissions.deny` for `Read(<path>)`, plus a PreToolUse deny for commands that call `security` on the `maisecrets` service, `dump-keychain`, or `env`/`printenv`. Effort S. Defends: direct reads that bypass rehydration. Text matching is bypassable, so treat it as defence in depth behind item 1.
3. **Fix the keychain ACL and the argv leak**: create items with an empty trusted-application list (`-T ""`) for persistent entries, test the dialog, and stop passing the value with `-w value`. Correct the comment at `vault.py:157`. Effort S. Defends: silent reads by any same-user process.
4. **Signed helper with data-protection keychain and `.userPresence`** for persistent entries; TTL entries stay silent. Effort L. Defends: silent reads, including the "Always Allow" collapse of item 3.
5. **Rehydrate by reference, not by value**: rewrite `⟦SECRET_c7⟧` to a helper call that the command runs, so the "ask" dialog shows no plaintext; add the target hosts and the reference names to `permissionDecisionReason`. Set `permissions.disableBypassPermissionsMode` so "ask" cannot be skipped. Effort S–M. Defends: on-screen disclosure and bypass-mode skips.
6. **Per-session budget and append-only audit log in the plugin**: for example at most N distinct persistent references per session and per minute, deny beyond that, log reference, session, command hash and time. Effort S. Defends: bulk automatic outflow through the hook path only (see the warning in section 3).
7. **Exact-value redaction in PostToolUse**: match every live value (keyed HMAC) on non-alphanumeric token boundaries and on base64/hex forms; replace the unkeyed `sha256[:12]` in `index.json`. Effort M. Defends: values echoed back to the model; offline enumeration of low-entropy PII.
8. **Managed-settings hardening**: `allowManagedHooksOnly`, `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`, and deny writes to `~/.claude` and the plugin folder. Effort S. Defends: an agent that edits hooks or settings to disable the plugin, and credential leaks through inherited environment.
