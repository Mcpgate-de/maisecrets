# Changelog

## Unreleased

## [0.4.0] - 2026-09-27

- **Changed for everyone:** the block notice is new (plain words, what was found, the prompt with the
  short forms, where the values stay and for how long), and the first session start only offers
  `/ms` (`/maisecrets:shortcut`) instead of installing it. An existing `/ms` keeps working.

- **The block notice speaks plainly** and shows what was found (masked), the prompt with the short
  forms, where the values stay and for how long.
- **`/maisecrets:list`** shows what is stored, masked; **`/maisecrets:forget <key>`** deletes one entry.
- **You see every redaction**: one line names the values replaced in a tool result.
- **The session start is shorter** and names no file paths; `/ms` is offered once instead of being
  installed, and Codex gets tips that work there.
- **The `secret-hygiene` skill** finds leaked secrets in a repository and its history (date, author,
  pushed or not, provider), guides the rotation, and writes redacted copies of files to share.

### Breaking

- the secret-hygiene skill, a plain block notice, /maisecrets:list and /maisecrets:forget (a77f8ad)

### Features

- audit the local Claude Code and Codex transcripts for secrets that already reached the provider (df96aba)
- a plain block notice that shows what was found and what would be sent; /maisecrets:list and /maisecrets:forget; the skill reports date, author, pushed state, provider and every skip (91e5b79)
- secret-hygiene finds leaked secrets by location, guides the rotation, writes redacted copies (fb5ef18)

### Fixes

- the skill tests run in CI and a skipped test is no proof; the release waits for the beliefs replay (2750b3b)
- review findings - a ++ line is content, labels in a sentence, expire keeps its lock, the scrub keeps bytes and mode; feat(skill): the ChatGPT listing and a flat zip (37c330b)
- the scan runs on every core, keyword rules only near their keywords, no size limit; fix(beliefs): each replay run gets a fresh bytecode cache (2b969e2)

### Other

- Merge branch 'main' into feat/secret-hygiene-skill (d22334e)
- Merge remote-tracking branch 'origin/main' into feat/secret-hygiene-skill (de7f2df)

## [0.3.33] - 2026-09-27

- **An MCP call that gets a real value now asks you first** (Claude Code), also in auto and bypass
  mode, with a warning when the value sits in a message body or another published text. Unattended
  runs (`claude -p`) refuse it. On Codex, which cannot ask, a placeholder in such a text field is refused.

### Fixes

- an MCP call gets a real value only after the user confirms; Codex refuses a value in published text (bdb5589)

## [0.3.32] - 2026-09-27

### Fixes

- no .claude-plugin/icon.svg, so the portal reads the icon URL from the manifest; a 30-character subtitle for OpenAI (16e9e0b)

## [0.3.31] - 2026-09-27

### Fixes

- verify_release expects the Codex manifest in the release commit; the test reads that list too (2bdb33f)

## [0.3.30] - 2026-09-27

### Fixes

- a reader retries while another hook process replaces the index or the store (Windows PermissionError) (bfb211c)
- the release job stages the Codex manifest it bumps; a test reads the job's git add line (c67483a)
- the manifest icon is the URL of the PNG on main, which the listing preview renders (bc7f087)

## [0.3.29] - 2026-09-27

### Features

- a Codex manifest with the interface fields and icon; hooks.log names the desktop entry point (da5db56)

## [0.3.28] - 2026-09-27

### Features

- the mcpgate mark as the plugin icon (7594fb5)

### Fixes

- a PNG as the manifest icon (cce176d)
- the icon in every place a listing looks for it (5cbb758)
- block and redaction notices one fact per line, and no slash commands on Codex (953da8b)

## [0.3.27] - 2026-09-27

### Features

- privacy page and the listing URLs in the manifest (bc376f0)

## [0.3.26] - 2026-09-27

### Fixes

- exact allowed-tools per command, a plugin icon, no environment token in the GitHub wait (6bbbaa3)

## [0.3.25] - 2026-09-27

- `/maisecrets:shortcut --remove` takes the personal `/ms` away and keeps it away.

### Fixes

- a revert releases as a patch; tests for the operations paths and the release tools (4273160)

## [0.3.24] - 2026-09-27

### Features

- the first session start installs a personal /ms once, unless one exists or shortcut is off (503cf08)

### Fixes

- the plugin's own command names are never a labelled secret (a6b1f6c)

## [0.3.23] - 2026-09-26

- The first session start installs a personal `/ms` for `/maisecrets:send` (unless one exists
  or `"shortcut": false`); `/maisecrets:shortcut [name]` does it by hand.
- `/maisecrets:put` explains the SSH case (no clipboard: use a label in a prompt).

### Features

- /maisecrets:shortcut installs a personal /ms; the answer to a sent prompt shows the text (53553e7)

### Fixes

- one path separator style in the wrapper under Git Bash (9c31784)
- the wrapper honours HOME under Git Bash on Windows (b39ab76)

## [0.3.22] - 2026-09-26

- **Codex users: re-trust the hooks once in `/hooks` after this update.** `hooks/hooks.json`
  changed (Write/Edit/MultiEdit/NotebookEdit joined the PreToolUse matcher, and every hook
  has a `commandWindows` entry). Until the hooks are trusted again, Codex runs no maisecrets
  hook and says nothing.
- The plaintext `jsonfile` store now needs `"allow_plaintext_store": true` in the config
  (or the policy); it is the test store.
- A wrong type or an unknown key in `~/.maisecrets/config.json` no longer changes anything
  silently: the strict defaults apply and the session start names the key. A broken machine
  policy file blocks every prompt and names the key.
- Keychain values are stored base64-marked (`b64:`), so umlauts round-trip; entries written
  by earlier versions are still read.
- Every hook run is recorded in `~/.maisecrets/hooks.log` (no value, no command).
- Write, Edit, MultiEdit and NotebookEdit resolve a placeholder in their content like an MCP
  argument (session rule, cap, audit line with the file name); `"resolve_in_files": false`
  turns that off.
- Requires Python 3.11+; without it every prompt is blocked and the message names what to
  install.

### Features

- Write and Edit resolve a placeholder like an MCP argument; Windows run dir without uid (9b1cf00)
- second review round applied - private FIFO dir, shell-context scanner, model-facing texts, policy file, retention (099032d)

### Fixes

- the block notice says a placeholder resolves only where maisecrets is active (e2a1db4)
- the primer allows a value in a file or a command when the user asks for it (1a60541)
- second-round findings - command-word refusals, no POSIX grants, private tmp run dir, config fallback, keychain line limit, hooks.log (71e2826)

## [0.3.21] - 2026-09-26

### Features

- Codex on Windows runs the hooks through a PowerShell launcher (c8d0606)

### Fixes

- the Codex launcher is a batch file, run as cmd.exe /C like Codex does (e7bd8d2)

## [0.3.20] - 2026-09-26

### Fixes

- the up-front read tests accept the resolver form Git Bash uses (061258b)
- fail closed on the plugin's own faults and deliver Bash values through a FIFO read up front in the main shell (9170416)

## [0.3.19] - 2026-09-26

### Features

- /maisecrets:send sends the kept rewritten prompt without a clipboard; a failed resolve terminates the command; a grant serves retries; a copied nonce is denied (caf0a98)

### Fixes

- retry the atomic replace while another process reads the index (WinError 5 under concurrency) (4f671dd)
- the lock is taken per index mutation, not for a process's life; the Codex harness preloads in a subprocess; tests keep the open lock file; the release gate steps aside when main moved on (c723767)
- hook processes running at once no longer break each other: per-process temp files, one lock per vault home, unique scrub temp names (6b0ab8c)

## [0.3.18] - 2026-09-26

### Fixes

- the blocked prompt and an MCP resolve are scrubbed from the transcript by a detached child that waits for the record; the harness now really checks transcripts (353643b)

## [0.3.17] - 2026-09-26

### Fixes

- drop the root plugin.json, with it Codex discovered none of the four hooks; the Codex harness installs the plugin through Codex's own discovery (723bb8f)

## [0.3.16] - 2026-09-26

### Fixes

- a labelled value counts from 8 characters, said in the tip and the README (97701a0)

## [0.3.15] - 2026-09-26

### Features

- bare token prefixes live in rules/prefixes.txt, one line each, extended by pull request; CONTRIBUTING.md (4a66d5c)

## [0.3.14] - 2026-09-26

### Fixes

- Cloudflare user API tokens (cfut_) are a secret shape when bare; gitleaks 8.30 needs the word cloudflare and an assignment sign (e17ff23)

## [0.3.13] - 2026-09-26

### Features

- one short tip per day at session start (label a password, /maisecrets:put, session rule, report, audit); off with tips=false (8d6a66c)

## [0.3.12] - 2026-09-26

### Features

- German credential labels (passwort, kennwort, geheimnis, schluessel, zugangsdaten); /maisecrets:put stores the clipboard value and hands back the placeholder (3b67aaa)

## [0.3.11] - 2026-09-26

### Fixes

- release token recreated after the namespace move dropped every project access token; GitLab stays under the personal namespace (cbe8995)

## [0.3.10] - 2026-09-26

### Features

- /maisecrets:report bug <text> and feature <text> open a prefilled issue without a detection event (bb07a67)

## [0.3.9] - 2026-09-26

### Fixes

- a span that contains a placeholder is never a hit (curl -u app:⟦SECRET_c1⟧ minted a second reference); README opens with what the user sees (bd1e9b3)

## [0.3.8] - 2026-09-26

### Fixes

- every file read names UTF-8; the audit-log test read the file with the platform encoding and failed on windows-latest (254cc36)

## [0.3.7] - 2026-09-26

### Features

- notify the claude.ai organisation marketplace from the tag pipeline with a signed push event (41da293)

## [0.3.6] - 2026-09-26

### Fixes

- webhook signing secrets (whsec_) are a secret shape; a bare one on its own line passed. References are numbered in text order (3a9ce0b)

## [0.3.5] - 2026-09-26

### Fixes

- drop userConfig, which Claude Code 2.1.223 rejects as an invalid manifest and then loads no hook at all; the harness fails when the plugin did not load (29e75d9)

## [0.3.4] - 2026-09-26

### Fixes

- a fixed-length secret shape is extended to the end of the token run; harnesses check the marker tail (56b3a92)

## [0.3.3] - 2026-09-26

### Features

- /maisecrets:report and maisecrets report open a prefilled GitHub issue from the last detection event, never with a value (991d1de)

## [0.3.2] - 2026-09-26

### Fixes

- the creating session always may resolve an entry, also for entries written before the sessions list existed (b649f66)

## [0.3.1] - 2026-09-26

### Fixes

- while the major is 0, feat and fix bump the last number and only a breaking change bumps the middle one (6fc978f)

## [0.3.0] - 2026-09-26

### Features

- session-bound references, one-time grants for Bash, MCP argument resolution, exact-match redaction, limiter and audit log (f337394)

## [0.2.0] - 2026-09-26

### Features

- release job derives the version from commit subjects, tags, and mirrors main and tags to GitHub over a deploy key (52eacb2)

## [0.1.0] - 2026-09-26

- Day-1 prototype: detector (patterns from an earlier internal scrubber), placeholder
  tokens `<TYPE_cN:display>`, vault with TTL and metadata index (jsonfile and
  macOS keychain backends), three Claude Code hooks, harness with a fake
  Anthropic upstream, 4 scenarios, golden hook payload shapes.
- Detector as data: gitleaks, Presidio and detect-secrets rulesets vendored;
  placeholder `⟦TYPE_cN:display⟧` aligned with the gateway; keychain, Credential
  Locker and encrypted-file backends with TTL; Codex adapter; harnesses for
  Claude Code and Codex against fake upstreams.

From 0.2.0 on, every section above is generated by `scripts/release.py` from the
commit subjects since the previous tag.
