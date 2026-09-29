# Changelog

## Unreleased

- **Codex on Windows: a removed plugin folder now blocks instead of letting the tool run.** Codex
  removes the folder of the old version when it installs a new one, also under an open session
  (codex-cli 0.159.0, measured). The Windows command of each hook (`commandWindows`, run by
  `cmd.exe`) now checks for the launcher first and answers with a block when it is gone, as the
  macOS and Linux command already did. The text tells Codex users to exit and run `codex resume`
  instead of a Claude Code command.

- **Code after a colon is no longer stored as a secret.** A line such as `if not token: <statement>`
  put the statement word into the vault, and maisecrets then redacted that word in every later text,
  in source code too. A statement keyword after a label (`break`, `return`, `pass`, `raise`, …) is not
  a value now; so a password that is exactly such a word is not stored either. One lowercase word after a label, with
  the sentence going on, is still stored: without a dictionary it looks like a password of letters,
  and a missed password costs more than a false positive.

- **The false positives of the old detector are deleted at the next session start.** A statement
  word such as `return` that an earlier version stored after a label stayed in the vault until it
  expired, and maisecrets redacted it in every text until then. The session start now deletes these
  entries and names their keys once. It finds them by fingerprint and reads no stored value. The
  same word stored by `/maisecrets:put` or another rule stays.

- **A subagent's report no longer stops the session.** When a subagent quoted a value in the shape of
  a secret, its report reached the session as a prompt, and maisecrets blocked it until you pressed
  Cmd+V or `/ms`. A model of this session wrote that text, so the block protected nothing. The report
  now passes when it proves itself against the files of this session: the call that started the
  subagent, the subagent's own transcript, and its last answer. A value that anyone added outside the
  answer still blocks. `"pass_agent_reports": false` in `~/.maisecrets/config.json` turns this off.

- **Fewer false alarms in source code.** A run over the Python standard library (36.6 MB, no real
  secret in it) found 38 "secrets", 666 "IP addresses of a person" and 26 "phone numbers". These are
  no longer hits: a name on the right side of an assignment (`authkey=authkey`, `self.token = nextchar`,
  `TOKEN_ENDS = TSPECIALS | WSP`), a word of an error message (`pwd: expected bytes`), a format string,
  a time zone (`key = "Europe/Dublin"`), a mask (`*******`), a signed number in code (`a = +4294967296`),
  a number with more than 15 digits, and the documentation, shared, reserved and multicast address
  ranges and the public DNS resolvers. A quoted value, a value in a properties file and a phone
  number in prose are still found.

- **Test passwords no longer stop the work.** A password that maisecrets finds only by its label
  (`password = '…'`) is a fixture in test code: in a file on a test path, in a grep line of a test
  file, or after a test marker such as `def test_`, `assert` or `describe(`. A pasted unit test now
  passes, and a Read of a test file keeps its fixtures. A token shape (`glpat-`, `AKIA`, a private
  key) and personal data are still found in test code.

## [0.5.14] - 2026-09-29

- **The restart command stands on a line of its own** in the refusal of the guard, so it is easy to
  see, and a triple click copies just that line. The refusal now says the command *was* copied to
  your clipboard: a terminal with copy-on-select (the default in Ghostty) replaces the clipboard as
  soon as you select text, also text in the refusal itself.

### Fixes

- the restart command stands on its own line; the refusal says it was copied (3fef4b4)

### Other

- Merge branch 'fix/guard-message-layout' into 'main' (0d17b8b)

## [0.5.13] - 2026-09-29

- **Synced installs: the guard now gives the restart command.** After a synced update,
  `/reload-plugins` can keep the path of the gone plugin folder (anthropics/claude-code#97847), and
  then it cannot load maisecrets again. The refusal of the guard now says so and names the command
  that works: exit, then `claude --resume <id of this session>` in the directory where the session
  started. Run `/maisecrets:guard install` once more if you installed the guard yourself.
- **The guard puts that command on your clipboard**, once per session (`pbcopy` on macOS, `clip` on
  Windows, `wl-copy`, `xclip` or `xsel` on Linux). Exit, paste, press Enter. The refusal says so only
  when the copy worked. `MAISECRETS_GUARD_CLIPBOARD=off` turns it off.

### Features

- the resume command goes to the clipboard, once per session (857be68)

### Fixes

- the refusal gives the restart command when /reload-plugins cannot help (7f1292e)

### Other

- Merge branch 'fix/guard-restart-hint' into 'main' (8f58a86)

## [0.5.12] - 2026-09-29

- **Windows without Git Bash: maisecrets now protects Claude Code there.** Claude Code runs a hook
  command in PowerShell when Git for Windows is not installed. The hook commands of 0.5.11 were bash
  only: PowerShell refused to parse them, the hook failed without a block, and a prompt with a secret
  reached the model. Each hook command now works in bash and in PowerShell. The `PowerShell` tool of
  Claude Code meets the store guard, and a placeholder in a PowerShell command is refused with the
  reason.
- **A guard you installed yourself** (`/maisecrets:guard install`, not a synced install) keeps the tool
  list of its version. Run `/maisecrets:guard install` once more after this update, so that it also
  covers the `PowerShell` tool.
- **Codex users: re-trust the hooks once in `/hooks` after this update.** `hooks/hooks.json` changed.
  Until the hooks are trusted again, Codex runs no maisecrets hook and says nothing.

### Fixes

- refusals name what works without Git Bash; the PowerShell part has a test (2920339)
- the store guard knows the Credential Locker listing, the launchers' get and two Windows spellings (a2023ac)
- maisecrets protects Claude Code on Windows without Git Bash (8ad4795)
- every generation of the synced folder counts; the guard's own refusal names it (f979433)

### Other

- Merge branch 'feat/windows-powershell' into 'main' (83ba31b)

## [0.5.11] - 2026-09-29

- **Synced installs: a guard against the update gap, set up by maisecrets itself.** An update of a
  plugin that the organisation syncs from claude.ai can leave a session without maisecrets, silently.
  At its next session start a synced maisecrets places `~/.claude/maisecrets-guard.py` and registers
  it once in `~/.claude/settings.json` (a backup first, only the hooks change, one line says so). The
  guard blocks a prompt or tool call that maisecrets did not answer and names `/reload-plugins`.
  `/maisecrets:guard remove` takes it away; `"guard": false` in the config or the machine policy
  keeps it off. Installs from the marketplace and Codex are not touched.
- **Codex:** a placeholder in a file edit (`apply_patch`) is now resolved, and a patch against the
  maisecrets store is refused.

### Features

- a guard outside the plugin folder stops a session in which an update left maisecrets not running (4cdbdcd)

### Fixes

- "guard": false works without a guard.json; a person's --off stays their own (72eef2d)
- a multi-line value stays file content in a Codex patch; the guard waits for the answer (8d28b90)
- the update window reads the change time; the measured folder counts per account (8e7b4cc)
- no lasting block after an organisation removes maisecrets; the script is guarded too (c02e964)
- a patch header behind any whitespace is a header; the guard expects by account (3a158d4)
- two registrations pass a healthy call; an indented Codex patch header is a header (5af2899)
- Codex apply_patch resolves a placeholder and never writes the maisecrets store (5f3a399)

### Other

- Merge branch 'fix/guard-windows-tests' into 'main' (3c998cd)
- Merge branch 'feat/codex-apply-patch' into 'main' (746374c)

## [0.5.10] - 2026-09-29

- **Behaviour change: maisecrets adds no approval of its own by default.** A value still never
  reaches the model, and a form where it could turn into code is still refused. What changed: an
  MCP call and an ssh command that get a real value no longer ask first, and on Codex a value in a
  published-text field (`text`, `message`, `body` …) now goes in. In Claude Code your permission
  rules decide, as for any other call; in Codex maisecrets answers `allow`, as it did for Bash and
  for other MCP fields, and Codex's sandbox and MCP tool approval still apply. To keep the ask of
  0.5.9 for MCP and ssh, set `"rehydration": "confirm"` in `~/.maisecrets/config.json` or in the
  machine policy. `confirm` is stricter than 0.5.9 on the other paths: Bash and Write/Edit ask too,
  and Codex refuses every rehydration, because it cannot ask. `"block"` turns rehydration off.
- **For administrators:** a machine policy file that exists but cannot be read now makes the hooks
  fail closed (before, it counted as no policy). Keep it and its folder readable by every user. A
  key in it that looks like a misspelled `rehydration`, `resolve_in_files` or `ssh_via_sandbox`
  blocks rehydration until it is fixed; other unknown keys are ignored with a warning.

### Features

- maisecrets adds no approval of its own by default; rehydration confirm and block are optional (9eead0c)

### Fixes

- the limiter answers an empty key list without an index error (82264ef)
- a lowered key cap no longer breaks a call with known keys (9725364)
- a misspelled safety key blocks even next to a valid setting; caps count per call (650167c)
- a setting that cannot be read as written blocks rehydration; no partial resolve (cdb57a8)
- an ignored config file never loosens the rehydration policy (a043a33)

### Other

- Merge branch 'feat/rehydration-policy' into 'main' (b945f23)

## [0.5.9] - 2026-09-28

- **Codex:** `hooks/hooks.json` changed in this release, so Codex asks once in `/hooks` to trust
  the hooks again.

### Features

- sudo -n before a read-only remote command counts as read-only (a1711d2)
- Norwegian and Czech credential labels, regions no and cz (85a8649)
- Portuguese and Danish credential labels, regions pt, br and dk (161762c)
- French and Dutch credential labels, regions fr, lu, be and nl (b7da1cf)
- Korean and Thai credential labels (6cff625)
- Polish and Turkish credential labels (46d578e)
- Finnish and Swedish credential labels (02c2f1b)
- Spanish and Italian credential labels (1b2ca9c)

### Fixes

- the context window is cut from the original text, then lowered (1d2918c)
- Turkish labels in capitals, such as ŞİFRE: (ce1aef5)
- a refusal about the store says what the user does next (1aad280)
- a second hop names one ssh per host; the sandbox e2e runs an ops user's forms (e64bec6)
- a false-positive report names the forget command and deletes nothing itself (6a1ea89)
- a refusal names the form that works, and the primer says what to do (e5f806a)
- /ms sends the blocked prompt of its own session, also when two sessions wait (f90cc47)
- a hook command that finds no launcher refuses; Claude Code still skips a moved plugin (f6b2cb8)
- a space before the colon of a label, as French typography writes it (a8fad39)

### Security

- every fail-closed answer has the shape of the client that asked (481810d)
- a hook that cannot work refuses in JSON, which Codex reads too (12b8400)
- a session id is a name, never a path, and a command cannot set it (e1bae80)
- an entry point that cannot import the plugin's code refuses instead of passing (1793d1c)
- an MCP resource read that names the store is refused (fd2e23a)

### Other

- Merge branch 'fix/i2-windows-form' into 'main' (287f6d2)
- Merge branch 'feat/label-languages-l10n' into 'main' (69a4d9d)
- Merge branch 'ci/faster-matrix-and-prepush-scan' into 'main' (fbd732a)

## [0.5.8] - 2026-09-28

### Fixes

- recognise a Windows file URI that names the store (3cca981)
- name an unknown key only when it is a typo of a real one (55f491f)
- catch a value JSON-escaped twice in an MCP result (3e46e48)

### Security

- catch another session's value that a command printed as hex or base64 (431ad59)
- refuse a hard link, a file URI and a configured home path into the store (356bbfc)
- block a prompt that carries a value the store already holds (fabbd5f)

### Other

- Merge branch 'fix/windows-invariant-paths' into 'main' (21d9ff5)
- Merge branch 'feat/invariant-beliefs' into 'main' (ad2711b)

## [0.5.7] - 2026-09-28

### Fixes

- the transcript scrub opens the file in binary mode on Windows (c1a8b56)
- Grep without a path, Windows digit scrub, Unicode word boundary (4aa1eb6)
- the Codex review of the read gate, short values and the digit scrub (e07b32f)
- a detected value of only digits is scrubbed from the transcript (8f537bd)
- Read, Grep and Glob never read the store (96f92f3)
- a short value the session put in comes back masked (1d8cfa3)
- the ssh route works in the Linux sandbox (335ee7c)

### Other

- Merge branch 'fix/windows-binary-scrub' into 'main' (2301d89)
- Merge branch 'fix/linux-sandbox-proxy-login' into 'main' (46a3b62)

## [0.5.6] - 2026-09-28

### Features

- ssh_approval per-session, one approval per value and session (e0b9bc3)

### Fixes

- journalctl --synchronize-on-exit is not read-only (bcd1a4a)
- the sealed directory stays sealed; stateful commands leave the read-only list (150dc88)
- the Codex review of the ssh session approval (be8be6a)

### Other

- Merge branch 'feat/ssh-session-approval' into 'main' (78f0e8c)

## [0.5.5] - 2026-09-28

### Fixes

- a plugin linter; the report frontmatter parses as YAML again (d2ad842)
- the shell rule counts only input and traces that reach the shell (c85b8a4)

### Other

- Merge branch 'fix/shell-rule-scope' into 'main' (f0c5ca0)

## [0.5.4] - 2026-09-28

### Features

- run on Python 3.9, the stock python3 of macOS (d4a95b9)

### Fixes

- the second Codex round, shell input and trace settings anywhere (41e3978)
- four findings from the Codex review of the 0.5.3 follow-ups (9964898)
- four points from testing 0.5.2 (encoder rule, arguments, browser, report) (16881b6)
- env -S in its real words, and a backslash-newline joins the line (2ebd713)

### Other

- Merge branch 'fix/tests-under-xdist' into 'main' (465df55)

## [0.5.3] - 2026-09-28

### Features

- ssh gets a value on stdin inside the Claude Code sandbox, after a confirm (8eb8e5a)

### Fixes

- the final review follow-ups for the ssh route (2d434e2)
- the final review of the ssh route and the command-word rules (54889dd)
- the ssh safety net no longer refuses a sentence or a part without a value (7e1004d)
- the ssh options follow the command word, past wrapper option arguments (9015378)
- ssh in any other form is refused, and the guard checks the proxy (4b11421)
- the second review round of the ssh route (341f7d2)
- a command word hidden by quotes, a variable or a runner is still checked (985ff2a)
- the ssh route reads options after the host and the whole remote command (dee6b85)
- the ssh route also switches off shared ssh connections (a814d85)
- a short value glued to its label is a value (65bd51e)

### Other

- Merge branch 'feat/ssh-through-the-sandbox' into 'main' (dc08fbd)

## [0.5.2] - 2026-09-27

### Features

- each release also goes to a GitHub branch with only the runtime files (4554787)
- no install offer where no agent CLI exists (a web or mobile chat) (0d7dbfb)
- every task starts with a protection check, and the skill installs the hooks after a yes (0b241fb)

### Fixes

- the release tree builder passes NUL-separated bytes to git (2294a44)
- the release tree builder uses the release identity when git has none (93f1b9b)
- the hook waits for its watchdog thread before it ends (7c4c63f)
- the zip folders can be opened, and the offer text comes with the verdict (00c909a)
- the protection check follows this agent's own hook run, and the offer asks first (6a50c95)

### Other

- Merge branch 'fix/release-tree-binary-on-windows' into 'main' (00eda11)
- Merge branch 'fix/hook-waits-for-its-watchdog' into 'main' (e9c7762)
- Merge branch 'feat/skill-installs-the-protection-2' into 'main' (a74d9d8)

## [0.5.1] - 2026-09-27

### Features

- label languages as data files and regions from the system setting (46a7d5a)
- the first session start says how to try maisecrets (9a40916)

### Fixes

- expire counts only the values it deleted (a4c23b2)
- the commit before a release goes to the GitHub branch ci, not main (349da5e)
- a release moves only the last number; a higher one needs approval (e92e7ab)

### Other

- Merge branch 'fix/release-bumps-only-the-patch' into 'main' (ac124b6)

## [0.5.0] - 2026-09-27

### Breaking

- a breaking change of a silent type is listed under Breaking (ab8927d)

### Features

- pass and token are labels, a value may start with a symbol, the matrix is a gate; fix(ci): the repo scan checks each file and its own exit code (5168298)

### Fixes

- the skip gate accepts the native clipboard test (c681f9b)
- clip gets UTF-16 without a byte order mark (c5658b7)
- a placeholder word inside a random token is chance (daea5bb)
- read the clipboard without a byte order mark (adf4b59)
- the clipboard keeps ⟦ ⟧, and the tests never reach the real clipboard (990c45c)
- the unit and beliefs jobs install procps for ps (77f10b6)
- status closes the files it reads (5370e91)
- repair never gives a new value the key of an old placeholder (0bf9d0a)
- get refuses an entry past its expiry that the sweep has not purged (86bfca7)
- a value-serving child ends when its FIFO is taken back (ba1197b)
- a file store that refuses is reported, never a traceback (f96bead)
- wipe --yes deletes hooks.log as the notice says (a967d0d)
- a prefix-only IPv6 address no longer shows whole (b962e32)
- a gitleaks "match" allowlist sees the whole match (8f9bbfb)
- the keyword window ends one line too early (860ba9e)
- two distinct characters after a label are a value (178ebb1)
- an unquoted value after a label ends at the first whitespace (17603ad)
- a dotted reference after a credential label is not a value (51dde31)
- a store call that times out raises RuntimeError without the argv (d8f28f0)
- a stored value that comes back URL-encoded or JSON-escaped is replaced (c36fdef)
- a damaged vault index withholds the tool output instead of passing it raw (3e8e971)
- a payload that is JSON but no object is blocked instead of let through (c23f154)
- release the lock when the index read inside a mutation raises (de86fb5)
- a policy file that is not one JSON object fails closed (9ebcd60)
- CLI and session start print a traceback on a damaged index or a bad policy (5af6016)

### Other

- Merge branch 'fix/windows-tests' into 'main' (822d85f)
- Merge branch 'test/broad-coverage' into 'main' (3927b78)
- Merge branch 'worktree-agent-ad7d100b64b11e581' into test/broad-coverage (81b1370)
- Merge branch 'test/detection-matrix' into test/broad-coverage (727462b)
- Merge branch 'worktree-agent-a2b325182b96548dd' into test/broad-coverage (c0d7c5a)
- Merge branch 'worktree-agent-a6a8b806dc28f22d5' into test/broad-coverage (ef51017)
- Merge branch 'worktree-agent-ae2d480d350f472c4' into test/broad-coverage (ed8d1f3)
- Merge branch 'worktree-agent-a596d168a13bf9617' into test/broad-coverage (d43d2c2)

## [0.4.2] - 2026-09-27

- **The block notice is three lines:** what kind of thing was found, the one next step (⌘V or
  Ctrl+V, or /ms), and where to report a wrong detection. What is stored and for how long is in
  `/maisecrets:list`.

### Features

- a three-line block notice - the kind found, the one next step, the report (efa93cd)

## [0.4.1] - 2026-09-27

### Fixes

- an expired entry no longer breaks status, list and a new paste of the same value (f8172bf)

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
