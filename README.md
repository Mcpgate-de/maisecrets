# maisecrets

[maisecrets.dev](https://maisecrets.dev) · by [mcpgate](https://mcpgate.de) · Apache-2.0 · free

Keeps secrets and PII out of the cloud model. Works as a plugin for Claude Code
(and Cowork) and for Codex, from the same `hooks/hooks.json`.

**What it does, deterministically and locally:**

1. **You type a secret or a personal value** (a token, a password after a
   label, any e-mail address, a phone number with a country code, an IBAN, a
   card number, a public IP, and German identifiers by default). A
   `UserPromptSubmit` hook
   detects it, stores it in a local vault, blocks the prompt, and keeps the
   rewritten prompt with a placeholder such as `⟦SECRET_c1⟧` or
   `⟦EMAIL_c1:ma•••@example.org⟧`. Type `/maisecrets:send` to send it as is,
   or paste it from the clipboard where one exists. The value never reached
   the model. Measured: zero API requests for a blocked prompt.
2. **The model reads a file or runs a command that outputs a secret.** A
   `PostToolUse` hook redacts the result before the model sees it.
3. **The model uses a placeholder in a Bash command or a tool argument.** A
   `PreToolUse` hook lets the command read the value once under a one-time
   grant, or inserts it into the tool argument, right before execution. The
   output is redacted again on the way back. See "Gates around a resolve".

Everything a hook runs is readable source in this folder. No download, no
package install, no dependency outside the Python standard library and the
system tools it names (`security`, PowerShell, `openssl`, a clipboard tool).

What it does not do: detect names, follow a value through an encoding a
command applies, or protect against a process that runs as you. "Known gaps"
below lists every limit that was measured.

## What it looks like

You ask Claude to set up a deploy script and it reads your `.env`:

```
$ cat .env                          # what the command printed
DB_PASSWORD=example-hunter2-9Qz
STRIPE_KEY=sk_live_example…

                                    # what the model received
DB_PASSWORD=⟦SECRET_c1⟧
STRIPE_KEY=⟦SECRET_c2⟧
```

Claude writes the deploy command with the placeholder. You approve this,
and only this:

```
curl -u "app:⟦SECRET_c1⟧" https://db.example.internal/migrate
```

At execution the placeholder is read once from your keychain, the request
carries the real password, and the command's output comes back with any
value replaced again. The password was never in the prompt, the transcript,
or the model's context.

You paste a token into the prompt by accident:

```
> please check why glpat-EXAMPLEEXAMPLE1234567 fails in CI
maisecrets: 1 SECRET detected and stored as SECRET_c3. The prompt did not
reach the model. The rewritten prompt is in the clipboard: paste and send again.
```

Zero requests left the machine for that prompt. The rewritten prompt reads
`please check why ⟦SECRET_c3⟧ fails in CI`, and Claude can use the
placeholder in a command as above.

## Status

Released from `main` on every merge (`CHANGELOG.md`, tags `vX.Y.Z`, 0.x scale:
a feature or a fix bumps the last number). Vault backend per platform:

| platform | backend | where the values live |
|---|---|---|
| macOS | `keychain` | login keychain via `security`, no iCloud sync flag |
| Windows | `windows-vault` | Credential Locker (`PasswordVault`, DPAPI) via PowerShell |
| Linux | `encrypted-file` | `openssl` AES-256-CBC + PBKDF2 + HMAC tag, key file 0600 |
| any | `jsonfile` | plaintext 0600, TEST MODE only |

Hooks run through `hooks/run.sh` (bash), which looks for a Python 3.11+ as
`python3`, `python`, `py -3`, a versioned name, or the Homebrew, `/usr/local`
and python.org paths. Claude Code on Windows requires Git Bash, so the
launcher runs there too. Codex on Windows has no Git Bash, so every hook also
names a `commandWindows` entry: `hooks/run.cmd` runs the same `dispatch.py`
from `cmd.exe`, the shell Codex uses for a Windows hook. Without a Python
3.11+ the launcher blocks every prompt and every tool call and withholds every
tool result, and its message names what to install: fail closed, with a cause.

Proven with the harness on macOS (Claude Code 2.1.283) and on Debian 13
(2.1.223), 7 scenarios each, on every push in CI; Windows through the GitHub
Actions matrix (unit tests, both launchers, Credential Locker round trip), not
yet with a live Claude Code session. Codex (codex-cli 0.155.1): the same
`hooks/hooks.json`, Codex sets `CLAUDE_PLUGIN_ROOT` itself; `harness/codex.py`
proves the three tool scenarios against a fake Responses upstream on every
push and, with `--real`, against the real model. `docs/TESTING.md` has the
record. GitHub is a read-only mirror of the primary repository; issues and
pull requests are welcome there.

## Client support

✅ proven by the harness in this repo or seen live · ☑️ same runtime or possible per the
vendor's hook docs, not measured · ⚠️ partly · ❌ no hook

| client | prompt | rehydrate | redact | adapter |
|---|:---:|:---:|:---:|---|
| Claude Code CLI | ✅ | ✅ | ✅ | built |
| Cowork, Claude desktop app | ☑️ | ☑️ | ☑️ | same hooks and manifest; not measured by the harness |
| Codex CLI | ✅ | ✅ | ✅ | built; hooks need one trust review per user (`/hooks`) unless an admin ships them as managed hooks; on Windows a shell placeholder is denied (PowerShell rewrite not built) |
| Codex in the ChatGPT desktop app | ✅ | ✅ | ✅ | same plugin runtime; block, rewrite and redaction seen live (2026-09-27), not in the harness |
| Codex IDE extension | ☑️ | ☑️ | ☑️ | same plugin runtime; not measured |
| Gemini CLI | ☑️ | ☑️ | ☑️ | not planned |
| Cursor | ☑️ | ☑️ | ⚠️ MCP only | waits for a shell-output hook |
| Copilot CLI | ⚠️ SDK only | ☑️ | ☑️ | waits for a prompt hook |
| OpenCode | ❌ | ☑️ | ☑️ | waits for a prompt hook |
| Antigravity | ❌ | ☑️ | ❌ | not supportable |
| Chat apps, web, mobile | ❌ | ❌ | ❌ | no hooks |

The three columns are the three guards: block a prompt that carries a
value, resolve a placeholder at execution, redact tool output before the
model sees it. A client with ❌ or ⚠️ under prompt or redact cannot be made
safe by this plugin; it would look protected and leak. The hook names
behind each mark are in `docs/CLIENTS.md`.

## Requirements

Python 3.11 or newer on the PATH the client gives its hooks (`python3 --version`).
A stock Mac ships 3.9: `brew install python` or the python.org installer.
Windows: `winget install Python.Python.3.12`. Linux: your package manager, plus
`openssl` for the vault and `xclip` if you want the clipboard. Without it the
plugin blocks every prompt and names the missing piece.

## Install

```bash
claude plugin marketplace add Mcpgate-de/maisecrets     # the GitHub repo is its own marketplace
claude plugin install maisecrets@maisecrets             # user scope; new session or /reload-plugins
claude plugin update maisecrets@maisecrets              # later versions
```

Codex (CLI, IDE extension, and the Codex agent inside the ChatGPT desktop app):

```bash
codex plugin marketplace add https://github.com/Mcpgate-de/maisecrets.git
codex plugin add maisecrets@maisecrets
```

Codex reads `.codex-plugin/plugin.json` (listing texts, icon) and the hooks from
`hooks/hooks.json`.

Codex skips a plugin's hooks until you review and trust them once: open `/hooks`
in Codex and trust the maisecrets entries. Until then nothing is protected and
the plugin cannot tell you so, because no hook of it runs. A workspace admin
can ship the hooks as managed hooks (`requirements.toml`, MDM), which are
trusted by policy and cannot be disabled. The plain ChatGPT chat, web and
mobile have no local runtime and no hooks.

For development:

```bash
claude --plugin-dir /path/to/maisecrets                 # one session, straight from the checkout
python3 -m unittest discover -s tests -v               # under three seconds
python3 harness/run.py                                 # 7 scenarios against a fake upstream
python3 harness/codex.py [--real]                      # 3 scenarios through codex exec
python3 scripts/replay_can_fail.py                     # 20 proofs: each control's test goes red without it
python3 scripts/derived_counts.py                      # the numbers in the docs, measured again
scripts/install-hooks.sh                               # git pre-commit / pre-push
```

## Update and uninstall

```bash
claude plugin update maisecrets@maisecrets             # or a new session with an org-synced plugin
claude plugin uninstall maisecrets@maisecrets
codex plugin remove maisecrets@maisecrets
```

Uninstalling keeps the stored values until their TTL ends. To delete them,
the metadata and the logs at once, run `maisecrets wipe --yes` from the plugin
folder (`/maisecrets:status` prints the folder):

```bash
bash <plugin folder>/hooks/run.sh wipe --yes
```

or delete the `maisecrets` items in Keychain Access or Credential Manager and
the `~/.maisecrets` folder by hand. `wipe` reports when an item refused to go.

## For administrators

**Rollout.** claude.ai: an organisation admin adds a private or internal
marketplace repository under organisation settings and sets the availability
(available, installed by default, required). The sync accepts no public
repository, so create a private one with a `.claude-plugin/marketplace.json`
that lists maisecrets with this repository as its source, or mirror this
repository into a namespace you control and review each release there before
your members get it. ChatGPT workspace: Admin > Plugins > Add > Import
marketplace, with the same `marketplace.json`; the sync runs daily or on
"Sync now". Codex CLI users trust the hooks once in `/hooks`; a change to
`hooks/hooks.json` asks again, and until then Codex runs no maisecrets hook and
says nothing. Managed hooks (`requirements.toml` through MDM) are trusted by
policy.

**Updates.** A new version reaches a member when `version` in
`.claude-plugin/plugin.json` changes: at the next session start for an
org-synced plugin, with `claude plugin update` otherwise. Every session starts
with one line `maisecrets X.Y.Z active`; its absence means the plugin did not
load. A rollback is a `git revert` on `main`: the pipeline releases it as the
next patch version.

**Settings you can enforce.** A machine policy file wins over the user's
`~/.maisecrets/config.json` and cannot be changed from there:
`/Library/Application Support/maisecrets/policy.json` (macOS),
`%ProgramData%\maisecrets\policy.json` (Windows), `/etc/maisecrets/policy.json`
(Linux). Any key from "Options" goes in it; typical: `backend`,
`scrub_transcript`, `max_ttl_seconds`, `pii_regions`, `report_url`,
`resolve_in_files`.
`/maisecrets:status` names the keys that come from the policy. The plaintext
`jsonfile` store is refused unless the policy or the user sets
`allow_plaintext_store`.

**What is written where.** `~/.maisecrets/index.json` holds metadata and keyed
fingerprints, a masked display for PII, and session ids; metadata of an expired
value is deleted after `keep_purged_days` (30). `audit.log` holds one line per
resolve (time, session, key, tool, the command with placeholders; capped at
`audit_max_lines`). `events.log` holds the last 200 detections (rule name and
type). `pending/` holds a blocked prompt with placeholders for 15 minutes.
`hooks.log` holds one line per hook run (capped at 2000); the client column names
the entry point, `claude/local-agent` for a Cowork session. The FIFOs a value
is delivered through live in `$XDG_RUNTIME_DIR/maisecrets` or
`maisecrets-<uid>` in the temp directory, for up to 120 s. The values live in
the store of the platform; on macOS a value longer than about 2.8 KB (a private
key) is passed to `security` on its command line, visible to `ps` for the
milliseconds of the call, because the stdin form has a line limit. Nothing leaves the machine: no hook
opens a network connection. Two exceptions to state to a data-protection
officer: the Windows Credential Locker can roam through a Microsoft account on
a machine that is not domain-joined (set `backend` to `encrypted-file` by
policy if that matters), and `/maisecrets:report` opens the browser on a
prefilled issue at `report_url` (set it to your tracker, or to `null` to turn
reporting off).

**Diagnosis.** `/maisecrets:status` prints version, plugin folder, Python,
store, policy keys and log counts. `/maisecrets:audit` prints the last
resolves. `MAISECRETS_DEBUG_LOG=<file>` in the client's environment records one
line per hook call (event, client, duration, answer; never a value).
`bash <plugin folder>/hooks/run.sh wipe --yes` is the offboarding step; a
damaged `index.json` is rebuilt with `… run.sh repair` (stored values are
deleted, the counters continue). `hooks.log` in `~/.maisecrets` records every
hook run (time, event, client, session, tool, decision, duration; no value and
no command), so "the plugin did nothing" can be told from "the hook did not
run".

## What the plugin runs, sends and fetches

- Runs: `bash hooks/run.sh <event>` (or `hooks/run.cmd` for Codex on Windows)
  → `hooks/dispatch.py` on the matching hook events. Each reads one JSON
  payload from stdin and prints one JSON object. A Bash command with a
  placeholder reads the value from a FIFO in the per-user runtime or temp
  directory (POSIX) or through `hooks/resolve.py` under a one-time grant
  (Windows Git Bash).
- Writes: under `~/.maisecrets`: `index.json` (metadata and keyed
  fingerprints, never a value), `audit.log`, `events.log`, `hooks.log`,
  `pending/`, `.announced`; the value FIFOs in the per-user runtime or temp
  directory; the vault backend; on a blocked prompt the clipboard. With
  `scrub_transcript` on, it masks the raw value inside the client's transcript
  file named in the hook payload, in place, because the client writes the
  prompt to disk before or after the hook runs. "For administrators" has the
  retention of each file.
- Sends and fetches: nothing. No hook opens a network connection.
  `/maisecrets:report` opens your browser on a prefilled issue page; the
  Windows Credential Locker may roam through a Microsoft account.

## Options

All options live in `~/.maisecrets/config.json` (next section) and take
effect on the next hook call. The manifest declares no `userConfig` on
purpose: Claude Code 2.1.223 rejects a manifest with that key and then loads
no hook at all, silently. A guard that vanishes on an older client is worse
than one without a settings dialog. At the first session start, and at every
start in test mode, a notice names the active store, its path and where to
change it. `python3 -m maisecrets.cli status` prints the same at any time.

## Vault

`~/.maisecrets/config.json` (all optional):

```json
{
  "backend": "keychain",
  "ttl_seconds": {"default": 86400, "CARD": 3600},
  "max_ttl_seconds": 2592000,
  "renew_on_use": true,
  "scrub_transcript": true,
  "block_at_mentions": true,
  "pii_regions": ["generic", "de"],
  "max_keys_per_session": 25,
  "max_resolves_per_hour": 60,
  "report_url": "https://github.com/Mcpgate-de/maisecrets/issues"
}
```

`backend`: `keychain` (macOS), `windows-vault`, `encrypted-file` (Linux and
any other), `jsonfile` (test mode, plaintext). `pii_regions`: Presidio
regions besides the generic ones. `tips`: `false` turns off the one-line tip
that appears once a day at session start.

Every entry has a TTL. Each use renews it, up to `max_ttl_seconds`. On
expiry the value is deleted and the metadata stays as a record. Commands:
`python3 -m maisecrets.cli list | get <KEY> | put | audit | expire | scan | config`.

**What the store does and does not do.** The keychain, the Credential Locker
and the encrypted file keep the value off the disk in plaintext and away from
other users. None of them stops a process that runs as you: `security`,
PowerShell or openssl hand the value to any such process without a dialog
(`docs/THREAT-MODEL.md`). The gates below stand in front of the agent, not in
front of you.

## Handing a value to Claude on purpose

Paste it. A value with a known shape (a token, a key, an IBAN) is blocked,
stored, and comes back as a placeholder in your clipboard. A password without
a shape needs a label or the vault command:

- label it: `password: …`, `passwort: …`, `api_key=…` (English, Spanish and
  German labels are recognised; the value counts from 8 characters, so
  `password: yes` is not a hit);
- or copy the value and run `/maisecrets:put` in Claude Code; the placeholder
  replaces the value in your clipboard. Paste the placeholder into your next
  message, and Claude uses it in commands and tool calls. Over SSH and in a
  headless session there is no clipboard: type the value after a label
  (`passwort: …`) instead; the block stores it and names the placeholder.

A bare password in prose, such as "use Sommer2026 for the login", is not
detected. That is a limit of pattern detection, not a setting.

**Sending a blocked prompt.** `/maisecrets:send` sends the rewritten prompt as
it is, without the clipboard. A plugin cannot register a command without its
namespace, so the first session start writes a personal `/ms` for it into
`~/.claude/commands` (a fixed wrapper in `~/.maisecrets/bin` finds the
installed plugin at run time, so it survives updates); an existing `/ms` is
left alone, `"shortcut": false` turns this off, `/maisecrets:shortcut [name]`
installs it by hand. The answer starts with `Sent: ` and the
text that went out, because Remote Control shows neither a blocked prompt nor
a slash command's expansion; the block notice itself is not shown there
either (reported to the vendor).

## Reporting a wrong detection

Every block and every redaction leaves an event in `~/.maisecrets/events.log`
(hook, client, rule name, type, plugin version; never a value). In Claude Code,
`/maisecrets:report last <why it is wrong>` opens a GitHub issue prefilled from
the last event; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` open one without an event.
The CLI form is `python3 -m maisecrets.cli report …`. The value is not in the
event, so it cannot be in the issue; describe its shape in words.

## Gates around a resolve

A placeholder turns back into its value only here:

- **In the session where the value came in.** A reference resolves in the
  session where a human typed or pasted it, where the value was detected in a
  prompt, or where the value appeared in a tool result. A reference minted in
  session A resolves in session B only after you paste it into a prompt there.
  Keys are counters, so an injected text could otherwise name one it never saw.
- **Read up front in Bash.** The hook prefixes the command with
  `__ms_1="$(cat <fifo>)" || exit 97;` and turns `⟦SECRET_c1⟧` into
  `$__ms_1` in its quoting context. A detached process serves the value once
  through a FIFO in a directory only you can enter (`$XDG_RUNTIME_DIR/maisecrets`
  where the system has one, else `maisecrets-<uid>` in the temp directory; owner
  and mode are checked, a symlink is refused). It is readable from inside Codex's
  sandbox, which can neither write the vault nor read the keychain, and from a
  Claude Code sandbox that denies `~/.maisecrets`. On POSIX no grant is minted,
  so nothing is redeemable afterwards; on Windows Git Bash the resolver script
  reads the value under a one-time grant. The command you approve, the transcript and the tool record carry no
  value. A missing delivery ends the whole command with exit 97 before
  anything runs, also for references inside pipelines and subshells; nothing
  ever runs with an empty value. Every key is checked before anything is
  served, so a refused command leaves no value waiting. A value with quotes or
  `$(` arrives byte for byte in the contexts the rewrite can prove: plain,
  `'…'`, `"…"`, inside `$(…)`, an unquoted heredoc. A placeholder inside
  another shell (`bash -c`, `ssh`, `eval`, `su -c`), a quoted heredoc, `$'…'`
  or backticks, an interpreter with inline code (`python3 -c`, `perl -e`),
  `awk -v`, and a command that would encode, slice or trace the value
  (`base64`, `xxd`, `${x:0:4}`, `set -x`, `PS4=`) are refused with the
  reason, because there the value would be parsed a second time or leave in a
  shape the redaction cannot see. The check reads command words, so
  `python3 script.py ⟦KEY⟧`, `docker run -e T=⟦KEY⟧ img` and a word inside
  quotes or a comment pass. A refused command is refused as a whole: split off
  the step that needs the value and run it on its own.
- **Inline for Write and Edit.** A placeholder in the content of Write, Edit,
  MultiEdit or NotebookEdit is resolved like an MCP argument, under the same
  session rule, cap and audit line (the line names the file). The client's
  permission prompt then shows the diff with the value: that is the moment you
  see what goes on disk. `"resolve_in_files": false` (a policy can set it)
  turns this off; then the file tools refuse a placeholder and the way to a
  file is a Bash command you approve (`printf '%s' ⟦KEY⟧ > file`). The
  maisecrets home itself is never written by the agent.
- **Codex approves nothing here.** Codex accepts a rewritten command only
  together with `allow`, which skips its own approval prompt for that call.
  On Codex the gates above are the whole control; on Claude Code the normal
  permission rules still apply to the rewritten command.
- **Inline for MCP tools, after you confirm.** An argument has no shell to read
  from, so the value is inserted after the same session rule, and in Claude Code
  every such call stops at a permission prompt, also in auto and bypass mode. The
  prompt shows the call with the real value and names the fields; a field that
  carries published text (`text`, `message`, `body`, `comment`, `description`,
  `subject` …) gets a warning, because the value goes out with the message. In an
  unattended run (`claude -p`) nobody can confirm, so the call is refused and the
  model reads the reason, never the value. Codex cannot ask: there a placeholder
  in such a text field is refused, and one in another field (a recipient, an id)
  resolves without a prompt.
- **Under a cap.** `max_keys_per_session` (25) distinct keys per session and
  `max_resolves_per_hour` (60) in total; above that the call is denied and the
  reason names the cap. Every resolve writes one line to `~/.maisecrets/audit.log`
  (time, session, key, tool, command with placeholders; never a value):
  `python3 -m maisecrets.cli audit`.
- **Not by the agent reading or changing the store.** A Bash command that
  calls `maisecrets get`, `security … maisecrets`, names `~/.maisecrets` or a
  delivery path, and a Write/Edit under `~/.maisecrets`, are denied and the
  reason names the pattern. This is text matching, a backstop; the boundary
  is the gates above, and a process that runs as you is not stopped by it.

Recommended in your Claude Code settings, outside the plugin: the sandbox with
`sandbox.credentials` deny for `.env` files and `~/.maisecrets`, and
`injectHosts` for the hosts a value may go to. That closes the paths no hook
sees: a command that sends `.env` or `printenv` somewhere without printing it
(a command that pipes `.env` into an upload). The hook redacts only what comes back.

## Detection rules

Four sources, one scanner (`maisecrets/detect.py`):

- **gitleaks** ruleset, vendored as data under `maisecrets/rules/` (MIT,
  version in `GITLEAKS_VERSION`, refresh with `scripts/sync_gitleaks.py vX.Y.Z`):
  ~220 secret shapes with keywords, entropy thresholds and allowlists. No
  gitleaks binary is used.
- **Presidio** pattern recognizers, vendored as data under `maisecrets/rules/`
  (MIT, version in `PRESIDIO_VERSION`, refresh with `scripts/sync_presidio.py`):
  country-specific PII with scores and context words. Regions are opt-in via
  `pii_regions` in the config (default `generic` and `de`: Steuer-ID,
  Sozialversicherungsnummer, Personalausweis, Reisepass, USt-ID,
  Krankenversicherung, PLZ, Kfz, LANR, BSNR, Handelsregister). Checksums for
  the German types are ported and checked against Presidio
  (`scripts/check_validators_against_presidio.py`). A digit-only shape such as
  a Steuer-ID is reported only with a context word nearby, even when the
  checksum passes.
- **detect-secrets** (Yelp, Apache-2.0, version in `DETECT_SECRETS_VERSION`,
  refresh with `scripts/sync_detect_secrets.py vX.Y.Z`): credentials
  recognised by position (`password = …`, `api_key: "…"`, `user:pass@host`),
  with its heuristic filters ported (templated, indirect, sequential values
  are not secrets).
- **Own rules**, six of them, for what none of the three covers: email (a
  bounded regex; the unbounded one took 11 s on an 80 KB dotted run), phone
  with a country code, `Bearer …` outside curl, `?api_key=…` in a URL, and
  full-length GitLab runner and deploy tokens.
- Prefixes newer than the vendored rulesets live in
  `maisecrets/rules/prefixes.txt`, one line each, extended by pull request
  (`CONTRIBUTING.md`): `glrt-`, `gldt-`, `whsec_`, `cfut_` so far, the last
  two found bare in real prompts on 2026-09-26.
- A secret shape with a fixed length (gitleaks: `glpat-[\w-]{20}`) is
  extended to the end of the token characters, so a longer token does not
  leave its tail in the clear (found with a 24-char token, 2026-09-26).

IBAN, credit card and IP come from Presidio's regexes with our validators
(mod-97, Luhn, public-range check). A card number without a word like
"card" or "Kreditkarte" nearby is not reported: Presidio scores the bare
shape low, and a 16-digit number passes Luhn one time in ten.

Measure what the rules would catch on your own recordings, values never
printed: `scripts/replay_sessions.py --claude --codex`.

## Known gaps (measured or documented)

What the plugin does not protect. Each item is a limit of the mechanism, not
a to-do.

- **No hook, no protection.** Claude Chat, ChatGPT Chat, the web and the
  mobile apps run no plugin hooks. Cowork does, Claude Code does, Codex does.
- **A client that rejects the manifest loads nothing and says nothing.**
  Claude Code 2.1.223 did so for a manifest key it did not know. Check with
  `/hooks` that maisecrets is listed; the harness checks the debug log.
- **A hook that exceeds the client's timeout fails open** (10 s for the
  prompt hook, 20 s for tool output, set in `hooks/hooks.json`). The plugin's
  own watchdog answers fail-closed before that (7 s, 16 s for tool output:
  block, deny, or withheld output), and a hook that crashes answers the same
  way; Claude Code ignores exit 2 from `PostToolUse`, so the raw output would
  otherwise reach the model. Codex runs the tool anyway when a hook fails, so
  there the watchdog is the only net. A tool result with more than 100 new
  values is masked without storing the rest.
- **Tool output above 50K characters** is spilled to a file by Claude Code
  and is not rewritten.
- **`@file` mentions** inline a file outside the hook pipeline. The prompt
  hook blocks them when the path exists; ask Claude to read the file instead.
- **Names are not detected.** Regex only, by design.
- **A transformed value can pass.** For a value this session resolved, the
  output is checked as a substring in plain, base64, hex, URL-encoded and
  JSON-escaped form, and a resolving command may not encode it in the first
  place. Every other live value is matched by whole token, by the pieces of a
  URL or a `KEY=value` line, and by the rest of the line; a value split across
  lines, or encoded by a command that carried no placeholder, comes back
  unredacted. Values shorter than 8 characters are matched by shape only.
- **Every store hands a value to any process of the same user**, and so does
  a FIFO that waits for a granted command: another process of yours can read
  it during the up to 120 s the command takes to start. The gates stand in
  front of the agent, not in front of you; a Touch ID gate needs a signed
  helper and is not built. See "Vault" and `docs/THREAT-MODEL.md`.
- **Every e-mail address, phone number with a country code and public IP
  counts**, also your own and your colleagues'. `git log`, `dig` and `ip addr`
  come back with placeholders. Set `"pii_regions": ["generic"]` to drop the
  German identifiers; there is no allow-list for single values yet.
- **Placeholders resolve in Bash, MCP tool arguments and the file tools.** In
  WebFetch or a subagent prompt they stay text. A subagent shares its parent's session; a
  headless run (`codex exec`, `claude -p`) is a session of its own, so a
  reference from an earlier run is foreign there.
- **A reference in a prompt is admitted as typed by a human**, also when the
  prompt was built from an issue body or a log in a headless run.
- **Codex on Windows** runs commands in PowerShell, where the bash quoting
  contexts of the grant rewrite do not apply. The prompt block, the output
  redaction and the inline MCP resolve run through `hooks/run.cmd`; a
  placeholder in a shell command is denied with a reason. The launcher is
  proven in the GitHub Actions Windows job in the exact form Codex uses
  (`cmd.exe /C`, block and pass with a UTF-8 payload), not yet in a live
  Codex session.

## Licence

Apache-2.0. `docs/PROTOCOL.md` is the specification a gateway implements,
`docs/THREAT-MODEL.md` says what is defended, `docs/TESTING.md` what was measured.
The licensor is named in `NOTICE`; the vendored rule sets carry their own licences.
