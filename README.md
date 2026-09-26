# maisecrets

by [mcpgate](https://mcpgate.de) · Apache-2.0 · free

Keeps secrets and PII out of the cloud model. Works as a plugin for Claude Code
(and Cowork) and for Codex, from the same `hooks/hooks.json`.

**What it does, deterministically and locally:**

1. **You type a secret or a customer address.** A `UserPromptSubmit` hook
   detects it, stores it in a local vault, blocks the prompt, and puts the
   rewritten prompt with a placeholder such as `⟦SECRET_c1⟧` or
   `⟦EMAIL_c1:ma•••@example.org⟧` into your clipboard. Paste, send. The value
   never reached the model. Measured: zero API requests for a blocked prompt.
2. **The model reads a file or runs a command that outputs a secret.** A
   `PostToolUse` hook redacts the result before the model sees it.
3. **The model uses a placeholder in a Bash command or a tool argument.** A
   `PreToolUse` hook lets the command read the value once under a one-time
   grant, or inserts it into the tool argument, right before execution. The
   output is redacted again on the way back. See "Gates around a resolve".

Everything a hook runs is readable source in this folder. No download, no
package install, no dependency outside the Python standard library.

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

Hooks run through `hooks/run.sh` (bash), which picks `python3`, `python` or
`py -3`. Claude Code on Windows requires Git Bash, so the launcher runs there
too; install Python with `winget install Python.Python.3.12`. Without a
Python 3.11+ the launcher exits 2 and prompts are blocked: fail closed.

Proven with the harness on macOS (Claude Code 2.1.283) and on Debian 13
(2.1.223), 6 scenarios each, version 0.3.5; Windows through the GitHub Actions matrix
(unit tests, launcher, Credential Locker round trip), not yet with a live
Claude Code session. Codex (codex-cli 0.155.1): the same `hooks/hooks.json`
works unchanged, Codex sets `CLAUDE_PLUGIN_ROOT` itself; `harness/codex.py`
proves the three tool scenarios against a fake Responses upstream and, with
`--real`, against the real model (3 of 3 on 2026-09-26). `docs/TESTING.md`
has the record.

## Client support

✅ proven by the harness in this repo · ☑️ possible per the vendor's hook docs
(read 2026-09-26, not measured) · ⚠️ partly · ❌ no hook

| client | prompt | rehydrate | redact | adapter |
|---|:---:|:---:|:---:|---|
| Claude Code, Cowork | ✅ | ✅ | ✅ | built |
| Codex | ✅ | ✅ | ✅ | built |
| Gemini CLI | ☑️ | ☑️ | ☑️ | not planned (successor: Antigravity) |
| Cursor | ☑️ | ☑️ | ⚠️ MCP only | waits for a shell-output hook |
| Copilot CLI | ⚠️ SDK only | ☑️ | ☑️ | waits for a prompt hook |
| OpenCode | ❌ | ☑️ | ☑️ | waits for a prompt hook |
| Antigravity | ❌ | ☑️ | ❌ | not supportable |
| Chat apps, web, mobile | ❌ | ❌ | ❌ | no hooks |

The three columns are the three guards: block a prompt that carries a
value, resolve a placeholder at execution, redact tool output before the
model sees it. A client with ❌ or ⚠️ under prompt or redact cannot be made
safe by this plugin; it would look protected and leak. The hook names
behind each mark are in `docs/CONCEPT.md`, "Provider coverage".

## Install

```bash
claude plugin marketplace add Mcpgate-de/maisecrets     # the GitHub repo is its own marketplace
claude plugin install maisecrets@maisecrets             # user scope; new session or /reload-plugins
claude plugin update maisecrets@maisecrets              # later versions
```

For development:

```bash
claude --plugin-dir /path/to/maisecrets                 # one session, straight from the checkout
python3 -m unittest discover -s tests -v               # 48 tests, under a second
python3 harness/run.py                                 # 6 scenarios against a fake upstream
python3 harness/codex.py [--real]                      # 3 scenarios through codex exec
scripts/install-hooks.sh                               # git pre-commit / pre-push
```

## Install (organisation, claude.ai)

An organisation admin adds a **private** GitHub repository as a marketplace
source under claude.ai organisation settings ("Sync from GitHub" lists private
repositories only and needs the Claude GitHub App installed on it) and sets
the availability (available, installed by default, or required). For this
plugin that source is the private GitLab project itself, through a GitLab
configuration with a read-only access token under Organization settings >
Claude Code (public beta); the release pipeline tells the marketplace when
main moved. Members never need access
to the repository: organization sync packages the plugin. The public GitHub
repository cannot be the organisation source (the sync accepts only private
or internal marketplace repositories), but it may be referenced as a plugin
source from a private one. Claude Code then offers the plugin to
every member; a new version is picked up when the `version` in
`.claude-plugin/plugin.json` changes, which the release job does on every
merge to `main`. With `autoUpdate` on the marketplace entry the update lands
at session start; otherwise `claude plugin update maisecrets@<marketplace>`.

## What the plugin runs, sends and fetches

- Runs: `bash hooks/run.sh <event>` → `hooks/dispatch.py` on the matching
  hook events. Each reads one JSON payload from stdin and prints one JSON
  object. A granted Bash command runs `hooks/resolve.py` once.
- Writes: `~/.maisecrets/index.json` (metadata and keyed fingerprints, never
  a value), `~/.maisecrets/audit.log`, the vault backend, and, on a blocked
  prompt, the clipboard. With `scrub_transcript`
  on, it rewrites the raw prompt inside the Claude Code transcript file named
  in the hook payload, because Claude Code writes the prompt to disk before
  the hook runs.
- Sends and fetches: nothing. No network access in any hook.

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
regions besides the generic ones.

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
  German labels are recognised);
- or copy the value and run `/maisecrets:put` in Claude Code; the placeholder
  replaces the value in your clipboard. Paste the placeholder into your next
  message, and Claude uses it in commands and tool calls.

A bare password in prose, such as "use Sommer2026 for the login", is not
detected. That is a limit of pattern detection, not a setting.

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

- **In the session where a human typed it.** A reference minted in session A
  resolves in session B only after you paste it into a prompt there. Keys are
  counters, so an injected text could otherwise name one it never saw.
- **Through a one-time grant in Bash.** The hook rewrites `⟦SECRET_c1⟧` to
  `$(python resolve.py SECRET_c1 --grant NONCE)` in the quoting context of the
  placeholder. The command you approve, the transcript and the tool record
  carry no value; the command reads it once, and the nonce dies. A value with
  quotes or `$(` arrives byte for byte instead of becoming shell syntax.
- **Inline for MCP tools.** An argument has no shell to read from, so the value
  is inserted after the same session rule. The permission prompt of the client
  then shows your own value at the point of the real call.
- **Under a cap.** `max_keys_per_session` (25) distinct keys per session and
  `max_resolves_per_hour` (60) in total; above that the call is denied and the
  reason names the cap. Every resolve writes one line to `~/.maisecrets/audit.log`
  (time, session, key, tool, command with placeholders; never a value):
  `python3 -m maisecrets.cli audit`.
- **Not by the agent reading the store.** A Bash command that calls
  `maisecrets get`, `security … maisecrets` or reads the vault files is denied.
  This is text matching, a backstop; the boundary is the grant.

Recommended in your Claude Code settings, outside the plugin: the sandbox with
`sandbox.credentials` deny for `.env` files and `~/.maisecrets`, and
`injectHosts` for the hosts a value may go to. That closes `cat .env` and
`printenv`, which no hook sees.

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
- **The prompt hook is fail-open on timeout** (30 s in Claude Code). The
  detector is regex only and runs in milliseconds; keep it that way.
- **Tool output above 50K characters** is spilled to a file by Claude Code
  and is not rewritten.
- **`@file` mentions** inline a file outside the hook pipeline. The prompt
  hook blocks them when the path exists; ask Claude to read the file instead.
- **Names are not detected.** Regex only, by design.
- **A transformed value passes.** Base64, split across lines, or a value with
  spaces and quotes inside prose comes back unredacted; exact match works on
  whole tokens and on the rest of a `KEY=value` line.
- **Every store hands a value to any process of the same user.** The gates
  stand in front of the agent, not in front of you; a Touch ID gate needs a
  signed helper and is not built. See "Vault" and `docs/THREAT-MODEL.md`.
- **Codex on Windows** runs commands in PowerShell, where the bash quoting
  contexts of the grant rewrite do not apply. Not tested.

## Licence

Apache-2.0. See `docs/CONCEPT.md` for the concept and the decisions.
