# maisecrets

Keeps secrets and PII out of the cloud model. Works as a plugin for Claude Code
(and Cowork), with a Codex adapter next.

**What it does, deterministically and locally:**

1. **You type a secret or a customer address.** A `UserPromptSubmit` hook
   detects it, stores it in a local vault, blocks the prompt, and puts the
   rewritten prompt with a placeholder such as `⟦SECRET_c1⟧` or
   `⟦EMAIL_c1:ma•••@example.org⟧` into your clipboard. Paste, send. The value
   never reached the model. Measured: zero API requests for a blocked prompt.
2. **The model reads a file or runs a command that outputs a secret.** A
   `PostToolUse` hook redacts the result before the model sees it.
3. **The model uses a placeholder in a Bash command.** A `PreToolUse` hook
   inserts the real value right before execution. The output is redacted
   again on the way back.

Everything a hook runs is readable source in this folder. No download, no
package install, no dependency outside the Python standard library.

## Status

Day-1 prototype (2026-09-26). Vault backend per platform:

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

Proven on macOS (Claude Code 2.1.283) and Debian 13 (2.1.223) with the
harness; Windows through the GitHub Actions matrix (unit tests, launcher,
Credential Locker round trip), not yet with a live Claude Code session.
Codex (codex-cli 0.155.1): the same `hooks/hooks.json` works unchanged, Codex
sets `CLAUDE_PLUGIN_ROOT` itself; `harness/codex.py` proves the three tool
scenarios against a fake Responses upstream.

## Install (development)

```bash
claude --plugin-dir /path/to/maisecrets                 # one session only
claude plugin marketplace add /path/to/maisecrets       # the repo is its own marketplace
claude plugin install maisecrets@maisecrets             # every session (user scope)
python3 -m unittest discover -s tests -v               # 23 tests, milliseconds
python3 harness/run.py                                 # 4 scenarios against a fake upstream
scripts/install-hooks.sh                               # git pre-commit / pre-push
```

## Install (organisation, claude.ai)

An organisation admin adds the GitHub repository as a marketplace source
under claude.ai organisation settings and sets the availability (available,
installed by default, or required). Claude Code then offers the plugin to
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

Claude Code asks for these when the plugin is installed (`userConfig` in
`.claude-plugin/plugin.json`); they reach the hooks as
`CLAUDE_PLUGIN_OPTION_<KEY>` and override `~/.maisecrets/config.json`:

| option | default | meaning |
|---|---|---|
| `backend` | `auto` | `keychain` (macOS), `windows-vault`, `encrypted-file` (Linux), `jsonfile` (test mode) |
| `pii_regions` | `de` | Presidio regions besides the generic ones, comma-separated |
| `ttl_hours` | `24` | lifetime of a stored value; every use renews it, up to 30 days |
| `report_url` | empty | shown in the block notice so a wrong detection can be reported |

At the first session start, and at every start in test mode, a notice names
the active store, its path and where to change it. `python3 -m maisecrets.cli
status` prints the same at any time.

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
  "gateway_servers": ["phase6-ai-gateway"]
}
```

Every entry has a TTL. Each use renews it, up to `max_ttl_seconds`. On
expiry the value is deleted and the metadata stays as a record. Commands:
`python3 -m maisecrets.cli list | get <KEY> | put | audit | expire | scan | config`.

**What the store does and does not do.** The keychain, the Credential Locker
and the encrypted file keep the value off the disk in plaintext and away from
other users. None of them stops a process that runs as you: `security`,
PowerShell or openssl hand the value to any such process without a dialog
(`docs/THREAT-MODEL.md`). The gates below stand in front of the agent, not in
front of you.

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

IBAN, credit card and IP come from Presidio's regexes with our validators
(mod-97, Luhn, public-range check). A card number without a word like
"card" or "Kreditkarte" nearby is not reported: Presidio scores the bare
shape low, and a 16-digit number passes Luhn one time in ten.

Measure what the rules would catch on your own recordings, values never
printed: `scripts/replay_sessions.py --claude --codex`.

## Known gaps (measured or documented)

- `@file` mentions inline content outside the hook pipeline. The prompt hook
  blocks them when the path exists; ask Claude to read the file instead.
- The `UserPromptSubmit` hook is fail-open on timeout (30 s default). The
  detector is regex only and runs in milliseconds; keep it that way.
- Tool output above 50K characters is spilled to a file by Claude Code and is
  not rewritten.
- Names are not detected. Regex only, by design, for now.
- A value that a command transforms (base64, split across lines) comes back
  unredacted; exact match works on whole tokens and on the rest of a
  `KEY=value` line.
- Gateway (MCP) arguments are resolved on the client until the gateway's
  deposit endpoint exists; the value then travels to the gateway like any
  other argument.
- Codex on Windows runs commands in PowerShell, where the bash quoting
  contexts of the grant rewrite do not apply. Not tested.

## Licence

Apache-2.0. See `docs/CONCEPT.md` for the concept and the decisions.
