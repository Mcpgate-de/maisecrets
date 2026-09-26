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

Day-1 prototype (2026-09-26). Default vault backend on macOS is `keychain`
(login keychain via `security`, no iCloud sync flag; smoke-tested against the
real keychain). Elsewhere, and with `"backend": "jsonfile"`, values sit in a
plaintext file under `~/.maisecrets/` with mode 0600, marked TEST MODE.
Windows Credential Manager: not yet.

## Install (development)

```bash
claude --plugin-dir /path/to/maisecrets                 # one session only
claude plugin marketplace add /path/to/maisecrets       # the repo is its own marketplace
claude plugin install maisecrets@maisecrets             # every session (user scope)
python3 -m unittest discover -s tests -v               # 23 tests, milliseconds
python3 harness/run.py                                 # 4 scenarios against a fake upstream
scripts/install-hooks.sh                               # git pre-commit / pre-push
```

## What the plugin runs, sends and fetches

- Runs: `python3 hooks/user_prompt.py`, `hooks/pre_tool.py`, `hooks/post_tool.py`
  on the matching hook events. Each reads one JSON payload from stdin and
  prints one JSON object.
- Writes: `~/.maisecrets/index.json` (metadata, never a value), the vault
  backend, and, on a blocked prompt, the clipboard. With `scrub_transcript`
  on, it rewrites the raw prompt inside the Claude Code transcript file named
  in the hook payload, because Claude Code writes the prompt to disk before
  the hook runs.
- Sends and fetches: nothing. No network access in any hook.

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
`python3 -m maisecrets.cli list | get <KEY> | expire | scan | config`.

## Detection rules

Four sources, one scanner (`maisecrets/detect.py`):

- **gitleaks** ruleset, vendored as data under `maisecrets/rules/` (MIT,
  version in `GITLEAKS_VERSION`, refresh with `scripts/sync_gitleaks.py vX.Y.Z`):
  ~220 secret shapes with keywords, entropy thresholds and allowlists. No
  gitleaks binary is used.
- **Presidio** pattern recognizers, vendored as data under `maisecrets/rules/`
  (MIT, version in `PRESIDIO_VERSION`, refresh with `scripts/sync_presidio.py`):
  country-specific PII with scores and context words. Languages are opt-in via
  `pii_languages` in the config (default `en` and `de`: Steuer-ID,
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
- Gateway (MCP) tool calls are passed through unchanged; a placeholder in a
  gateway argument is resolved by the gateway once the deposit endpoint
  exists.

## Licence

Apache-2.0. See `docs/CONCEPT.md` for the concept and the decisions.
