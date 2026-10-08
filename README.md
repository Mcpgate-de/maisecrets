# maisecrets

[maisecrets.dev](https://maisecrets.dev) · by [mcpgate](https://mcpgate.de) · Apache-2.0 · free

An AI agent sees what you type and what its tools print: passwords, tokens, a
customer's e-mail address. maisecrets intercepts detected secrets and personal
data before they reach the cloud model. The real value goes back in only where
the call happens, and the model never sees it there either. By default
maisecrets adds no approval of its own: in Claude Code your permission rules
decide, as before; in Codex maisecrets answers `allow`, and Codex's sandbox and
its approval of MCP tools still apply. maisecrets itself sends no
prompt, value or telemetry to a server.

```bash
claude plugin marketplace add Mcpgate-de/maisecrets
claude plugin install maisecrets@maisecrets     # then start a new session
```

It works as a plugin for Claude Code (and Cowork) and for Codex, from the same
`hooks/hooks.json`. Codex and the other install paths: see [Install](#install).

**What it does, deterministically and locally:**

1. **You type a secret or a personal value** (a token, a password after a
   label, an e-mail address, a phone number with a country code, an IBAN, a
   card number, a public IP, and German identifiers by default; test data such
   as `example.com` stays alone, see "Test data that maisecrets leaves alone"). A
   `UserPromptSubmit` hook
   detects it, stores it in a local vault, blocks the prompt, and keeps the
   rewritten prompt with a placeholder such as `⟦SECRET_c1⟧` or
   `⟦EMAIL_c1:ma•••@•••.de⟧`. Type `/maisecrets:send` to send it as is,
   or paste it from the clipboard where one exists. The value never reached
   the model. Measured: zero API requests for a blocked prompt.
   **On Claude Code 2.1.287 and later (in the desktop app's Code tab from
   2.1.286), as a rule, there is no block and no resend:** a mod (`claude-mod/maisecrets-mod.mjs`) replaces the values with placeholders and
   the prompt goes on at once (the hook still blocks a prompt with an `@file`
   mention, a timeout of the mod, and a session where mods are off); your message on screen shows the placeholders, and the
   record of the prompt as typed in the transcript file is masked in place. The
   hook stays the gate: when the mod does not run or fails, the hook blocks as
   above. `"rewrite_prompts": false` keeps the block. See "The mod".
2. **The model reads a file or runs a command that outputs a secret.** A
   `PostToolUse` hook redacts the result before the model sees it.
3. **The model uses a placeholder in a Bash command or a tool argument.** A
   `PreToolUse` hook lets the command read the value once under a one-time
   grant, or inserts it into the tool argument, right before execution. The
   output is redacted again on the way back. See "Gates around a resolve".
   A form where the value could turn into code is refused; every other form
   runs without a maisecrets prompt, unless you set a stricter
   [rehydration policy](#rehydration-policy-optional).

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

Claude writes the deploy command with the placeholder. Claude Code's permission
prompt, if your rules ask for one, shows this, and only this:

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
maisecrets: a secret was found and kept from the AI.

    ⌘V  pastes the cleaned prompt. Then send it, or type /ms to send it at once.

Something wrong? /maisecrets:report · maisecrets by mcpgate.de
```

Zero requests left the machine for that prompt. The rewritten prompt reads
`please check why ⟦SECRET_c3⟧ fails in CI`, and Claude can use the
placeholder in a command as above.

## Status

Released from `main` on every merge (`CHANGELOG.md`, tags `vX.Y.Z`). A release
moves only the last number; a higher one needs the owner's approval. Vault backend per platform:

| platform | backend | where the values live |
|---|---|---|
| macOS | `keychain` | login keychain via `security`, no iCloud sync flag |
| Windows | `windows-vault` | Credential Locker (`PasswordVault`, DPAPI) via PowerShell |
| Linux | `encrypted-file` | `openssl` AES-256-CBC + PBKDF2 + HMAC tag, key file 0600 |
| any | `jsonfile` | plaintext 0600, TEST MODE only |

Hooks run through `hooks/run.sh` (bash), which looks for a Python 3.9+ as
`python3`, `python`, `py -3`, a versioned name, or the Homebrew, `/usr/local`
and python.org paths. Claude Code on Windows runs a hook command in Git Bash
when Git for Windows is installed, and in PowerShell when it is not (pwsh 7,
else Windows PowerShell 5.1; read from Claude Code 2.1.284). So each command
in `hooks/hooks.json` is one text that both shells read: bash runs
`hooks/run.sh` and stops there, and PowerShell, which sees that part as a
comment, runs `hooks/run.cmd`. Codex on Windows runs the `commandWindows`
entry of each hook through `cmd.exe`, which starts `hooks/run.cmd` too. Both
launchers run the same `dispatch.py`. Without a Python
3.9+ the launcher blocks every prompt and every tool call and withholds every
tool result, and its message names what to install: fail closed, with a cause.

Proven with the harness on macOS (Claude Code 2.1.283) and on Debian 13
(2.1.223), the scenarios of `harness/run.py`, on every push in CI; Windows through the GitHub
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
| Claude Code CLI | ✅ | ✅ | ✅ | built; from 0.6.0 with mods (2.1.287+) a prompt with a value is rewritten with placeholders instead of blocked, measured live and in the harness; on Windows without Git Bash the shell tool is PowerShell, and a placeholder in a PowerShell command is refused (no PowerShell rewrite) |
| Claude desktop app, Code tab | ✅ | ✅ | ✅ | same hooks and manifest; a blocked prompt, an MCP call that resolves (with the ask and warning of 0.5.9, now `rehydration: confirm`), and a redacted Bash output seen live (2026-09-28); the mod (mods from 2.1.286) rewrites the prompt, seen live with Claude Code 2.1.288 (2026-10-06): the model got the placeholder, and your own message bubble shows the text as typed (a local display); not in the harness |
| Cowork | ✅ | ✅ | ✅ | same hooks as the desktop app; whether the mod loads there is not measured, so count on the block |
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

Python 3.9 or newer on the PATH the client gives its hooks (`python3 --version`).
The stock `python3` of macOS (3.9) is enough; nothing to install on a Mac.
Windows: install Python for all users, as an administrator:
`winget install --id Python.Python.3.12 --exact --scope machine`. Codex on Windows
runs commands as a sandbox user, and that user cannot start a Python installed for one
person only (`docs/CLIENTS.md`, "Codex on Windows: the sandbox user"). Linux: your package manager, plus
`openssl` for the vault and `xclip` if you want the clipboard. Without it the
plugin blocks every prompt and names the missing piece.

## Install

```bash
claude plugin marketplace add Mcpgate-de/maisecrets     # the GitHub repo is its own marketplace
claude plugin install maisecrets@maisecrets             # user scope; new session or /reload-plugins
claude plugin update maisecrets@maisecrets              # later versions
```

**Updates and open sessions.** A hook runs from the plugin folder of its version.
When Claude Code cannot find that folder, it shows `Plugin directory does not
exist` and runs the tool without the hook: every protection of that session is
off until `/reload-plugins` or a new session. No code of the plugin runs then, so
maisecrets cannot warn you itself. The harness measures this on every run
(scenario `plugin_folder_moved`, Claude Code 2.1.283: no hook runs, the tool
runs; anthropics/claude-code#97847). A client that runs the hook command anyway
gets a refusal: the command tests for the launcher first and blocks without it,
in bash, in PowerShell and, for Codex on Windows (`commandWindows`), in
`cmd.exe`. Codex needs this most: it removes the folder of the old version as
soon as it installs a new one, and an open Codex session then runs the command
of a folder that is gone (codex-cli 0.159.0, measured 2026-09-29). Exit that
session and run `codex resume`.

The install from the Claude plugin directory does not have this refusal. The
directory accepts only a hook command that names one program, so its copy (the
GitHub branch `release`) runs `run.sh` or `run.cmd` directly. If that folder is
gone, the hook does not run. Claude Code on Windows then also needs Git Bash. A
directory install keeps the old version folder for 14 days, so an open session
keeps its hooks. The install from this repository (`main`) keeps the refusal.

- Installed from this GitHub marketplace (the commands above), a previous version
  stays for 14 days, "so a session that already loaded the old version keeps
  running" ([Claude Code docs](https://code.claude.com/docs/en/plugins/loading#cleanup-of-previous-versions)).
  This is the install path we recommend.
- Synced from claude.ai, the previous folder moved to `~/.claude/plugins/.trash`
  when another Claude Code session started and synced (observed with Claude Code
  2.1.283 on 2026-09-28; not documented). A session that was open then lost its
  hooks. After an update, run `/reload-plugins` in every open session. That is
  not always enough: on 2026-09-29 (Claude Code 2.1.284) `/reload-plugins` kept
  the path of the gone folder (`/plugin` showed `commands path not found …
  maisecrets~g2`), and only a new process loaded maisecrets again: exit, then
  `claude --resume <session id>` in the directory where the session started (the
  guard puts this command on your clipboard, once per session). The
  session that started the sync can lose them too: on 2026-09-29 (Claude Code
  2.1.284) the folder was rewritten one second after a session started, and that
  session ran no maisecrets hook while `/plugin` showed the new version.
- **The guard closes this for a synced install.** It is a small hook outside the
  plugin folder (`~/.claude/maisecrets-guard.py`). Every maisecrets hook writes a
  heartbeat for its call once it has answered; when none comes (maisecrets did not
  run, or started and died), the guard blocks the prompt, denies
  the tool call or withholds the result. Without a sign of an update it asks to
  run the call again first, so an agent that works alone goes on; after an update
  it names `/reload-plugins` and the restart command. It stays
  silent for an account without maisecrets, for a plugin you switched off, and
  for Codex. Measured with the real client: `plugin_folder_moved_guarded` (the
  command does not run) and `bash_rehydrate_guarded` (a healthy session passes).
  - A synced maisecrets sets it up by itself: its session start places the script
    and, once, registers it in `~/.claude/settings.json` (a backup first, only the
    hooks change, one line in the session-start message says so). It protects the
    sessions after that one. `/maisecrets:guard remove` takes it away and it stays
    away; `"guard": false` in `~/.maisecrets/config.json` or in the machine policy
    keeps it off. A `settings.json` that is not valid JSON is left alone.
  - An admin who prefers central settings can register it in the Claude Code
    managed settings instead (`python3 -m maisecrets.cli guard managed` prints the
    entries); on a machine where maisecrets never ran that command answers `{}`.
  - Installed another way: `/maisecrets:guard install` does the same by hand.
  - Its cost: each prompt and tool call waits for the heartbeat, which the
    maisecrets hook of the same call writes as it starts (both run in parallel);
    without maisecrets it waits 5 s and then refuses. The refusal names
    `/reload-plugins`, then `claude --resume` with the id of this session for the
    case that the reload does not help, and, for a maisecrets that is off on purpose, the way out
    from a terminal: `python3 ~/.claude/maisecrets-guard.py --off` (it stays off;
    the agent cannot run it). A plugin switched off in the user, project, local or
    managed settings is left alone. The guard expects maisecrets for the account
    the synced copy registered under, so a second Claude profile is not blocked.
    On a Mac without the Command Line Tools there is no `python3`, and the guard
    answers nothing. It needs a claude.ai login: with an API key there is no
    account to compare, and `/maisecrets:guard status` says "expected: no".
    After an organisation takes maisecrets out of its sync the guard stops
    expecting it within 15 minutes; until then `--off` lets you work.
- For a team, an admin can roll out this marketplace with managed settings
  (`extraKnownMarketplaces` with `autoUpdate: true`, and `enabledPlugins`), so
  nobody has to type a command ([Claude Code docs](https://code.claude.com/docs/en/plugins/org)).

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
python3 -m unittest discover -s tests -v               # about 30 seconds
python3 harness/run.py                                 # 30 scenarios against a fake upstream (3 for the PowerShell tool of Windows)
python3 harness/codex.py [--real]                      # 8 scenarios through codex exec (four need --real)
python3 scripts/replay_can_fail.py                     # 99 proofs: each control's test, and each path of the four invariants, goes red without its guard
python3 scripts/derived_counts.py                      # the numbers in the docs, measured again
python3 scripts/lint_plugin.py                         # frontmatter YAML, manifests, hook paths (pre-commit, CI)
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

**The guard for synced installs.** An update of an org-synced plugin can leave a
session without its hooks. maisecrets registers a guard against that by itself
(`"guard": false` in the policy turns it off); the managed settings can carry it
instead (`python3 -m maisecrets.cli guard managed`). See "Updates and open sessions".

**Settings you can enforce.** A machine policy file wins over the user's
`~/.maisecrets/config.json` and cannot be changed from there:
`/Library/Application Support/maisecrets/policy.json` (macOS),
`%ProgramData%\maisecrets\policy.json` (Windows), `/etc/maisecrets/policy.json`
(Linux). Any key from "Options" goes in it; typical: `backend`,
`scrub_transcript`, `max_ttl_seconds`, `regions`, `report_url`,
`resolve_in_files`, `rehydration`.
Every user must be able to read the file and its folder (for example 0644 and
0755): a policy maisecrets cannot read makes every hook fail closed, because it
cannot tell what the policy says. A key it does not know is ignored with a
warning; a key that starts with `_` or `$` is a comment or a schema link. A key
that looks like a misspelled `rehydration`, `resolve_in_files` or
`ssh_via_sandbox` blocks rehydration until it is fixed.
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
milliseconds of the call, because the stdin form has a line limit. maisecrets itself sends nothing to a
server: no hook opens a network connection. Two exceptions to state to a data-protection
officer: the Windows Credential Locker can roam through a Microsoft account on
a machine that is not domain-joined (set `backend` to `encrypted-file` by
policy if that matters), and `/maisecrets:report` prints an issue text and a
link to `report_url`. It opens a browser only on a local desktop, and it files
the issue only with `--create` through the GitHub CLI. Set `report_url` to your
tracker, or set it to `null` to turn reporting off.

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
- The mod (Claude Code 2.1.287 and later) runs this computer's Python with the
  plugin's own `hooks/dispatch.py mod-prompt`, with fixed arguments and no shell,
  and hands it the prompt on stdin; "The mod" below lists each call.
- Writes: under `~/.maisecrets`: `index.json` (metadata and keyed
  fingerprints, never a value), `audit.log`, `events.log`, `hooks.log`,
  `pending/`, `.announced`, `destinations.json` (where each value went, never a
  value); the value FIFOs in the per-user runtime or temp
  directory; the vault backend; on a blocked prompt the clipboard. With
  `scrub_transcript` on, it masks the raw value inside the client's transcript
  file named in the hook payload, in place, because the client writes the
  prompt to disk before or after the hook runs. "For administrators" has the
  retention of each file.
- The skill runs `skills/secret-hygiene/scripts/scan_secrets.py` (reads files and
  `git log`) and `redact_copy.py` (writes a new file) when the model follows it; neither
  opens a network connection.
- Sends and fetches: no telemetry and no download. Three connections start from
  a command you run, and nothing else in the plugin opens one:
  - the ssh route of your own ssh command inside the Claude Code sandbox
    (`hooks/proxy_connect.py`, the `ProxyCommand` of that ssh call): one
    CONNECT through Claude Code's local sandbox proxy (localhost only) to the
    host you named, with the proxy login that Claude Code puts in
    `HTTPS_PROXY` for that sandbox;
  - before an ssh command that carries a value, `hooks/sandbox_probe.py` checks
    that it runs inside that sandbox: it tries direct connections to 1.1.1.1:443,
    8.8.8.8:53 and 9.9.9.9:443 (the sandbox must refuse them) and one CONNECT with
    a wrong login to the local sandbox proxy. It sends no data, and it runs only
    when `SANDBOX_RUNTIME=1` and a local sandbox proxy are set;
  - `/maisecrets:report … --create`, which runs the GitHub CLI (`gh`) with your
    own `gh` login to file the issue.
- Credentials: the hooks and the mod fetch no credential for a request of
  their own. They read the values you stored, from your operating system's
  store, only to put each one into the tool call you allow, which then goes
  where that call goes. The two commands above use the login that belongs to
  them: the ssh route sends the sandbox proxy login from `HTTPS_PROXY` to the
  local sandbox proxy, and `gh` uses its own GitHub login.
  `/maisecrets:report` prints the issue text and a prefilled link, and it
  files the issue only with `--create` (GitHub CLI, to `report_url`); the
  Windows Credential Locker may roam through a Microsoft account.

## Secret hygiene skill

The hooks stop a new value from reaching the model. The `secret-hygiene` skill deals with
values that already leaked. The model loads it when a task fits; in Claude Code it is also
`/maisecrets:secret-hygiene`. It does three things:

- **Check a repository.** `scan_secrets.py` lists the secrets in the working tree and, with
  `--history`, in every commit on every ref. A finding is a file, a line, a type, the rule, a
  length and a per-run id. The same id means the same value; the output never holds a value,
  a line of the file or a hash of the value, because the model reads it.
- **Install the protection.** A conversation starts with `protection_status.py`. It says ACTIVE
  only when a hook of the same agent ran for the call that started it. Otherwise the answer
  opens with an offer that names the source and the step the user must do, and the install
  commands run only after a yes. There is no offer in a web or mobile chat, and none without a
  Python 3.9 for the hooks. This is how the skill, which a store can list alone, brings the
  hooks along.
- **Check what the agents already received.** `audit_transcripts.py` reads the local Claude Code
  and Codex sessions and lists every secret that sat in a prompt, a tool result or a model answer,
  so it reached Anthropic or OpenAI: by type, rule, dates and sessions, never by value. On request
  it replaces the values in the local files (`--scrub`, then `--scrub --yes`), which does not
  take back what the provider received.
- **Contain a leak.** For a value that reached a chat, a commit, a log or a ticket, the skill
  gives the rotation steps per service from `references/rotation.md`: rotate first, clean up
  second. This part needs no shell, so it also works in a chat.
- **Make a file safe to share.** `redact_copy.py` writes `<name>.redacted<ext>` with every
  value replaced by `⟦TYPE_n⟧` and prints only the counts. The original is never changed.

The skill is not a guard. It works only when the model follows it, and it does not stop a
prompt. The history scan reads what each commit added; a value that entered only while a merge
conflict was resolved is not seen (`git log -p` shows no merge diff), and a file path that is
itself a secret is printed as it is. `python3 scripts/build_skill_zip.py` builds `dist/secret-hygiene.zip`, the
standalone skill with its own copy of the detector, for a skill upload without the plugin.

## Options

All options live in `~/.maisecrets/config.json` (next section) and take
effect on the next hook call. The manifest declares no `userConfig` on
purpose: Claude Code 2.1.223 rejects a manifest with that key and then loads
no hook at all, silently. A guard that vanishes on an older client is worse
than one without a settings dialog. At the first session start, and at every
start in test mode, a notice names the active store, its path and where to
change it. `python3 -m maisecrets.cli status` prints the same at any time.

### Settings you decide

`/maisecrets:settings` shows the settings that are yours to decide, grouped
(Protection, Using stored values), one card each: the value, its state (`not
decided`, `set by you`, `set by a policy`), what it does, and the command for
the next step:

```
Protection
  SSH consent · off · not decided
    Ask before each ssh command that changes something on a host.
    Turn on: /maisecrets:settings ssh_consent on
```

A key that is missing from `config.json` is not decided; `false` written there
is a decision, with the same effect. `--all` shows the advanced settings too.

To change one, send the change as your own prompt, alone:

```
/maisecrets:settings ssh_consent on
maisecrets: set ssh_consent on          (the same, and the form for Codex)
```

`on`, `off`, a choice the card names (`rehydration confirm`), or `default`,
which removes your decision so that the setting reads the default again.
The prompt hook writes `config.json`. After the slash command it lets the
command run on, which shows the new card; the sentence form is stopped and
does not reach the model. maisecrets changes a setting for nothing else: not
for a prompt the client injected (a scheduled task, a loop wakeup, an SDK
prompt), not for a subagent's report, and a Bash or PowerShell command that
carries the change (a nested `codex exec` or `claude -p` that would type it)
is refused. The AI can tell you about a setting and the prompt to send. A
setting from a machine policy cannot be changed here. The limit: a program
that runs as you can write the file itself, and maisecrets sees a command only
as text (C22 in the threat model).

**Hints.** maisecrets stays quiet until a case comes up that one of these
settings is about. Then the AI gets one sentence about it, and mentions it
once. For `ssh_consent` that case is the first ssh command that changes
something on a host (`ssh web1 'sudo systemctl restart nginx'`; not `ssh web1
uptime`; and only when the command succeeds: Claude Code reports a failed one
through another event). A hint comes once, also when hooks run at the same
time; if maisecrets cannot record it, it does not come at all. It does not come again after you decided, and
it does not come again because time passed: only a real change of the
feature brings it back, once. `"tips": false` turns hints off with the tips.
The settings list shows each hint as `not shown yet` or `shown` with its date;
`/maisecrets:settings hints reset` (or `maisecrets: reset hints`) lets them
come once more and changes no protection setting.

### Where your secrets went

maisecrets notes, on this computer only, where each stored secret was handed
to a tool call: a host named in the call (from a URL, also one in quoted text,
not one in a shell comment), an ssh host, or an MCP server and tool. In a Bash
command every host it names counts for each secret in it, also a second URL
that the value does not reach. A file or a command without a host is listed
apart, as a local use. `/maisecrets:list`
shows it under each secret:

```
SECRET_c7      SECRET  github_pat            3d   14        21h  -
    Seen at (a record, not a permission)
      other.example.net     1×     last less than an hour ago   new
      api.github.com        10+×   last 2 hours ago
    Local uses (not destination-protected)
      a file in ~/proj/     2–9×   last 3 days ago
```

This is a record, not a permission, and it stops nothing. The value is handed
out before the client asks you, so a call waits until the client reports that
it ran (also when it failed), and only then is it listed. A call you decline in
Claude Code's dialog is not listed (measured with the real client, whose
headless mode refuses the question). Codex sends
the same report for a command that ran or failed; a call it declines by its
approval policy never reaches the hooks. A call without a call id is not
listed: nothing could show that it ran. `new` marks a destination first seen in the
last 24 hours. When a secret that you used at one destination
(3 times on one day) goes to a new one for the first time, the AI tells you
once, in a sentence; this note does not come again. maisecrets does not
judge whether a destination is safe. Asking before a new destination comes
in a later version. `/maisecrets:settings secret_destinations off` stops the
record; nothing leaves the computer either way. When a value expires, its
record goes with it (if the record is busy at that moment, it goes 30 days
later with the metadata); forget and wipe delete it too.

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
  "rewrite_prompts": true,
  "strip_hidden_characters": true,
  "regions": ["auto"],
  "max_keys_per_session": 200,
  "max_resolves_per_hour": 1000,
  "report_url": "https://github.com/Mcpgate-de/maisecrets/issues"
}
```

`backend`: `keychain` (macOS), `windows-vault`, `encrypted-file` (Linux and
any other), `jsonfile` (test mode, plaintext). `tips`: `false` turns off the
one-line tip that appears once a day at session start.

`regions`: country codes, for example `["de", "us"]`. Each country adds its
Presidio rules for personal data, such as a German tax ID or a US social
security number. The entry `auto` is the country of your system setting (on
macOS and Windows the system setting, not `LANG`). The default is `["auto"]`.
An empty list keeps the generic rules only. The old key `pii_regions` still
works.

Credential labels come in languages. English labels (`password:`, `pass:`,
`token:`) are always on. maisecrets adds the labels of your system language
and of each region, for example `passwort:` and `kennwort:` for German. The
labels are data files in `maisecrets/rules/labels/`, one file per language.
A new language is one new file. Files exist for Czech, Danish, Dutch,
English, Finnish, French, German, Italian, Korean, Norwegian (Bokmål),
Polish, Portuguese, Spanish, Swedish, Thai and Turkish. Each word comes from
a reviewed translation of an open-source project, and
`docs/label-sources.md` names the source of each word. `/maisecrets:status` shows the regions, where
they came from, and the label languages.

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

**The mod.** Claude Code 2.1.287 and later loads JavaScript middleware from a
plugin ("mods"). maisecrets ships one in its own folder: `claude-mod/maisecrets-mod.mjs`,
named by the manifest (`"hooks": "./claude-mod/maisecrets-mod.json"`). Nothing else in
the plugin points into that folder.

- **The one event it handles:** `prompt.submit`, which fires when a prompt is about
  to be sent. The mod handles the event; it never calls `$.prompt.submit` itself,
  so it submits no prompt and changes no prompt of other code. It acts on a
  person's own prompt only (typed or queued at the terminal, sent through Remote
  Control, or the turn of `claude -p`). A subagent's report, another session's or
  a channel's message goes on unchanged to the settings hook.
- **What it reads:** the text of that prompt, the session id and the session's
  working directory. It reads no environment variable and no file.
- **What it runs:** this computer's Python with the plugin's own
  `hooks/dispatch.py mod-prompt`, the same code the settings hooks run, in the
  plugin folder. Each call is fixed text, with no shell: `python3 hooks/dispatch.py
  mod-prompt`; when that cannot start or ends with an error (on Windows `python3`
  is often a store stub, and `dispatch.py` refuses a Python older than 3.9),
  `py -3 …`, then `python …`. All tries share one limit of 8 seconds. It sets
  `PYTHONUTF8=1` for that process (over the environment it inherits), so that
  Windows reads the pipe as UTF-8. When no Python answers, the mod passes the
  prompt on unchanged and the settings hook blocks it.
- **What it sends, and where:** the prompt, the session id and the working
  directory go to that local process on stdin. The process detects the values,
  stores them in the local store, and answers with the prompt with placeholders.
  The mod passes that text on to Claude Code in place of the prompt. Nothing goes
  to a network address: the mod makes no network call, and the launcher has none.
  The process also starts the local transcript scrub, which masks the values in
  this session's transcript file on disk.

The settings hook in `hooks/hooks.json` runs after the mod and stays the gate.
When the mod does not load, fails, times out or gets an answer of another shape,
the prompt reaches the hook unchanged and the hook blocks it. `hooks/hooks.json`
is unchanged, so Codex and an older Claude Code keep the block. Measured on
2.1.291: the request holds the placeholder and not the value, also for a prompt
typed while a tool runs; the settings hook sees the placeholder; on 2.1.274 the
mod does not load and the hook blocks. Seen live in the desktop app's Code tab
with Claude Code 2.1.288: the prompt is rewritten and the model gets the
placeholder; your own message bubble there shows the text as you typed it, which
is the app's local display. Cowork is not measured. Mods are a rollout switch of the client:
where they are off (a saved switch, some third-party setups), the hook blocks.

**Sending a blocked prompt.** `/maisecrets:send` sends the rewritten prompt as
it is, without the clipboard. A plugin cannot register a command without its
namespace, so `/maisecrets:shortcut [name]` writes a personal `/ms` for it
into `~/.claude/commands` when you ask for it (a fixed wrapper in
`~/.maisecrets/bin` finds the installed plugin at run time, so it survives
updates); an existing `/ms` is left alone, `--remove` takes it away. The first
session start only names the command, once; `"shortcut": false` turns that
off. Codex gets no offer, because it has no plugin slash commands. The answer starts with `Sent: ` and the
text that went out, because Remote Control shows neither a blocked prompt nor
a slash command's expansion; the block notice itself is not shown there
either (reported to the vendor).

## Invisible characters

A tool result can carry text that the model reads and a person does not see. maisecrets removes two
kinds of such characters from every tool result (a file read, a command's output, a web page, an MCP
result, the keys of its JSON too) before the model reads it:

- **Unicode tag characters** (U+E0000 to U+E007F). Each one is the twin of an ASCII character, so a
  web page can hold a whole hidden instruction ("ASCII smuggling"). A value spelled in them goes
  away with them. Only the flags of England, Scotland and Wales keep their tags.
- **Variation selectors used as bytes** (U+FE00 to U+FE0F, U+E0100 to U+E01EF). By a rule of
  thumb, not the Unicode registry of variation sequences, a selector stays after a letter, a digit,
  punctuation or a symbol: VS15 or VS16 (text or emoji style) after any of them, VS1 to VS14 after
  one that is not ASCII, an ideographic selector after an assigned CJK ideograph. A second selector
  in a row, or one after a space, a control, a format, a combining, private or unassigned character,
  goes. "Assigned" means known to the Unicode version of the Python that runs the hook.

The zero-width joiner of emoji and the marks U+200E and U+200F stay. Bidi controls (U+202A to
U+202E, U+2066 to U+2069) stay too: they reorder what a person sees, but the model reads the text in
its logical order, and translation files need them. The file on disk does not change, only what
the model reads. In Codex, the session's rollout file holds the raw output, and a resumed session
reads it again: maisecrets overwrites each tag character, ideographic selector and VS1 to VS14 there
with spaces, at once and again whenever the file changes in the next 15 seconds. That rule is
blunter: in the rollout, the three flags and ideographic variants lose their selectors too. You get no question: one line says how many characters went, the model reads that they can
carry an instruction, and the audit log records the count, never the text.
`"strip_hidden_characters": false` turns it off.

This is not a detector of prompt injection. It takes away one way to hide one. A selector that the
rule keeps still holds something: one of three states (VS15, VS16, none) after any letter or
symbol, up to four bits after a character that is not ASCII, and up to one byte after a CJK
ideograph, where the rule keeps the ideographic selectors that Chinese and Japanese text use.

## Reporting a wrong detection

Every block and every redaction leaves an event in `~/.maisecrets/events.log`
(hook, client, rule name, type, plugin version; never a value). In Claude Code,
`/maisecrets:report last <why it is wrong>` prepares an issue from the last
event; `/maisecrets:report bug <what happened>` and
`/maisecrets:report feature <what it should do>` prepare one without an event.
The command prints the text and a prefilled link, so it also works over ssh and
in Remote Control. It opens a browser only on a local desktop, never in an ssh
session. Add `--create` to file the issue at once with the GitHub CLI (`gh`,
logged in). The arguments reach the CLI in a quoted heredoc, so a shell never
reads a reported command as code.
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
- **ssh through the Claude Code sandbox.** A value may go to your own servers
  over ssh on one condition: the command runs in Claude Code's Bash sandbox,
  where the operating system forces every connection through Claude Code's
  proxy and the proxy admits only the hosts you allow. Then the value goes
  on stdin. maisecrets adds no ask of its own by default: Claude Code's permission
  rules decide, as for any Bash command. With `"rehydration": "confirm"` Claude Code
  asks you first, showing the host and the remote command:

  ```
  printf '%s' ⟦EMAIL_c3⟧ | ssh aux01 'grep -F -f - /var/log/mail.log'
  ```

  Enable the sandbox in `~/.claude/settings.json`:

  ```json
  {"sandbox": {"enabled": true, "allowUnsandboxedCommands": false,
               "network": {"allowedDomains": ["aux01.example.com"], "strictAllowlist": true}}}
  ```

  maisecrets puts its own options first on the ssh line: a `ProxyCommand`
  (`hooks/proxy_connect.py`, because plain ssh has no network in the
  sandbox) and `ControlMaster=no`, `ControlPath=none`. Outside the sandbox the
  command stops before the value is read. Refused, with the reason:

  - a value inside ssh's arguments, a here-string or a heredoc into ssh;
  - a remote side that reads its program from stdin or passes the value on:
    no remote command, `bash`, `sh -s`, `python3` alone, `| sh`, `$SHELL`,
    `eval`, another `ssh`, `xargs sh -c`, and encoders such as `base64`;
  - an own proxy, jump host, shared connection, config file, host name or
    local command (`-J`, `-W`, `-S`, `-M`, `-F`, `-o ProxyCommand`,
    `-o HostName`, `-o LocalCommand`, …);
  - ssh on Codex, which has no host allowlist.

  What to know before you set it up:

  - The allowlist needs the host name ssh connects to, not the alias:
    `ssh -G aux01 | grep ^hostname` shows it.
  - Jump hosts (`ProxyJump` in `~/.ssh/config`) and connection sharing are
    off on this route: the sandbox proxy is the only way out.
  - The sandbox has no terminal and limits writes. Use a key without a
    passphrase prompt or an agent, and connect once outside the sandbox so
    the host key is in `~/.ssh/known_hosts`. `sudo ssh` drops the proxy
    variables and fails.
  - The remote command itself can pass the value on. The sandbox limits
    where the connection goes, not what the remote side does with the value.

  `"ssh_via_sandbox": false` switches the route off. Measured on macOS and
  Debian 13 with Claude Code 2.1.283.

  **One approval per session (opt-in, under `rehydration: confirm`).** With
  confirm, a search over many hosts asks for every command. Set
  `"ssh_approval": "per-session"` in
  `~/.maisecrets/config.json`: the first ssh use of a value asks once, and
  names this scope. After you allow it, the same value goes on stdin to ssh
  without a prompt for the rest of the session, at most 8 hours. The session
  approval covers only remote commands that read and print (`grep`, `zgrep`,
  `cat`, `tail`, `journalctl`, `sort`, `uniq -c` and the like), with no `>`,
  no `tee` and no `sort -o`. Any other remote command asks every time. The
  sandbox, the stdin rule and `allowedDomains` stay as they are: a host
  outside the list still gets a 403. The approval is recorded when the
  command you allowed reads the value, not when the prompt appears, so a
  declined prompt approves nothing. Measured in the macOS and the Linux
  (bubblewrap) sandbox against a real host with Claude Code 2.1.283
  (`harness/sandbox/ssh_e2e.py`). The default is `"per-command"`.
- **Inline for Write and Edit, and for a Codex patch.** In Codex a placeholder in the content
  lines of `apply_patch` resolves the same way, and a patch against the maisecrets home is
  refused (measured on codex-cli 0.158.0). A placeholder in the content of Write, Edit,
  MultiEdit or NotebookEdit is resolved like an MCP argument, under the same
  session rule, cap and audit line (the line names the file). When your
  permission rules ask (or with `rehydration: confirm`), the prompt shows the
  diff with the value: that is the moment you see what goes on disk. `"resolve_in_files": false` (a policy can set it)
  turns this off; then the file tools refuse a placeholder and the way to a
  file is a Bash command you approve (`printf '%s' ⟦KEY⟧ > file`). The
  maisecrets home itself is never written by the agent.
- **Codex gets "allow".** Codex accepts a rewritten input only together with
  `allow`. Measured with codex-cli 0.158.0 (`harness/codex.py --real`): the call
  of an MCP tool still needs the tool's approval in Codex
  (`mcp_text_field_rehydrate`), and a shell command still runs in Codex's
  sandbox: in a read-only sandbox the write is refused although the hook
  rewrote it (`allow_keeps_the_codex_sandbox`). Whether `allow` skips Codex's
  approval of an escalated shell command is not measured: `codex exec` offers
  no escalation. Codex 0.155.1 documented that it does, so on Codex treat the
  rewrite of a shell command as approved by maisecrets. On Claude Code the hook
  gives no decision, so the normal permission rules apply to the rewritten call.
- **Inline for MCP tools.** An argument has no shell to read from, so the value
  is inserted after the same session rule, cap and audit line, into every field
  that holds the placeholder. A field that carries published text (`text`,
  `message`, `body`, `comment`, `subject` …) is no exception: when you ask the
  agent to send a password over Slack, it goes out, and the model still sees
  only the placeholder. The client's permission rules decide whether the call
  runs.

## SSH consent (optional)

An agent with your SSH keys can run any command on any host it reaches, also
when no secret is in the command. Claude Code's own `permissions.ask:
["Bash(ssh:*)"]` matches only the start of a command, so `cd x && ssh …`,
`bash -c "ssh …"` and `timeout 30 ssh …` pass it. With `ssh_consent` on (send
`/maisecrets:settings ssh_consent on` as your prompt, see "Settings you decide";
a policy can set it; it is off by default),
maisecrets reads every ssh-family call (`ssh`, `scp`, `sftp`, `rsync` to a
host, `sshfs`, `ssh-copy-id`, `mosh`, `autossh`), also behind `cd …&&`,
`timeout`, `nohup`, `env`, `sudo` and `perl -e 'alarm N; exec @ARGV'`:

- **A read runs.** A remote command that prints only metadata about the host,
  from a short list with named options (`uptime`, `df -h`, `free`, `uname`,
  `ls`, `du`, `wc` of a literal absolute path, `systemctl is-active`), with no
  expansion and no redirect except `2>&1` and `>/dev/null` (any other
  redirect asks, also a local one: the hook cannot tell a quoted `">"` that
  ssh hands to the remote shell from a local one). The content of a
  file, a log or a process list (`cat`, `grep`, `journalctl`, `ps`,
  `systemctl status`) is a write: it can carry a credential. Paths like
  `/etc/shadow`, `.env`, `id_*`, `*.pem`, `/proc` or `/root` are never a read;
  that check is a heuristic, not a guarantee.
- **Every write asks.** Any other remote command, a login shell, `sudo`,
  `docker`, a copy, a port forward or tunnel (`-L`, `-R`, `-D`, `-w`), or local
  data on stdin. A yes allows that one command; the next write asks again.
- **A host you trust for a while: type it.** Send `maisecrets: allow ssh web1`
  as your own prompt (the question names the exact sentence). Writes to that
  host, and to the hosts of its group in `"ssh_host_groups": {"web": ["web1",
  "web2"]}`, then run without a question for 8 hours, in that session, for the
  main thread only: a subagent asks for itself. The host is as written, with
  its user and port (`-l`, `-p`, `-o User`, `-o Port`, `user@`, `scp://…:port`):
  `root@web1` and `web1:2222` are other hosts than `web1`. Only a prompt you
  type counts: not a scheduled or SDK prompt, and a Bash or PowerShell command
  that carries the sentence is refused.
- **Hosts where the AI may work on its own.** Your own lab or ops servers can
  be autonomous: writes there never ask, in any session, while every other
  host asks for each write. Send `/maisecrets:settings ssh_autonomous_hosts add
  ops1` (or `maisecrets: ssh autonomous ops1`), and `remove ops1` (or
  `maisecrets: ssh ask ops1`) to take one off. The host is as the ssh call
  writes it (`root@lab:2323` is not `lab`), or the name of a group in
  `ssh_host_groups` (then its members, not a host of that name); every host
  of a call must be on the list. The list changes from your own prompt, and
  the deny list holds there too. Limit: maisecrets reads commands as text, so
  a program that builds the sentence at run time and feeds it to a nested
  client (Codex does not say who wrote a prompt) can add a host; check the
  list in `/maisecrets:settings`.
- **A form maisecrets cannot read asks every time.** An ssh word in a nested
  shell (`bash -c`, `eval`, `xargs`, `find -exec`), a wrapper it does not
  know (`sshpass`, `setsid`, `flock`), a word built at run time when `ssh`
  is in its text (`$(which ssh)`, `S=ssh; $S`, `ssh $HOST`), two users or
  ports for one connection, `sudo -u` (another user's ssh config), an option that sends the
  connection elsewhere (`-J`, `-W`, `-S`, `-F`, `-o ProxyCommand`, `-o
  HostName`, `-o RemoteCommand`), `GIT_SSH_COMMAND`, `git -c core.sshCommand`,
  `RSYNC_RSH`, `DOCKER_HOST=ssh://`, the own ssh options of `sshfs` (also
  `-F`), `mosh` (also abbreviated) and `rsync -e`, `ssh -P` (a tag that
  selects a block of your ssh config), and any mention of `.ss…` outside an
  ssh call in a command that does not only read: a change to `~/.ssh` can send
  an approved alias elsewhere, and a list of writers is never complete
  (`rsync`, `tar -C`, `ln -s` …), so only reads are listed (`cat`, `ls`,
  `grep`, `head`, `diff` …), and a redirect into `.ss…` asks too. Write and
  Edit on `~/.ssh` ask as well.
- **The word ssh in quoted text runs freely, if every part of the line is a
  text command:** a quoted argument of a command that only prints or searches
  (`echo "use ssh"`, `grep "ssh" log`; not `rg`, `ag` or `sort`, which can
  start a program), the quoted text field of a `gh` or `glab` issue, pr, mr
  or release (`gh issue create --body "… ssh …"`), and the message of
  `git commit -m` or `git tag -m`. Every part of the line must be one of these
  commands, written as itself (no path, no variable, no wrapper), and outside
  quotes the line has no `$`, backtick, parenthesis, brace or redirect (other
  than `2>&1` or to `/dev/null`); inside double quotes a `$` comes only before
  a name (`"$HOME"`); `printf` and `test` have no `-v`, which names a variable
  the shell evaluates. Anywhere else, also unquoted
  (`grep ssh README.md`) or in a heredoc, the hook cannot tell text from a call,
  and it asks. A `#` comment is text only when no bracket, brace, parenthesis,
  backslash or backtick comes before it in the command, and the command has no
  carriage return: inside `(( ))`, `${ }` or `[[ ]]` the shell reads no comment
  and runs what follows. The same holds for a heredoc.
- **A short deny list is always refused:** `mkfs` or `wipefs` on a device,
  `dd` to a device, `rm -rf /`, a fork bomb, anywhere in a command that names
  an ssh-family call (quotes removed; as a command word, not as a file name;
  not in plain text that a lone `echo` only prints).
  It is an airbag, not the protection.
- **Codex** cannot ask. It refuses and names a sentence with a code, for
  example `maisecrets: allow ssh web1 123456`. Typed alone as your very next
  prompt within 10 minutes, it allows writes to that host for 8 hours; the
  prompt does not reach the model. Any other prompt ends the code. Codex sends
  no sign of who wrote a prompt, so there the code is the proof.

Measured on the maintainer's transcripts with `scripts/measure_ssh_consent.py
--skip-cwd maisecrets` (2026-10-07, the sessions that work on maisecrets itself
left out): real ops commands use `sudo` or `docker` on the remote side almost
always, so most are writes (88 %), and the consent per host carries them. 112
sessions with ssh, a median of 2 questions per session, 7 at the 90th
percentile, 48 at most. The script ignores groups and the 8-hour expiry.

A command name in another case (`SSH`, `Scp`) is the same program on macOS
and in PowerShell, so it counts too. A command line over 8,192 characters
that names ssh is not read at all: it asks (on Codex it is refused), so that
the answer always comes before the client's timeout.

Limits: maisecrets sees only the command text. A script file, an alias, a
variable that holds `ssh` and was set in an earlier command, or a word built
without the letters `ssh` in the text is not seen, and neither is a file that a
heredoc writes and the same command then runs. A program that git or gh starts
from its own configuration (a hook, an editor, a signing program, a browser)
is not checked; it gets the quoted text only as data. maisecrets reads the
command with its own small shell parser; other shell syntax that it reads
differently from bash or zsh can still hide a call (the reviews of 0.6.7 found
such forms only after one of the characters above). A mount (`sshfs`) or a tunnel
(`ssh -f -N -L`) that one consent started stays after the 8 hours, and the
local commands that use it ask nothing. On Codex the model sees the consent
code; maisecrets refuses a command that carries the sentence, but not one that
builds it at run time. The
`Monitor` tool of Claude Code runs a shell command outside the maisecrets
matcher (adding it would change the hook hash that Codex trusts). A program
that runs as you outside the sandbox can write the consent store. A hard
boundary needs host-side controls (restricted keys, `ForceCommand`, sudo
rules). Git over ssh (`git push`) is out of scope.

## Rehydration policy (optional)

The core does not change with this setting: a value stays out of the model on
every path, and a form where the value could become code is refused on every
path. The setting decides only whether maisecrets adds its own confirm where a
value is put into a call. `~/.maisecrets/config.json`, or the machine policy:

| `rehydration` | Claude Code | Codex |
|---|---|---|
| `"automatic"` (default) | no ask of ours; your permission rules decide | `allow` with the rewritten input |
| `"confirm"` | every call that gets a value asks, also in auto and bypass mode; the prompt names the fields and warns for a published-text field | refused before anything is resolved: Codex cannot ask with a rewritten input |
| `"block"` | refused before anything is resolved | refused |

It covers Bash, ssh, MCP tools and Write/Edit alike. `"resolve_in_files": false`
blocks the file tools alone; `"ssh_approval": "per-session"` works under
`confirm`. A value that is none of the three blocks. A `config.json` that is not
valid JSON, or holds no JSON object, blocks rehydration until it is fixed (it may
have said `block`), and
one ignored for a wrong type keeps what it made stricter (`rehydration`,
`resolve_in_files: false`, `ssh_via_sandbox: false`), so a typo never loosens
a setting. The refusal and `/maisecrets:status` name the file. In an unattended run (`claude -p`) nobody can answer a confirm, so the
call is refused and the model reads the reason, never the value. The whole
matrix, path by path: `tests/test_rehydration_matrix.py`.
- **Under a cap.** `max_keys_per_session` (200) distinct values per session and
  hour, and `max_resolves_per_hour` (1000) in total; above that the call is
  denied, and the reason names the command that raises the cap, for example
  `/maisecrets:settings max_resolves_per_hour 2000` (in Codex
  `maisecrets: set max_resolves_per_hour 2000`), typed as your own prompt. The cap
  is a brake for a session that would send all of its values out at once; the
  session rule above keeps every other value closed anyway. Replayed over five
  months of the maintainer's sessions, the busiest hour needed 67 values and 118
  uses; the old caps of 25 and 60 would have stopped 3 of 178 sessions that used
  values. Every resolve writes one line to `~/.maisecrets/audit.log`
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

## Test data that maisecrets leaves alone

maisecrets steps in only when a value that it can detect goes to the AI. Test data
does not need to look like a real secret, and these forms are never a hit:

- **In test code** (a file under `tests/`, `test_*.py`, `*_test.go`, `*.spec.ts`,
  `conftest.py`, or code after `def test_`, `assert`, `describe(`), a password that
  maisecrets finds only by its label (`password = "<value>"`) is a fixture.
  A token shape (`glpat-…`, `AKIA…`, a private key) and personal data are still found
  there: a real token in a test is a leak.
- **Anywhere:** a value that names itself (`testpass`, `secret123`, `Passw0rd!`,
  `my-test-token`), a placeholder (`<your-token>`, `${API_KEY}`, `{password}`,
  `changeme`, `xxxxxxxx`, `***`), and a default equal to its label or user
  (`POSTGRES_PASSWORD: postgres`, `admin:admin`).
- **Addresses:** e-mail at `example.com`, `example.org`, `example.net` and the domains
  `.test`, `.example`, `.invalid`, `.localhost`, a system mailbox such as `alerts@` or `noreply@`
  at `.local` or `.internal` (a person's mailbox there is found); IP addresses in
  the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and
  `2001:db8::/32`, private and loopback addresses.
- **An AWS key id in a SigV4 credential scope:** `X-Amz-Credential=AKIA…` in a presigned
  URL, `Credential=AKIA…` in an `Authorization` header. The id names the key; it is not
  the secret half. The same id anywhere else is still found.

If maisecrets stops something that is not a secret, `/maisecrets:report last <why>`
sends the rule name, never the value.

## Detection rules

Four sources, one scanner (`maisecrets/detect.py`):

- **gitleaks** ruleset, vendored as data under `maisecrets/rules/` (MIT,
  version in `GITLEAKS_VERSION`, refresh with `scripts/sync_gitleaks.py vX.Y.Z`):
  ~220 secret shapes with keywords, entropy thresholds and allowlists. No
  gitleaks binary is used.
- **Presidio** pattern recognizers, vendored as data under `maisecrets/rules/`
  (MIT, version in `PRESIDIO_VERSION`, refresh with `scripts/sync_presidio.py`):
  country-specific PII with scores and context words. The config key
  `regions` selects them (default: the country of the system setting; `de`
  gives Steuer-ID,
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
- **Own rules** for what none of the three covers: email (a
  bounded regex; the unbounded one took 11 s on an 80 KB dotted run), phone
  with a country code, `Bearer …` outside curl, `?api_key=…` in a URL, a
  password with no user in a URL (`redis://:…@host`), the secret half of an AWS
  key pair within a few lines after its `AKIA…` id, and full-length GitLab
  runner and deploy tokens.
- Prefixes newer than the vendored rulesets live in
  `maisecrets/rules/prefixes.txt`, one line each, extended by pull request
  (`CONTRIBUTING.md`): `glrt-`, `gldt-`, `whsec_`, `cfut_` so far, the last
  two found bare in real prompts on 2026-09-26.
- A secret shape with a fixed length (gitleaks: `glpat-[\w-]{20}`) is
  extended to the end of the token characters, so a longer token does not
  leave its tail in the clear (found with a 24-char token, 2026-09-26).
  The extension stops at a line break: a token that a line break splits
  (a hard-wrapped terminal line) keeps the part after the break in the clear.
  Joining the next line was measured on five months of session logs and left
  out: nearly every candidate was the next `.env` line, not the rest of a key.

IBAN, credit card and IP come from Presidio's regexes with our validators
(mod-97, Luhn, public-range check). A card number without a word like
"card" or "Kreditkarte" nearby is not reported: Presidio scores the bare
shape low, and a 16-digit number passes Luhn one time in ten.

Measure what the rules would catch on your own recordings, values never
printed: `scripts/replay_sessions.py --claude --codex`.

## Known gaps (measured or documented)

What the plugin does not protect. Each item is a limit of the mechanism, not
a to-do.

- **The output of a command that fails reaches the model as it is (Claude
  Code).** Claude Code reports a failed call through another hook event,
  whose answer cannot replace the output. A value that a failing command
  prints (`grep TOKEN .env` with exit 1, a script that prints its config and
  stops) is not redacted, and it stays in the transcript. Measured over one
  user's transcripts: 14 such outputs with a hit in 105,241 Bash calls over 90
  days, 1 of them a secret. A command that ends in a pipe (`… | tail`) is
  redacted as usual. maisecrets then stores the value (a repeat is redacted),
  cleans the transcript on disk, tells the AI not to use it, and shows you a
  line about it. See the threat model, "What is knowingly not defended".
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
  come back with placeholders. Set `"regions": []` to drop the country
  identifiers; there is no allow-list for single values yet.
- **Placeholders resolve in Bash, MCP tool arguments and the file tools.** In
  WebFetch or a subagent prompt they stay text. A subagent shares its parent's session; a
  headless run (`codex exec`, `claude -p`) is a session of its own, so a
  reference from an earlier run is foreign there.
- **A reference in a prompt is admitted as typed by a human**, also when the
  prompt was built from an issue body or a log in a headless run.
- **Claude Code on Windows without Git Bash** offers a `PowerShell` tool in
  place of Bash. maisecrets checks it like Bash for the store, in any case
  and with either slash, and refuses a placeholder in it with the reason:
  the rewrite knows POSIX quoting only. A placeholder in a file tool or an
  MCP argument works as on the other systems. The `/maisecrets:*` commands
  run through Bash and need Git Bash.
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
