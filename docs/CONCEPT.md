# Concept: secrets and PII never reach a cloud model

Status: 2026-09-26. Commissioned by Andi. This document records the goal and
every decision taken so far. Work packages follow from it.

## The goal in one sentence

A secret or a piece of personal data that lives on an employee's machine does
not leave that machine in plaintext towards a cloud model. The agent still
works with it. A local vault holds the value. The value is inserted only into
the real API call.

## What must hold

1. **Every client.** Claude Code, Claude Desktop/Cowork, ChatGPT, Codex. Mac
   and Windows. Mobile where reachable. Concessions are allowed and are named.
2. **Before the client, not inside the model.** Replacement happens locally
   and deterministically, before data leaves the machine.
3. **Rehydration.** An API call or tool call that carries a placeholder gets
   the real value inserted. The model never sees the value.
4. **One local vault per user.** Secure, with a UI, with clipboard
   integration, connectable to the ai-gateway (which then rehydrates on its
   side).
5. **Future-proof.** The solution must not depend on one client feature that
   the vendor can remove.

## What already exists (reference: ai-gateway origin/main 579949288)

- **#1180** Secret handling. Measurement: 185 real credentials in 3254
  sessions. 5 % in a tool argument, 15 % out of gateway responses, **80 %
  never at the gateway** (Read/Bash of .env and source code). Phase 0/1 on
  prod: store values come back as an opaque marker, no reveal endpoint. Open:
  deposit call, scope binding, local layer.
- **#1388** AWS/SES connector (Oleg). Oleg's proposal: out-of-band put/get
  against the gateway with a reference. Session recommendation: paste URL
  instead of a CLI put. Andi has not answered Oleg yet.
- **#1396** Resolvable token `<EMAIL_1:ma***@gmail.com>` instead of `mask`.
  No code yet. Prod runs on `mask`. Today's email regex destroys the token.
- **Wrapper sketch, 2026-09-15.** `secure_read`/`secure_bash` as MCP tools,
  native tools denied, placeholder `<<SECRET:xxxx>>`, vault per session.
- **Cost analysis** (~/llm-cost-analysis): a model router per step saves
  little. Splitting at task boundaries saves ~30 %.

## What the research of 2026-09-26 found

### Two assumptions from earlier sessions are wrong

1. "Claude Code hooks can only block." Wrong. `PreToolUse.updatedInput`
   replaces arguments, `PostToolUse.updatedToolOutput` replaces any tool
   result before it goes to the model. Only the typed prompt cannot be
   rewritten. The 80 % class is therefore reachable by hooks.
2. "A subscription login cannot go through a gateway." Wrong.
   `ANTHROPIC_BASE_URL` without a gateway credential keeps the subscription.
   Live test: the full `/v1/messages` body with the OAuth header arrived on
   `http://127.0.0.1`.

### Interception points per client

| Client | Own endpoint | Rewrite content | Mobile |
|---|---|---|---|
| Claude Code | yes, `ANTHROPIC_BASE_URL`, enforceable via MDM | hooks for tools; prompt only via proxy | n/a |
| Claude Desktop/Cowork, claude.ai login | no | no | — |
| Claude Desktop **3P mode** | yes, `inferenceGatewayBaseUrl` via MDM | no, redaction in the gateway | loses mobile and claude.ai web |
| Codex CLI | yes, `openai_base_url`, ChatGPT login possible | hooks for tools | n/a |
| ChatGPT desktop and mobile | no, certificate pinning (exceptions gone since 2026-04) | no | no |
| ChatGPT web / claude.ai web | browser DLP only, no rehydration | no | — |
| OpenCode | yes, `baseURL` | yes, `experimental.chat.messages.transform` | n/a |

### Tools on the market

- **Proxies with rehydration:** PrivAiTe (BSD-3, Anthropic + OpenAI +
  Responses, restores tool arguments), claude-code-redact `rdx` (Apache-2.0,
  deterministic tokens), pii-hole. All early, mapping mostly per request.
- **Secret injection on egress:** Infisical Agent Vault (MIT, MITM proxy,
  placeholder replaced in the outgoing request, encrypted SQLite, web UI),
  OneCLI (Rust). Secrets only, no PII in text.
- **Commercial:** Private AI, Protecto, Skyflow, Kong Enterprise. None
  documents restoring tool calls.
- **LiteLLM + Presidio** had a silent bug in 2026: tool arguments were not
  restored. LLM Guard is archived.
- **MCP spec 2025-11-25:** elicitation for secrets MUST be URL mode.
- **1Password for Claude** (July 2026): injects credentials into the web page
  outside the model context. Claude Code not mentioned.

### Why client-side redaction stays necessary despite an enterprise contract

ZDR does not cover Cowork, claude.ai chat and MCP servers. Flagged sessions
are kept by Anthropic for up to 2 years.

## Open questions for Andi

See the chat of 2026-09-26. Answers land in this document.

## Decisions of 2026-09-26

- **Slice 1 is the hook route, not the proxy.** A `UserPromptSubmit` hook
  detects deterministically, stores the value in the vault, blocks the
  prompt, and puts the rewritten prompt into the clipboard. Measured: a
  blocked prompt produces no API request. Covers Claude Code and Codex, not
  Cowork and ChatGPT. The proxy is slice 2.
- **Two traps from the test belong in the build:** the plaintext sits in the
  transcript as a `queue-operation` record, and the hook timeout (30 s) is
  fail-open. `suppressOriginalPrompt` belongs under `hookSpecificOutput`.
- **#1396 and #1388 are preparation, not blockers.** Andi works on #1396.
- **anonym.legal is not a solution** (second cloud, MCP acts too late, the
  published hook does not change the prompt). The tool shape
  anonymize/detokenize/list_sessions/delete_session is a usable pattern.
- **Vault, slice 1: operating-system store** (macOS keychain without the
  sync flag, Windows Credential Manager) via `keyring`, plus an own index file
  for type, purpose, expiry. Four functions: put, get, list, expire. Backend
  replaceable.
- **Do not build on LastPass.** phase6 uses LastPass, the future is open.
  `lastpass-cli`: last release v1.6.1 (2024-11-14), last commit 2025-04-22,
  219 open issues, no secret references. LastPass itself (blog 2026-05-15):
  "LastPass doesn't authenticate AI agents, issue OAuth tokens, or manage
  machine identities." The choice of password manager is its own decision and
  must not block this project.
- **Lifetime in the vault:** every entry has a TTL (start 24 h, like the
  gateway mapping). Each use renews it. On expiry only the value is deleted;
  the metadata entry (type, fingerprint, created, last used, session) stays as
  a record. An expired placeholder fails with "expired", an unknown one with
  "unknown"; neither passes through. Values live only in the keychain, the
  index file under `~/.maisecrets/` holds no value. Long-lived secrets belong
  in the password manager, not in the ephemeral vault.
- **TTL is configurable** on three levels: default per type in
  `~/.maisecrets/config`, value per entry at deposit time (purpose), and a
  cap that even renewal on use does not exceed (proposal 30 days). Renewal on
  use is its own switch.

## Shape of the tool (slice 1)

Not a skill: the model must not steer the replacement. Three building blocks:

1. **`maisecrets`, a binary** (brew / winget). Contains detector, keychain
   access and the hook commands `hook prompt`, `hook pre-tool`,
   `hook post-tool`, plus `list`, `get <ref>`, `expire`.
2. **Claude Code plugin `maisecrets`**: only the hook registration pointing at
   the binary (`claude plugin install maisecrets@sprinterli`). Codex: the
   same entry in `~/.codex/config.toml`. Both enforceable via MDM.
3. **Deposit endpoint in the ai-gateway** (`POST /api/vault/deposit`) plus a
   personal vault key per user from the gateway settings.

Daily use: `claude` as usual. On a hit: block notice, rewritten prompt in the
clipboard, Cmd+V, Enter. Lookup with `maisecrets get` (Touch ID).

## Gateway flow: the value moves into the gateway mapping before the tool call

1. The model calls a gateway tool with `<EMAIL_1>`.
2. `PreToolUse` recognises the gateway by the MCP server name and finds the
   placeholder.
3. The hook calls `POST /api/vault/deposit` (reference, value, type, TTL)
   with the vault key. The value lands in the existing encrypted per-user
   mapping (Redis, KMS). That is Oleg's "put" (#1388) and #1180 phase 2, done
   by a machine.
4. The tool call goes to the gateway unchanged with `<EMAIL_1>`; the gateway
   rehydrates (today only `*_write_actions`; read actions need a per-field
   opt-in).
5. Response: the scrubber knows the value and writes the same placeholder
   back.
6. `PostToolUse` checks locally for plaintext (second net).

The value travels only over TLS to the gateway, never to Anthropic. No
connection from the gateway back to the client is needed.

**For #1396:** client-minted references need their own range (e.g.
`⟦EMAIL_c1:…⟧`) that the gateway never mints. Otherwise a deposit overwrites a
foreign gateway entry with the same counter.

## Market and distribution (research 2026-09-26)

- **No finished tool does exactly this.** The official marketplace (340
  plugins) has no privacy plugin. Closest prior art:
  `l-mb/claude-code-redaction-hooks` (Apache-2.0, Python): block/redact per
  hook, mapping file, audit log, schema-drift harness. No rehydration, no
  vault, no gateway. Candidate to fork or to use as a reference.
- **Proven bypass:** `@file` in the prompt inlines the content past every
  hook. Countermeasure: block `@<path>`, force an explicit Read. Also: tool
  output above 50K characters is spilled to a file the hook does not rewrite.
- **Plugin hooks run in Cowork** (session on the machine), not in Chat and
  not on mobile. A plugin installed on the claude.ai account appears in
  Claude Code as a synced plugin; an Owner can set it to "Required".
  Distribution without MDM for Claude Code and Cowork. Not verified: whether
  UserPromptSubmit fires in Cowork for the Cowork prompt. A binary in `bin/`
  cannot be installed in Cowork; the script lives under `hooks/` in the
  plugin.
- **Vault backend replaceable:** OS keychain as default, 1Password (`op`),
  Bitwarden (`bw`) and Infisical as further backends behind put/get/list/expire.

## Enforcement by the company (docs, 2026-09-26)

Two routes, combinable (claude.com/docs/plugins/org-rollout):

1. **claude.ai console** (Team/Enterprise, Owner): Organization settings >
   Plugins & skills, own marketplace repo (GitHub/GitLab) or zip, availability
   **Required** = "installed and always on, members can't turn it off or
   remove it". Applies in claude.ai, Cowork and in Claude Code sessions that
   sync the account. Per-group assignment on Enterprise.
2. **Managed settings for Claude Code** (console, MDM plist
   `com.anthropic.claudecode`, registry, or `managed-settings.json`):
   `extraKnownMarketplaces` + `enabledPlugins` install and enable on every
   machine; "disabling one at their own scope doesn't stop it from loading".
   `strictKnownMarketplaces` + `disableSideloadFlags` lock out foreign
   sources. `allowManagedHooksOnly` lets only hooks from managed settings run.
   A base-URL change in the shell switches server-managed settings off, so
   for the proxy case use MDM or the file.

Codex: `requirements.toml` with `[hooks]`, `allow_managed_hooks_only = true`,
via MDM or cloud policy.

Not enforceable: chat in claude.ai, mobile, the ChatGPT apps.

## Product and protection (2026-09-26)

Andi wants to offer it as a free plugin/service. Trivial and rebuildable in a
day: block hook, clipboard, keychain put/get, regex, manifest. Not trivial,
accumulates: (1) the coverage map of leak paths per client version with a
harness against golden payloads, (2) the client–gateway protocol from #1180
(namespace, capabilities per entry, scope binding, TTL, deposit, blind
compare), (3) the before/after measurement, (4) a German PII corpus, (5) the
gateway as execution point. Protection through trademark, licence (plugin
Apache-2.0, gateway side BSL), reference implementation, installed base
(anonymous opt-in counter in the plugin). Clarify ownership phase6/mcpgate
before publication.

**Self-installation of the vault:** a `Setup` or `SessionStart` hook checks
`~/.maisecrets/`, downloads the signed binary, verifies the signature. Until
then the prompt hook blocks every hit (fail closed). No `bin/` in the plugin
(Cowork), script under `hooks/`. Cloud sessions and WSL load no local plugins.
*(Superseded below: the directory rules forbid downloads; the vault ships as
readable source inside the plugin.)*

## Carrier and name (2026-09-26)

- **Developed privately.** Repo on gitlab.com/Sprinterli (plumbing; a move into the mcpgate group on 2026-09-26 was reverted because a group project on the Free tier cannot mint project access tokens) with a mirror to
  github.com. Plugin, vault and protocol specification live there. The
  gateway part (deposit, rehydration for read actions) implements the
  specification in the ai-gateway; phase6 is the first user.
- **Codex in parallel.** Codex plugins have the same parts (skills, MCP,
  browser extensions, hooks in `hooks/hooks.json`), a marketplace from a
  GitHub repo, managed hooks via `requirements.toml` with
  `allow_managed_hooks_only` and `[features].hooks = true`. Non-managed plugin
  hooks must be approved once by the user. Installing a plugin over the web
  deploys no hook scripts; self-installation of the binary is mandatory. One
  core, one adapter per client (Codex: PostToolUse replaces via block
  feedback, updatedMCPToolOutput not supported).
- **Name.** Metaphor cloakroom (hand in the coat, get a ticket, reclaim at
  the exit). Candidates after the check of 2026-09-26 (NS-based, "free?" not
  proven): Garderobe (.dev/.com free?, npm/PyPI free), coatcheck (.dev free?,
  npm taken), ticketstub (.dev/.ai/.io free?), vaultstub (all free, bland).
  Understudy, Cloakroom, Decoy, StuntDouble taken. Nothing registered.
- **Andi's proposal: `maisecrets`** (checked 2026-09-26): GitHub user free,
  0 repos with the name, npm/PyPI/Homebrew free, gitlab.com user free,
  .dev/.ai/.io/.de without name servers; only .com has name servers (parked).
  Says what it is; covers PII only through the reading "my AI secrets".
- **Homepage/domain:** not needed for slice 1 nor for distribution via a
  marketplace repo (the Claude directory requires a public GitHub repo; Codex
  plugins come from a marketplace repo). Binaries via GitHub releases, docs in
  the README. A domain becomes necessary for a directory submission (privacy
  policy, support contact; checklists not read) and for selling. Hedge:
  reserve the .dev once the name is final.
- **Further clients, by demand:** OpenCode (plugin with
  `experimental.chat.messages.transform`, can rewrite the prompt, better than
  hooks), Cursor hooks (beforeSubmitPrompt can block; rewrite unverified),
  GitHub Copilot CLI hooks, Gemini CLI, Kiro, Claude Agent SDK and Codex SDK
  (the same hooks), headless `-p` in CI. All except OpenCode unverified.
- **Name now?** No. Working name `maisecrets`. Fix it at the latest before
  the first external installation: the plugin name then sits in foreign
  `enabledPlugins` entries and in the Homebrew formula. A repo rename is cheap
  (redirects).

## Store requirements and approach (2026-09-26)

**Claude directory** (pre-submission checklist): public GitHub repo,
`.claude-plugin/plugin.json`, README ≥ 40 words, LICENSE. Everything a hook
runs lives in the plugin folder. No compiled executables (held for a
reviewer), no launchers/package installs in hook scripts, commands as a full
path from `${CLAUDE_PLUGIN_ROOT}`, no credentials from the environment, the
README describes everything that runs/sends/fetches. Validation in the
developer portal is possible without submitting.

**OpenAI directory**: verified identity, published privacy policy; for remote
MCP plugins website/support/terms URLs and 5+3 test cases. Whether a pure
hook plugin needs the URLs: not found.

**For phase6 and first users an own marketplace repo is enough**
(enabledPlugins/Required for Claude, workspace marketplace for Codex).

**Consequence: the vault is not installed afterwards, it ships with the
plugin**: readable source in the plugin (hook script or local MCP server
`node ${CLAUDE_PLUGIN_ROOT}/vault/server.js`), keychain directly via
`security` (macOS) and PowerShell (Windows), no dependencies. SessionStart
only creates `~/.maisecrets/`. Open: which interpreter is reliably present on
Windows (python3 is missing, node no longer ships with Claude Code); measure
before packaging.

**Approach:** Day 1 hooks in `~/.claude/hooks/` + JSON vault
`~/.maisecrets/vault.json` (0600, test mode) + detector from pii_scrubber +
clipboard + listener harness. Day 2–3 keychain backend, TTL/index, PreToolUse
insertion in Bash, PostToolUse scrub, mutation probe per hook. Week 2 plugin
folder, portal validation, marketplace repo `Mcpgate-de/maisecrets`, 2–3
phase6 Macs, Codex hooks.json, Cowork test. Then gateway deposit, OpenCode,
privacy policy/domain, directory. First building block: the harness (golden
payloads against hook drift).

## Provider coverage (2026-09-26)

One core (detector, vault, placeholder), one adapter per provider (manifest,
hook names, block/rewrite fields). Proven: Claude Code/Cowork/Desktop Code
(hooks: block prompt, rewrite tool I/O), Codex CLI and Codex in the ChatGPT
app (same format; output via block feedback). Docs, untested: ChatGPT Work
mode runs plugin hooks in the Codex runtime. OpenCode: own npm plugin, can
rewrite the prompt (correction 2026-09-26: the current plugin API lists
`tool.execute.before/after` as modifiable, no prompt hook). Checked in the
vendor docs on 2026-09-26 (README "Client support" has the marks), hook
names per guard:

| client | block a prompt | rehydrate | redact output |
|---|---|---|---|
| Gemini CLI | `BeforeModel` may rewrite | `BeforeTool` may rewrite | `AfterTool` may redact |
| Cursor | `beforeSubmitPrompt` blocks | `beforeShellExecution` | `postToolUse` for MCP results only; `afterShellExecution` cannot rewrite |
| Copilot CLI | `userPromptSubmitted` → `modifiedPrompt`, SDK hooks only | `preToolUse` → `modifiedArgs` | `postToolUse` → `modifiedResult` |
| OpenCode | none | `tool.execute.before` | `tool.execute.after` |
| Antigravity CLI | none (`PreInvocation` injects only) | `PreToolUse` → `overwrite` | none (`PostToolUse` expects `{}`) |

Unchecked: Kiro. No adapter: Claude Chat, ChatGPT Chat, web, mobile.

Antigravity CLI (`agy` 1.2.11, checked 2026-09-26 from the hook doc embedded
in the binary): own `hooks.json` contract, named hooks in `plugins/<name>/hooks.json`
or `.agents/hooks.json`, camelCase payloads. `PreToolUse` on `run_command` gets
`toolCall.args.CommandLine` and may answer `decision` allow/deny/ask plus
`overwrite` for the arguments, so rehydration and a deny are possible.
`PostToolUse` expects `{}` back: a tool result cannot be rewritten. There is no
prompt hook; `PreInvocation` carries no prompt and can only inject messages.
Two of the three guards (block a prompt, redact a result) have no hook to live
in, so an adapter would only rehydrate and deny. Not built; `agy plugin
validate` accepts the plugin layout but finds no hooks in it.
