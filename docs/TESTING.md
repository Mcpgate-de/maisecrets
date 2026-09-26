# Testing record

## Harness (fake Anthropic upstream, Claude Code 2.1.283)

Runs in CI on every push (`harness_claude`, `harness_codex`): a real binary,
an empty HOME, a dummy key, the fake upstream. Measured 2026-09-26: Claude
Code needs no login when `ANTHROPIC_BASE_URL` points at the fake.

Run 2026-09-26 (evening), 6 scenarios, 0 failures:

| scenario | what it proves |
|---|---|
| prompt_secret | a typed secret is blocked; 0 requests reach the upstream; the transcript on disk carries no secret |
| read_env | a Read of `.env` reaches the model with `⟦SECRET_c1⟧` and `⟦EMAIL_c1:…⟧`, never the values |
| bash_echo | `cat .env` output is redacted before the model sees it |
| bash_rehydrate | `⟦SECRET_c1⟧` in a Bash command is read under a one-time grant at execution; the file the command wrote holds the value, the requests and the rewritten `tool_input` hold no value |
| bash_rehydrate_quoted | a value with quotes, `$(` and spaces inside single quotes arrives byte for byte, and comes back redacted by exact match although it has no known shape |
| bash_foreign_ref | a reference the session never saw in a prompt is denied; the model reads `foreign-session` in the tool result; no file is written |

Golden payload shapes captured in `harness/golden/` (top-level keys, `tool_input`
keys, `tool_response` keys per event and tool). A later Claude Code version
that changes a shape fails the harness with "schema drift".

## Plugin must load, or nothing runs (Debian, Claude Code 2.1.223, 2026-09-26)

The first harness run of 0.3.4 on Debian failed 16 checks at once: every
secret reached the upstream, no placeholder resolved. `--debug-file` showed
why: `Plugin maisecrets has an invalid manifest file` and `Registered 0 hooks
from 0 plugins`. Bisected by removing one manifest field at a time: 2.1.223
rejects `userConfig`; 2.1.283 accepts it. A rejected manifest does not block
anything, it just loads nothing. The manifest carries no `userConfig` now,
and the harness fails a scenario when the debug log does not show
`Registered N hooks from M plugins` with N, M ≥ 1. Debian 13 with 2.1.223
after the fix (0.3.5, cloned from the public GitHub repo): 6 of 6 green.

## The transcript check looked at nothing (2026-09-26, evening)

The harness derived the transcript folder from the cwd and got the name wrong
(Claude Code rewrites `_` and prepends `/private` on macOS), so "transcript
on disk carries no secret" had never been checked. Found by a mutation probe
that stayed green. The harness now finds the transcript by session id and
fails when it finds none. What the real check then showed, both fixed:

- The blocked prompt's record is written AFTER the `UserPromptSubmit` hook
  returned (at hook time the file did not exist), so the in-hook scrub found
  nothing. A detached child now polls the transcript for up to 15 s and
  scrubs the record when it appears.
- For an MCP tool call, Claude Code logs the `PreToolUse` hook's stdout,
  which carries `updatedInput` with the value, as a `hook_success`
  attachment. `PostToolUse` now scrubs the inserted values (found by keyed
  fingerprint in the executed `tool_input`), doubly escaped forms included.
  Scenario `mcp_rehydrate` (server-everything's echo tool) covers it; with
  the scrub switched off it goes red.

Also found: a maisecrets copy synced from the developer's claude.ai account
loaded next to the `--plugin-dir` checkout and answered first, so the harness
had been exercising the released version instead of the working tree. The
harness settings now disable `maisecrets@synced`.

## Field report Oleg (Linux, Claude Code over SSH and Remote Control, 2026-09-26)

Confirmed: prompt block, Bash rehydration over SSH, output redaction of
values never seen before. Found: (1) no clipboard over SSH, no block notice
in Remote Control → `/maisecrets:send` sends the kept rewritten prompt without
copying; (2) a burned grant substituted "" and the command ran (`grep` said
"0 matches") → the resolver call now terminates the command on failure and a
grant serves retries within its lifetime; (3) one tool result came back
empty once, cause unknown, not reproduced; (4) MCP values inline: measured the
same day, the model sees placeholders only and the transcript is scrubbed.

## Mutation probes

| date | mutation | expected | observed |
|---|---|---|---|
| 2026-09-26 | `PostToolUse` removed from `hooks/hooks.json` | read_env and bash_rehydrate go red | 5 failures: 2 leaks + 2 missing placeholders in read_env, 1 leak in bash_rehydrate. Hook restored, harness green again. |

## Unit tests

44 tests (`tests/test_core.py`, `tests/test_gates.py`, `tests/test_platform_backend.py`),
run in under a second. The gate tests execute the rewritten command through a
real bash and compare bytes, so a broken quoting context or a leaked value
fails them:

| control (docs/THREAT-MODEL.md) | test that goes red without it |
|---|---|
| C4 session rule | `test_reference_resolves_only_in_a_session_that_saw_it`, `test_mcp_foreign_session_is_denied…` |
| C5 one-time grant | `test_grant_is_single_use_and_bound_to_its_key` |
| C6 quoting contexts | `test_value_arrives_byte_for_byte_in_every_quoting_context` (unquoted, single, double, two refs) |
| C7 limiter | `test_limiter_caps_distinct_keys_per_session_and_resolves_per_hour` |
| C8 store-read backstop | `test_agent_reads_of_the_store_are_denied` |
| C9 audit line | `test_audit_line_names_key_tool_and_context_but_no_value` |
| C10 keyed fingerprint | `test_index_carries_no_reversible_fingerprint` |
| C2 exact match | `test_shapeless_value_is_redacted_by_exact_match` |

## Hook latency (end to end, fresh python process per hook, median of 7, 2026-09-26)

| hook | input | before lazy compile | after |
|---|---|---:|---:|
| UserPromptSubmit | 100-char prompt, no hit | 91 ms | 40 ms |
| PreToolUse | `git status`, no placeholder | 50 ms | 50 ms |
| PostToolUse | 120 KB Bash output, no hit | 197 ms | 116 ms |
| PostToolUse | 2 KB `.env` with 3 hits | 94 ms | 47 ms |
| (python3 startup alone) | | 23 ms | 23 ms |

Throughput of the scan itself: about 5 s per MB of text with all rules on
(the replay), 0.1 ms for a prompt.

## Replay over recordings (first impression, 20 Claude transcripts, 22 MB)

Distinct values by type, same 20 files, three rule states on one afternoon:

| state | SECRET | EMAIL | IP | other |
|---|---:|---:|---:|---|
| gitleaks + Presidio + detect-secrets, untuned | 101 | 48 | 8 | CRYPTO 42, DE_PLZ 15 |
| after fixing 5 false-positive classes | 42 | 48 | 6 | none |
| after placeholder / identifier / system-user filters | 25 | 43 | 6 | none |

False-positive classes found and fixed by the replay: context words matched as
substrings ("ort" inside "report" made every 5-digit number a PLZ); the
whole curl command taken as the secret (first non-empty capture group now);
detect-secrets keyword rules run across lines (per line now); prose and i18n
labels as values; crypto addresses inside base64; "::" and "fe80::" as IPv6;
"Bearer" across a line break; placeholder-shaped values
(`YOUR_PORTKEY_API_KEY`, `sk-ant-bogus`); identifier-shaped values
(`secret_value`); `git@host` and `noreply@` as email addresses. Also a crash:
Presidio's IP regex swallowed a CIDR suffix and the validator raised; every
validator call is guarded now.

The full replay over 3.7 GB (Claude) + 0.5 GB (Codex) is scheduled for a
later run with the tuned rules; at 5 s/MB it takes hours.

## Codex harness (codex-cli 0.155.1, fake Responses upstream, 2026-09-26)

**Discovery gap found by a peer session (Codex 0.157.1):** the installed plugin
was enabled and Codex discovered 0 of its 4 hooks. Bisected on copies: with
the root `plugin.json` (the portable Agent Plugins manifest) present, 0 hooks;
without it, 4. The root manifest is gone. The first harness wrote `hooks.json`
straight into `CODEX_HOME` and so never exercised discovery; it now installs
the checkout as a local marketplace plugin, the way a user gets it.
Mutation probe: with the root manifest put back, `prompt_secret` goes red
with two leaks (request body, rollout); without it 3 of 3 green.

**Real upstream, 2026-09-26 evening (`--real`, gpt-5.6-sol): 3 of 3 green.**
The first real run found a leak the fake runs had hidden: the gitleaks
`gitlab-pat` shape is fixed at 20 characters, the harness marker has 24, and
the last 4 reached the model in the clear. The detector now extends a secret
match to the end of the token run, and both harnesses check the marker's tail
as well as the whole marker. The real model also declined `print .env verbatim`
on its own; the scenario asks for the variable names instead.

`python3 harness/codex.py` runs the same three tool scenarios through
`codex exec` with an isolated `CODEX_HOME`, a custom provider pointed at
`harness/fake_openai.py` (Responses SSE, code-mode `exec` tool, zstd request
bodies) and no credits. 3 of 3 green: the marker never reaches an upstream
request body, the rollout on disk, or the final message; placeholders do.

Measured on the way, both against the Codex hook docs:

- `PostToolUse` with `continue: false` + `stopReason` let the RAW tool output
  reach the model. `decision: "block"` + `reason` replaced it with the redacted
  text. maisecrets uses `block` for Codex.
- Codex writes the raw command output into its rollout file
  (`event_msg / item_completed / CommandExecution`) before `PostToolUse` runs,
  outside the hook path. maisecrets scrubs `transcript_path` after redaction,
  the same way it does for Claude Code's `queue-operation` record.
- With the built-in `openai` provider Codex tries a WebSocket upgrade first and
  retries five times before falling back to HTTP; a custom provider with
  `supports_websockets = false` avoids that.

