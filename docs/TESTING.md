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

## Field report from a colleague (Linux, Claude Code over SSH and Remote Control, 2026-09-26)

Confirmed: prompt block, Bash rehydration over SSH, output redaction of
values never seen before. Found: (1) no clipboard over SSH, no block notice
in Remote Control → `/maisecrets:send` sends the kept rewritten prompt without
copying; (2) a burned grant substituted "" and the command ran (`grep` said
"0 matches") → the resolver call now terminates the command on failure and a
grant serves retries within its lifetime; (3) one tool result came back
empty once, cause unknown, not reproduced; (4) MCP values inline: measured the
same day, the model sees placeholders only and the transcript is scrubbed.

## Two more reviews (Codex adapter, failure modes; 2026-09-26 night)

`docs/reviews/2026-09-26-codex-adapter.md` and `-failure-modes.md`. Closed
the same night: a keychain error text carried the value in its argument
list (no `check=True`, type-only error texts); a hook past the client's
timeout fails open on both clients (7 s watchdog answers fail-closed;
`PostToolUse` withholds the output on any failure, because Claude Code
ignores exit 2 there); the resolver could not run inside Codex's sandbox
(the value now comes through a FIFO served by a detached child, read up
front in the main shell, `exit 97` before anything runs); `kill $$` did
not reach pipelines or subshells (the up-front read does); `os.replace` on
the transcript lost later records and changed the mode (in-place masking
now); a damaged index became an empty one and would have overwritten
`SECRET_c1` (refused and kept aside now); the lock was per process life
(per mutation now, with a 6 s deadline that fails closed); two Vault objects
in one process could wait for each other (one lock per path per process);
a pending prompt older than 15 min is not sent. Open: Codex `allow` skips
its approval prompt (documented in the README); a plugin-side confirm step;
Codex on Windows: the hooks run since `commandWindows` + `hooks/run.cmd`
(checked in the Windows matrix job in the form Codex uses, `cmd.exe /C`,
block and pass with a UTF-8 payload), a Bash placeholder is still denied, no live session
yet; an echo-and-count MCP server in the real
Codex harness to measure retries after a block-as-output.

## Beliefs: every control's test proves it can fail

`beliefs/<control>.toml` names, per documented control, the tests that own it and one
mutation of the guarded code (file, anchor, replacement). `scripts/replay_can_fail.py`
runs the owning tests green, applies the mutation, runs them again and demands red, then
restores the file; it runs in the pre-push hook and in the CI job `beliefs_can_fail_replay`
on every push. `tests/test_beliefs_well_formed.py` keeps the layer honest statically: every
named test exists, every anchor occurs exactly once, every code-enforced control (C1–C10,
C12–C17) has a belief. `scripts/derived_counts.py` measures the numbers this document and the
README state (test count, scenario counts, proof count) and refuses a stale one; it runs in
the `manifests` job. Both ideas come from the ai-gateway's beliefs layer, cut to the size of
this repository: no provenance vocabulary, no shards, TOML instead of YAML so the standard
library reads it.

## Mutation probes

| date | mutation | expected | observed |
|---|---|---|---|
| 2026-09-26 | `PostToolUse` removed from `hooks/hooks.json` | read_env and bash_rehydrate go red | 5 failures: 2 leaks + 2 missing placeholders in read_env, 1 leak in bash_rehydrate. Hook restored, harness green again. |

## Unit tests

420 tests (`tests/test_core.py`, `tests/test_skill.py`, `tests/test_gates.py`, `tests/test_operations.py`, `tests/test_release_tools.py`, `tests/test_beliefs_well_formed.py`, `tests/test_platform_backend.py`;
the last one runs only with `MAISECRETS_NATIVE_BACKEND_TEST=1` or in CI, because it
touches the real store), in under three seconds. The gate tests execute the rewritten command through a
real bash and compare bytes, so a broken quoting context or a leaked value
fails them:

| control (docs/THREAT-MODEL.md) | test that goes red without it |
|---|---|
| C4 session rule | `test_reference_resolves_only_in_a_session_that_saw_it`, `test_mcp_foreign_session_is_denied…` |
| C5 up-front read | `test_value_is_delivered_once_and_a_missing_delivery_fails_the_whole_command`, `test_a_refused_key_leaves_no_value_waiting`, `test_the_run_dir_is_private_and_refused_when_it_is_not` |
| C6 quoting contexts | `test_value_arrives_byte_for_byte_in_every_quoting_context`, `test_value_arrives_inside_a_command_substitution_and_an_unquoted_heredoc`, `test_contexts_the_rewrite_cannot_place_are_refused_with_the_reason` (a value with `$(touch …)` never runs), `test_a_command_that_would_transform_the_value_is_refused` |
| C13 fail closed | `test_exactly_one_answer_leaves_the_process_when_the_watchdog_fires`, `test_fail_closed_texts_say_whether_the_tool_ran`, `test_damaged_index_stays_damaged_until_repaired`, `test_config_with_a_wrong_type_names_the_key_and_defaults_stay_untouched`, `test_config_error_in_the_policy_names_the_key_in_the_answer`, `test_post_tool_with_a_broken_payload_withholds_instead_of_failing_open` |
| C6 command words | `test_nested_shell_spellings_are_refused_and_a_value_never_runs`, `test_ordinary_commands_pass_and_the_value_arrives`, `test_backslash_quoted_heredoc_is_refused_like_a_quoted_one` |
| C5 no grant on POSIX | `test_no_grant_is_redeemable_after_a_posix_rewrite`, `test_a_second_key_that_cannot_be_served_takes_the_first_back`, `test_a_refused_command_writes_no_audit_line` |
| run log | `test_hooks_log_records_every_run_without_values` |
| C14 file tools | `test_file_tools_never_resolve_and_the_home_is_off_limits` |
| client detection | `test_client_is_read_from_the_payload_before_the_environment` |
| C3 transcript scrub | `test_transcript_scrub_keeps_every_record_valid_json` |
| C2 resolved values | `test_value_in_url_path_query_prefix_and_encodings_is_redacted`, `test_a_result_above_the_cap_is_masked_without_storing` |
| C7 limiter | `test_limiter_caps_distinct_keys_per_session_and_resolves_per_hour` |
| C8 store-read backstop | `test_agent_reads_of_the_store_are_denied` |
| C9 audit line | `test_audit_line_names_key_tool_and_context_but_no_value` |
| C10 keyed fingerprint | `test_index_carries_no_reversible_fingerprint` |
| C2 exact match | `test_shapeless_value_is_redacted_by_exact_match` |
| C16 confirm an MCP value | `test_mcp_arguments_are_resolved_in_place_keeping_the_shape`, `test_a_value_in_a_message_body_is_confirmed_with_a_warning_or_refused_on_codex` |
| C17 skill output | `test_a_value_only_in_the_history_is_found_and_never_printed`, `test_the_redacted_copy_holds_no_value_and_the_original_is_kept`, `test_the_standalone_zip_has_one_skill_root_and_runs_without_the_plugin` |

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

