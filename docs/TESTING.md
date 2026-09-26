# Testing record

## Harness (fake Anthropic upstream, Claude Code 2.1.283)

Run 2026-09-26, 4 scenarios, 0 failures:

| scenario | what it proves |
|---|---|
| prompt_secret | a typed secret is blocked; 0 requests reach the upstream; the transcript on disk carries no secret |
| read_env | a Read of `.env` reaches the model with `⟦SECRET_c1⟧` and `⟦EMAIL_c1:…⟧`, never the values |
| bash_echo | `cat .env` output is redacted before the model sees it |
| bash_rehydrate | `⟦SECRET_c1⟧` in a Bash command is replaced by the real value at execution; the file the command wrote holds the value, the requests hold only the placeholder |

Golden payload shapes captured in `harness/golden/` (top-level keys, `tool_input`
keys, `tool_response` keys per event and tool). A later Claude Code version
that changes a shape fails the harness with "schema drift".

## Mutation probes

| date | mutation | expected | observed |
|---|---|---|---|
| 2026-09-26 | `PostToolUse` removed from `hooks/hooks.json` | read_env and bash_rehydrate go red | 5 failures: 2 leaks + 2 missing placeholders in read_env, 1 leak in bash_rehydrate. Hook restored, harness green again. |

## Unit tests

22 tests, `tests/test_core.py`, run in milliseconds. Not yet mutation-probed
individually.

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
