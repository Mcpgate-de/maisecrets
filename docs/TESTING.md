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
