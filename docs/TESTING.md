# Testing

What runs, where, and what makes it fail. The history of each finding is in the commit messages.

## Suites

| suite | command | where it runs |
|---|---|---|
| unit tests | `python3 -m unittest discover -s tests` | pre-push hook, GitLab `unit` (Linux, 3.12 and 3.9), GitHub on Windows and macOS |
| beliefs | `python3 scripts/replay_can_fail.py` (one worker per CPU, each in a copy of the tree; `--jobs 1` for serial) | pre-push hook, GitLab `beliefs_can_fail_replay` |
| stated numbers | `python3 scripts/derived_counts.py` | pre-push hook, GitLab `manifests` |
| repository scan | `python3 scripts/scan_tree.py` | GitLab `no_secrets_in_tree` |
| Claude Code harness | `python3 harness/run.py` | pre-push hook (needs `claude`), GitLab `harness_claude` |
| Codex harness | `python3 harness/codex.py` | GitLab `harness_codex` |
| native store and clipboard | `MAISECRETS_NATIVE_BACKEND_TEST=1`, `MAISECRETS_NATIVE_CLIPBOARD_TEST=1` | GitHub runners only: they use the real keychain and clipboard |
| Codex with a real model | `python3 harness/codex.py --real` | by hand: `mcp_text_field_rehydrate`, `allow_keeps_the_codex_sandbox`, `apply_patch_rehydrate` and `apply_patch_store_refused` need a real model (an MCP call, a sandbox and a patch the fake upstream cannot script) |
| ssh through the sandbox | `MAISECRETS_E2E_HOST=<ssh alias> MAISECRETS_E2E_IP=<address> python3 harness/sandbox/ssh_e2e.py` | by hand before a release that touches the ssh route, on macOS and on Linux: the real Claude Code sandbox against a real host, under `rehydration: automatic` (cases 0a to 0f) and `confirm` |
| Windows end to end | `GITLAB_COM_TOKEN=… python3 scripts/windows_e2e.py [--rev REV]` | by hand before a release that touches the hooks, the launchers or the harness: GitLab-hosted Windows runners of a separate project, in three shapes (PowerShell 7, Windows PowerShell 5.1, Git Bash). Each job runs `harness/windows/shell_probe.py` (which shell runs a hook, and the `hooks.json` command in each shell) and `harness/run.py` with the shell tool the client offers (`MAISECRETS_HARNESS_SHELL_TOOL`) |

715 tests (`tests/test_*.py`), about 35 seconds on an M-series laptop. The GitHub matrix runs on
the tested commit of a release (branch `ci`) and on a push to main without a release.

## What makes a test count

- **A belief per control.** `beliefs/*.toml` names, per control of `docs/THREAT-MODEL.md`,
  the tests that own it and one mutation of the guarded code. The replay runs the tests green,
  applies the mutation, demands red, and restores the file. A skipped test is no evidence.
- **An invariant over every path.** A mechanism belief proves one guard; an invariant belief
  (`beliefs/inv-*.toml`, `kind = "invariant"`) proves one goal over every path to it. It names
  several tests and a mutation per path (`[[proof]]`, each with a `path`). The replay runs the
  tests green once, then each mutation, and demands that every mutation turns at least one test
  red and that every test is red under at least one mutation; a test that no mutation reaches is
  named as ballast. The four invariants:

  | invariant | module | the population it covers |
  |---|---|---|
  | I1 a stored value never reaches output the model or the person reads | `test_invariant_model_output.py` | every hook event, both clients, six tool-response shapes, the encodings of an own oracle for a resolved value and for another session's value as its own token, every refusal, the fail-closed answers, the prompt that goes on, the session-start message; every output field is classified |
  | I2 a rewrite never grants more than the call (Claude Code; Codex is the named exception) | `test_invariant_rewrite_grants_no_more.py` | 20 Bash command shapes (quotes, heredoc, assignments, loops, subshells, ssh with sudo), MCP inputs nested and as JSON text, Write and Edit; an own checker that knows the delivery forms as text; a call without a placeholder gets no grant |
  | I3 no agent tool reads vault material | `test_invariant_store_reads.py` | every tool that reads a path, from `tests/client_tools.json` (the harness checks that list against the real client's tool list on every run; checked against the matcher), twelve spellings of a store path, searches over a parent, MCP paths and file URIs, Bash with the default and the configured home; and the other side, a path next to the store passes |
  | I4 every detected value can be scrubbed from a transcript | `test_invariant_transcript_scrub.py` | every value the detector returns on the matrix, the token corpus and one PII value per type, in ten record shapes and two JSON writers, across the read window, and through the hooks |

  Each oracle is the test's own: it builds the encodings and escapes without the product's
  helpers, so a form the product forgets stays red.
- **No unexpected skip.** `scripts/no_unexpected_skips.py` fails the CI job on any skip except
  the two native tests.
- **The rehydration matrix.** `tests/test_rehydration_matrix.py` holds one hand-written table:
  path (Bash, ssh, MCP, an MCP published-text field, file tools) × client (Claude Code, Codex) ×
  policy (`automatic`, `confirm`, `block`) → defer, allow, ask or deny, and a second table for the
  Windows capabilities. Each cell drives the real `pre_tool` with a stored value and checks the
  decision, where the value went (a real bash for Bash on POSIX; on Windows the decision only), that
  no reason names it, and that a refusal left nothing behind that a test can see: no audit line, no
  approval token, no value waiting in the run directory (the sealed first-use directory cannot be
  listed; the approval store names its token). An ssh rewrite is not run here: its bytes are proven
  in the real sandbox by `harness/sandbox/ssh_e2e.py`. The precheck and the record are not one
  transaction: a hook of a parallel call can take the last slot of a cap in between, and then the
  refused call has written the audit line of its first key. No value leaves and no cap is passed. It also checks the default, a setting that is no policy, the
  shapes refused under every policy, a good key next to a refused one, and, by the syntax tree of
  `hooks.py`, every call site that returns a rewrite and every function that builds one. The code's own table (`rehydration.outcome`) is never read by the test. Five C16 beliefs
  mutate the policy and its call sites. The harness proves the same on the real clients: `mcp_rehydrate`,
  `mcp_rehydrate_confirm`, `bash_ssh_automatic`, `bash_ssh_asks` (Claude Code) and
  `bash_rehydrate_confirm`, `mcp_text_field_rehydrate`, `allow_keeps_the_codex_sandbox`,
  `apply_patch_rehydrate`, `apply_patch_store_refused` (Codex).
- **The guard.** `tests/test_guard.py` runs the guard and the maisecrets hook as two processes of
  one event: with maisecrets every event passes, without it every event is stopped. It also holds
  the name both sides compute, the account check, and the synced install that places the script.
  The harness proves it with the real client: `plugin_folder_moved_guarded` (the folder goes away
  mid-session and the command does not run) and `bash_rehydrate_guarded` (a healthy session passes).
- **Payloads from the real client.** A client-specific row of a matrix uses a payload captured from
  that client (`tests/client_payloads/`, recorded with `harness/codex.py` and the `dump` option,
  ids replaced). The Codex file row first used Claude Code's `Write`; Codex sends `apply_patch`, and
  every cell was green while real Codex edits resolved nothing.
- **Generated inputs with known answers.** `tests/detection_matrix.py` builds 2,500 cases from
  labels (the denylist and `maisecrets/rules/labels/*.txt`), separators, value shapes and
  context; the gate compares the full result per case. The matrix takes the label files of the
  active languages (English and German under the pinned test locale). `tests/test_label_languages.py`
  runs each other label file the same way with its language on, and checks prose with each word.
- **Real bytes.** The gate tests run the rewritten command through a real bash and compare the
  bytes that arrive.

## Isolation

Every test module imports `tests/_isolate.py` first. It gives the process a temp vault home and
a temp dir, pins `MAISECRETS_LOCALE=de_DE`, and removes the variables of the client that
started the run (`CODEX_*`, `CLAUDE_CODE_*`, `CLAUDE_PLUGIN_OPTION_*`, `CLAUDECODE`). Tripwires
for `pbcopy`, `open`, `security` and `powershell` come first on `PATH`. Windows finds
`clip.exe` and `powershell.exe` in System32 before `PATH`, so a sitecustomize installs
`tests/_platform_fakes.py` in every Python child on every platform. `tests/_hygiene.py` checks
that no test left the process state changed or a value-serving child alive.

## Coverage

```
COVERAGE_PROCESS_START=<rc> COVERAGE_RCFILE=<rc> python3 -m coverage run -m unittest discover -s tests
```

The rc needs `parallel = True` and absolute `source` paths: the skill scripts run with a temp
repository as their working directory. 2026-09-27: 95 % of the lines in `maisecrets/`,
`hooks/` and the skill scripts.
