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
| ssh through the sandbox | `MAISECRETS_E2E_HOST=<ssh alias> MAISECRETS_E2E_IP=<address> python3 harness/sandbox/ssh_e2e.py` | by hand before a release that touches the ssh route, on macOS and on Linux: the real Claude Code sandbox against a real host |

572 tests (`tests/test_*.py`), about 35 seconds on an M-series laptop. The GitHub matrix runs on
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
  named as ballast. The three invariants:

  | invariant | module | the population it covers |
  |---|---|---|
  | I1 a stored value never reaches output the model or the person reads | `test_invariant_model_output.py` | every hook event, both clients, six tool-response shapes, the encodings of an own oracle for a resolved value and for another session's value as its own token, every refusal, the fail-closed answers, the prompt that goes on, the session-start message; every output field is classified |
  | I3 no agent tool reads vault material | `test_invariant_store_reads.py` | every tool that reads a path (checked against the matcher), twelve spellings of a store path, searches over a parent, MCP paths and file URIs, Bash with the default and the configured home; and the other side, a path next to the store passes |
  | I4 every detected value can be scrubbed from a transcript | `test_invariant_transcript_scrub.py` | every value the detector returns on the matrix, the token corpus and one PII value per type, in ten record shapes and two JSON writers, across the read window, and through the hooks |

  Each oracle is the test's own: it builds the encodings and escapes without the product's
  helpers, so a form the product forgets stays red. I2, the invariant for a Codex rewrite, waits for
  the Codex design (C5).
- **No unexpected skip.** `scripts/no_unexpected_skips.py` fails the CI job on any skip except
  the two native tests.
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
