# Testing

What runs, where, and what makes it fail. The history of each finding is in the commit messages.

## Suites

| suite | command | where it runs |
|---|---|---|
| unit tests | `python3 -m unittest discover -s tests` | pre-push hook, GitLab `unit`, GitHub on Windows, macOS, Linux |
| beliefs | `python3 scripts/replay_can_fail.py` | pre-push hook, GitLab `beliefs_can_fail_replay` |
| stated numbers | `python3 scripts/derived_counts.py` | pre-push hook, GitLab `manifests` |
| repository scan | `python3 scripts/scan_tree.py` | GitLab `no_secrets_in_tree` |
| Claude Code harness | `python3 harness/run.py` | pre-push hook (needs `claude`), GitLab `harness_claude` |
| Codex harness | `python3 harness/codex.py` | GitLab `harness_codex` |
| native store and clipboard | `MAISECRETS_NATIVE_BACKEND_TEST=1`, `MAISECRETS_NATIVE_CLIPBOARD_TEST=1` | GitHub runners only: they use the real keychain and clipboard |

536 tests (`tests/test_*.py`), about 35 seconds on an M-series laptop. The GitHub matrix runs on
the tested commit of a release (branch `ci`) and on a push to main without a release.

## What makes a test count

- **A belief per control.** `beliefs/*.toml` names, per control of `docs/THREAT-MODEL.md`,
  the tests that own it and one mutation of the guarded code. The replay runs the tests green,
  applies the mutation, demands red, and restores the file. A skipped test is no evidence.
- **No unexpected skip.** `scripts/no_unexpected_skips.py` fails the CI job on any skip except
  the two native tests.
- **Generated inputs with known answers.** `tests/detection_matrix.py` builds 2,500 cases from
  labels (the denylist and `maisecrets/rules/labels/*.txt`), separators, value shapes and
  context; the gate compares the full result per case.
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
