# maisecrets: notes for an agent working in this repository

maisecrets is a Claude Code and Codex plugin. Its hooks keep secrets and personal data out of the
model: they block a prompt that carries one, replace values with placeholders such as
`⟦SECRET_c1⟧`, put the real value into a tool call only where the user allows it, and redact tool
output. `README.md` says what it does for users; `docs/` holds the design.

## Read first

- `docs/THREAT-MODEL.md`: the controls C1 to C18, what each one blocks and where it ends.
- `docs/REPO-STANDARDS.md`: layout, git hooks, CI, versions and releases, remotes, directory rules.
- `docs/TESTING.md`: the test layers and how to run them.
- `docs/PROTOCOL.md` and `docs/CLIENTS.md`: the hook payloads of each client.

## Rules

- **Never touch the real store.** Tests and probes use a temp home: `MAISECRETS_HOME` set to a new
  directory with `config.json` `{"backend": "jsonfile", "allow_plaintext_store": true}`
  (`tests/_isolate.py` does this). Never read `~/.maisecrets`, a keychain or a Credential Locker.
- **Never read session transcripts** to find test data. Use synthetic values.
- **No personal names, private hosts or real email addresses** in the repository. It is public.
- **Versions:** a release moves only the last number (`scripts/release.py`). A minor or major bump
  needs the maintainer's approval (`MAISECRETS_RELEASE_BUMP`).
- **Commit subjects** follow `type(scope): text`; `feat fix perf security deps` become the
  changelog line, so write them for the user.
- **Commit often, push rarely.** Each push runs the GitLab pipeline and two GitHub runners. Collect
  commits and push them together.

## Where the code lives

- GitLab (`gitlab.com/Sprinterli/maisecrets`) is the primary repository and runs the CI. A merge
  to `main` there releases: the release job tags it, and the mirror job pushes `main`, the tag and a
  `release` branch (runtime files only, `scripts/build_release_tree.py`) to GitHub.
- GitHub (`Mcpgate-de/maisecrets`) is the public mirror, the install marketplace and the issue
  tracker. Never merge on GitHub: the next mirror push would fail as not a fast-forward. Take a
  GitHub pull request into GitLab (`git fetch <github> pull/<n>/head:pr-<n>`, merge request there);
  a commit with `Fixes Mcpgate-de/maisecrets#<n>` closes the issue when the mirror pushes it.

## Checks before a push

```bash
python3 -m unittest discover -s tests          # also with /usr/bin/python3 (3.9, the oldest supported)
python3 scripts/replay_can_fail.py             # each belief's test must go red under its mutation
python3 scripts/scan_tree.py                   # no secret shape in the tree, test literals included
python3 scripts/derived_counts.py              # the numbers stated in the docs
python3 scripts/lint_plugin.py                 # frontmatter YAML, manifests, hook paths, command names
ruff check --select E,F,W --line-length 120 maisecrets hooks harness tests scripts skills
python3 harness/run.py                         # the real claude client against a fake upstream
```

The git hooks (`scripts/install-hooks.sh`) run these on commit and push. CI runs as root in
`python:3.12-slim` and `python:3.9-slim`: a test that depends on file permissions must allow for
root.

## Known traps

- A unit test cannot show what the real Claude Code sandbox allows. The ssh route and the session
  approval were measured end to end in the sandbox against a real host; a design that passed every
  unit test failed there (the sandbox denies writes outside the working directory).
- `claude plugin validate --strict` does not parse the frontmatter strictly; the directory check
  does. `scripts/lint_plugin.py` covers that gap.
- A plugin update removes the plugin folder of an open session (synced plugins) and its hooks then
  fail open until `/reload-plugins`. Nothing in the plugin can prevent it (README, "Updates and
  open sessions").
