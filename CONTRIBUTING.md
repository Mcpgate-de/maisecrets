# Contributing

The quickest useful contribution is a token prefix that went through
undetected. Add one line to `maisecrets/rules/prefixes.txt`:

```
<service>-<token-kind>    <prefix>[A-Za-z0-9_-]{<minimum length>,}
```

and one line to `tests/test_core.py` next to the existing prefix test, with a
synthetic value of the right shape. Never a real value, not even a revoked
one: the pre-commit hook scans the diff and refuses it.

Everything else follows the same three rules: a commit subject
`type(scope): text` (the subject is the changelog line), a test that fails
without the change, and no value anywhere in the tree. `docs/REPO-STANDARDS.md`
has the details; `docs/THREAT-MODEL.md` says what the plugin defends.

Wrong detections and feature requests: `/maisecrets:report` in Claude Code
prepares the issue, or open one on the repository's issues page.

The GitHub repository is a read-only mirror of the primary repository. Open
a pull request there; a maintainer applies it upstream, and the mirror brings
it back with your authorship. Run `scripts/install-hooks.sh` once, so the
pre-commit hook scans your diff and checks your commit subject.
