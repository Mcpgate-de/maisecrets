# Repo standards and requirements

What this repository must satisfy, and why. Items marked **now** are in place
as of 2026-09-26. Items marked **before public** gate the first public
release. Items marked **before directory** gate the submission to the Claude
and OpenAI plugin directories.

## Layout and hygiene (now)

- `maisecrets/` core, `hooks/` entry points, `harness/` live hook harness,
  `tests/` unit tests, `docs/` concept and decisions, `scripts/` tooling.
- Everything a hook runs lives inside the plugin folder. No symlink, no
  submodule, no binary, no package install at runtime (Claude directory
  checklist).
- `.gitignore` excludes caches and harness output. Nothing under
  `~/.maisecrets/` is ever committed.
- `LICENSE` Apache-2.0, `README.md` describes what the plugin runs, writes,
  sends and fetches (the directory reviewer reads it), `CHANGELOG.md`.

## Git hooks (now)

- `.githooks/pre-commit`: staged diff through our own detector, manifests
  parse, unit tests. Installed by `scripts/install-hooks.sh`, which pins
  `core.hooksPath` for this repo because the global `~/.git-hooks` would
  otherwise bypass it.
- `.githooks/pre-push`: refuses tag pushes, runs unit tests, runs the hook
  harness when `claude` is on PATH. `MAISECRETS_SKIP_HARNESS=1` skips only the
  harness. Nothing skips the tests.

## CI on gitlab.com (now)

- `.gitlab-ci.yml`: workflow rules for MR pipelines, `main`, tags, schedules.
  Stages validate (manifests, `claude plugin validate --strict`, commit
  subject format, no secrets in tree, ruff), test (unittest, the Claude Code
  harness and the Codex harness against their fake upstreams, with an empty
  HOME and a dummy key, versions pinned), mirror, release. Runner capability
  tag `docker` on the netcup host.
- Release gate: the `release` job waits until the GitHub Actions matrix
  (Windows, macOS, Linux) is green for the tested SHA on the public mirror
  (`scripts/wait_for_github_checks.py`, public API, no token). Windows was
  red across four releases on 2026-09-26 because nothing waited for it.

## Versions and releases (now)

- Claude Code fetches a plugin update only when the `version` string in
  `.claude-plugin/plugin.json` changes (manifest reference, "version"). The
  bump is therefore the release, and it is never typed by hand.
- Commit subjects follow `type(scope): text`, types `feat fix perf security
  deps docs ci test chore build style refactor`, `!` or `BREAKING CHANGE` for
  a breaking change. CI job `commit_format` refuses anything else; the
  `.githooks/commit-msg` hook catches it before the commit.
- **The subject is the changelog line.** `feat fix perf security deps` are
  rendered into `CHANGELOG.md` under the next version, so write them for the
  user: what changed for them. `docs ci test chore build style refactor` are
  not rendered: a repository move, a CI change or a wording fix is not a
  release note. What operators need to know goes into this file, not into
  the changelog.
- `scripts/release.py` derives the next version from the commits since the
  last `v*` tag: breaking → major, `feat` → minor, `fix perf security deps`
  → patch, the rest → no release. While the major is 0 the scale shifts one
  step down (breaking → 0.x+1.0, everything else → 0.x.y+1), so a 0.x
  release is small and the middle number stays a compatibility signal. It writes
  the version into the three manifests and a generated section into
  `CHANGELOG.md`.
- The `release` job runs on every push to `main` after the tests, commits
  `chore(release): vX.Y.Z` with `ci.skip`, and pushes the tag `vX.Y.Z`. The tag
  pipeline validates again and mirrors. Nobody pushes a tag by hand: the
  pre-push hook refuses it.
- Difference to the ai-gateway: no changelog fragments and no build counter.
  A plugin version is read by users and by the updater, so it is real semver,
  derived from the commit types instead of claimed in a fragment.
- Credentials: `MAISECRETS_CI_PUSH_TOKEN` (project access token
  `maisecrets-ci-release`, `write_repository`, expires 2027-09-25) and
  `MAISECRETS_GITHUB_DEPLOY_KEY` (file variable, deploy key with write access
  on the GitHub repo only). Both protected, so only protected refs see them:
  `main` and the tags `v*` (protected tags, create level Maintainer). The
  first tag pipeline ran before the tags were protected and got an empty
  key variable; the mirror job now fails loudly on an empty key.

- claude.ai organisation marketplace: synced from the private GitLab project
  through a read-only project token (`claude-ai-org-sync`, Reporter,
  `read_api` + `read_repository`). "Sync automatically" wants a Standard
  Webhooks signature that gitlab.com does not send (403 on every delivery),
  so the tag pipeline's `notify_marketplace` job sends the signed push event
  itself (`scripts/notify_marketplace.py`, variables
  `MAISECRETS_CLAUDE_MARKETPLACE_URL` and `MAISECRETS_CLAUDE_WEBHOOK_SECRET`).

## Remotes (now)

- Primary: `gitlab.com/Sprinterli/maisecrets`, private; it is also the source
  the claude.ai organisation marketplace syncs from. Mirror:
  `github.com/Mcpgate-de/maisecrets`, public, the marketplace for everyone,
  written only by the CI `mirror` job (`origin/main` and tags, deploy key,
  host keys pinned in `.ci-known-hosts-github`). Nobody pushes to GitHub by
  hand. A second private GitHub mirror for the organisation sync existed for
  two hours on 2026-09-26 and was removed once the GitLab source worked.
- GitLab stays under the personal namespace on purpose: a project inside a
  gitlab.com group on the Free tier cannot mint project access tokens, and
  a transfer drops the existing ones (measured 2026-09-26: the release token
  and the org-sync token were gone after the move and had to be recreated).
  The brand lives on GitHub (`Mcpgate-de`) and on the homepage, not in the
  GitLab path.

## Licensing (before public)

- Apache-2.0 for the plugin. Gateway-side implementation lives in the
  ai-gateway under its own licence; this repo owns the protocol spec.
- Detection rules: gitleaks (MIT), Presidio (MIT) and detect-secrets
  (Apache-2.0) are vendored as data under `maisecrets/rules/`, each with its
  licence file, version file and sync script. The six own rules in
  `detect.py` are plain regular expressions; `NOTICE` records every origin.

## Security and privacy (before public)

- `SECURITY.md` with a contact and a disclosure window.
- Threat model in `docs/`: what the vault protects against (values in cloud
  transcripts, plaintext on disk) and what it does not (another process of
  the same user, a compromised machine).
- Privacy statement for the directories: the plugin collects nothing and
  sends nothing. If an opt-in install counter is added, it needs its own
  paragraph and a URL.

## Directory submission (before directory)

- Claude: public GitHub repo, `.claude-plugin/plugin.json`, README ≥ 40 words,
  LICENSE, validation in the developer portal, security scan reads the source.
- OpenAI: verified identity, published privacy policy; for MCP plugins also
  website, support and terms URLs plus 5 positive and 3 negative test cases.
- Domain: `maisecrets.dev` is registered (2026-09-26) and is the
  `homepage` in the manifests; it points at the product page under
  mcpgate.de. `maisecrets.io` is not registered. The OpenAI route needs a
  website with privacy and support pages behind that domain.

## Testing discipline (now)

- Unit tests: `python3 -m unittest discover -s tests`.
- Harness: `python3 harness/run.py`, fake upstream, every request body scanned.
- Every new guard gets a mutation probe: remove it, the harness or a test must
  go red. Probe results are recorded in `docs/TESTING.md` with the count.
