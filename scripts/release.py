#!/usr/bin/env python3
"""Release tooling: the version is derived from the commit subjects, never typed.

Why the number matters: Claude Code fetches a plugin update only when the
``version`` string in ``.claude-plugin/plugin.json`` changes
(code.claude.com/docs/en/plugins/manifest-reference, "version"). A release
that forgets the bump ships nothing. So the bump is computed here from the
commits since the last release tag and written into every manifest by CI.

Commit subject format (checked by ``check`` in CI):

    type(scope)!: subject          type: feat fix perf security deps docs
                                         ci test chore build style refactor

Bump rules, applied to all commits since the last ``v*`` tag:

    breaking (``!`` or "BREAKING CHANGE")   major   (minor while the major is 0)
    feat                                    minor
    fix, perf, security, deps               patch
    docs, ci, test, chore, build, style,
    refactor                                none
    a subject without a known type          patch   (listed under "Other")

``chore(release): …`` commits are ignored. No releasable commit: exit 3.

Subcommands:
    next      print the next version, or exit 3 when there is nothing to release
    notes     print the changelog section for the next version
    apply     write the version into the manifests and the section into CHANGELOG.md
    check     manifests agree on one version; commit subjects since <base> are well-formed
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "plugin.json")
CHANGELOG = ROOT / "CHANGELOG.md"

TYPES_MINOR = {"feat"}
TYPES_PATCH = {"fix", "perf", "security", "deps"}
TYPES_NONE = {"docs", "ci", "test", "chore", "build", "style", "refactor"}
KNOWN = TYPES_MINOR | TYPES_PATCH | TYPES_NONE
SUBJECT_RE = re.compile(r"^(?P<type>[a-z]+)(\((?P<scope>[^)]+)\))?(?P<bang>!)?: (?P<text>\S.*)$")
SECTION = {"feat": "Features", "fix": "Fixes", "perf": "Fixes", "security": "Security", "deps": "Dependencies"}


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def last_tag() -> str | None:
    tags = [t for t in _git("tag", "--list", "v*", "--sort=-v:refname").split() if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    return tags[0] if tags else None


def manifest_version(path: str = MANIFESTS[0]) -> str:
    data = json.loads((ROOT / path).read_text())
    if path.endswith("marketplace.json"):
        return data["plugins"][0]["version"]
    return data["version"]


def commits_since(ref: str | None) -> list[tuple[str, str, str]]:
    """(sha, subject, body) for every commit after ``ref`` (all commits when None)."""
    rng = f"{ref}..HEAD" if ref else "HEAD"
    raw = _git("log", "--format=%H%x00%s%x00%b%x1e", rng)
    out = []
    for rec in raw.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, subject, body = (rec.split("\x00") + ["", ""])[:3]
        out.append((sha, subject, body))
    return out


def classify(subject: str, body: str) -> tuple[str, str, bool]:
    """(type or "other", text, breaking)."""
    m = SUBJECT_RE.match(subject)
    breaking = "BREAKING CHANGE" in body
    if not m or m.group("type") not in KNOWN:
        return "other", subject, breaking
    return m.group("type"), m.group("text"), breaking or bool(m.group("bang"))


def bump_for(commits: list[tuple[str, str, str]]) -> str | None:
    level = None
    order = {"patch": 1, "minor": 2, "major": 3}
    for _sha, subject, body in commits:
        if subject.startswith("chore(release):"):
            continue
        typ, _text, breaking = classify(subject, body)
        if breaking:
            cand = "major"
        elif typ in TYPES_MINOR:
            cand = "minor"
        elif typ in TYPES_PATCH or typ == "other":
            cand = "patch"
        else:
            continue
        if level is None or order[cand] > order[level]:
            level = cand
    return level


def next_version(current: str, level: str) -> str:
    major, minor, patch = (int(p) for p in current.split("."))
    if level == "major" and major == 0:
        level = "minor"  # 0.x: a breaking change is a minor bump, as semver allows
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def plan() -> tuple[str, str, list[tuple[str, str, str]]] | None:
    tag = last_tag()
    current = tag[1:] if tag else manifest_version()
    commits = commits_since(tag)
    level = bump_for(commits)
    if level is None:
        return None
    return current, next_version(current, level), commits


def render_notes(version: str, commits: list[tuple[str, str, str]]) -> str:
    groups: dict[str, list[str]] = {}
    for sha, subject, body in commits:
        if subject.startswith("chore(release):"):
            continue
        typ, text, breaking = classify(subject, body)
        if typ in TYPES_NONE:
            continue
        section = "Breaking" if breaking else SECTION.get(typ, "Other")
        groups.setdefault(section, []).append(f"- {text} ({sha[:7]})")
    lines = [f"## [{version}] - {_dt.date.today().isoformat()}", ""]
    for section in ("Breaking", "Features", "Fixes", "Security", "Dependencies", "Other"):
        if section in groups:
            lines += [f"### {section}", ""] + groups[section] + [""]
    return "\n".join(lines).rstrip("\n") + "\n"


def apply(version: str, notes: str) -> None:
    for rel in MANIFESTS:
        path = ROOT / rel
        text = path.read_text()
        new, n = re.subn(r'("version":\s*")\d+\.\d+\.\d+(")', rf"\g<1>{version}\g<2>", text, count=1)
        if n != 1:
            raise SystemExit(f"{rel}: no version field to update")
        path.write_text(new)
    changelog = CHANGELOG.read_text() if CHANGELOG.exists() else "# Changelog\n"
    # hand-written bullets under "## Unreleased" are kept and become the first block of the release
    m = re.search(r"^## Unreleased\n(?P<body>.*?)(?=^## |\Z)", changelog, re.S | re.M)
    unreleased = m.group("body").strip("\n") if m else ""
    if unreleased:
        head, _blank, rest = notes.split("\n", 2)
        notes = head + "\n\n" + unreleased + "\n\n" + rest
    section = notes
    if m:
        changelog = changelog[: m.start()] + "## Unreleased\n\n" + section + "\n" + changelog[m.end():]
    else:
        changelog = changelog.rstrip("\n") + "\n\n## Unreleased\n\n" + section
    CHANGELOG.write_text(changelog)


def check(base: str | None) -> int:
    rc = 0
    versions = {rel: manifest_version(rel) for rel in MANIFESTS}
    if len(set(versions.values())) != 1:
        print(f"version mismatch: {versions}")
        rc = 1
    else:
        print(f"manifests agree: {manifest_version()}")
    if base:
        bad = []
        for sha, subject, _body in commits_since(base):
            if subject.startswith("chore(release):") or subject.startswith("Merge "):
                continue
            m = SUBJECT_RE.match(subject)
            if not m or m.group("type") not in KNOWN:
                bad.append(f"  {sha[:7]} {subject}")
        if bad:
            print("commit subjects that do not follow type(scope): subject with a known type:")
            print("\n".join(bad))
            print("known types:", " ".join(sorted(KNOWN)))
            rc = 1
        else:
            print(f"commit subjects since {base}: well-formed")
    return rc


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "next"
    if cmd == "check":
        return check(argv[2] if len(argv) > 2 else None)
    p = plan()
    if p is None:
        print("nothing to release: no feat/fix/perf/security/deps/untyped commit since the last tag", file=sys.stderr)
        return 3
    current, version, commits = p
    if cmd == "next":
        print(version)
    elif cmd == "notes":
        sys.stdout.write(render_notes(version, commits))
    elif cmd == "apply":
        apply(version, render_notes(version, commits))
        print(f"{current} -> {version}: manifests and CHANGELOG.md updated")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
