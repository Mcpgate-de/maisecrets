#!/usr/bin/env python3
"""Build the tree of the `release` branch: only the files the plugin needs at run time.

The Anthropic directory checks every file it gets, and it blocked two versions on literals in the
test files (2026-09-27). The tests, the CI files, the release scripts and the developer docs are
never run by the plugin, so the `release` branch leaves them out. The allowlist below is the
whole content: a new runtime folder must be added here, and a test checks that every path the
hooks and the commands name is in the tree.

    python3 scripts/build_release_tree.py list [<ref>]       the paths, one per line
    python3 scripts/build_release_tree.py commit <ref> [<parent>] -m <message>
                                                              write a commit, print its id

`commit` writes the tree into a temporary index, so the working copy and the real index stay as
they are. With <parent> the new commit continues that history; without it, it starts one.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

# folders and files of the plugin at run time, and the documents a user reads
RUNTIME = (".claude-plugin/", ".codex-plugin/", "hooks/", "maisecrets/", "commands/", "skills/", "assets/",
           "LICENSE", "NOTICE", "README.md", "PRIVACY.md", "SECURITY.md", "CHANGELOG.md",
           "docs/CLIENTS.md", "docs/PROTOCOL.md", "docs/THREAT-MODEL.md", "docs/label-sources.md")


def _git(*args: str, env: dict | None = None, text: bool = True) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=text, env=env)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def paths(ref: str = "HEAD") -> list[str]:
    tracked = _git("ls-tree", "-r", "--name-only", ref).splitlines()
    keep = [p for p in tracked
            if any(p == r or (r.endswith("/") and p.startswith(r)) for r in RUNTIME) and "__pycache__" not in p]
    return sorted(keep)


def commit(ref: str, parent: str | None, message: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(d, "index"))
        _git("read-tree", "--empty", env=env)
        # NUL-separated bytes both ways: in text mode Windows writes CRLF into the pipe, and git
        # then reads paths that end in a carriage return (the release tree test on windows-latest)
        rows = subprocess.run(["git", "ls-tree", "-r", "-z", ref], capture_output=True, check=True).stdout
        wanted = {p.encode() for p in paths(ref)}
        info = b"".join(row + b"\0" for row in rows.split(b"\0") if row and row.split(b"\t", 1)[1] in wanted)
        r = subprocess.run(["git", "update-index", "-z", "--index-info"], input=info, env=env, capture_output=True)
        if r.returncode != 0:
            raise SystemExit(f"git update-index failed: {r.stderr.decode(errors='replace').strip()[:300]}")
        tree = _git("write-tree", env=env).strip()
    args = ["commit-tree", tree, "-m", message] + (["-p", parent] if parent else [])
    # the release identity when none is configured: a CI container has no git identity
    ident = dict(os.environ)
    for role in ("AUTHOR", "COMMITTER"):
        ident.setdefault(f"GIT_{role}_NAME", "maisecrets release")
        ident.setdefault(f"GIT_{role}_EMAIL", "ci@maisecrets.local")
    return _git(*args, env=ident).strip()


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "list":
        print("\n".join(paths(argv[2] if len(argv) > 2 else "HEAD")))
        return 0
    if len(argv) >= 5 and argv[1] == "commit" and "-m" in argv:
        i = argv.index("-m")
        rest = argv[2:i]
        print(commit(rest[0], rest[1] if len(rest) > 1 else None, argv[i + 1]))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
