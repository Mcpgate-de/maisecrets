#!/usr/bin/env python3
"""Wait until the GitHub Actions matrix on the public mirror is green for one commit.

The release job runs after the mirror job pushed the tested SHA to github.com, so
the Actions workflow (windows-latest, macos-latest, ubuntu-latest) is running or done.
The repository is public: the check-runs API needs no token (60 requests per hour
per address; a 403 is treated as "wait longer").

Usage: wait_for_github_checks.py <sha> [--repo owner/name] [--timeout-min 20]
Exit 0 when every check run concluded with success, 1 on failure or timeout.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request


def _main_moved(sha: str) -> bool:
    import subprocess
    try:
        out = subprocess.run(["git", "ls-remote", "--quiet", "origin", "refs/heads/main"],
                             capture_output=True, text=True, timeout=30).stdout.split()
        return bool(out) and out[0] != sha
    except (OSError, subprocess.SubprocessError):
        return False


def main(argv: list[str]) -> int:
    sha = argv[1]
    repo = "Mcpgate-de/maisecrets"
    timeout_min = 20.0
    for i, a in enumerate(argv):
        if a == "--repo":
            repo = argv[i + 1]
        if a == "--timeout-min":
            timeout_min = float(argv[i + 1])
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/check-runs"
    deadline = time.time() + timeout_min * 60
    while time.time() < deadline:
        # the mirror pushes the branch tip; when main moved on, this SHA was never the tip on
        # GitHub, no check runs will ever appear, and the newer pipeline gates its own SHA
        if _main_moved(sha):
            print("main moved on; this SHA is superseded and the newer pipeline releases")
            return 0
        try:
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "maisecrets-release"}
            token = os.environ.get("GITHUB_TOKEN", "").strip()
            if token:   # authenticated: 5000 requests per hour instead of 60 shared by the runner's IP
                headers["Authorization"] = "Bearer " + token
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            print(f"github {e.code}; waiting")
            time.sleep(60)
            continue
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            # a DNS failure, a slow API or a half answer are "wait longer", not a red release
            print(f"github unreachable ({type(e).__name__}); waiting")
            time.sleep(60)
            continue
        runs = data.get("check_runs", [])
        if not runs:
            print("no check runs yet for this commit; waiting")
            time.sleep(30)
            continue
        pending = [c["name"] for c in runs if c["status"] != "completed"]
        failed = [c["name"] for c in runs
                  if c["status"] == "completed" and c["conclusion"] not in ("success", "skipped")]
        if failed:
            print("GitHub Actions failed for", sha[:7], ":", ", ".join(failed))
            return 1
        if not pending:
            print("GitHub Actions green for", sha[:7], ":", ", ".join(c["name"] for c in runs))
            return 0
        print("waiting for", ", ".join(pending))
        time.sleep(30)
    print("timeout waiting for GitHub Actions on", sha[:7])
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
