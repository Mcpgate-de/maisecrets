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
import sys
import time
import urllib.error
import urllib.request


def main(argv: list[str]) -> int:
    sha = argv[1]
    repo = "Sprinterli/maisecrets"
    timeout_min = 20.0
    for i, a in enumerate(argv):
        if a == "--repo":
            repo = argv[i + 1]
        if a == "--timeout-min":
            timeout_min = float(argv[i + 1])
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/check-runs"
    deadline = time.time() + timeout_min * 60
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                       "User-Agent": "maisecrets-release"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            print(f"github {e.code}; waiting")
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
