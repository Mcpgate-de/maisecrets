#!/usr/bin/env python3
"""Run maisecrets end to end on GitLab-hosted Windows runners, from a commit of this repository.

The e2e project (gitlab.com/Sprinterli/maisecrets-e2e) is a test sink: it holds no history of its
own. This script builds a commit of HEAD (or --rev) whose `.gitlab-ci.yml` is
`harness/windows/gitlab-ci.yml`, force-pushes it to the e2e project, waits for the pipeline and
prints each job's result lines. Each run goes to its own branch `e2e/<short sha of REV>` (the
project protects `main` against a force push). The working tree and the index stay untouched (`git commit-tree`
with a temporary index).

The push goes from a temporary bare repository that holds only this commit. The e2e project is not
a remote of this repository, and the push gate of this repository (.githooks/pre-push) guards the
pushes to `origin`; the e2e pipeline is itself the test.

Credentials: the push uses the git credential helper for the host of `origin` (the user part of the
`origin` URL is kept). The API calls read GITLAB_COM_TOKEN from the environment.

Usage: windows_e2e.py [--rev REV] [--branch NAME] [--job NAME ...] [--timeout-min 90] [--no-wait]
       windows_e2e.py --report PIPELINE_ID [JOB ...]
Exit 0 when every job succeeded, 1 otherwise.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = "Sprinterli/maisecrets-e2e"
API = "https://gitlab.com/api/v4"
CI_FILE = "harness/windows/gitlab-ci.yml"
# the lines of a job log that carry a result: harness scenarios, unittest summary, the collect step
RESULT = re.compile(r"^(\[(OK |FAIL|GAP|SKIP)\]|shell of a settings hook|     -|failures:|Ran \d+ tests|OK( \(|$)|"
                    r"FAILED|=====|node v|pwsh on PATH|pwsh on the PATH|the job runs in|pwsh 7 folder|git bash:|shell|"
                    r".*Hook (SessionStart|UserPromptSubmit|PreToolUse|PostToolUse))")


def _git(*args: str, env: dict | None = None, cwd: Path = ROOT) -> str:
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True,
                          text=True).stdout.strip()


def build_commit(rev: str) -> str:
    """A commit with the tree of `rev` plus the e2e CI file as `.gitlab-ci.yml`; no parent."""
    ci_blob = _git("rev-parse", f"{rev}:{CI_FILE}")
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        _git("read-tree", rev, env=env)
        _git("update-index", "--add", "--cacheinfo", f"100644,{ci_blob},.gitlab-ci.yml", env=env)
        tree = _git("write-tree", env=env)
    src = _git("rev-parse", "--short", rev)
    subject = _git("log", "-1", "--format=%s", rev)
    return _git("commit-tree", tree, "-m", f"e2e: {src} {subject}")


def push_url() -> str:
    """The e2e project on the host of `origin`, with the user part of `origin` and never its password:
    the git credential helper answers for that user."""
    origin = urllib.parse.urlsplit(_git("remote", "get-url", "origin"))
    if origin.scheme != "https" or not origin.hostname:
        raise SystemExit("origin is not an https URL; this script pushes over https with the credential helper")
    netloc = (f"{origin.username}@" if origin.username else "") + origin.hostname
    return urllib.parse.urlunsplit(("https", netloc, f"/{PROJECT}.git", "", ""))


def push(sha: str, branch: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        _git("init", "--quiet", "--bare", tmp)
        _git("fetch", "--quiet", str(ROOT), sha, cwd=Path(tmp))
        r = subprocess.run(["git", "push", "--quiet", "--force", push_url(), f"{sha}:refs/heads/{branch}"], cwd=tmp)
        if r.returncode:
            # not CalledProcessError: its message prints the command, and with it the URL
            raise SystemExit(f"git push to {PROJECT} failed (exit {r.returncode})")


def _api(path: str) -> object:
    token = os.environ.get("GITLAB_COM_TOKEN", "")
    if not token:
        raise SystemExit("GITLAB_COM_TOKEN is not set")
    req = urllib.request.Request(f"{API}/projects/{urllib.parse.quote(PROJECT, safe='')}{path}",
                                 headers={"PRIVATE-TOKEN": token})
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read().decode("utf-8", "replace")
    return json.loads(body) if r.headers.get_content_type() == "application/json" else body


def _get(path: str) -> object:
    for attempt in range(5):
        try:
            return _api(path)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            if attempt == 4:
                raise
            print(f"api {path}: {e}; retry", flush=True)
            time.sleep(15)
    raise AssertionError("unreachable")


def find_pipeline(sha: str, deadline: float) -> dict:
    while time.time() < deadline:
        found = _get(f"/pipelines?sha={sha}&per_page=5")
        if found:
            return found[0]
        time.sleep(10)
    raise SystemExit(f"no pipeline for {sha}")


def wait(pipeline_id: int, deadline: float) -> dict:
    last = ""
    while time.time() < deadline:
        p = _get(f"/pipelines/{pipeline_id}")
        jobs = _get(f"/pipelines/{pipeline_id}/jobs?per_page=50")
        state = " ".join(f"{j['name']}={j['status']}" for j in sorted(jobs, key=lambda j: j["name"]))
        if state != last:
            print(time.strftime("%H:%M:%S"), p["status"], state, flush=True)
            last = state
        if p["status"] in ("success", "failed", "canceled", "skipped"):
            return p
        time.sleep(30)
    raise SystemExit(f"pipeline {pipeline_id} still running at the timeout")


def report(pipeline_id: int, only: list[str]) -> bool:
    ok = True
    for j in sorted(_get(f"/pipelines/{pipeline_id}/jobs?per_page=50"), key=lambda j: j["name"]):
        if only and j["name"] not in only:
            continue
        ok = ok and j["status"] == "success"
        print(f"\n## {j['name']}: {j['status']}  ({j.get('duration') or 0:.0f} s)  {j['web_url']}")
        log = _get(f"/jobs/{j['id']}/trace")
        # a line of the job log starts with a time stamp and a stream id ("2026-09-29T12:47:34.278649Z 01O ")
        lines = [re.sub(r"^\S+Z [0-9a-f]+[OE]\+? ?", "", re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)).rstrip()
                 for s in str(log).splitlines()]
        picked = [s for s in lines if RESULT.match(s)]
        print("\n".join(picked[-80:]) if picked else "\n".join(lines[-40:]))
    return ok


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--report"]:
        return 0 if report(int(argv[2]), argv[3:]) else 1
    rev, branch, timeout_min, only, no_wait = "HEAD", "", 90.0, [], False
    it = iter(argv[1:])
    for a in it:
        if a == "--rev":
            rev = next(it)
        elif a == "--branch":
            branch = next(it)
        elif a == "--timeout-min":
            timeout_min = float(next(it))
        elif a == "--job":
            only.append(next(it))
        elif a == "--no-wait":
            no_wait = True
        else:
            raise SystemExit(__doc__)
    deadline = time.time() + timeout_min * 60
    sha = build_commit(rev)
    branch = branch or f"e2e/{_git('rev-parse', '--short', rev)}"
    push(sha, branch)
    print(f"pushed {sha[:12]} ({_git('rev-parse', '--short', rev)}) to {PROJECT} {branch}", flush=True)
    p = find_pipeline(sha, deadline)
    print(f"pipeline {p['id']} {p['web_url']}", flush=True)
    if no_wait:
        return 0
    wait(p["id"], deadline)
    return 0 if report(p["id"], only) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
