#!/usr/bin/env python3
"""Tell the claude.ai organisation marketplace that main moved, so it re-syncs.

claude.ai's "Sync automatically" for a GitLab marketplace expects a webhook signed in the
Standard Webhooks format (headers webhook-id, webhook-timestamp, webhook-signature). gitlab.com
sends webhook-id and webhook-timestamp but no signature (measured 2026-09-26: every delivery
answered 403 "Missing webhook signature headers"), so the GitLab-side webhook never works.
This script sends the same push event, signed, from the release pipeline instead. The endpoint
answered {"status": "published", "published": true} to it.

Environment:
  MAISECRETS_CLAUDE_MARKETPLACE_URL     the endpoint claude.ai shows under "Configure webhook"
  MAISECRETS_CLAUDE_WEBHOOK_SECRET      its secret (whsec_…), a masked CI variable
  CI_COMMIT_SHA, CI_PROJECT_PATH, CI_PROJECT_URL, CI_DEFAULT_BRANCH (GitLab CI)

Without the two MAISECRETS_* variables the script exits 0 and says so: a fork has no
organisation marketplace to notify.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid


def main() -> int:
    url = os.environ.get("MAISECRETS_CLAUDE_MARKETPLACE_URL", "").strip()
    secret = os.environ.get("MAISECRETS_CLAUDE_WEBHOOK_SECRET", "").strip()
    if not url or not secret:
        print("notify_marketplace: no marketplace URL/secret configured, nothing to notify")
        return 0
    if secret.startswith("whsec_"):
        secret = secret[len("whsec_"):]
    key = base64.b64decode(secret)
    sha = os.environ.get("CI_COMMIT_SHA", "")
    path = os.environ.get("CI_PROJECT_PATH", "Sprinterli/maisecrets")
    web = os.environ.get("CI_PROJECT_URL", "https://gitlab.com/" + path)
    branch = os.environ.get("CI_DEFAULT_BRANCH", "main")
    body = json.dumps({
        "object_kind": "push", "event_name": "push", "ref": f"refs/heads/{branch}",
        "checkout_sha": sha, "after": sha,
        "project": {"path_with_namespace": path, "default_branch": branch, "web_url": web,
                    "git_http_url": web + ".git"},
        "repository": {"name": path.split("/")[-1], "homepage": web},
    })
    msg_id = "msg_" + uuid.uuid4().hex
    ts = str(int(time.time()))
    sig = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.{body}".encode(), hashlib.sha256).digest()).decode()
    req = urllib.request.Request(url, data=body.encode(), method="POST", headers={
        "Content-Type": "application/json", "webhook-id": msg_id, "webhook-timestamp": ts,
        "webhook-signature": "v1," + sig, "X-Gitlab-Event": "Push Hook"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(f"notify_marketplace: http {r.status} {r.read().decode()[:200]}")
            return 0
    except urllib.error.HTTPError as e:
        print(f"notify_marketplace: http {e.code} {e.read().decode()[:300]}")
        return 1
    except urllib.error.URLError as e:
        print(f"notify_marketplace: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
