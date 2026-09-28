"""One approval per value and session for the ssh route (opt-in: config `ssh_approval: "per-session"`).

An ops user runs about ten commands on each of fifty hosts, and a prompt for each of them is not
usable (feedback on 0.5.3, 2026-09-28). With the option on, the first ssh use of a value asks
once; after that the same value goes on stdin to ssh without a prompt for the rest of the
session, at most APPROVAL_HOURS, and only with read-only remote commands.

The hook cannot see the answer to its "ask", and in headless mode Claude Code refuses an ask
without running anything (measured with Claude Code 2.1.283, also with bypassPermissions). What
proves the answer is the value being read: the approved command reads it from a FIFO, and the
child that serves the FIFO runs outside the sandbox. The first use's FIFO sits in a directory
nobody can list (mode 0300), and only the rewritten command the user allowed holds its name; the
child confirms the approval when that FIFO is read. A blind reader of the run directory found the
FIFO and confirmed without a yes (Codex review, 2026-09-28), and a code the command writes back is
no proof: the Claude Code sandbox denies that write. The store keeps only a hash of the token, so
reading the file gives nothing to confirm with; the raw token lives in the child's memory. A token
is used once and ends after PENDING_SECONDS; a command the hook did not ask about has no token and
approves nothing.

Limit: a program that runs as the user outside the sandbox can write this store like any file of
the user. The option needs the sandbox, which denies those writes, and the hook refuses commands
that name the store or this module.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import time
from contextlib import contextmanager

from .vault import HOME, atomic_write, read_text_retry

APPROVAL_HOURS = 8
PENDING_SECONDS = 15 * 60
STORE = "ssh-approvals.json"


def _path():
    return HOME / STORE


def _load() -> dict:
    try:
        data = json.loads(read_text_retry(_path()))
    except (OSError, ValueError):
        return {"pending": {}, "approved": {}}
    if not isinstance(data, dict):
        return {"pending": {}, "approved": {}}
    data.setdefault("pending", {})
    data.setdefault("approved", {})
    return data


@contextmanager
def _locked():
    """One writer at a time: two hook runs at once lost an update or confirmed one token twice."""
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(HOME / ".ssh-approvals.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _save(data: dict) -> None:
    now = time.time()
    # expired records go on every write: the file stays small and holds nothing that still counts
    data["pending"] = {h: p for h, p in data["pending"].items() if p.get("until", 0) > now}
    data["approved"] = {s: {k: t for k, t in keys.items() if t > now}
                        for s, keys in data["approved"].items()}
    data["approved"] = {s: keys for s, keys in data["approved"].items() if keys}
    atomic_write(_path(), json.dumps(data, sort_keys=True))


def remember_pending(session: str | None, keys: list[str]) -> str | None:
    """The ask for these keys in this session; the token the serving child confirms, or None."""
    if not session or not keys:
        return None
    import secrets
    token = secrets.token_urlsafe(24)
    with _locked():
        data = _load()
        data["pending"][_h(token)] = {"session": session, "keys": sorted(set(keys)),
                                      "until": time.time() + PENDING_SECONDS}
        _save(data)
    return token


def confirm(token: str | None) -> list[str]:
    """The approved command read the value: its keys are approved for its session. The keys, or []
    when the token is unknown, used or too old."""
    if not token:
        return []
    with _locked():
        data = _load()
        pending = data["pending"].pop(_h(token), None)
        if pending is None:
            return []
        if pending.get("until", 0) <= time.time():
            _save(data)
            return []
        until = time.time() + APPROVAL_HOURS * 3600
        approved = data["approved"].setdefault(pending["session"], {})
        for k in pending.get("keys", []):
            approved[k] = until
        _save(data)
    return list(pending.get("keys", []))


def approved(session: str | None, keys: list[str]) -> bool:
    """Whether every one of these keys is approved for ssh in this session now."""
    if not session or not keys:
        return False
    now = time.time()
    got = _load()["approved"].get(session, {})
    return all(got.get(k, 0) > now for k in keys)
