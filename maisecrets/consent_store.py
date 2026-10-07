"""The consents of `ssh_consent` (maisecrets/ssh_consent.py): which hosts a write may reach without a question.

A consent covers a host, or the hosts of its group in `ssh_host_groups`, for one session and one agent
(the main thread or one subagent: subagents share the session id, and a subagent that read untrusted
text must not inherit the main thread's yes; plan review of #8, 2026-10-06), for APPROVAL_HOURS.

How a yes is proven, since the hook cannot see the answer to its own `ask` and a hook entry point can be
called by anyone (an agent can run `run.sh post-tool` with a payload it wrote):

- Claude Code on POSIX: the asked command first reads a FIFO in the sealed directory (mode 0300, nobody
  can list it), served by a detached child outside the sandbox. Only the command the user allowed holds
  its name; the child confirms the pending consent when the FIFO is read (the proof of ssh_approval.py).
- Codex, which cannot ask: the refusal names a sentence with a code that the hook made at that moment
  (`maisecrets: allow ssh HOST CODE`); typed alone as the next prompt, it grants. Text written before the
  refusal (a pasted document, a headless prompt built from an issue) cannot know the code.

The store keeps only hashes of tokens and codes. Limit, as for every file of the user: a program that runs
as the user outside the sandbox can write this store; the hook refuses commands that name it.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

from .vault import HOME, _lock_for, atomic_write, read_text_retry

APPROVAL_SECONDS = 8 * 3600
PENDING_SECONDS = 15 * 60
CODE_SECONDS = 10 * 60
STORE = "ssh-consent.json"


def _path():
    return HOME / STORE


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _who(session: str, agent: str | None) -> str:
    return f"{session}|{agent or ''}"


def _load() -> dict:
    try:
        data = json.loads(read_text_retry(_path()))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    for k in ("pending", "codes", "approved"):
        if not isinstance(data.get(k), dict):
            data[k] = {}
    now = time.time()
    data["pending"] = {k: v for k, v in data["pending"].items() if isinstance(v, dict) and v.get("until", 0) > now}
    data["codes"] = {k: v for k, v in data["codes"].items() if isinstance(v, dict) and v.get("until", 0) > now}
    for who, hosts in list(data["approved"].items()):
        kept = {h: u for h, u in (hosts.items() if isinstance(hosts, dict) else []) if isinstance(u, (int, float))
                and u > now}
        if kept:
            data["approved"][who] = kept
        else:
            del data["approved"][who]
    return data


def _save(data: dict) -> None:
    atomic_write(_path(), json.dumps(data, sort_keys=True))


def covered(session: str | None, agent: str | None, hosts: list[str]) -> bool:
    """Whether every host has an unexpired consent for this session and agent."""
    if not session or not hosts:
        return False
    approved = _load()["approved"].get(_who(session, agent), {})
    return all(h in approved for h in hosts)


def remember_pending(session: str, agent: str | None, hosts: list[str]) -> str:
    """A token for the ask; the raw token goes only to the serving child, the store keeps its hash."""
    token = secrets.token_hex(16)
    with _lock_for(HOME / ".ssh-consent.lock"):
        data = _load()
        data["pending"][_h(token)] = {"who": _who(session, agent), "hosts": sorted(set(hosts)),
                                      "until": time.time() + PENDING_SECONDS}
        _save(data)
    return token


def confirm(token: str) -> bool:
    """The asked command read its FIFO: the person said yes. One use per token."""
    with _lock_for(HOME / ".ssh-consent.lock"):
        data = _load()
        rec = data["pending"].pop(_h(token), None)
        if not rec:
            _save(data)
            return False
        until = time.time() + APPROVAL_SECONDS
        data["approved"].setdefault(rec["who"], {}).update({h: until for h in rec["hosts"]})
        _save(data)
    return True


def new_code(session: str, agent: str | None, hosts: list[str]) -> str:
    """A code for the Codex sentence, made when the hook refuses; six digits, ten minutes, one use."""
    code = f"{secrets.randbelow(10 ** 6):06d}"
    with _lock_for(HOME / ".ssh-consent.lock"):
        data = _load()
        data["codes"][_h(f"{session}|{code}")] = {"who": _who(session, agent), "hosts": sorted(set(hosts)),
                                                  "until": time.time() + CODE_SECONDS}
        _save(data)
    return code


def grant_by_code(session: str, host: str, code: str) -> list[str] | None:
    """The person typed the sentence with its host and code: the hosts it grants, or None."""
    with _lock_for(HOME / ".ssh-consent.lock"):
        data = _load()
        rec = data["codes"].get(_h(f"{session}|{code}"))
        if not rec or host not in rec["hosts"]:
            return None
        del data["codes"][_h(f"{session}|{code}")]
        until = time.time() + APPROVAL_SECONDS
        data["approved"].setdefault(rec["who"], {}).update({h: until for h in rec["hosts"]})
        _save(data)
    return rec["hosts"]


def drop_codes(session: str) -> None:
    """A prompt that is not the sentence ends the open codes of its session: the refusal says "the next prompt"."""
    data = _load()
    if not any(str(v.get("who", "")).startswith(session + "|") for v in data["codes"].values()):
        return
    with _lock_for(HOME / ".ssh-consent.lock"):
        data = _load()
        data["codes"] = {k: v for k, v in data["codes"].items() if not str(v.get("who", "")).startswith(session + "|")}
        _save(data)
