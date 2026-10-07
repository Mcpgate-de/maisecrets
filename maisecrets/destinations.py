"""Where each stored secret was sent (setting `secret_destinations`: observe by default, or off).
Mcpgate-de/maisecrets#13.

Observe only: this module never decides whether a call runs. It notes, on this computer only, each destination a
stored secret went to, and shows it in /maisecrets:list. A seen destination is a record, never a permission: `seen`
and `allowed` are kept apart in the store, and `allowed` is not used by any decision yet (a later protect mode).

Destinations:
- network: a host from a URL in a Bash command, an ssh host (as maisecrets/ssh_consent.py reads it), an MCP server
  and tool. The tool, not the server, because one gateway server carries many services, one tool each; an `action`
  is the operation inside a service, not a destination (scripts/measure_binding.py, 2026-10-07: with `action` in the
  key 16 of 56 secrets would have several destinations, with server and tool 5). A tool that serves several services
  names its service in a `service` or `provider` field, which then joins the key.
- local: a file (Write, Edit) or a Bash command without a host. Listed, never a destination, never a hint.

The one hint (maisecrets/settings.py HINTS) comes at the first pattern break: a secret with ESTABLISHED_USES uses on
one day at one network destination goes to a network destination it never went to. 3 uses on one day was measured
as the threshold (scripts/measure_binding.py over 90 days of one user's transcripts: 1/1 gave 56 breaks, 2/1 18,
3/1 8, 3/2 1, 5/2 0); a stricter one would almost never fire, a looser one counts the setup of a new token.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from .vault import HOME, LockTimeout, _lock_for, atomic_write

ESTABLISHED_USES = 3
STORE = "destinations.json"
_LOCK = HOME / ".destinations.lock"
_URL = re.compile(r"https?://[^\s'\"<>`|;)]+")
_MAX_SESSIONS = 50


def _path() -> Path:
    return HOME / STORE


def _load() -> dict:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    for k in ("secrets", "pending_hint", "interactive"):
        if not isinstance(data.get(k), dict if k != "interactive" else list):
            data[k] = {} if k != "interactive" else []
    return data


def _save(data: dict) -> None:
    atomic_write(_path(), json.dumps(data, indent=1, sort_keys=True) + "\n")


def hosts_in(command: str) -> list[str]:
    hosts = set()
    for url in _URL.findall(command or ""):
        try:
            host = urlparse(url).hostname
        except ValueError:
            continue
        if host:
            hosts.add(host.lower())
    return sorted(hosts)


def destinations_of(tool: str, tool_input: dict, ssh_hosts: list[str] | None = None) -> list[tuple[str, str]]:
    """(kind, label) per destination of one call: kind "network" or "local". The label is what the person reads."""
    if tool in ("Bash", "PowerShell"):
        command = str(tool_input.get("command") or "")
        found = [("network", h) for h in hosts_in(command)]
        found += [("network", "ssh " + h) for h in sorted(set(ssh_hosts or []))]
        return found or [("local", "a command on this computer")]
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        server, name = parts[1] if len(parts) > 1 else "?", parts[2] if len(parts) > 2 else "?"
        service = tool_input.get("service") or tool_input.get("provider")
        label = f"MCP {server} · {name}" + (f" · {service}" if isinstance(service, str) and service else "")
        return [("network", label)]
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"):
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        folder = os.path.dirname(path) or "."
        home = str(Path.home())
        if folder.startswith(home):
            folder = "~" + folder[len(home):]
        return [("local", f"a file in {folder}/")]
    return [("local", f"a {tool} call")]


def note(key: str, session: str | None, agent: str | None, destinations: list[tuple[str, str]]) -> bool:
    """Record one use per destination. True when this use is the first pattern break the hint is for (the caller
    gives the hint only once, globally). Never raises: a record that cannot be written must not stop the call."""
    try:
        with _lock_for(_LOCK):
            data = _load()
            rec = data["secrets"].setdefault(key, {"seen": {}, "allowed": {}})
            seen = rec.setdefault("seen", {})
            rec.setdefault("allowed", {})          # kept apart from seen; no decision reads it yet
            now = time.time()
            today = time.strftime("%Y-%m-%d")
            established = any(d.get("kind") == "network" and d.get("max_day_uses", 0) >= ESTABLISHED_USES
                              for d in seen.values())
            pattern_break = False
            for kind, label in destinations:
                ident = f"{kind}:{label}"
                d = seen.get(ident)
                if d is None:
                    if kind == "network" and established:
                        pattern_break = True
                    d = seen[ident] = {"kind": kind, "label": label, "uses": 0, "first": now, "last": now,
                                       "day": today, "day_uses": 0, "max_day_uses": 0}
                if d.get("day") != today:
                    d["day"], d["day_uses"] = today, 0
                d["uses"] += 1
                d["day_uses"] += 1
                d["max_day_uses"] = max(d.get("max_day_uses", 0), d["day_uses"])
                d["last"] = now
            if pattern_break and session and not agent and session in data["interactive"]:
                data["pending_hint"][session] = now
            _save(data)
            return pattern_break
    except (OSError, LockTimeout, ValueError, TypeError):
        return False


def mark_interactive(session: str) -> None:
    """The person typed a prompt in this session: a hint here has a reader (a headless run has none)."""
    try:
        with _lock_for(_LOCK):
            data = _load()
            if session in data["interactive"]:
                return
            data["interactive"] = (data["interactive"] + [session])[-_MAX_SESSIONS:]
            _save(data)
    except (OSError, LockTimeout, ValueError):
        pass


def take_pending(session: str | None) -> bool:
    """A pattern break of this session waits for its hint; take it (once)."""
    if not session:
        return False
    try:
        with _lock_for(_LOCK):
            data = _load()
            if data["pending_hint"].pop(session, None) is None:
                return False
            _save(data)
            return True
    except (OSError, LockTimeout, ValueError):
        return False


def of(key: str) -> dict:
    return _load()["secrets"].get(key, {"seen": {}, "allowed": {}})


def summary() -> tuple[int, int, int]:
    """(secrets with a network destination, network destinations, secrets with more than one)."""
    secrets = _load()["secrets"]
    counts = [sum(1 for d in r.get("seen", {}).values() if d.get("kind") == "network") for r in secrets.values()]
    counts = [c for c in counts if c]
    return len(counts), sum(counts), sum(1 for c in counts if c > 1)


def list_opened() -> float:
    """When /maisecrets:list was last shown, and note now: a destination first seen after it is marked `new`."""
    try:
        with _lock_for(_LOCK):
            data = _load()
            before = float(data.get("list_shown", 0) or 0)
            data["list_shown"] = time.time()
            _save(data)
            return before
    except (OSError, LockTimeout, ValueError):
        return 0.0


def uses_text(n: int) -> str:
    return "1×" if n <= 1 else "2–9×" if n < 10 else "10+×"


def when_text(ts: float, now: float | None = None) -> str:
    age = max(0.0, (now or time.time()) - ts)
    if age < 3600:
        return "less than an hour ago"
    if age < 86400:
        return f"{int(age // 3600)} hours ago" if age >= 7200 else "1 hour ago"
    days = int(age // 86400)
    return "1 day ago" if days == 1 else f"{days} days ago"


def forget(keys: list[str]) -> None:
    try:
        with _lock_for(_LOCK):
            data = _load()
            for k in keys:
                data["secrets"].pop(k, None)
            _save(data)
    except (OSError, LockTimeout, ValueError):
        pass
