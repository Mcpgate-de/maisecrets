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
A label is cleaned (one printable line, a secret shape hidden, a service field only as a name), and the record of a
secret keeps its MAX_PER_SECRET most recent destinations.

The one hint (maisecrets/settings.py HINTS) comes at the first pattern break: a secret with ESTABLISHED_USES uses on
one day at one network destination goes to a network destination it never went to. 3 uses on one day was measured
as the threshold (scripts/measure_binding.py over 90 days of one user's transcripts: 1/1 gave 56 breaks, 2/1 18,
3/1 8, 3/2 1, 5/2 0); a stricter one would almost never fire, a looser one counts the setup of a new token.
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from .vault import HOME, LockTimeout, _Lock, atomic_write

ESTABLISHED_USES = 3
STORE = "destinations.json"
class _ShortLock(_Lock):
    """The vault lock waits up to 6 s, which is right for the store and wrong here: a busy record must cost a call
    at most this long, and then the record is skipped (codex review of 0.6.7: two keys waited 12 s)."""
    LOCK_DEADLINE = 0.3


_LOCK = _ShortLock(HOME / ".destinations.lock")
_URL = re.compile(r"https?://[^\s'\"<>`|;)]+")
_MAX_SESSIONS = 50


def _path() -> Path:
    return HOME / STORE


class Corrupt(ValueError):
    pass


_FIELDS = {"kind": str, "label": str, "uses": int, "first": (int, float), "last": (int, float), "day": str,
           "day_uses": int, "max_day_uses": int}
MAX_PER_SECRET = 50       # a call the model writes chooses a label; the record of one secret stays bounded


def _well_formed(d) -> bool:
    return isinstance(d, dict) and all(isinstance(d.get(k), t) and not isinstance(d.get(k), bool)
                                       and not (isinstance(d.get(k), float) and not math.isfinite(d[k]))
                                       for k, t in _FIELDS.items())


def _clean(data: dict) -> dict:
    """Keep only well-formed records: a file another program changed must not crash the list (codex review)."""
    secrets = data.get("secrets") if isinstance(data.get("secrets"), dict) else {}
    kept = {}
    for key, rec in secrets.items():
        if not (isinstance(key, str) and isinstance(rec, dict) and isinstance(rec.get("seen", {}), dict)):
            continue
        seen = {i: d for i, d in rec.get("seen", {}).items() if isinstance(i, str) and _well_formed(d)}
        if len(seen) > MAX_PER_SECRET:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1]["last"])[-MAX_PER_SECRET:])
        kept[key] = {"seen": seen, "allowed": rec.get("allowed") if isinstance(rec.get("allowed"), dict) else {}}
    data["secrets"] = kept
    return data


def _load(strict: bool = False) -> dict:
    """The store, cleaned. With strict, a file that exists and does not parse raises Corrupt: a writer must not
    replace what it cannot read (it moves it aside first, see _load_for_write)."""
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError, RecursionError):
        if strict:
            raise Corrupt(STORE)
        data = {}
    if not isinstance(data, dict):
        if strict:
            raise Corrupt(STORE)
        data = {}
    data = _clean(data)
    for k in ("secrets", "pending_hint", "interactive"):
        if not isinstance(data.get(k), dict if k != "interactive" else list):
            data[k] = {} if k != "interactive" else []
    return data


def _save(data: dict) -> None:
    atomic_write(_path(), json.dumps(data, indent=1, sort_keys=True) + "\n")


def _load_for_write() -> dict:
    """Under the lock: the store to change. A corrupt file is moved aside (destinations.json.corrupt) and a new one
    begins, so nothing the person had is overwritten unseen; /maisecrets:status lists the file."""
    try:
        return _load(strict=True)
    except Corrupt:
        aside = _path().with_name(STORE + ".corrupt")
        n = 0
        while aside.exists():
            n += 1
            aside = _path().with_name(f"{STORE}.corrupt.{int(time.time())}.{n}")
        os.replace(_path(), aside)   # an OSError ends this note: a file not moved aside is never written over
        return _load()


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


_UNPRINTABLE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def clean_label(text: str) -> str:
    """One printable line of at most 80 characters: a label comes from a call the model wrote (a service field, a
    path), and a newline or a terminal escape in it must not draw lines into /maisecrets:list (codex review)."""
    text = _UNPRINTABLE.sub("?", str(text))
    text = re.sub(r"\s+", " ", text).strip()
    from . import detect
    for m in sorted(detect.scan(text), key=lambda m: -m.start):
        if m.type == "SECRET":
            text = text[:m.start] + "<hidden>" + text[m.end:]
    return text[:77] + "..." if len(text) > 80 else text


def destinations_of(tool: str, tool_input: dict, ssh_hosts: list[str] | None = None) -> list[tuple[str, str]]:
    """(kind, label) per destination of one call: kind "network" or "local". The label is what the person reads."""
    if tool in ("Bash", "PowerShell"):
        command = str(tool_input.get("command") or "")
        if tool == "Bash":
            from .hooks import _shell_contexts           # a URL in a # comment goes nowhere (codex review of 0.6.7)
            ctxs = _shell_contexts(command)
            command = "".join(ch if cx != "comment" else " " for ch, cx in zip(command, ctxs))
        found = [("network", h) for h in hosts_in(command)]
        found += [("network", "ssh " + h) for h in sorted(set(ssh_hosts or []))]
        return [(k, clean_label(v)) for k, v in found] or [("local", "a command on this computer")]
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        server, name = parts[1] if len(parts) > 1 else "?", parts[2] if len(parts) > 2 else "?"
        service = tool_input.get("service") or tool_input.get("provider")
        # a name, not free text: the model writes this field, and a value in it must not land in the record (Opus)
        if not (isinstance(service, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", service)):
            service = ""
        label = f"MCP {server} · {name}" + (f" · {service}" if service else "")
        return [("network", clean_label(label))]
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"):
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        folder = os.path.dirname(path) or "."
        home = str(Path.home())
        if folder.startswith(home):
            folder = "~" + folder[len(home):]
        return [("local", clean_label(f"a file in {folder}/"))]
    return [("local", clean_label(f"a {tool} call"))]


def note(keys: list[str], session: str | None, agent: str | None, destinations: list[tuple[str, str]]) -> bool:
    """Record one use per key and destination, all keys of a call under one short lock. True when the call is a
    pattern break (the caller gives the hint only once, globally). Never raises: a record that cannot be written
    must not stop the call."""
    try:
        with _LOCK:
            data = _load_for_write()
            pattern_break = False
            for key in dict.fromkeys(keys):
                pattern_break = _note_one(data, key, destinations) or pattern_break
            if pattern_break and session and not agent and session in data["interactive"]:
                data["pending_hint"][session] = time.time()
            data["pending_hint"] = {s: t for s, t in data["pending_hint"].items() if s in data["interactive"]}
            _save(data)
            return pattern_break
    except (OSError, LockTimeout, ValueError, TypeError, KeyError):
        return False


def _note_one(data: dict, key: str, destinations: list[tuple[str, str]]) -> bool:
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
            if len(seen) >= MAX_PER_SECRET:
                del seen[min(seen, key=lambda i: seen[i]["last"])]     # the oldest goes
            d = seen[ident] = {"kind": kind, "label": label, "uses": 0, "first": now, "last": now,
                               "day": today, "day_uses": 0, "max_day_uses": 0}
        if d.get("day") != today:
            d["day"], d["day_uses"] = today, 0
        d["uses"] += 1
        d["day_uses"] += 1
        d["max_day_uses"] = max(d.get("max_day_uses", 0), d["day_uses"])
        d["last"] = now
    return pattern_break


def mark_interactive(session: str) -> None:
    """The person typed a prompt in this session: a hint here has a reader (a headless run has none)."""
    try:
        with _LOCK:
            data = _load_for_write()
            if session in data["interactive"]:
                return
            data["interactive"] = (data["interactive"] + [session])[-_MAX_SESSIONS:]
            _save(data)
    except (OSError, LockTimeout, ValueError, RecursionError):
        pass


def take_pending(session: str | None) -> bool:
    """A pattern break of this session waits for its hint; take it (once)."""
    if not session:
        return False
    try:
        with _LOCK:
            data = _load_for_write()
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


NEW_SECONDS = 24 * 3600   # `new` in the list: first seen in the last day. Not "since the list was opened": the
                          # model runs the list too (commands/list.md), and a list it ran would clear the marks (Opus)


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


def forget(keys: list[str]) -> bool:
    """Drop the records of these keys. False when the record could not be written: the caller says so."""
    try:
        with _LOCK:
            data = _load_for_write()
            for k in keys:
                data["secrets"].pop(k, None)
            _save(data)
            return True
    except (OSError, LockTimeout, ValueError):
        return False


def wipe() -> bool:
    """Delete the whole record under its lock (a writer that holds it would write it back after an unlink)."""
    try:
        with _LOCK:
            for p in [_path(), *HOME.glob(STORE + ".corrupt*")]:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
            return True
    except (OSError, LockTimeout):
        return False
