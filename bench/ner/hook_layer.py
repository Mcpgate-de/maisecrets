"""Experimental, never imported by maisecrets: the PERSON layer inside the real hook path (docs/NER-EXPERIMENT.md,
"The hook path"). `install()` wraps the detector's `scan` (maisecrets.detect is the same module object), so every hook
that redacts a tool result runs the deterministic scan first and then asks the local service of bench/ner/sidecar.py
within a time budget. What the wrapper promises, and bench/ner/hook_experiment.py proves:

- the deterministic findings come first and are returned as they are; a PERSON span is added only where none lies;
- a slow service (over the budget), a dead one, a refused connection or an answer it cannot read: the deterministic
  findings alone, as without the layer;
- installed but switched off: the hooks answer byte for byte as without it.

Only the tool channel (a tool result, a file): a typed prompt keeps today's path."""
from __future__ import annotations

import json
import socket
import time

from maisecrets.detection import core

STATE = {"active": False, "socket": "", "budget_s": 0.3, "calls": 0, "asked": 0, "added": 0, "timeouts": 0,
         "errors": 0, "ner_s": []}
_ORIGINAL = core.scan


def _ask(text: str, occupied: list) -> list:
    deadline = time.monotonic() + STATE["budget_s"]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(STATE["budget_s"])
        s.connect(STATE["socket"])
        s.sendall((json.dumps({"text": text, "occupied": occupied}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError
            s.settimeout(left)
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError
            buf += chunk
        return json.loads(buf)["add"]
    finally:
        s.close()


def layered_scan(text, enabled=None, channel="prompt", path="", rule_list=None):
    found = _ORIGINAL(text, enabled, channel, path, rule_list)          # deterministic first, always
    if not STATE["active"] or channel != "tool" or rule_list is not None or enabled is not None or not text:
        return found
    STATE["calls"] += 1
    occupied = [[m.start, m.end, m.type] for m in found]
    t = time.monotonic()
    try:
        STATE["asked"] += 1
        add = _ask(text, occupied)
    except (TimeoutError, socket.timeout):
        STATE["timeouts"] += 1
        return found
    except Exception:                  # a dead service, a refused socket, an answer it cannot read: no word of it
        STATE["errors"] += 1
        return found
    finally:
        STATE["ner_s"].append(time.monotonic() - t)
    extra = []
    try:
        for s, e, _score in add:
            s, e = int(s), int(e)
            if 0 <= s < e <= len(text) and not any(s < m.end and m.start < e for m in found) and \
                    not any(s < x.end and x.start < e for x in extra):
                extra.append(core.Match("ner-person", "NAME", text[s:e], s, e))
    except Exception:
        STATE["errors"] += 1
        return found
    STATE["added"] += len(extra)
    return sorted(found + extra, key=lambda m: m.start) if extra else found


def install(socket_path: str, budget_ms: int = 300, active: bool = True) -> None:
    STATE.update(active=active, socket=socket_path, budget_s=budget_ms / 1000, calls=0, asked=0, added=0, timeouts=0,
                 errors=0, ner_s=[])
    core.scan = layered_scan


def uninstall() -> None:
    core.scan = _ORIGINAL
