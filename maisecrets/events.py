"""Detection events for bug reports: what was found (kind, type, length), where (hook,
client), under which version. Never a value, never a display. ``maisecrets report`` turns
the last event into a prefilled GitHub issue URL."""
from __future__ import annotations

import json
import os
import platform
import sys
import time
import urllib.parse
from pathlib import Path

from .vault import HOME

EVENTS = HOME / "events.log"
KEEP = 200
ISSUES_URL = "https://github.com/Sprinterli/maisecrets/issues/new"


def plugin_version() -> str:
    try:
        manifest = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"
        return json.loads(manifest.read_text(encoding="utf-8")).get("version", "?")
    except (OSError, ValueError):
        return "?"


def record(hook: str, client: str, entries: list) -> None:
    """One line per detection event; the last KEEP lines are kept."""
    if not entries:
        return
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "hook": hook, "client": client, "version": plugin_version(),
            "hits": [{"key": e.key, "type": e.type, "kind": e.kind} for e in entries],
        })
        old: list[str] = []
        if EVENTS.exists():
            old = EVENTS.read_text(encoding="utf-8").splitlines()[-(KEEP - 1):]
        fd = os.open(EVENTS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(old + [line]) + "\n")
    except OSError:
        pass


def load(n: int = 20) -> list[dict]:
    try:
        lines = EVENTS.read_text(encoding="utf-8").splitlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def issue_url(event: dict, note: str = "") -> str:
    """A GitHub issue link with the event's facts in the body. The value is not in the event,
    so it cannot be in the link; the reporter describes the shape in words."""
    hits = ", ".join(f"{h['type']} via `{h['kind']}`" for h in event.get("hits", []))
    first = event.get("hits", [{}])[0]
    title = f"False positive: {first.get('kind', '?')} ({first.get('type', '?')})"
    body = "\n".join([
        "## What maisecrets detected",
        f"- hits: {hits}",
        f"- hook: `{event.get('hook')}` · client: `{event.get('client')}` · at {event.get('ts')}",
        f"- plugin version: {event.get('version')} · {platform.system()} {platform.release()} · "
        f"Python {sys.version_info.major}.{sys.version_info.minor}",
        "",
        "## Why it is wrong",
        note or "(describe the shape of the text, not the value itself: e.g. 'a build id of 20 hex chars "
                "after the word token')",
        "",
        "## What should happen instead",
        "",
        "_This report was prepared by `maisecrets report`. It carries no value; please keep it that way._",
    ])
    q = urllib.parse.urlencode({"title": title, "body": body, "labels": "false-positive"})
    return f"{ISSUES_URL}?{q}"


def generic_issue_url(kind: str, text: str) -> str:
    """A bug or a feature request straight from the session: title from the user's words,
    environment facts in the body, no event and no value."""
    label = "enhancement" if kind == "feature" else "bug"
    title = ("Feature: " if kind == "feature" else "Bug: ") + (text.strip()[:70] or "(describe it)")
    body = "\n".join([
        f"## {'What should maisecrets do' if kind == 'feature' else 'What happened'}",
        text.strip() or "(describe it here)",
        "",
        "## Environment",
        f"- plugin version: {plugin_version()} · {platform.system()} {platform.release()} · "
        f"Python {sys.version_info.major}.{sys.version_info.minor}",
        "",
        "_Prepared by `maisecrets report`; it carries no value._",
    ])
    q = urllib.parse.urlencode({"title": title, "body": body, "labels": label})
    return f"{ISSUES_URL}?{q}"


def open_in_browser(url: str) -> bool:
    import subprocess
    try:
        if platform.system() == "Darwin":
            subprocess.run(["open", url], check=True, timeout=5)
        elif platform.system() == "Windows":
            os.startfile(url)  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", url], check=True, timeout=5)
        return True
    except Exception:  # noqa: BLE001 - any failure just means "print the link"
        return False
