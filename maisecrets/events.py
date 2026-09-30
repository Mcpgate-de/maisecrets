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
ISSUES_URL = "https://github.com/Mcpgate-de/maisecrets/issues/new"


def plugin_version() -> str:
    try:
        manifest = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"
        return json.loads(manifest.read_text(encoding="utf-8")).get("version", "?")
    except (OSError, ValueError):
        return "?"


def record(hook: str, client: str, entries: list, outcome: str = "") -> None:
    """One line per detection event; the last KEEP lines are kept."""
    if not entries:
        return
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "hook": hook, "client": client, "version": plugin_version(),
            "hits": [{"key": e.key, "type": e.type, "kind": e.kind} for e in entries],
            **({"outcome": outcome} if outcome else {}),
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
    return link(*issue_parts(event, note))


def generic_issue_url(kind: str, text: str) -> str:
    return link(*generic_issue_parts(kind, text))


def tracker() -> str | None:
    """The configured `report_url`: a policy can point it to its own tracker, or set null to turn
    reporting off. The report ignored it and always used ISSUES_URL (found 2026-09-28)."""
    from .vault import load_config
    url = load_config().get("report_url", ISSUES_URL)
    return url.strip() or None if isinstance(url, str) else None


def tracker_or_error() -> tuple[str | None, str | None]:
    """The tracker, or the reason it cannot be known: a broken config must not stop a report of
    that same problem, but it must not send one past a policy either."""
    try:
        return tracker(), None
    except Exception as exc:  # noqa: BLE001 - ConfigError and RuntimeError both name the file
        return None, str(exc)


def github_repo(url: str | None) -> str | None:
    """owner/repo when the tracker is a GitHub repository, else None."""
    parts = urllib.parse.urlsplit(url or "")
    path = [x for x in parts.path.split("/") if x]
    if parts.scheme == "https" and parts.hostname == "github.com" and len(path) >= 2 and path[2:3] in ([], ["issues"]):
        return f"{path[0]}/{path[1]}"
    return None


def link(title: str, body: str, label: str) -> str | None:
    """A prefilled new-issue link on a GitHub tracker, the tracker itself on another one, or None
    when reporting is off."""
    url = tracker()
    repo = github_repo(url)
    if repo:
        q = urllib.parse.urlencode({"title": title, "body": body, "labels": label})
        return f"https://github.com/{repo}/issues/new?{q}"
    return url


def issue_parts(event: dict, note: str = "") -> tuple[str, str, str]:
    """Title, body and label of a false-positive issue with the event's facts. The value is not in
    the event, so it cannot be in the issue; the reporter describes the shape in words."""
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
    return title, body, "false-positive"


def generic_issue_parts(kind: str, text: str) -> tuple[str, str, str]:
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
    return title, body, label


def create_with_gh(title: str, body: str, label: str) -> str | None:
    """Create the issue with the GitHub CLI when it is installed and logged in; the URL of the new
    issue, or None. Arguments as a list and the body on stdin: no shell reads the text."""
    import shutil
    import subprocess
    gh = shutil.which("gh")
    repo = github_repo(tracker())
    if not gh or not repo:
        return None
    # the host and the repository come from report_url alone: GH_HOST or GH_REPO in the environment
    # sent the issue to another host (Codex review, 2026-09-28)
    env = {k: v for k, v in os.environ.items() if k not in ("GH_HOST", "GH_REPO")} | {"GH_HOST": "github.com"}
    base = [gh, "issue", "create", "-R", f"github.com/{repo}", "--title", title, "--body-file", "-"]
    for argv in (base + ["--label", label], base):   # the label may not exist in the repo
        try:
            r = subprocess.run(argv, input=body, capture_output=True, text=True, timeout=60, env=env)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()[-1]
    return None


def has_local_browser(env=None) -> bool:
    """A browser opens where the person sits only on a local desktop. Over ssh, `open` or
    `xdg-open` start it on the remote machine, and without a display xdg-open fell back to w3m,
    which took over the Claude Code terminal (feedback on 0.5.2, 2026-09-28)."""
    env = os.environ if env is None else env
    if any(env.get(k) for k in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")):
        return False
    if platform.system() in ("Darwin", "Windows"):
        return True
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def open_in_browser(url: str) -> bool:
    import subprocess
    if not has_local_browser():
        return False
    # no terminal for the opener: a text browser it picks cannot take over the session
    quiet = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    try:
        if platform.system() == "Darwin":
            subprocess.run(["open", url], check=True, timeout=5, **quiet)
        elif platform.system() == "Windows":
            os.startfile(url)  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", url], check=True, timeout=5, **quiet)
        return True
    except Exception:  # noqa: BLE001 - any failure just means "print the link"
        return False
