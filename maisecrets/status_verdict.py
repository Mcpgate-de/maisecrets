"""The verdict on top of /maisecrets:status: at most six lines, each `ok`, `warn`, `FAIL` (or `n/a`), and each `warn`
or `FAIL` names the next command. Every `ok` claims only what was checked: "the prompt hook ran 3 min ago", never
"the protection works".

The version line reads the marketplace copy the client fetched itself (Claude Code: `plugins/known_marketplaces.json`
and its `installLocation`; Codex: `.tmp/marketplaces/<name>`, measured on codex-cli 0.169.0). It makes no network
request, so it knows a newer version only after the client fetched the marketplace; else it says "newest unknown".
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .home import ConfigError

HOOK_NAMES = (("user-prompt", "the prompt hook"), ("pre-tool", "the tool-call hook"),
              ("post-tool", "the tool-result hook"))
RECENT = 120         # the tool-call hook of this very command ran within this many seconds


def ago(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return f"{s} s ago"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 2 * 86400:
        return f"{s // 3600} h ago"
    return f"{s // 86400} days ago"


def _json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _version_tuple(v) -> tuple | None:
    try:
        parts = tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return None
    return parts if len(parts) == 3 else None


# --- the hooks of this session ------------------------------------------------------------------------------------

def last_runs(log: Path, session: str | None) -> dict:
    """{event: the time of its last row in hooks.log}, of this session's rows when a session is known. hooks.log keeps
    the first 40 characters of the session id; a row of an older version (8 characters) does not count, because Codex
    thread ids share their first characters for about a minute."""
    out: dict = {}
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            rows = f.read().splitlines()
    except OSError:
        return out
    tag = session[:40] if session else None
    for row in rows:
        cols = row.split("\t")
        if len(cols) < 4 or (tag and cols[3] != tag):
            continue
        try:
            at = time.mktime(time.strptime(cols[0], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, OverflowError):
            continue
        out[cols[1]] = max(at, out.get(cols[1], 0))
    return out


def this_session(log: Path, sessions: list) -> str | None:
    """Of the session ids the command got (one client can run inside the other and pass its variable on), the one
    whose tool-call hook ran last: the hook of this very command ran a moment ago."""
    if len(sessions) < 2:
        return sessions[0] if sessions else None
    return max(sessions, key=lambda s: last_runs(log, s).get("pre-tool", 0))


def hooks_verdict(log: Path, session, now: float | None = None) -> tuple[str, str]:
    """`ok` only when, in this session, the tool-call hook ran in the last 2 minutes (this command is a tool call) and
    the prompt hook ran at all (every session starts with a prompt)."""
    now = time.time() if now is None else now
    if isinstance(session, list):
        session = this_session(log, session)
    runs = last_runs(log, session)
    seen = ", ".join(f"{name} {ago(now - runs[ev])}" if ev in runs else f"{name} not yet"
                     for ev, name in HOOK_NAMES)
    if not session:
        if not runs:
            return "warn", ("hooks: this command runs outside a client session, and hooks.log has no hook run. "
                            "Next: run /maisecrets:status inside Claude Code or Codex")
        return "warn", (f"hooks: this command runs outside a client session, so it cannot check one. Last runs in any "
                        f"session: {seen}. Next: run /maisecrets:status inside Claude Code or Codex")
    if not runs:
        return "FAIL", ("hooks: no maisecrets hook ran in this session. Next: in Claude Code run /reload-plugins or "
                        "start a new session; in Codex trust the maisecrets hooks in /hooks")
    if "user-prompt" not in runs:
        return "FAIL", (f"hooks: the prompt hook did not run in this session ({seen}). Next: in Claude Code run "
                        "/reload-plugins or start a new session; in Codex trust the maisecrets hooks in /hooks")
    if now - runs.get("pre-tool", 0) > RECENT:
        return "warn", (f"hooks: the tool-call hook did not run in the last {RECENT // 60} minutes, although this "
                        f"command is a tool call. In this session: {seen}. Next: start a new session (Claude Code: "
                        "/reload-plugins first)")
    return "ok", f"hooks: in this session {seen}"


# --- the version --------------------------------------------------------------------------------------------------

def installed_version(root: Path) -> str:
    for manifest in (root / ".claude-plugin" / "plugin.json", root / ".codex-plugin" / "plugin.json"):
        data = _json(manifest)
        if isinstance(data, dict) and data.get("version"):
            return str(data["version"])
    return "?"


def _plugin_dir(checkout: Path) -> Path | None:
    """The maisecrets folder inside a marketplace checkout, from its manifest (a source path in the checkout)."""
    for manifest in (checkout / ".agents" / "plugins" / "marketplace.json",
                     checkout / ".claude-plugin" / "marketplace.json"):
        data = _json(manifest)
        if not isinstance(data, dict):
            continue
        for entry in data.get("plugins") or []:
            if not isinstance(entry, dict) or entry.get("name") != "maisecrets":
                continue
            src = entry.get("source")
            if isinstance(src, dict) and src.get("source") == "local":
                src = src.get("path")
            if not isinstance(src, str):
                return None             # another repository or ref: its version is not in this checkout
            target = (checkout / src).resolve()
            try:
                target.relative_to(checkout.resolve())
            except ValueError:
                return None
            return target
    return None


def _checkout_version(checkout: Path) -> str | None:
    folder = _plugin_dir(checkout)
    if folder is None:
        return None
    for manifest in (folder / ".codex-plugin" / "plugin.json", folder / ".claude-plugin" / "plugin.json"):
        data = _json(manifest)
        if isinstance(data, dict) and _version_tuple(data.get("version")):
            return str(data["version"])
    return None


def _install_kind(root: Path, claude_dir: Path, codex_home: Path) -> tuple[str, str | None]:
    """("claude" | "codex" | "synced" | "other", the marketplace name) of the folder maisecrets runs from."""
    for kind, base in (("claude", claude_dir / "plugins" / "cache"), ("codex", codex_home / "plugins" / "cache")):
        try:
            parts = root.resolve().relative_to(base.resolve()).parts
        except (OSError, ValueError):
            continue
        return kind, (parts[0] if parts else None)
    if f"{os.sep}plugins{os.sep}synced{os.sep}" in str(root.resolve()):
        return "synced", None
    return "other", None


def newest(root: Path, claude_dir: Path, codex_home: Path) -> dict:
    """What the marketplace copies on this computer say. Keys: installed, kind, market, newest (or None), fetched
    (a time or None), where (which client fetched it)."""
    kind, market = _install_kind(root, claude_dir, codex_home)
    info = {"installed": installed_version(root), "kind": kind, "market": market, "newest": None, "fetched": None,
            "where": None}
    found: list = []
    if kind == "claude":
        known = _json(claude_dir / "plugins" / "known_marketplaces.json")
        known = known if isinstance(known, dict) else {}
        for name, entry in known.items():
            if market and name != market or not isinstance(entry, dict):
                continue
            loc = entry.get("installLocation")
            loc = Path(loc) if isinstance(loc, str) else claude_dir / "plugins" / "marketplaces" / name
            v = _checkout_version(loc)
            if v:
                fetched = entry.get("lastUpdated")
                found.append((v, name, fetched if isinstance(fetched, str) else None, "Claude Code"))
    elif kind == "codex":
        base = codex_home / ".tmp" / "marketplaces"
        names = [market] if market else []
        for name in names:
            loc = base / name
            v = _checkout_version(loc)
            if v:
                try:
                    fetched = time.strftime("%Y-%m-%d %H:%M", time.localtime(loc.stat().st_mtime))
                except OSError:
                    fetched = None
                found.append((v, name, fetched, "Codex"))
    best = max(found, key=lambda f: _version_tuple(f[0]) or (0,), default=None)
    if best:
        info.update(newest=best[0], market=best[1], fetched=best[2], where=best[3])
    return info


def update_command(info: dict) -> str:
    market = info.get("market") or "maisecrets"
    if info["kind"] == "codex":
        return f"codex plugin add maisecrets@{market}, then trust the maisecrets hooks again in /hooks"
    return f"claude plugin update maisecrets@{market}, then start a new session"


def version_verdict(info: dict) -> tuple[str, str]:
    inst, new = info["installed"], info["newest"]
    if info["kind"] == "synced":
        return "warn", (f"version: {inst} (synced by your organisation); newest unknown, the organisation's sync "
                        "decides. Next: ask your admin, or start a new session to get a synced update")
    if not new:
        why = ("no marketplace copy found on this computer" if info["kind"] in ("claude", "codex")
               else "maisecrets runs from a folder no marketplace installed")
        nxt = ("codex plugin marketplace upgrade" if info["kind"] == "codex"
               else f"claude plugin marketplace update {info.get('market') or 'maisecrets'}" if info["kind"] == "claude"
               else "update that folder yourself (a checkout: git pull)")
        return "warn", f"version: {inst}; newest unknown ({why}). Next: {nxt}, then /maisecrets:status"
    fetched = f", fetched {info['fetched'][:16].replace('T', ' ')}" if info.get("fetched") else ""
    a, b = _version_tuple(inst), _version_tuple(new)
    if not a:
        return "warn", (f"version: the installed version {inst!r} cannot be compared with {new} in the marketplace "
                        f"copy of {info['where']}{fetched}. Next: {update_command(info)}")
    if not b or b > a:
        return "warn", (f"version: {inst} is installed; {new} is in the marketplace copy of {info['where']}{fetched}. "
                        f"Next: {update_command(info)}")
    return "ok", (f"version: {inst}, the newest in the marketplace copy of {info['where']}{fetched} (that copy is "
                  "only as new as its last fetch)")


def newer_version_note(root: Path, claude_dir: Path, codex_home: Path) -> str | None:
    """One sentence for the session start when a marketplace copy holds a newer version; None otherwise."""
    try:
        info = newest(root, claude_dir, codex_home)
        a, b = _version_tuple(info["installed"]), _version_tuple(info["newest"] or "")
    except Exception:  # noqa: BLE001 - the session start must not fail on it
        return None
    if not (a and b and b > a):
        return None
    return f"maisecrets {info['newest']} is available (this is {info['installed']}): {update_command(info)}."


# --- Codex, the store, the incidents ------------------------------------------------------------------------------

def codex_verdict(root: Path, codex_home: Path) -> tuple[str, str]:
    from . import codex_trust
    roots = [root] if codex_trust._plugin_id(root, codex_home) else sorted(
        (p.parent.parent for p in (codex_home / "plugins" / "cache").glob("*/maisecrets/*/hooks/hooks.json")),
        key=lambda p: p.stat().st_mtime)[-1:]
    if not roots:
        return "n/a", "codex: Codex did not install maisecrets on this computer"
    lines = codex_trust.status_lines(roots[0], codex_home)
    text = "; ".join(lines) or "codex hooks: unknown"
    if any("WARNING" in ln for ln in lines):
        return "FAIL", (text.replace("WARNING: ", "") + ". Next: open /hooks in Codex and trust the maisecrets "
                        "entries")
    if any("unknown" in ln or "another maisecrets" in ln for ln in lines):
        return "warn", text + ". Next: open /hooks in Codex and check the maisecrets entries"
    return "ok", text + f" (version folder {roots[0].name})"


def store_verdict() -> tuple[str, str]:
    try:
        from .vault import Vault
        v = Vault()
        live = sum(1 for e in v.list() if not e.purged)
        v.backend.get("maisecrets-status-probe")          # a read of a key that does not exist: the store answers
    except ConfigError:
        raise                         # the command prints the configuration error alone (cli.main)
    except Exception as exc:  # noqa: BLE001 - the verdict names the failure; the details below say more
        return "FAIL", (f"store: it did not answer a read ({type(exc).__name__}). Every prompt with a value is "
                        "blocked until it does. Next: /maisecrets:report incident, and the store line under Details")
    name = {"KeychainBackend": "the macOS login keychain", "WindowsVaultBackend": "the Windows Credential Locker",
            "EncryptedFileBackend": "the encrypted file", "JsonFileBackend": "the PLAINTEXT test file"}.get(
        type(v.backend).__name__, type(v.backend).__name__)
    if v.backend.test_mode:
        return "warn", (f"store: {name} answered a read ({live} value(s) stored), but it is test mode. Next: write "
                        '{"backend": "encrypted-file"} to config.json (see Details)')
    return "ok", f"store: {name} answered a read ({live} value(s) stored)"


def incidents_verdict() -> tuple[str, str]:
    from . import incidents
    groups, damaged = incidents.load()
    if damaged:
        return "warn", "incidents: the record is damaged. Next: /maisecrets:report incident"
    closed = sum(int(g.get("count", 0)) for g in groups.values() if g.get("class") == "fail-closed")
    other = sum(int(g.get("count", 0)) for g in groups.values() if g.get("class") != "fail-closed")
    markers = len(incidents.unfolded_markers())
    if not closed and not other and not markers:
        return "ok", f"incidents: none recorded in the last {incidents.WINDOW_DAYS} days"
    parts = []
    if closed:
        parts.append(f"{closed} times maisecrets refused a call it could not check (safe, but it stopped work)")
    if other:
        parts.append(f"{other} times a side step failed (a cleanup or a record)")
    if markers:
        parts.append(f"{markers} not yet counted")
    return "warn", (f"incidents in the last {incidents.WINDOW_DAYS} days: {'; '.join(parts)}. These are faults of "
                    "maisecrets itself; act when they repeat or stop your work. Next: /maisecrets:report incident")


# --- all of it ----------------------------------------------------------------------------------------------------

def _guarded(fn, *args) -> tuple[str, str]:
    try:
        return fn(*args)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - one line that fails must not hide the others
        return "warn", f"{getattr(fn, '__name__', 'check')}: could not be checked ({type(exc).__name__})"


def lines(root: Path, claude_dir: Path | None = None, codex_home: Path | None = None) -> list[str]:
    from . import selftest
    from .home import HOME
    if claude_dir is None:
        claude_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    if codex_home is None:
        from .codex_vault import codex_home as _codex_home
        codex_home = _codex_home()
    sessions = selftest.sessions_of_this_command()
    checks = [_guarded(hooks_verdict, HOME / "hooks.log", sessions),
              _guarded(lambda: version_verdict(newest(root, claude_dir, codex_home))),
              _guarded(codex_verdict, root, codex_home),
              _guarded(store_verdict),
              _guarded(incidents_verdict),
              _guarded(lambda: selftest.verdict(None, sessions, installed_version(root)))]
    return [f"  {state:<5} {text}" for state, text in checks]
