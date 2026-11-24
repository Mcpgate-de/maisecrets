"""The checks on top of /maisecrets status: one line per check, each `ok`, `warn`, `FAIL` (or `n/a`), with a short
fact, and for `warn` or `FAIL` the next command. The head line says whether this session is protected. Every fact
claims only what was checked: "the prompt hook ran 3 min ago", never "the protection works". The longer facts of a
check (Check.detail) go to `/maisecrets status all`; what each check means is in docs/HOW-IT-WORKS.md, "Status".

The version line reads the marketplace copy the client fetched itself (Claude Code: `plugins/known_marketplaces.json`
and its `installLocation`; Codex: `.tmp/marketplaces/<name>`, measured on codex-cli 0.169.0). It makes no network
request, so it knows a newer version only after the client fetched the marketplace; else it says "newest unknown".
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import NamedTuple, Optional

from .home import ConfigError

HOOK_NAMES = (("user-prompt", "the prompt hook"), ("pre-tool", "the tool-call hook"),
              ("post-tool", "the tool-result hook"))
SHORT = (("user-prompt", "prompt"), ("pre-tool", "tool call"), ("post-tool", "result"))
RECENT = 120         # the tool-call hook of this very command ran within this many seconds
NAMES = ("hooks", "version", "codex", "store", "incidents", "self-test")
MARK = {"ok": "\u2713", "warn": "!", "FAIL": "\u2717", "n/a": "\u2013"}   # one column wide each
NAME_COL = 11
FACT_COL = 20        # every fact of a warn or FAIL line fits here, so all arrows stand in one column
WIDTH = 80           # no check line wider than this with realistic facts (tests/test_status_verdict.py)


class Check(NamedTuple):
    state: str                  # ok, warn, FAIL, n/a
    name: str                   # one of NAMES, or an optional note: demo, names
    fact: str                   # short: what was checked
    next: Optional[str]         # the next command, for warn and FAIL
    detail: Optional[str]       # the longer fact, for `status all`
    note: Optional[str] = None  # a line under the fact in the short status: why, when the fact alone does not say it


def reload_next(client: str | None) -> str:
    """The step when a hook did not run: a new Claude Code session (/reload-plugins keeps the old plugin folder after
    a synced update, docs/ADMIN.md "Updates and open sessions"), and in Codex the hooks trusted again."""
    return {"claude": "start a new session", "codex": "trust maisecrets in /hooks"}.get(
        client, "a new session (Codex: /hooks)")


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

def last_runs(log: Path, session: str | None, mod: bool = False) -> dict:
    """{event: the time of its last row in hooks.log}, of this session's rows when a session is known. hooks.log keeps
    the first 40 characters of the session id; a row of an older version (8 characters) does not count, because Codex
    thread ids share their first characters for about a minute. The rows of the mod (note_mod) count only with `mod`,
    and then only they: a mod row is no hook run."""
    out: dict = {}
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            rows = f.read().splitlines()
    except OSError:
        return out
    tag = session[:40] if session else None
    for row in rows:
        cols = row.split("\t")
        if len(cols) < 4 or (tag and cols[3] != tag) or (cols[1] == MOD_EVENT) != mod:
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


def _hook_facts(runs: dict, now: float) -> str:
    """The hooks that ran, in short words: "prompt 3 s ago, tool call 0 s ago"."""
    return ", ".join(f"{short} {ago(now - runs[ev])}" for ev, short in SHORT if ev in runs)


def hooks_verdict(log: Path, session, now: float | None = None, client: str | None = None) -> Check:
    """`ok` only when, in this session, the tool-call hook ran in the last 2 minutes (this command is a tool call) and
    the prompt hook ran at all (every session starts with a prompt)."""
    now = time.time() if now is None else now
    if isinstance(session, list):
        session = this_session(log, session)
    runs = last_runs(log, session)
    seen = ", ".join(f"{name} {ago(now - runs[ev])}" if ev in runs else f"{name} not yet"
                     for ev, name in HOOK_NAMES)
    if not session:
        detail = (f"this command runs outside a client session; last runs in any session: {seen}" if runs
                  else "this command runs outside a client session, and hooks.log has no hook run")
        return Check("warn", "hooks", "no client session", "run it in Claude Code or Codex", detail)
    if not runs:
        return Check("FAIL", "hooks", "no hook ran", reload_next(client),
                     "no maisecrets hook ran in this session")
    if "user-prompt" not in runs:
        return Check("FAIL", "hooks", "no prompt hook", reload_next(client),
                     f"the prompt hook did not run; in this session: {seen}")
    if now - runs.get("pre-tool", 0) > RECENT:
        return Check("warn", "hooks", "no tool-call hook", "a new session",
                     f"the tool-call hook did not run in the last {RECENT // 60} minutes, although this command is a "
                     f"tool call; in this session: {seen}")
    return Check("ok", "hooks", f"ran ({_hook_facts(runs, now)})", None, f"in this session: {seen}")


# --- the mod of Claude Code ---------------------------------------------------------------------------------------

MOD_EVENT = "mod"
MOD_NOTE = ("The mod is off: no lock or click on values and references. Type commands as text, such as "
            "maisecrets: sref login NAME.")


def note_mod(payload: dict) -> None:
    """A `mod` row in hooks.log for the session of the payload: the mod asked (hooks/dispatch.py, its prompt check and
    its ask at the session start). mod_verdict reads it. Never raises. A tool call that runs dispatch.py is refused
    (shell_commands); a row only hides a note, it grants nothing."""
    try:
        from .home import HOME
        sess = str(payload.get("session_id") or "-")[:40]
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(HOME / "hooks.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:     # hooks._run_log caps the file at its next row
            f.write(f"{stamp}\t{MOD_EVENT}\tclaude\t{sess}\t-\tpass\t0ms\tmod\n")
    except (OSError, AttributeError):
        pass


def mod_verdict(log: Path, sessions, client: str | None) -> Check | None:
    """A warn in Claude Code when this session's prompt hook ran and the mod never asked in it: then no lock and no
    click draw a value or a reference, and a slash form that needs the mod does not run. None in Codex, in Cowork
    (there the mod draws nothing in any case), outside a session, and before the first prompt of the session."""
    if client != "claude":
        return None
    from . import cowork
    if cowork.active():
        return None
    session = this_session(log, sessions) if isinstance(sessions, list) else sessions
    if not session or "user-prompt" not in last_runs(log, session) or last_runs(log, session, mod=True):
        return None
    return Check("warn", "mod", "did not run", None,
                 "the prompt hook ran in this session, but the Claude Code mod (claude-mod/maisecrets-mod.mjs) asked "
                 "nothing; mods need Claude Code 2.1.287 or later, and a switch of the client can turn them off",
                 MOD_NOTE)


def ran_since(log: Path, session, event: str, since) -> bool:
    """Whether hooks.log holds a row of `event` for this session at or after `since` (epoch seconds). A row's time is
    cut to whole seconds, so a row of the second of `since` counts. A row of the mod is no hook run (last_runs)."""
    if not isinstance(session, str) or not session:
        return False
    try:
        floor = int(float(since))
    except (TypeError, ValueError, OverflowError):
        floor = 0
    return last_runs(log, session).get(event, -1) >= floor


def hooks_watch(payload: dict) -> dict:
    """The mod's question a moment after a person's prompt went on to the model (claude-mod/maisecrets-mod.mjs, the
    hooks watch): did the prompt hook of this session leave its row since the prompt (`since`)? {"ran": bool}, or
    {"ran": None} where the mod must say nothing: in Cowork, as mod_verdict. Writes nothing."""
    from . import cowork
    if cowork.active():
        return {"ran": None}
    from .home import HOME
    return {"ran": ran_since(HOME / "hooks.log", payload.get("session_id"), "user-prompt", payload.get("since"))}


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


def _update_short(info: dict) -> str:
    """The update command for the check line: Codex's own; in Claude Code the plugin menu (the full command is in
    the detail and in update_command)."""
    market = info.get("market") or "maisecrets"
    return f"codex plugin add maisecrets@{market}" if info["kind"] == "codex" else "/plugin, then update maisecrets"


def version_verdict(info: dict) -> Check:
    inst, new = info["installed"], info["newest"]
    if info["kind"] == "synced":
        return Check("warn", "version", "synced by your org", "ask your admin",
                     "synced by your organisation: its sync decides; a new session gets a synced update")
    if not new:
        why = ("no marketplace copy found on this computer" if info["kind"] in ("claude", "codex")
               else "maisecrets runs from a folder no marketplace installed")
        nxt = ("codex plugin marketplace upgrade" if info["kind"] == "codex"
               else "/plugin, update the marketplace" if info["kind"] == "claude"
               else "git pull in that folder")
        full = (f"claude plugin marketplace update {info.get('market') or 'maisecrets'}" if info["kind"] == "claude"
                else nxt)
        return Check("warn", "version", "newest unknown", nxt, f"{inst}; newest unknown: {why}; next: {full}")
    fetched = f", fetched {info['fetched'][:16].replace('T', ' ')}" if info.get("fetched") else ""
    copy = f"the marketplace copy of {info['where']}{fetched}"
    a, b = _version_tuple(inst), _version_tuple(new)
    if not a:
        return Check("warn", "version", "not comparable", _update_short(info),
                     f"the installed version {inst!r} cannot be compared with {new} in {copy}; next: "
                     f"{update_command(info)}")
    if not b or b > a:
        return Check("warn", "version", f"{new} is newer", _update_short(info),
                     f"{inst} is installed; {new} is in {copy}; next: {update_command(info)}")
    return Check("ok", "version", f"{inst}, the newest", None,
                 f"the newest in {copy} (that copy is only as new as its last fetch)")


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

def codex_verdict(root: Path, codex_home: Path) -> Check:
    from . import codex_trust
    roots = [root] if codex_trust._plugin_id(root, codex_home) else sorted(
        (p.parent.parent for p in (codex_home / "plugins" / "cache").glob("*/maisecrets/*/hooks/hooks.json")),
        key=lambda p: p.stat().st_mtime)[-1:]
    if not roots:
        return Check("n/a", "codex", "not installed", None, "Codex did not install maisecrets on this computer")
    lines = codex_trust.status_lines(roots[0], codex_home)
    text = "; ".join(lines) or "codex hooks: unknown"
    if any("WARNING" in ln for ln in lines):
        return Check("FAIL", "codex", "hooks not trusted", "trust them in /hooks in Codex",
                     text.replace("WARNING: ", ""))
    if any("unknown" in ln or "another maisecrets" in ln for ln in lines):
        return Check("warn", "codex", "trust unknown", "check them in /hooks in Codex", text)
    return Check("ok", "codex", "trusted", None, text + f" (version folder {roots[0].name})")


def _values(n: int) -> str:
    return f"{n} value" + ("" if n == 1 else "s")


def store_verdict() -> Check:
    try:
        from .vault import Vault
        v = Vault()
        live = sum(1 for e in v.list() if not e.purged)
        v.backend.get("maisecrets-status-probe")          # a read of a key that does not exist: the store answers
    except ConfigError:
        raise                         # the command prints the configuration error alone (cli.main)
    except Exception as exc:  # noqa: BLE001 - the verdict names the failure; the details say more
        return Check("FAIL", "store", "no answer", "/maisecrets report incident",
                     f"the store did not answer a read ({type(exc).__name__}); every prompt with a value is blocked "
                     "until it does")
    name = {"KeychainBackend": "macOS keychain", "WindowsVaultBackend": "Windows Credential Locker",
            "EncryptedFileBackend": "encrypted file", "JsonFileBackend": "test file"}.get(
        type(v.backend).__name__, type(v.backend).__name__)
    if v.backend.test_mode:
        return Check("warn", "store", f"{name}, {_values(live)}", "set backend in config.json", None)
    return Check("ok", "store", f"{name}, {_values(live)}", None, None)


def incidents_verdict() -> Check:
    from . import incidents
    groups, damaged = incidents.load()
    days = incidents.WINDOW_DAYS
    if damaged:
        return Check("warn", "incidents", "record damaged", "/maisecrets report incident",
                     "the incident record is damaged")
    closed = sum(int(g.get("count", 0)) for g in groups.values() if g.get("class") == "fail-closed")
    other = sum(int(g.get("count", 0)) for g in groups.values() if g.get("class") != "fail-closed")
    markers = len(incidents.unfolded_markers())
    if not closed and not other and not markers:
        return Check("ok", "incidents", f"none in {days} days", None, None)
    parts = []
    if closed:
        parts.append(f"{closed} times maisecrets refused a call it could not check (safe, but it stopped work)")
    if other:
        parts.append(f"{other} times a side step failed (a cleanup or a record)")
    if markers:
        parts.append(f"{markers} not yet counted")
    return Check("warn", "incidents", f"{closed + other + markers} in {days} days", "/maisecrets report incident",
                 "; ".join(parts))


# --- all of it ----------------------------------------------------------------------------------------------------

def _guarded(fn, *args) -> Check:
    try:
        return fn(*args)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - one line that fails must not hide the others
        name = getattr(fn, "__name__", "check").replace("_verdict", "")
        return Check("warn", name if name in NAMES else "check", "not checked", "/maisecrets report incident",
                     f"could not be checked ({type(exc).__name__})")


def client_of(log: Path, sessions: list) -> str | None:
    """"codex" or "claude": the client of the session whose tool-call hook ran last; None outside a session."""
    session = this_session(log, sessions)
    if not session:
        return None
    return "codex" if session == os.environ.get("CODEX_THREAD_ID") else "claude"


def report(root: Path, claude_dir: Path | None = None, codex_home: Path | None = None) -> dict:
    """{"checks": [Check, ...], "client": "claude" | "codex" | None (outside a client session), "version": str}."""
    from . import selftest
    from .home import HOME
    if claude_dir is None:
        claude_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    if codex_home is None:
        from .codex_vault import codex_home as _codex_home
        codex_home = _codex_home()
    log = HOME / "hooks.log"
    sessions = selftest.sessions_of_this_command()
    client = client_of(log, sessions)
    version = installed_version(root)
    checks = [_guarded(lambda: hooks_verdict(log, sessions, client=client)),
              _guarded(lambda: version_verdict(newest(root, claude_dir, codex_home))),
              _guarded(codex_verdict, root, codex_home),
              _guarded(store_verdict),
              _guarded(incidents_verdict),
              _guarded(lambda: selftest.verdict(None, sessions, version, client=client))]
    names = names_verdict()
    if names:
        checks.append(names)
    checks += cowork_notes()
    try:
        mod = mod_verdict(log, sessions, client)
    except Exception:  # noqa: BLE001 - a note that cannot be read is no check
        mod = None
    if mod:
        checks.append(mod)
    dm = demo_verdict(sessions)
    if dm:
        checks.append(dm)
    old = older_verdict()
    if old:
        checks.append(old)
    return {"checks": checks, "client": client, "version": version}


def older_verdict() -> Check | None:
    """A note while an older maisecrets ran in the last day (it may still be open) and a gateway login was used
    (maisecrets/older_versions.py): a warn, never a FAIL. None otherwise."""
    from . import older_versions
    found = older_versions.status()
    if not found:
        return None
    return Check("warn", "older", f"{found[0]} ran in 24 h"[:FACT_COL], "restart the old sessions", found[1])


def names_verdict() -> Check | None:
    """The name source of /maisecrets ner (ner_health.verdict): a warn with the cause and the step when it is set and
    cannot be used, never a FAIL. None without a source, or when the check itself fails."""
    try:
        from . import ner_health
        from .home import load_config
        return ner_health.verdict(load_config())
    except Exception:  # noqa: BLE001 - a note that cannot be read is no check
        return None


def cowork_notes() -> list:
    """In Cowork, the notes of a task: the settings hold for this task only (a new task starts a new VM), and, while no
    name source is set, names are off with the reason (cowork.names_off). Outside Cowork none."""
    from . import cowork
    if not cowork.active():
        return []
    notes = [Check("warn", "settings", "this task only", None,
                   "Cowork keeps the settings and the stored values in the VM of this task; a new task starts with "
                   "the defaults", "a new Cowork task starts with the defaults")]
    try:
        from .home import load_config
        off = cowork.names_off(load_config())
    except Exception:  # noqa: BLE001 - a note that cannot be read is no check
        off = False
    if off:
        why = cowork.NAMES_WHY[:1].upper() + cowork.NAMES_WHY[1:] + "."
        notes.append(Check("warn", "names", "off in this task", "/maisecrets term add NAME",
                           f"names are off in this Cowork task: {cowork.NAMES_WHY}. /maisecrets term add NAME masks "
                           "a word of your own.", why + " The step masks a word of your own."))
    return notes


def demo_verdict(sessions) -> Check | None:
    """A note while the demo is on in this session (maisecrets/demo.py), so it is never forgotten: a warn, never a FAIL
    (the session is protected; no prompt reaches the AI at all). None while it is off."""
    from . import demo
    try:
        on = demo.active_in(sessions if isinstance(sessions, list) else [sessions])
    except Exception:  # noqa: BLE001 - a note that cannot be read is no check
        return None
    if not on:
        return None
    if demo.damaged():
        return Check("warn", "demo", "state unreadable", "/maisecrets demo off",
                     "the demo state cannot be read, so maisecrets sends no prompt of any session; "
                     "/maisecrets demo off resets it")
    return Check("warn", "demo", "on, none sent to AI", "/maisecrets demo off",
                 "the demo is on: maisecrets answers each prompt itself, and no prompt reaches the AI")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def head_line(version: str, checks: list, client: str | None) -> str:
    """The lock only for a session that was checked: 🔒 with no FAIL, ⚠️ with one (an open
    lock looked like the closed one); outside a session no claim."""
    fails = sum(c.state == "FAIL" for c in checks)
    warns = sum(c.state == "warn" for c in checks)
    tail = (f" · {_plural(fails, 'failure')}" if fails else f" · {_plural(warns, 'note')}" if warns else "")
    if client is None:
        return f"maisecrets {version} · status outside a client session{tail}"
    if fails:
        return f"\u26a0\ufe0f maisecrets {version} is NOT protecting this session{tail}"
    if any(c.name == "names" and c.state == "warn" for c in checks):
        # secrets are protected; a person's name in a tool result is left to the rules (ner_health)
        return f"\U0001F512 maisecrets {version} protects secrets in this session; names are not checked{tail}"
    if any(c.name == "mod" and c.state == "warn" for c in checks):
        # the hooks protect; without the mod no value or reference is drawn, and the slash forms need it
        return f"\U0001F512 maisecrets {version} protects this session; mod off: no lock or click{tail}"
    return f"\U0001F512 maisecrets {version} protects this session{tail or ' · all checks ok'}"


def check_lines(checks: list, client: str | None = None) -> list[str]:
    """One line per check: mark, name, fact, and for warn and FAIL the next command, the arrows in one column.
    In Codex a command is typed as `maisecrets: status test`."""
    if client == "codex":
        from .forms import codex
        checks = [c._replace(next=codex(c.next)) if c.next else c for c in checks]
    out = []
    for c in checks:
        line = f" {MARK.get(c.state, '?')} {c.name:<{NAME_COL}} {c.fact}"
        if c.next and c.state in ("warn", "FAIL"):
            line = f" {MARK.get(c.state, '?')} {c.name:<{NAME_COL}} {c.fact:<{FACT_COL}}  \u2192  {c.next}"
        out.append(line)
        if c.note:
            import textwrap
            indent = " " * (NAME_COL + 4)
            out += textwrap.wrap(c.note, WIDTH, initial_indent=indent, subsequent_indent=indent)
    return out


def detail_lines(checks: list) -> list[str]:
    """The longer facts of each check, for `status all`."""
    return [f"{c.name}: {c.detail}" for c in checks if c.detail]


def summary_line(conf, probe, rules: int, active) -> str:
    """One line of key facts: the names source and its state, the rule count, the regions, the label languages."""
    url = conf.get("url") if isinstance(conf, dict) else None
    if not url:
        names = "names: off"
    else:
        from .detection import remote
        src = ("gateway" if conf.get("gateway") else "local service" if remote.is_local(str(url))
               else "service on the network")
        ok, text = probe or (False, "")
        ms = re.search(r"answers \((\d+) ms\)", text)
        names = (f"names: {src} ({ms.group(1)} ms)" if ok and ms else f"names: {src}, answers" if ok
                 else f"names: {src}, not asked" if "not asked" in text or "Unix socket" in text
                 else f"names: {src}, not answering")
    regions = list(active.regions)
    return " \u00b7 ".join([names, f"rules: {rules}", f"region{'s' if len(regions) != 1 else ''}: {', '.join(regions)}",
                            _plural(len(active.languages), "label language")])


def form(command: str, client: str | None) -> str:
    """`status all` as the person types it: /maisecrets status all, in Codex `maisecrets: status all`, and both when
    the client is not known."""
    slash, typed = f"/maisecrets {command}", f"maisecrets: {command}"
    if client == "codex":
        return typed
    return slash if client == "claude" else f"{slash} (Codex: {typed})"
