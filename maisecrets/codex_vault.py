"""Vault references in Codex: the client side of vault_refs.py for codex-cli (measured on 0.162.0).

Three facts of Codex shape this module (docs/CLIENTS.md, "Codex: vault references"):

- A repository's `.codex/config.toml` merges deeply over the user's `$CODEX_HOME/config.toml`. A project layer that
  names a user entry can give it another URL, and a static `http_headers` header of that entry then goes to that URL.
  So maisecrets never writes `http_headers`. It writes one `http_headers_helper` line on the user entry: a fixed
  command (codex_helper.py) that Codex runs at connect time in the session folder, and that prints the header only
  when no project layer of that folder has servers (codex_helper.header_for), else `{}`.
- The PostToolUse payload names the tool only (`mcp__<server>__<tool>`), with no server, URL or scope. The server is
  found by Codex's own name rule; a project layer with servers, or a name that two entries could make, notes nothing.
- Codex reads config.toml when it starts: a helper line added in a session works from the next start.

The write changes one line of config.toml and nothing else: a parse before and after must differ in exactly that key
of that entry, or nothing is written. Needs tomllib (Python 3.11+); without it, and on Windows, this module is off.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

from . import codex_helper
from .vault import _DEFAULT_HOME, HOME, _lock_for, atomic_write

HELPER_KEY = "http_headers_helper"
HELPER_FILE = HOME / "bin" / "codex-vault-helper.py"   # outside the plugin folder: an update moves that folder
STATE = HOME / "vault-refs" / "codex-helper.json"       # profile -> name -> {"url", "header"}; the helper reads it
LOCK_STALE = 10.0


def available() -> bool:
    """Codex vault references run here: tomllib exists and this is not Windows (not measured there)."""
    return os.name != "nt" and codex_helper._toml() is not None


def codex_home() -> Path:
    base = os.environ.get("CODEX_HOME")
    return Path(base).expanduser() if base else Path.home() / ".codex"


def config_path() -> Path:
    """The user layer of Codex: the only file maisecrets changes."""
    return codex_home() / "config.toml"


def profile() -> str:
    return os.path.realpath(str(config_path()))


def _origin_ok(url: object) -> bool:
    from .vault_refs import origin_of
    return bool(origin_of(url))


def user_servers(data: dict | None = None) -> dict[str, str]:
    """name -> URL of each user entry with an https URL (streamable HTTP, not switched off)."""
    if data is None:
        data = codex_helper.load(profile()) or {}
    servers = data.get("mcp_servers")
    if not isinstance(servers, dict):
        return {}
    return {name: spec["url"] for name, spec in servers.items()
            if isinstance(name, str) and isinstance(spec, dict) and "command" not in spec
            and spec.get("enabled", True) is not False and _origin_ok(spec.get("url"))}


# ------------------------------------------------------------- tool names --
def _sanitize(s: str) -> str:
    """codex-mcp/src/mcp/mod.rs sanitize_responses_api_tool_name: each character outside [A-Za-z0-9_] becomes `_`."""
    return re.sub(r"[^A-Za-z0-9_]", "_", s) or "_"


def namespace(server: str) -> str:
    """The tool name prefix of a server, without its `__` delimiter: `mcp__` + sanitized name, trailing `_` trimmed
    (core/src/tools/handlers/mcp.rs join_tool_name). A hashed or shortened name never matches: no note."""
    ns = _sanitize(server)
    ns = ns if ns.startswith("mcp__") else "mcp__" + ns
    return ns.rstrip("_")


def server_of_tool(tool: object, servers) -> str | None:
    """The one entry whose prefix the tool name has; None for no match or for two (`a` and `a__b`)."""
    if not isinstance(tool, str):
        return None
    hits = [n for n in servers if tool.startswith(namespace(n) + "__") and len(tool) > len(namespace(n)) + 2]
    return hits[0] if len(hits) == 1 else None


def mcp_server_of(payload: dict) -> dict | None:
    """The `mcp_server` field that Claude Code sends and Codex does not: {"name", "source": "user"} for a tool of a
    user entry that nothing else can name in this session folder, else None (the token stays text)."""
    if not available():
        return None
    data = codex_helper.load(profile())
    servers = user_servers(data)
    name = server_of_tool(payload.get("tool_name"), servers)
    if name is None:
        return None
    home = os.path.dirname(profile())
    if not codex_helper.user_entry_is_plain(data, name, servers[name]) \
            or codex_helper.profile_files_bring_servers(home) \
            or codex_helper.project_brings_servers(payload.get("cwd"), home):
        return None
    return {"name": name, "source": "user"}


# ------------------------------------------------------------ the helper --
def helper_command(name: str, url: str) -> str:
    """The command line of the entry. `-I`: no environment and no script folder on the import path. The `|| echo`
    keeps the server working when the Python is gone (a helper that fails stops the connection, measured)."""
    import shlex
    parts = [sys.executable, "-I", str(HELPER_FILE), str(STATE), profile(), name, url]
    return " ".join(shlex.quote(p) for p in parts) + " 2>/dev/null || echo '{}'"


def is_ours(value: object) -> bool:
    """A helper line this maisecrets home wrote: it names our helper file and our state file."""
    return isinstance(value, str) and str(HELPER_FILE) in value and str(STATE) in value


def place_helper() -> bool:
    """Copy codex_helper.py to HELPER_FILE when it is missing or differs. Never raises."""
    import shutil
    try:
        src = Path(__file__).resolve().parent / "codex_helper.py"
        if HELPER_FILE.exists() and HELPER_FILE.read_bytes() == src.read_bytes():
            return False
        HELPER_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = HELPER_FILE.with_name(HELPER_FILE.name + ".tmp")
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, HELPER_FILE)
        return True
    except OSError:
        return False


def write_state(entries: dict[str, tuple[str, str]]) -> None:
    """name -> (url, header) of this profile, read by the helper; an empty dict takes every header back at once."""
    with _lock_for(STATE.parent / ".lock"):
        try:
            data = json.loads(STATE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        data = data if isinstance(data, dict) else {}
        mine = {n: {"url": u, "header": h} for n, (u, h) in entries.items()}
        if data.get(profile()) == mine or (not mine and profile() not in data):
            return
        if mine:
            data[profile()] = mine
        else:
            data.pop(profile(), None)
        atomic_write(STATE, json.dumps(data, indent=1))


# --------------------------------------------------------- the line edit --
def toml_string(s: str) -> str:
    """A TOML basic string."""
    out = []
    for ch in s:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _header_re(name: str) -> re.Pattern:
    """The table header `[mcp_servers.<name>]` in its bare, basic-quoted or literal-quoted key form."""
    forms = [re.escape(toml_string(name)), re.escape(f"'{name}'")]
    if re.fullmatch(r"[A-Za-z0-9_-]+", name):
        forms.append(re.escape(name))
    return re.compile(r"[ \t]*\[[ \t]*mcp_servers[ \t]*\.[ \t]*(?:" + "|".join(forms) + r")[ \t]*\][ \t]*(?:#.*)?")


def _expected(data: dict, name: str, value: str | None) -> dict:
    import copy
    want = copy.deepcopy(data)
    spec = want["mcp_servers"][name]
    if value is None:
        spec.pop(HELPER_KEY, None)
    else:
        spec[HELPER_KEY] = value
    return want


def _parse(text: str) -> dict | None:
    toml = codex_helper._toml()
    try:
        data = toml.loads(text) if toml else None
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def plan(text: str, name: str, value: str | None) -> str | None:
    """text with the helper line of entry `name` set to value (None: our line removed), or None when that cannot be
    done as one line: another form of the table, two headers, a parse that differs in anything else."""
    data = _parse(text)
    if data is None or not isinstance(data.get("mcp_servers"), dict) or not isinstance(data["mcp_servers"].get(name),
                                                                                         dict):
        return None
    lines = text.splitlines(keepends=True)
    eol = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    rx = _header_re(name)
    heads = [i for i, ln in enumerate(lines) if rx.fullmatch(ln.rstrip("\r\n"))]
    if len(heads) != 1:
        return None
    head = heads[0]
    current = data["mcp_servers"][name].get(HELPER_KEY)
    out = list(lines)
    if current is not None:
        if not is_ours(current):
            return None                    # a helper someone else wrote stays
        # our line: the first `http_headers_helper = "…"` line after the table header that decodes to the value
        mine = None
        for i in range(head + 1, len(lines)):
            m = re.fullmatch(r"[ \t]*http_headers_helper[ \t]*=[ \t]*(\".*\")[ \t]*", lines[i].rstrip("\r\n"))
            if m and (_parse("v = " + m.group(1)) or {}).get("v") == current:
                mine = i
                break
        if mine is None:
            return None
        del out[mine]
    if value is not None:
        if not lines[head].endswith(("\n", "\r\n")):
            out[head] = lines[head] + eol
        out.insert(head + 1, f"{HELPER_KEY} = {toml_string(value)}{eol}")
    new = "".join(out)
    return new if _parse(new) == _expected(data, name, value) else None


class _Lock:
    """maisecrets' own lock on the file (Codex takes none): `<file>.maisecrets.lock`, stale after 10 s."""

    def __init__(self, path: Path, wait: float) -> None:
        self.dir, self.wait = path.with_name(path.name + ".maisecrets.lock"), wait

    def __enter__(self):
        deadline = time.time() + self.wait
        while True:
            try:
                os.mkdir(self.dir, 0o700)
                self.ino = os.stat(self.dir).st_ino
                return self
            except FileExistsError:
                try:
                    if time.time() - os.stat(self.dir).st_mtime > LOCK_STALE:
                        os.rmdir(self.dir)
                        continue
                except OSError:
                    continue
                if time.time() > deadline:
                    raise TimeoutError("the config lock is busy") from None
                time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        try:
            if os.stat(self.dir).st_ino == self.ino:
                os.rmdir(self.dir)
        except OSError:
            pass


def in_a_repository(path: str) -> bool:
    """The file lies in a git work tree (a dotfiles repository, a CODEX_HOME inside a project): a repository carries
    it, so maisecrets never writes it."""
    d = os.path.dirname(os.path.realpath(path))
    while True:
        if os.path.lexists(os.path.join(d, ".git")):
            return True
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


def may_change_config() -> bool:
    """As vault_refs._may_change_config for Claude Code: a test home never changes the person's Codex config."""
    if not available():
        return False
    if os.environ.get("MAISECRETS_TEST_HOME_OWNED"):
        import tempfile
        return profile().startswith(os.path.realpath(tempfile.gettempdir()) + os.sep)
    return HOME == _DEFAULT_HOME or bool(os.environ.get("CODEX_HOME"))


def _write(real: str, text: str) -> None:
    """A temporary file in the same folder, renamed over the file; the mode of the file stays."""
    try:
        mode = os.stat(real).st_mode & 0o777
    except OSError:
        mode = 0o600
    tmp = f"{real}.maisecrets.{os.getpid()}.tmp"
    try:
        os.unlink(tmp)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, real)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _backup(real: str, data: bytes) -> str:
    backup = real + ".maisecrets-backup"
    try:
        os.unlink(backup)
    except FileNotFoundError:
        pass
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return backup


def apply_config(wanted: dict[str, tuple[str, str]], lock_wait: float = 5.0) -> tuple[list[str], list[str], Path,
                                                                                         Path]:
    """The helper lines of the user config as they should be: ours on each wanted entry (name -> (url, header)) whose
    URL is still that URL, none of ours elsewhere. The state file first, so a header goes at once when it is taken
    back. Returns (added, removed, path, backup). A symlinked config is written through to its target, as Codex does."""
    path = Path(profile())
    backup = Path(str(path) + ".maisecrets-backup")
    write_state(wanted)
    if not path.is_file() or in_a_repository(str(path)):
        return [], [], path, backup
    for _attempt in range(2):
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return [], [], path, backup
        data = _parse(text)
        if data is None:
            return [], [], path, backup       # a file that does not parse is not touched
        new, added, removed = text, [], []
        plain = user_servers(data)
        servers = data.get("mcp_servers") if isinstance(data.get("mcp_servers"), dict) else {}
        for name, spec in servers.items():
            if not isinstance(name, str) or not isinstance(spec, dict):
                continue
            url = plain.get(name)
            have = spec.get(HELPER_KEY)
            want = helper_command(name, url) if url and wanted.get(name, ("",))[0] == url else None
            if want is not None and isinstance(spec.get("http_headers"), dict) and any(
                    k.lower() == codex_helper.HEADER.lower() for k in spec["http_headers"]):
                continue                       # a Client-Vault header someone else wrote
            if have == want or (want is None and not is_ours(have)):
                continue
            step = plan(new, name, want)
            if step is None:
                continue                       # another form of the table: left as it is
            new = step
            (added if want is not None else removed).append(name)
        if new == text:
            try:
                backup.unlink()                # nothing to change: the backup of the last change goes
            except OSError:
                pass
            return [], [], path, backup
        with _Lock(path, lock_wait):
            try:
                if path.read_bytes() != raw:
                    continue                   # Codex wrote the file meanwhile: once more from its new text
            except OSError:
                return [], [], path, backup
            _backup(str(path), raw)
            _write(str(path), new)
        return added, removed, path, backup
    return [], [], path, backup


def notice(name: str) -> str:
    from .vault_refs import HEADER
    return (f"maisecrets: the MCP server {name} supports {HEADER}. From the next start of Codex, maisecrets puts this "
            "server's values into your local files and commands; the AI still sees only tokens. To turn it off: "
            "/maisecrets:settings client_header false. More: README, section \"Vault references\".")
