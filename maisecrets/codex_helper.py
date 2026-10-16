"""The Client-Vault header for Codex: the `http_headers_helper` of a user-scope MCP server entry.

Codex runs this command when it connects to the server, in the folder of the session, with a cleared environment,
and sends the JSON object it prints as HTTP headers to the origin of the server's URL (codex-cli 0.162.0, measured:
MCP requests and the authorization-code token request; never the browser leg). A static `http_headers` entry would
not be safe: a repository's `.codex/config.toml` merges over the user's config and can set another URL for the same
entry, and the static header then goes to that URL (measured). This helper checks that case each time:

- the state file of maisecrets names this entry of this config file, with this URL, and a header;
- the user's config.toml still has this entry with this URL, and no profile of the user can change it;
- no project layer of the session folder (`<folder>/.codex/config.toml`, from the folder up to the root) has any
  `mcp_servers` table, and every such file parses.

Only then it prints `{"Client-Vault": "v=1, kid=:…:"}`; in every other case `{}`. It never exits with an error:
a helper that fails stops Codex from connecting to the server (measured), so the command line in config.toml also
ends in `|| echo {}`. Standard library only, Python 3.11 or later (tomllib); the hooks import the same checks.

Usage (Codex runs it): python3 -I codex_helper.py <state file> <codex config.toml> <server name> <server URL>
"""
from __future__ import annotations

import json
import os
import re
import sys

HEADER = "Client-Vault"
_HEADER_RE = re.compile(r"v=1, kid=:[A-Za-z0-9+/]{43}=:")
MAX_FILE = 4 * 1024 * 1024            # a config file larger than this is not read: no header


def _toml():
    try:
        import tomllib
    except ImportError:               # Python before 3.11
        return None
    return tomllib


def load(path: str) -> dict | None:
    """The parsed TOML file, or None when it is missing, too large, unreadable or not TOML."""
    toml = _toml()
    if toml is None:
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            return None
        data = toml.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _mentions_servers(node: object, depth: int = 0) -> bool:
    """Any key `mcp_servers` at any depth: a project layer can also carry servers inside a profile table."""
    if depth > 64:
        return True
    if isinstance(node, dict):
        return any(k == "mcp_servers" or _mentions_servers(v, depth + 1) for k, v in node.items())
    if isinstance(node, list):
        return any(_mentions_servers(v, depth + 1) for v in node)
    return False


def _ancestors(folder: str) -> list[str]:
    out: list[str] = []
    for start in (os.path.abspath(folder), os.path.realpath(folder)):
        d = start
        while True:
            if d not in out:
                out.append(d)
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    return out


def project_brings_servers(folder: object, codex_home: str) -> bool:
    """True when a project layer of this session folder has an `mcp_servers` table, when such a file cannot be read
    or parsed, or when the folder is unknown. Codex reads `<dir>/.codex/config.toml` from the project root down to the
    folder; this looks from the folder up to the file system root, which is the same set or more. The `.codex`
    folder that is the user's CODEX_HOME is the user layer, not a project layer (Codex skips it too)."""
    if not isinstance(folder, str) or not folder or not os.path.isabs(folder) or _toml() is None:
        return True
    home = os.path.realpath(codex_home)
    for d in _ancestors(folder):
        dot = os.path.join(d, ".codex")
        if os.path.realpath(dot) == home:
            continue
        path = os.path.join(dot, "config.toml")
        if not os.path.lexists(path):
            continue
        data = load(path)
        if data is None or _mentions_servers(data):
            return True
    return False


def user_entry_is_plain(data: dict | None, name: str, url: str) -> bool:
    """The user's config has this entry with this URL as its own, and no profile of the user can replace it: a top
    level `profile` key, or `mcp_servers` inside `profiles`, could give the entry another URL."""
    if not isinstance(data, dict) or "profile" in data or _mentions_servers(data.get("profiles")):
        return False
    servers = data.get("mcp_servers")
    spec = servers.get(name) if isinstance(servers, dict) else None
    return isinstance(spec, dict) and spec.get("url") == url and "command" not in spec


def profile_files_bring_servers(codex_home: str) -> bool:
    """A profile file `<CODEX_HOME>/<name>.config.toml` (selected with --profile) that has servers, or that does not
    parse."""
    try:
        names = os.listdir(codex_home)
    except OSError:
        return True
    for n in names:
        if n.endswith(".config.toml"):
            data = load(os.path.join(codex_home, n))
            if data is None or _mentions_servers(data):
                return True
    return False


def header_for(state_file: str, config: str, name: str, url: str, folder: str) -> str | None:
    """The header value for this entry in this folder, or None."""
    try:
        with open(state_file, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError, RecursionError):
        return None
    profile = os.path.realpath(config)
    rec = state.get(profile, {}).get(name) if isinstance(state, dict) and isinstance(state.get(profile), dict) else None
    if not isinstance(rec, dict) or rec.get("url") != url:
        return None
    header = rec.get("header")
    if not isinstance(header, str) or not _HEADER_RE.fullmatch(header):
        return None
    codex_home = os.path.dirname(profile)
    if not user_entry_is_plain(load(profile), name, url) or profile_files_bring_servers(codex_home):
        return None
    if project_brings_servers(folder, codex_home):
        return None
    return header


def main(argv: list[str]) -> int:
    header = None
    try:
        if len(argv) == 4:
            header = header_for(argv[0], argv[1], argv[2], argv[3], os.getcwd())
    except Exception:  # noqa: BLE001 - a helper that fails stops the server: never
        header = None
    sys.stdout.write(json.dumps({HEADER: header} if header else {}))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
