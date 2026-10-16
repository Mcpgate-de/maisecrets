"""Vault references (docs/PROTOCOL.md section 4): a token that an MCP server minted gets its value from that server.

An MCP server may replace a value in its tool result with a token of the server range, `⟦EMAIL_1⟧` or
`⟦EMAIL_1:display⟧` (no `c`; PROTOCOL.md section 1). When the model later writes that token into a Write,
Edit, MultiEdit, NotebookEdit or Bash call, the hook asks the server for the value and puts it in; the model
sees only the token. The server gives a value only to a key that this vault announced:

- K: 32 random bytes per MCP origin and client profile, kept in the store with no placeholder.
- The announcement: a static `Client-Vault: v=1, kid=:<base64 SHA-256(K)>:` header on the user-scope entry of
  that server in the client's config. The client sends it on its OAuth token request, where the server binds
  the kid to the person who logged in.
- The resolve: the endpoint that the server names in its protected resource metadata (RFC 9728), called with
  `Authorization: Bearer <K>`. All values, or one error for the whole batch.

The hook notes a token only from a result of an `mcp__*` tool whose server entry is user scope (`source: user`),
keyed by the origin of that entry's URL. A token that was never noted stays text. Standard library only.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit

from .vault import _DEFAULT_HOME, HOME, _lock_for, atomic_write

OPEN, CLOSE = "⟦", "⟧"
# the server range: no `c`, a counter from 1 (PROTOCOL.md section 1); the display part is for humans only
SERVER_REF_RE = re.compile(rf"{OPEN}(?P<type>[A-Z][A-Z_]*?)_(?P<n>[1-9]\d{{0,8}})(?::[^{OPEN}{CLOSE}]{{0,80}})?{CLOSE}")
_SERVER_KEY_RE = re.compile(r"[A-Z][A-Z_]*?_[1-9]\d{0,8}")
HEADER = "Client-Vault"
_HEADER_RE = re.compile(r"v=1, kid=:(?P<kid>[A-Za-z0-9+/]{43}=):")
# an ISO 8601 time as the server may send it; anything else is never shown (a server must not put text before the AI)
_TIME_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)")
MAX_REFS = 100
MAX_REQUEST_BYTES = 64 * 1024
MAX_ANSWER_BYTES = 1024 * 1024
METADATA_TTL = 3600                   # an answer of the metadata endpoint, either way, is kept this long
CONNECT_TIMEOUT = 2.0
SOCKET_TIMEOUT = 4.0
BUDGET = 5.5                          # both requests together, inside the hook's 7 s watchdog
MAX_NOTES_PER_ORIGIN = 5000
LOCK_STALE = 10.0                     # the client's own lock rule for its config file

DIR = HOME / "vault-refs"
NOTES = DIR / "notes.json"            # profile -> origin -> key -> {"type", "seen": {MCP URL: seen_at}, "sessions"}
RELEASED = DIR / "released.json"      # session -> [{"name", "t"}]: the values a server gave, kept in the store 1 h
NOTE_TTL = 24 * 3600                  # a token seen longer ago than this stays text
RELEASE_WINDOW = 3600                 # a value a server gave is hunted in tool output this long, as a stored one
MAX_SESSIONS_PER_NOTE = 20
KEYS = DIR / "keys.json"              # profile -> origin -> {"kid", "created"}; never K
ENDPOINTS = DIR / "endpoints.json"    # origin + path -> {"endpoint", "t"}


class Refused(Exception):
    """No value: the reason names keys, the origin and the status, never a value."""


# ------------------------------------------------------------------ tokens --
def find(text: str) -> list[tuple[str, int, int]]:
    """(key, start, end) for every token of the server range in text."""
    return [(f"{m.group('type')}_{m.group('n')}", m.start(), m.end()) for m in SERVER_REF_RE.finditer(text)]


def is_server_key(key: str) -> bool:
    return bool(_SERVER_KEY_RE.fullmatch(key))


def _now_iso(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))


# ---------------------------------------------------------- client config --
def claude_json() -> Path:
    """The config file of this client profile: the one that holds the user-scope MCP servers."""
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(base) / ".claude.json" if base else Path.home() / ".claude.json"


def profile() -> str:
    return str(claude_json().resolve())


def origin_of(url: object) -> str | None:
    """`https://host[:port]` of an https URL with a host, in lower case and without the default port."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password:
        return None
    if port == 0:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port and port != 443 else "")


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def user_servers(config: dict | None = None) -> dict[str, str]:
    """name -> URL of each user-scope server (top-level `mcpServers`) with an https URL."""
    data = config if config is not None else (_read_json(claude_json()) or {})
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return {}
    return {name: spec["url"] for name, spec in servers.items()
            if isinstance(spec, dict) and origin_of(spec.get("url"))}


# ------------------------------------------------------------------- the key --
def _store_name(origin: str) -> str:
    return "_maisecrets_vref_" + hashlib.sha256(f"{profile()}\0{origin}".encode()).hexdigest()[:24]


def kid_of(k: bytes) -> str:
    return base64.b64encode(hashlib.sha256(k).digest()).decode()


def header_value(k: bytes) -> str:
    return f"v=1, kid=:{kid_of(k)}:"


def bearer_of(k: bytes) -> str:
    return base64.urlsafe_b64encode(k).decode().rstrip("=")


def _key(backend, origin: str, create: bool) -> bytes | None:
    raw = backend.get(_store_name(origin))
    if raw:
        try:
            k = bytes.fromhex(raw.strip())
            if len(k) == 32:
                return k
        except ValueError:
            pass
    if not create:
        return None
    k = secrets.token_bytes(32)
    backend.put(_store_name(origin), k.hex(), label="maisecrets vault reference key",
                comment="maisecrets: the key that gets values back from a server; not a placeholder value.")
    return k


def _known_keys() -> dict:
    return (_read_json(KEYS) or {}).get(profile()) or {}


def _remember_key(origin: str, kid: str) -> None:
    with _lock_for(DIR / ".lock"):
        data = _read_json(KEYS) or {}
        mine = data.setdefault(profile(), {})
        if mine.get(origin, {}).get("kid") != kid:
            mine[origin] = {"kid": kid, "created": _now_iso()}
            atomic_write(KEYS, json.dumps(data, indent=1))


# ------------------------------------------------------ the header write --
class _ConfigLock:
    """The client's own lock on its config: a `<file>.lock` folder. A lock younger than 10 s is waited for; an older
    one is stale and taken over."""

    def __init__(self, path: Path, wait: float = 5.0) -> None:
        self.dir = path.with_name(path.name + ".lock")
        self.wait = wait

    def __enter__(self):
        deadline = time.time() + self.wait
        while True:
            try:
                os.mkdir(self.dir, 0o700)
                self.ino = os.stat(self.dir).st_ino
                return self
            except FileExistsError:
                try:
                    age = time.time() - os.stat(self.dir).st_mtime
                except OSError:
                    continue                    # it went away: try again
                if age > LOCK_STALE:
                    try:
                        os.rmdir(self.dir)
                    except OSError:
                        pass
                    continue
                if time.time() > deadline:
                    raise TimeoutError("the client holds its config lock")
                time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        try:
            if os.stat(self.dir).st_ino == self.ino:     # another process took it over as stale: it is theirs
                os.rmdir(self.dir)
        except OSError:
            pass


def _write_config(path: Path, data: dict) -> None:
    """A temporary file in the same folder, renamed over the original; the mode of the original stays."""
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        mode = 0o600
    tmp = path.with_name(f"{path.name}.maisecrets.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _header_key(headers: dict) -> str | None:
    return next((h for h in headers if isinstance(h, str) and h.lower() == HEADER.lower()), None)


def _kid_in(value: object) -> str | None:
    m = _HEADER_RE.fullmatch(value) if isinstance(value, str) else None
    return m.group("kid") if m else None


def ensure_headers(cfg: dict, backend) -> str | None:
    """At session start (Claude Code): the header on every user-scope server with an https URL, one key per origin.
    A header of ours (a kid this profile made) goes again from an entry that no longer qualifies, and from every
    entry with `client_header` false; a header someone else wrote stays. Only `mcpServers.<name>.headers` changes.
    The keys are made before the client's lock is taken, so the lock is held for a re-read and a write only; a file
    that is not valid JSON is not touched, and a backup is written before a change. Returns one line for the
    session-start message, or None."""
    if HOME != _DEFAULT_HOME and not os.environ.get("CLAUDE_CONFIG_DIR"):
        return None                         # a test home never changes the client config of the person
    path = claude_json()
    first = _read_json(path) if path.is_file() else None
    if first is None:
        return None
    on = cfg.get("client_header", True) is not False
    keys: dict[str, bytes] = {}
    if on:
        for url in user_servers(first).values():
            origin = origin_of(url)
            if origin not in keys:
                # one step under maisecrets' own lock: two starts at once made two keys, and the header could name
                # the one the store lost (Fable review, round 3)
                with _lock_for(DIR / ".lock"):
                    keys[origin] = _key(backend, origin, create=True)
                    _remember_key(origin, kid_of(keys[origin]))
    ours = {v.get("kid") for v in _known_keys().values() if isinstance(v, dict)} | {kid_of(k) for k in keys.values()}
    backup = path.with_name(path.name + ".maisecrets-backup")
    if _apply_headers(copy.deepcopy(first), keys, ours) == ([], []):
        # nothing to change: no lock, and the backup of the last change goes (it holds every server's credentials)
        try:
            backup.unlink()
        except OSError:
            pass
        return None
    with _ConfigLock(path):
        data = _read_json(path)
        if data is None:
            return None
        added, removed = _apply_headers(data, keys, ours)
        if not added and not removed:
            return None
        shutil.copy2(path, backup)
        os.chmod(backup, 0o600)
        _write_config(path, data)
    parts = []
    if added:
        parts.append(f"maisecrets added its {HEADER} header to {len(added)} MCP server(s) in {path}, so a server that "
                     "supports it can give values back to this computer")
    if removed:
        parts.append(f"maisecrets removed its {HEADER} header from {len(removed)} MCP server(s) in {path}")
    return "; ".join(parts) + f" (backup until the next start: {backup.name}; client_header false turns it off)."


def _apply_headers(data: dict, keys: dict, ours: set) -> tuple[list[str], list[str]]:
    """Change the headers in data (the parsed config) in place; returns (added, removed) server names."""
    added: list[str] = []
    removed: list[str] = []
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            headers = spec.get("headers")
            if headers is not None and not isinstance(headers, dict):
                continue                       # a shape we do not know: left as it is
            have = _header_key(headers or {})
            origin = origin_of(spec.get("url"))
            want = header_value(keys[origin]) if origin in keys else None
            if want is None:
                if have and _kid_in(headers[have]) in ours:
                    del headers[have]
                    if not headers:
                        del spec["headers"]
                    removed.append(name)
                continue
            if have == HEADER and headers[have] == want:
                continue
            headers = spec.setdefault("headers", {})
            if have:
                del headers[have]
            headers[HEADER] = want
            added.append(name)
    return added, removed


# --------------------------------------------------------------- the notes --
def _off(cfg: dict | None) -> bool:
    return cfg is not None and cfg.get("client_header", True) is False


def note_result(payload: dict, cfg: dict) -> int:
    """PostToolUse: note each server-range token of an MCP result from a user-scope server with a key. The result
    stays as it is. Returns the number of tokens noted."""
    if cfg.get("client_header", True) is False:
        return 0
    tool = str(payload.get("tool_name") or "")
    server = payload.get("mcp_server") if isinstance(payload.get("mcp_server"), dict) else {}
    if not tool.startswith("mcp__") or server.get("source") != "user" or not isinstance(server.get("name"), str):
        return 0
    found: dict[str, str] = {}

    def walk(node) -> None:
        if isinstance(node, str):
            for m in SERVER_REF_RE.finditer(node):
                found[f"{m.group('type')}_{m.group('n')}"] = m.group("type")
        elif isinstance(node, list):
            for x in node:
                walk(x)
        elif isinstance(node, dict):
            for x in node.values():
                walk(x)
    walk(payload.get("tool_response"))
    if not found:
        return 0
    url = user_servers().get(server["name"])
    origin = origin_of(url)
    if not origin or origin not in _known_keys():
        return 0
    session = payload.get("session_id")
    if not isinstance(session, str) or not session:
        return 0
    seen = _now_iso()
    with _lock_for(DIR / ".lock"):
        data = _read_json(NOTES) or {}
        mine = data.setdefault(profile(), {}).setdefault(origin, {})
        for key, type_ in found.items():
            old = mine.pop(key, None)           # re-inserted last: the oldest notes are first
            old = old if isinstance(old, dict) else {}
            where = old.get("seen") if isinstance(old.get("seen"), dict) else {}
            sessions = [x for x in (old.get("sessions") or []) if isinstance(x, str) and x != session]
            # one entry per server URL: two servers on one origin can both send EMAIL_1, for two people
            mine[key] = {"type": type_, "seen": {**where, url: seen},
                         "sessions": (sessions + [session])[-MAX_SESSIONS_PER_NOTE:]}
        while len(mine) > MAX_NOTES_PER_ORIGIN:
            del mine[next(iter(mine))]
        atomic_write(NOTES, json.dumps(data, indent=1))
    return len(found)


def _seen_time(value: object) -> float | None:
    import calendar
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")) if isinstance(value, str) else None
    except ValueError:
        return None


def _notes(session: str | None) -> dict:
    """origin -> key -> {"type", "seen": {url: seen_at}}: what this client profile saw in this session, in the last
    NOTE_TTL. A token that another session saw stays text here, as a stored value of another session does (C4)."""
    mine = (_read_json(NOTES) or {}).get(profile())
    if not isinstance(mine, dict) or not session:
        return {}
    now = time.time()
    out: dict = {}
    for origin, notes in mine.items():
        if not isinstance(notes, dict):
            continue
        for key, note in notes.items():
            if not isinstance(note, dict) or session not in (note.get("sessions") or []):
                continue
            seen = note.get("seen") if isinstance(note.get("seen"), dict) else {}
            fresh = {u: t for u, t in seen.items()
                     if isinstance(u, str) and (_seen_time(t) or 0) > now - NOTE_TTL}
            if fresh:
                out.setdefault(origin, {})[key] = {"type": note.get("type"), "seen": fresh}
    return out


def noted(keys: list[str], session: str | None) -> dict[str, list[str]]:
    """key -> the origins that noted it for this session, for the keys that any origin noted."""
    out: dict[str, list[str]] = {}
    for origin, mine in _notes(session).items():
        if not isinstance(mine, dict):
            continue
        for key in keys:
            if isinstance(mine.get(key), dict):
                out.setdefault(key, []).append(origin)
    return out


def noted_elsewhere(text: str, cfg: dict | None, session: str | None) -> list[str]:
    """The server tokens of text that this profile noted, but not for this session or not in the last NOTE_TTL: they
    get a reason, as a stored value of another session does. A token never noted stays text."""
    refs = list(dict.fromkeys(k for k, _a, _b in find(text)))
    if _off(cfg) or not refs:
        return []
    here = noted(refs, session)
    mine = (_read_json(NOTES) or {}).get(profile())
    if not isinstance(mine, dict):
        return []
    return [k for k in refs if k not in here
            and any(isinstance(notes, dict) and isinstance(notes.get(k), dict) for notes in mine.values())]


def find_noted(text: str, cfg: dict | None, session: str | None) -> list[tuple[str, int, int]]:
    """The server-range tokens in text that a server result noted for this session; any other one stays text, and
    every one does when client_header is off."""
    refs = find(text)
    if not refs or _off(cfg):
        return []
    known = noted(list(dict.fromkeys(k for k, _a, _b in refs)), session)
    return [r for r in refs if r[0] in known]


# --------------------------------------------------------------- transport --
def _cafile(cfg: dict) -> str | None:
    f = cfg.get("client_vault_cafile")
    return f if isinstance(f, str) and f else None


def _request(cfg: dict, method: str, url: str, headers: dict, body: bytes | None, deadline: float):
    """_send in a thread that the caller waits for until the deadline only: a socket timeout bounds one read, not a
    server that sends one header line every few seconds."""
    import threading
    box: dict = {}

    def run() -> None:
        try:
            box["ok"] = _send(cfg, method, url, headers, body, deadline)
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            box["err"] = exc
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(max(0.0, deadline - time.monotonic()) + 0.1)
    if "ok" in box:
        return box["ok"]
    if "err" in box:
        raise box["err"]
    raise TimeoutError("the server took too long")


def _send(cfg: dict, method: str, url: str, headers: dict, body: bytes | None, deadline: float):
    """One HTTPS request with no redirect and no proxy. Returns (status, headers, body) with the body cut above
    MAX_ANSWER_BYTES + 1, so a longer body is seen as too long."""
    parts = urlsplit(url)
    left = deadline - time.monotonic()
    if left <= 0.2:
        raise TimeoutError("no time left")
    ctx = ssl.create_default_context(cafile=_cafile(cfg))
    conn = http.client.HTTPSConnection(parts.hostname, 443 if parts.port is None else parts.port,
                                       timeout=min(CONNECT_TIMEOUT, left),
                                       context=ctx)
    try:
        conn.connect()
        conn.sock.settimeout(min(SOCKET_TIMEOUT, max(0.2, deadline - time.monotonic())))
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request(method, path, body=body, headers=headers)
        answer = conn.getresponse()
        chunks, size = [], 0
        while size <= MAX_ANSWER_BYTES:
            if time.monotonic() > deadline:
                raise TimeoutError("the answer took too long")
            chunk = answer.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return answer.status, {k.lower(): v for k, v in answer.getheaders()}, b"".join(chunks)
    finally:
        conn.close()


def _is_json(headers: dict) -> bool:
    return headers.get("content-type", "").split(";")[0].strip().lower() == "application/json"


def endpoint(cfg: dict, url: str, deadline: float) -> str | None:
    """The resolve endpoint that the server of this MCP URL names (RFC 9728 metadata, `client_vault_endpoint`): an
    https URL of the same origin, or None. Kept per origin and path for METADATA_TTL, either way."""
    origin = origin_of(url)
    if not origin:
        return None
    path = urlsplit(url).path.rstrip("/")
    cache_key = origin + path
    cache = _read_json(ENDPOINTS) or {}
    hit = cache.get(cache_key)
    try:
        age = time.time() - float(hit.get("t")) if isinstance(hit, dict) else -1.0
    except (TypeError, ValueError):
        age = -1.0
    if 0 <= age < METADATA_TTL:
        cached = hit.get("endpoint")
        if cached is None:
            return None
        if isinstance(cached, str) and origin_of(cached) == origin:
            return cached
    found = None
    try:
        status, headers, body = _request(cfg, "GET", f"{origin}/.well-known/oauth-protected-resource{path}",
                                         {"Accept": "application/json"}, None, deadline)
        if status == 200 and _is_json(headers) and len(body) <= MAX_ANSWER_BYTES:
            meta = json.loads(body.decode("utf-8"))
            candidate = meta.get("client_vault_endpoint") if isinstance(meta, dict) else None
            if origin_of(candidate) == origin:
                found = candidate
    except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
        return None                             # not cached: the next call asks again
    with _lock_for(DIR / ".lock"):
        cache = _read_json(ENDPOINTS) or {}
        cache[cache_key] = {"endpoint": found, "t": time.time()}
        atomic_write(ENDPOINTS, json.dumps(cache, indent=1))
    return found


# ---------------------------------------------------------------- the resolve --
_CODES = {(401, "unknown_key"), (403, "pending"), (403, "clock_skew"), (404, "unknown_ref"), (410, "expired"),
          (429, "rate_limited"), (503, "disabled")}


def _safe_time(value: object) -> str | None:
    return value if isinstance(value, str) and _TIME_RE.fullmatch(value) else None


def _why(origin: str, status: int, code: str | None, body: dict, headers: dict, keys: list[str]) -> str:
    host = urlsplit(origin).hostname
    names = ", ".join(f"⟦{k}⟧" for k in keys)
    if code == "unknown_key":
        return (f"{host} does not know this computer's key yet. It learns it at the next login to that server "
                "from this client")
    if code == "pending":
        when = _safe_time(body.get("activates_at")) or "later"
        return (f"{host} links this computer from {when}, or earlier when the person confirms the notice the "
                "server sent them")
    if code == "clock_skew":
        return f"the clock of this computer is off by more than 5 minutes for {host}; the person fixes the clock"
    if code == "unknown_ref":
        return f"{host} does not know one of {names}; use only tokens from a result of that server"
    if code == "expired":
        return f"{names} are older than {host}'s data; read the data again and use the new tokens"
    if code == "rate_limited":
        after = headers.get("retry-after", "")
        return f"{host} reached its limit" + (f"; try again in {after} s" if after.isdigit() else "; try later")
    if code == "disabled":
        return f"{host} has switched this off"
    return f"{host} gave no usable answer (HTTP {status})"


def resolve(cfg: dict, backend, keys: list[str], session: str | None,
            deadline: float | None = None) -> dict[str, tuple[str, str]]:
    """key -> (value, origin) for every key, or Refused. All or nothing, for every origin together."""
    if not keys:
        return {}
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    if _off(cfg):
        raise Refused("vault references are off (client_header false)")
    notes = _notes(session)
    where_from: dict[str, set] = {}
    for origin, mine in notes.items():
        for k in keys:
            note = mine.get(k) if isinstance(mine, dict) else None
            seen = note.get("seen") if isinstance(note, dict) else None
            for url in (seen if isinstance(seen, dict) else {}):
                where_from.setdefault(k, set()).add((origin, url))
    ambiguous = [k for k in keys if len(where_from.get(k, ())) > 1]
    if ambiguous:
        raise Refused(f"⟦{ambiguous[0]}⟧ came from more than one server, so maisecrets cannot tell which one to ask")
    groups: dict[tuple[str, str], list[str]] = {}
    for k in keys:
        if k not in where_from:
            raise Refused(f"⟦{k}⟧ was not seen in a result of an MCP server")
        groups.setdefault(next(iter(where_from[k])), []).append(k)
    current = set(user_servers().values())
    out: dict[str, tuple[str, str]] = {}
    for (origin, url), mine in groups.items():
        host = urlsplit(origin).hostname
        if len(mine) > MAX_REFS:
            raise Refused(f"{len(mine)} tokens of {host} in one call; at most {MAX_REFS} go in one call")
        if url not in current or origin_of(url) != origin:
            raise Refused(f"{host} is no longer a user-scope MCP server of this client")
        k = _key(backend, origin, create=False)
        if k is None:
            raise Refused(f"this computer has no key for {host}; a new session writes it")
        where = endpoint(cfg, url, deadline)
        if not where:
            raise Refused(f"{host} does not name a vault endpoint, or could not be reached")
        body = json.dumps({"now": _now_iso(),
                           "refs": [{"key": key, "seen_at": notes[origin][key]["seen"][url]} for key in mine]}).encode()
        if len(body) > MAX_REQUEST_BYTES:
            raise Refused(f"the request to {host} is larger than 64 KB")
        try:
            status, headers, raw = _request(cfg, "POST", where, {"Authorization": f"Bearer {bearer_of(k)}",
                                                                 "Content-Type": "application/json",
                                                                 "Accept": "application/json"}, body, deadline)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise Refused(f"{host} could not be reached ({type(exc).__name__})") from None
        answer = None
        if len(raw) <= MAX_ANSWER_BYTES and _is_json(headers):
            try:
                answer = json.loads(raw.decode("utf-8"))
            except ValueError:
                answer = None
        answer = answer if isinstance(answer, dict) else None
        if status == 200 and answer is not None:
            values = answer.get("values")
            if isinstance(values, dict) and all(isinstance(values.get(key), str) for key in mine):
                for key in mine:
                    out[key] = (values[key], origin)
                continue
            raise Refused(f"{host} gave no usable answer (a value is missing or not text)")
        code = answer.get("error") if answer is not None else None
        code = code if (status, code) in _CODES else None
        raise Refused(_why(origin, status, code, answer or {}, headers, mine))
    return out


def probe(cfg: dict, backend, origin: str, url: str) -> str:
    """The binding state of one origin for /maisecrets:status: a resolve with no tokens."""
    k = _key(backend, origin, create=False)
    if k is None:
        return "no key yet (a new session writes it)"
    deadline = time.monotonic() + BUDGET
    where = endpoint(cfg, url, deadline)
    if not where:
        return "the server names no vault endpoint (or could not be reached)"
    try:
        status, headers, raw = _request(cfg, "POST", where, {"Authorization": f"Bearer {bearer_of(k)}",
                                                             "Content-Type": "application/json"},
                                        json.dumps({"now": _now_iso(), "refs": []}).encode(), deadline)
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return f"could not be reached ({type(exc).__name__})"
    try:
        answer = json.loads(raw.decode("utf-8")) if _is_json(headers) and len(raw) <= MAX_ANSWER_BYTES else None
    except ValueError:
        answer = None
    answer = answer if isinstance(answer, dict) else {}
    if status == 200:
        return "linked"
    code = answer.get("error")
    if (status, code) == (403, "pending"):
        return f"pending until {_safe_time(answer.get('activates_at')) or 'a time the server did not give'}"
    if (status, code) == (401, "unknown_key"):
        return "not linked (the next login to that server links it)"
    return f"unknown (HTTP {status}{', ' + code if isinstance(code, str) and (status, code) in _CODES else ''})"


def remember_released(backend, session: str | None, values: dict[str, tuple[str, str]]) -> None:
    """The values a server gave for this session go into the store as one entry with no placeholder, for
    RELEASE_WINDOW: a command that prints one, or an Edit result that shows it, is redacted to the server's token
    like a value the session resolved (Fable review). Older entries leave the store here."""
    if not session or not values:
        return
    now = time.time()
    name = "_maisecrets_vrel_" + secrets.token_hex(12)
    backend.put(name, json.dumps([[v, f"{OPEN}{k}{CLOSE}"] for k, (v, _o) in values.items()]),
                label="maisecrets server values", comment="maisecrets: values a server gave, for one hour; "
                                                          "not a placeholder value.")
    with _lock_for(DIR / ".lock"):
        data = _prune(backend, _read_json(RELEASED) or {}, now)
        data.setdefault(session, []).append({"name": name, "t": now})
        atomic_write(RELEASED, json.dumps(data, indent=1))


def _expired(item: object, now: float) -> bool:
    try:
        return not isinstance(item, dict) or not 0 <= now - float(item.get("t")) < RELEASE_WINDOW
    except (TypeError, ValueError):
        return True


def _prune(backend, data: dict, now: float) -> dict:
    """data without the entries older than RELEASE_WINDOW; their values leave the store."""
    out: dict = {}
    for sess, items in data.items():
        keep = []
        for item in items if isinstance(items, list) else []:
            if not _expired(item, now):
                keep.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                try:
                    backend.delete(item["name"])
                except (RuntimeError, OSError):
                    keep.append(item)            # tried again at the next prune
        if keep:
            out[sess] = keep
    return out


def prune_released(backend) -> None:
    """At session start and when an expired entry is seen: the values older than their hour leave the store."""
    data = _read_json(RELEASED)
    if not data:
        return
    now = time.time()
    if not any(_expired(i, now) for items in data.values() for i in (items if isinstance(items, list) else [None])):
        return
    with _lock_for(DIR / ".lock"):
        data = _prune(backend, _read_json(RELEASED) or {}, now)
        if data:
            atomic_write(RELEASED, json.dumps(data, indent=1))
        else:
            try:
                RELEASED.unlink()
            except OSError:
                pass


def released(backend, session: str | None) -> list[tuple[str, str]]:
    """(value, token) for every value a server gave this session in the last RELEASE_WINDOW."""
    items = (_read_json(RELEASED) or {}).get(session or "") if session else None
    out: list[tuple[str, str]] = []
    now = time.time()
    if any(_expired(i, now) for i in (items if isinstance(items, list) else [])):
        prune_released(backend)
    for item in items if isinstance(items, list) else []:
        if _expired(item, now):
            continue
        raw = backend.get(str(item.get("name")))
        try:
            pairs = json.loads(raw) if raw else []
        except ValueError:
            pairs = []
        out.extend((v, t) for v, t in pairs if isinstance(v, str) and isinstance(t, str))
    return out


def has_released() -> bool:
    """Any value a server gave in the last hour, in any session: then the output hook opens the store."""
    now = time.time()
    data = _read_json(RELEASED) or {}
    return any(not _expired(i, now) for items in data.values() for i in (items if isinstance(items, list) else []))


def audit(values: dict[str, tuple[str, str]], session: str | None, tool: str, context: str) -> bool:
    """One audit line per value, as for a stored value; the key carries the host. False when it cannot be written."""
    try:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(HOME / "audit.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            ctx = context.replace("\n", " ").replace("\t", " ")[:160]
            for key, (_value, origin) in values.items():
                f.write(f"{stamp}\t{(session or '-')[:8]}\t{key}@{urlsplit(origin).hostname}\t{tool}\t{ctx}\n")
        return True
    except OSError:
        return False


def status_lines(cfg: dict, backend, check: bool = True) -> list[str]:
    """One line per user-scope server of this profile."""
    if cfg.get("client_header", True) is False:
        return ["vault references: off (client_header false)"]
    if HOME != _DEFAULT_HOME and not os.environ.get("CLAUDE_CONFIG_DIR"):
        return ["vault references: off, because this maisecrets home is not the default one and CLAUDE_CONFIG_DIR "
                "is not set"]
    servers = user_servers()
    if not servers:
        return ["vault references: no user-scope MCP server with an https URL"]
    known = _known_keys()
    lines = []
    for name, url in servers.items():
        origin = origin_of(url)
        if origin not in known:
            lines.append(f"vault references: {name} ({origin}): no key yet (a new session writes it)")
            continue
        state = probe(cfg, backend, origin, url) if check else "not checked"
        lines.append(f"vault references: {name} ({origin}): {state}")
    return lines
