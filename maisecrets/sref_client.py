"""Sensitive References: the resolver client of maisecrets (ai-gateway docs/security/sensitive-references-1576/
16-resolver-client-contract.md, profiles oauth-resolver-1, local-file-1 and mcpgate-process-1).

A gateway that writes canonical references (`⟦sref:<kind>:<id>⟧`, optionally with a display part) into tool results
resolves them for a client of its own: maisecrets logs in once (OAuth 2.1, PKCE S256, a loopback redirect, the
person consents in the browser), keeps the token in the store, and asks for the values when the model writes a
reference into a file or a command. The model sees only the reference. This is the successor of the vault
references (vault_refs.py, the Client-Vault header) and runs beside them behind the setting `sref_resolver` until it
is proven end to end.

- Discovery: `GET /.well-known/oauth-protected-resource[<path>]` names `sensitive_references.resolve_endpoint`,
  its scope and its sink profiles; the authorization server's metadata names the authorize, token and register
  endpoints.
- Resolve: `POST <resolve_endpoint>` with `Authorization: Bearer srefr_…`, the references, the sink type
  (`local_file` with the file's path, or `process` with the command's name) and gets all values or one error with
  counts. A refused batch is shown as counts; the client never retries one reference at a time.
- The token: `srefr_…` for one hour, a refresh token for 30 days that rotates on each use. Both live in the store,
  under one entry per gateway origin; never in a file of the plugin, never in a log.

Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

from .vault_refs import Refused, _is_json, _net_errors, _request, origin_of

OPEN, CLOSE = "⟦", "⟧"
# the canonical form, with the optional display part a gateway may add (it is for the model; the resolver reads the id)
SREF_RE = re.compile(rf"{OPEN}sref:(?P<kind>[A-Za-z0-9_-]{{1,32}}):(?P<id>[A-Za-z0-9_-]{{20,128}})"
                     rf"(?::(?P<display>[^{OPEN}{CLOSE}]{{0,80}}))?{CLOSE}")
SCOPE = "sensitive-references.resolve"
SINKS = {"local_file": "local-file-1", "process": "mcpgate-process-1"}
MAX_REFS = 100
MAX_REQUEST_BYTES = 64 * 1024
BUDGET = 8.0
_STORE_PREFIX = "_maisecrets_sref_"


def find(text: str) -> list:
    """(reference, canonical, start, end) for each reference in the text; canonical drops the display part."""
    return [(m.group(0), f"{OPEN}sref:{m.group('kind')}:{m.group('id')}{CLOSE}", m.start(), m.end())
            for m in SREF_RE.finditer(text)]


def _get_json(cfg: dict, url: str, deadline: float) -> dict | None:
    try:
        status, headers, body = _request(cfg, "GET", url, {"Accept": "application/json"}, None, deadline)
    except _net_errors():
        return None
    if status != 200 or not _is_json(headers):
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def discover(cfg: dict, mcp_url: str, deadline: float | None = None) -> dict | None:
    """The resolver of the gateway behind an MCP URL: {"origin", "resolve", "scope", "sinks", "authorize", "token",
    "register"}, or None when the gateway names none. Every endpoint must be https on the same origin."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    origin = origin_of(mcp_url)
    if not origin:
        return None
    path = urlsplit(mcp_url).path
    path = "" if path == "/" else path
    meta = _get_json(cfg, f"{origin}/.well-known/oauth-protected-resource{path}", deadline)
    block = meta.get("sensitive_references") if meta else None
    if not isinstance(block, dict) or origin_of(block.get("resolve_endpoint")) != origin:
        return None
    auth = _get_json(cfg, f"{origin}/.well-known/oauth-authorization-server", deadline) or {}
    ends = {k: auth.get(f"{k}_endpoint") for k in ("authorization", "token", "registration")}
    if any(origin_of(v) != origin for v in ends.values()):
        return None
    sinks = block.get("sink_profiles")
    return {"origin": origin, "resolve": block["resolve_endpoint"], "scope": block.get("resolve_scope") or SCOPE,
            "sinks": [s for s in sinks if isinstance(s, str)] if isinstance(sinks, list) else [],
            "authorize": ends["authorization"], "token": ends["token"], "register": ends["registration"]}


# ---------------------------------------------------------------- the token in the store --
def _entry(origin: str) -> str:
    return _STORE_PREFIX + hashlib.sha256(origin.encode()).hexdigest()[:16]


def _load(backend, origin: str) -> dict:
    try:
        raw = backend.get(_entry(origin))
        data = json.loads(raw) if raw else {}
    except (ValueError, TypeError, AttributeError):
        data = {}
    return data if isinstance(data, dict) else {}


def _keep(backend, origin: str, data: dict) -> None:
    backend.put(_entry(origin), json.dumps(data), label=f"maisecrets resolver login {origin}")


def forget(backend, origin: str) -> None:
    """Log out of one gateway: the tokens and the client id go."""
    try:
        backend.delete(_entry(origin))
    except (KeyError, AttributeError):
        pass


def logged_in(backend, origin: str) -> bool:
    return bool(_load(backend, origin).get("refresh"))


# ---------------------------------------------------------------- login --
def pkce() -> tuple:
    """(verifier, S256 challenge)."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register(cfg: dict, found: dict, redirect: str, deadline: float) -> str:
    """A client id from the gateway's registration endpoint (RFC 7591) for this loopback redirect."""
    body = json.dumps({"client_name": "maisecrets resolver", "redirect_uris": [redirect],
                       "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                       "token_endpoint_auth_method": "none", "scope": found["scope"]}).encode()
    try:
        status, headers, raw = _request(cfg, "POST", found["register"], {"Content-Type": "application/json",
                                                                         "Accept": "application/json"}, body, deadline)
    except _net_errors() as exc:
        raise Refused(f"the gateway could not be reached ({type(exc).__name__})") from None
    try:
        client_id = json.loads(raw.decode("utf-8")).get("client_id") if _is_json(headers) else None
    except (ValueError, RecursionError, AttributeError):
        client_id = None
    if status not in (200, 201) or not isinstance(client_id, str) or not client_id:
        raise Refused(f"the gateway did not register the resolver (HTTP {status})")
    return client_id


def authorize_url(found: dict, client_id: str, redirect: str, challenge: str, state: str) -> str:
    from urllib.parse import parse_qsl, urlunsplit
    parts = urlsplit(found["authorize"])
    query = parse_qsl(parts.query, keep_blank_values=True) + list({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect, "scope": found["scope"],
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
        "resource": found["origin"]}.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _token(cfg: dict, found: dict, form: dict, deadline: float) -> dict:
    try:
        status, headers, raw = _request(cfg, "POST", found["token"],
                                        {"Content-Type": "application/x-www-form-urlencoded",
                                         "Accept": "application/json"}, urlencode(form).encode(), deadline)
    except _net_errors() as exc:
        raise Refused(f"the gateway could not be reached ({type(exc).__name__})") from None
    try:
        data = json.loads(raw.decode("utf-8")) if _is_json(headers) else None
    except (ValueError, RecursionError):
        data = None
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("access_token"), str) \
            or not isinstance(data.get("refresh_token"), str):
        code = data.get("error") if isinstance(data, dict) else None
        if code == "invalid_grant":
            raise _Revoked(f"the gateway no longer accepts the login (HTTP {status}); run the login again")
        raise Refused(f"the gateway gave no token (HTTP {status}"
                      f"{', ' + code if code in _TOKEN_ERRORS else ''}); run the login again")
    return data


def finish_login(cfg: dict, backend, found: dict, client_id: str, redirect: str, code: str, verifier: str,
                 deadline: float | None = None) -> None:
    """The code from the loopback redirect, exchanged for the tokens, which go into the store."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    data = _token(cfg, found, {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                               "client_id": client_id, "code_verifier": verifier}, deadline)
    _keep(backend, found["origin"], {"client_id": client_id, "access": data["access_token"],
                                     "refresh": data["refresh_token"],
                                     "expires": time.time() + float(data.get("expires_in") or 3600)})


class _Revoked(Refused):
    """The authorization server refused the refresh token for good (invalid_grant): the login is gone."""


# the codes of the contract that an answer may name; any other string from the gateway is never shown, as it could
# carry a value or a reference id (codex review, 2026-11-02)
_TOKEN_ERRORS = frozenset({"invalid_grant", "invalid_client", "invalid_request", "unsupported_grant_type",
                           "access_denied", "invalid_scope", "invalid_target"})
_REASONS = frozenset({"unknown", "revoked", "expired", "malformed", "not_issued"})
_FORBIDDEN = {"insufficient_scope": "the login lacks the resolve scope", "not_enabled": "the person is not allowed to "
              "resolve references", "ineligible_sink": "this sink is not allowed"}


def _access(cfg: dict, backend, found: dict, deadline: float, renew: bool = False) -> str:
    rec = _load(backend, found["origin"])
    if not rec.get("refresh"):
        raise Refused(f"maisecrets is not logged in at {urlsplit(found['origin']).hostname}; "
                      "the person runs /maisecrets:sref login")
    if not renew and rec.get("access") and float(rec.get("expires") or 0) - time.time() > 60:
        return rec["access"]
    # the refresh token rotates on each use: the new pair replaces the old one at once; a refused one is forgotten,
    # so the next call asks for a login instead of trying it again
    try:
        data = _token(cfg, found, {"grant_type": "refresh_token", "refresh_token": rec["refresh"],
                                   "client_id": rec.get("client_id", "")}, deadline)
    except _Revoked:
        forget(backend, found["origin"])
        raise
    _keep(backend, found["origin"], {**rec, "access": data["access_token"], "refresh": data["refresh_token"],
                                     "expires": time.time() + float(data.get("expires_in") or 3600)})
    return data["access_token"]


# ---------------------------------------------------------------- resolve --
def _counts(reasons: object, batch: int) -> str:
    """The reasons of a refused batch, only the categories of the contract with a plausible count."""
    if not isinstance(reasons, dict):
        return ""
    parts = [f"{n} {k}" for k, n in sorted(reasons.items(), key=lambda kv: str(kv[0]))
             if k in _REASONS and type(n) is int and 0 < n <= batch]
    return ", ".join(parts)


def resolve(cfg: dict, backend, found: dict, refs: list, sink_type: str, destination: str,
            deadline: float | None = None) -> dict:
    """canonical reference -> value for every reference, or Refused (with counts, never a value or an id). All or
    nothing. sink_type is "local_file" (destination: the file's path) or "process" (the command's name)."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET
    canon = list(dict.fromkeys(refs))
    if not canon:
        return {}
    host = urlsplit(found["origin"]).hostname
    if sink_type not in SINKS:
        raise Refused(f"unknown sink {sink_type!r}")
    if SINKS[sink_type] not in found.get("sinks", []):
        raise Refused(f"{host} does not resolve into a {'file' if sink_type == 'local_file' else 'command'}")
    if not isinstance(destination, str) or not 1 <= len(destination) <= 4096:
        raise Refused("the destination must be 1 to 4096 characters")
    if len(canon) > MAX_REFS:
        raise Refused(f"{len(canon)} references in one call; at most {MAX_REFS} go in one call")
    body = json.dumps({"references": canon, "sink_type": sink_type, "destination": destination}).encode()
    if len(body) > MAX_REQUEST_BYTES:
        raise Refused(f"the request to {host} is larger than 64 KB")
    for attempt in (0, 1):
        token = _access(cfg, backend, found, deadline, renew=attempt == 1)
        try:
            status, headers, raw = _request(cfg, "POST", found["resolve"],
                                            {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                             "Accept": "application/json"}, body, deadline)
        except _net_errors() as exc:
            raise Refused(f"{host} could not be reached ({type(exc).__name__})") from None
        try:
            answer = json.loads(raw.decode("utf-8")) if _is_json(headers) else None
        except (ValueError, RecursionError):
            answer = None
        answer = answer if isinstance(answer, dict) else {}
        if status == 401 and attempt == 0:
            continue                       # an access token that expired early: one refresh, then once again
        break
    if status == 200:
        values = answer.get("values")
        if isinstance(values, dict) and all(isinstance(values.get(r), str) for r in canon):
            return {r: values[r] for r in canon}
        raise Refused(f"{host} gave no usable answer (a value is missing or not text)")
    code = answer.get("error")
    if status == 409 and code == "unresolvable":
        detail = _counts(answer.get("reasons"), len(canon))
        raise Refused(f"{host} resolved none of the {len(canon)} references"
                      + (f" ({detail})" if detail else "") + "; use only references from a current result")
    if status == 429:
        raise Refused(f"{host} reached the daily limit of resolved values; try again tomorrow")
    if status == 401:
        raise Refused(f"the login at {host} is no longer valid (consent withdrawn or expired); "
                      "the person runs /maisecrets:sref login")
    if status == 403:
        why = _FORBIDDEN.get(code, "forbidden") if isinstance(code, str) else "forbidden"
        raise Refused(f"{host} refused the resolve ({why})")
    raise Refused(f"{host} gave no usable answer (HTTP {status})")


def login(cfg: dict, backend, found: dict, open_browser, wait: float = 300.0) -> None:
    """The whole login: a loopback listener on 127.0.0.1 (a free port), the registration for its redirect, the
    browser at the authorize URL (`open_browser(url)`), the code back from the redirect (its state must match), and
    the tokens into the store. The listener answers one request and closes."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs

    box: dict = {}
    state = secrets.token_urlsafe(16)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a) -> None:
            pass

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(parts.query).items()}
            ok = parts.path == "/callback" and q.get("state") == state and bool(q.get("code"))
            if ok:
                box["code"] = q["code"]
            elif parts.path == "/callback" and q.get("state") == state and q.get("error") == "access_denied":
                box["denied"] = True
            page = (b"maisecrets: logged in. You can close this tab." if ok else
                    b"maisecrets: the login did not complete. Run it again.")
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    redirect = f"http://127.0.0.1:{httpd.server_address[1]}/callback"
    end = time.monotonic() + wait

    def serve() -> None:
        # until the callback of this login, the person's refusal, the time or 32 requests: another local process
        # that sends a request first gets an error page and does not end the login (codex review, 2026-11-02)
        for _ in range(32):
            left = end - time.monotonic()
            if left <= 0 or "code" in box or "denied" in box:
                return
            httpd.timeout = left
            httpd.handle_request()
    t = threading.Thread(target=serve, daemon=True)
    try:
        deadline = time.monotonic() + BUDGET
        client_id = register(cfg, found, redirect, deadline)
        verifier, challenge = pkce()
        t.start()
        open_browser(authorize_url(found, client_id, redirect, challenge, state))
        t.join(wait + 1)
    finally:
        httpd.server_close()
    if "code" not in box:
        raise Refused("the login did not complete: " + ("the person declined it" if box.get("denied") else
                                                         "no matching answer from the browser in time"))
    finish_login(cfg, backend, found, client_id, redirect, box["code"], verifier)
