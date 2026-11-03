"""Sensitive References in the hooks (hooks.py calls these): the references a command or a file of this session may
resolve, their values from the gateway's resolver, and their name in the audit. Kept apart from hooks.py, whose file
must stay under the size limit of the plugin directory."""
from __future__ import annotations

import os
import re


def note(payload: dict) -> None:
    """PostToolUse of an MCP tool: note the references of its result for this session (sref_notes.py)."""
    import json
    if not str(payload.get("tool_name") or "").startswith("mcp__") or \
            "sref:" not in json.dumps(payload.get("tool_response"), ensure_ascii=False):
        return
    from . import sref_notes
    from .hooks import client_of
    if client_of(payload) == "codex":
        from . import codex_vault
        payload = {**payload, "mcp_server": codex_vault.mcp_server_of(payload) or {}}
    sref_notes.note_result(payload)


def canonical(text: str, session: str | None, cfg: dict | None = None) -> str:
    """text with each server token (vault_refs.canonical_noted) and each reference this session received in its
    canonical form, without the display part. The display is chosen by whoever wrote the text; a quote or `$(` in it
    moved the shell analysis of a command (Fable review, 2026-11-02: `⟦sref:email:ID:'⟧ | base64` passed the
    refusals). The canonical form holds [A-Za-z0-9_:-] only."""
    from . import vault_refs
    text = vault_refs.canonical_noted(text, cfg, session)
    if "sref:" not in text:
        return text
    from . import sref_client, sref_notes
    found = sref_client.find(text)
    here = sref_notes.noted([r for r, _c, _a, _b in found], session)
    out = text
    for r, c, a, b in sorted(found, key=lambda x: -x[2]):
        if r in here:
            out = out[:a] + c + out[b:]
    return out


def refs(text: str, session: str | None, ctxs=None) -> tuple[list, list]:
    """The Sensitive References of text (sref_notes.py): (key, start, end) of each one this session received, the
    key being the reference without its brackets, and the ones it did not receive (they get a reason)."""
    if "sref:" not in text:
        return [], []
    from . import sref_client, sref_notes
    found = [(r, a, b) for r, _c, a, b in sref_client.find(text) if ctxs is None or ctxs[a] != "comment"]
    refs = [r for r, _a, _b in found]
    here = sref_notes.noted(refs, session)
    return [(r[1:-1], a, b) for r, a, b in found if r in here], sref_notes.noted_elsewhere(refs, session)


def audit_name(key: str) -> str:
    """The name of a server key in the audit; a Sensitive Reference by its kind and 4 characters of its id only (the
    id resolves for its user, so it is never written whole)."""
    if key.startswith("sref:"):
        kind, _sep, rest = key[5:].partition(":")
        return f"sref:{kind}:{rest[:4]}…"
    return key


def fetch(cfg: dict, backend, keys: list[str], session: str | None, sink: tuple[str, str]) -> dict:
    """key -> (value, origin) for each Sensitive Reference, from the resolver of the gateway that sent it, all or
    none; raises Refused (fixed text and counts only) otherwise."""
    from urllib.parse import urlsplit

    from . import sref_client, sref_notes
    here = sref_notes.noted([f"⟦{k}⟧" for k in keys], session)
    by_gateway: dict = {}
    for k in keys:
        if f"⟦{k}⟧" in here:               # only noted keys come here; any other one stays text
            by_gateway.setdefault(here[f"⟦{k}⟧"], []).append(k)
    out: dict = {}
    for (origin, url), ks in by_gateway.items():
        host = urlsplit(origin).hostname
        found = sref_client.discover(cfg, url)
        if not found:
            raise sref_client.Refused(f"{host} offers no resolver for references")
        if not sref_client.logged_in(backend, origin):
            raise sref_client.Refused(f"maisecrets has no login to {host} yet; the user runs /maisecrets:sref login "
                                      "once (in Codex: run.sh sref login)")
        canon = {k: sref_client.find(f"⟦{k}⟧")[0][1] for k in ks}
        values = sref_client.resolve(cfg, backend, found, list(dict.fromkeys(canon.values())), sink[0], sink[1])
        out.update({k: (values[c], origin) for k, c in canon.items()})
    return out


def precheck(cfg: dict, backend, keys: list[str], session: str | None) -> str | None:
    """Before a Bash command: each reference has a gateway that offers a resolver and a login there; else the reason,
    as server_values._server_fetch words it. It resolves nothing: the command fetches the value itself when it starts
    (grant, redeem)."""
    from urllib.parse import urlsplit

    from . import sref_client, sref_notes
    here = sref_notes.noted([f"⟦{k}⟧" for k in keys], session)
    why = None
    for origin, url in dict.fromkeys(here[f"⟦{k}⟧"] for k in keys if f"⟦{k}⟧" in here):
        host = urlsplit(origin).hostname
        if not sref_client.discover(cfg, url):
            why = f"{host} offers no resolver for references"
        elif not sref_client.logged_in(backend, origin):
            why = f"maisecrets has no login to {host} yet; the user runs /maisecrets:sref login once (in Codex: " \
                  "run.sh sref login)"
        if why:
            names = ", ".join(f"⟦{k}⟧" for k in keys)
            return (f"maisecrets: cannot get the value of {names} from the server that sent it: {why}. Do not ask "
                    "the user for the value; tell them this reason.")
    return None


GRANT_SECONDS = 120


def _grants():
    from .vault import HOME
    d = HOME / "sref" / "grants"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def grant(cfg: dict, key: str, session: str | None, program: str, command: str) -> str:
    """A one-time grant for one reference of a Bash command: the command redeems it when it starts
    (hooks/sref_value.py). A command that the client refuses after this hook never starts, so its reference is never
    resolved (prod run, 2026-11-03: a refused command still cost a resolve). Expired grants go here."""
    import json
    import secrets
    import time
    d = _grants()
    now = time.time()
    for f in d.glob("*.json"):
        try:
            if now - f.stat().st_mtime > GRANT_SECONDS:
                f.unlink()
        except OSError:
            pass
    nonce = secrets.token_urlsafe(18)
    path = d / f"{nonce}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"key": key, "session": session, "program": program, "command": command[:2000], "t": now}, f)
    return nonce


def redeem(nonce: str) -> str:
    """The value of the reference of a grant, once and within GRANT_SECONDS: the resolve (sink process), the audit line
    and the release for the echo replacement happen here, when the command really starts. Raises Refused."""
    import json
    import time

    from . import sref_client, vault_refs
    from .server_values import _server_release
    from .vault import Vault, load_config
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce or ""):
        raise sref_client.Refused("no such grant")
    d = _grants()
    path, taken = d / f"{nonce}.json", d / f"{nonce}.taken"
    try:
        os.replace(path, taken)                 # one redeem: a second one finds no file
    except OSError:
        raise sref_client.Refused("the grant was used or has expired") from None
    try:
        g = json.loads(taken.read_text(encoding="utf-8"))
    finally:
        taken.unlink()
    if time.time() - float(g.get("t", 0)) > GRANT_SECONDS:
        raise sref_client.Refused("the grant has expired")
    cfg = load_config()
    vault = Vault(cfg)
    key, session = g["key"], g.get("session")
    got = fetch(cfg, vault.backend, [key], session, ("process", g.get("program") or "sh"))
    _released, why = _server_release(vault, got, session, "Bash", g.get("command") or "")
    if why:
        raise vault_refs.Refused(why)
    return got[key][0]


def read_call(nonce: str) -> str:
    """The command substitution that reads one reference's value under its grant when the command starts."""
    import sys
    from pathlib import Path
    py = Path(sys.executable).as_posix()
    script = (Path(__file__).resolve().parent.parent / "hooks" / "sref_value.py").as_posix()
    return f'$("{py}" "{script}" {nonce})'


def program_of(command: str) -> str:
    """The name of the program a command runs, for the process sink: the first word after any VAR=value."""
    for word in command.split():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", word):
            return os.path.basename(word)[:255] or "sh"
    return "sh"
