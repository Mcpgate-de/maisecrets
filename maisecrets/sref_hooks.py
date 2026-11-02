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


def program_of(command: str) -> str:
    """The name of the program a command runs, for the process sink: the first word after any VAR=value."""
    for word in command.split():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", word):
            return os.path.basename(word)[:255] or "sh"
    return "sh"
