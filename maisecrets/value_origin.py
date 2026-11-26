"""Where a value that maisecrets masked by itself came from (#108): the tool whose result held it and the key it stood
after. The store keeps both on a new entry from a tool result (Entry.found_in, Entry.found_at); the permission prompt
of a call that gets the real value names them. A person who stored no value could not tell what "check the value"
asked for: the prompt said the same for an 8-digit token of a gateway answer as for a stored password."""
from __future__ import annotations

import json
import re
from typing import Any

from .placeholder import find_refs

# the key just before a value: `"grade_token": "`, `token=`, `api_key: '`
_KEY_BEFORE = re.compile(r"""["']?([A-Za-z_][\w.-]{0,63})["']?\s*(?:=>|:=|[:=])\s*["'`]?\s*\Z""")
_LOOK_BACK = 96


def found(text: str, matches: list, tool: str) -> list[tuple[str, str | None]]:
    """(tool, key) for each match, in the order of `matches`: the key is the word before the value, or None."""
    out = []
    for m in matches:
        k = _KEY_BEFORE.search(text[max(0, m.start - _LOOK_BACK):m.start])
        out.append((tool, k.group(1) if k else None))
    return out


def _server(tool: str) -> tuple[str, str]:
    """(server, tool) of `mcp__server__tool`; ("", tool) for a tool of the client."""
    parts = tool.split("__")
    return (parts[1], "__".join(parts[2:])) if len(parts) >= 3 and parts[0] == "mcp" else ("", tool)


def prompt_tail(vault, keys: list[str], tool: str) -> str:
    """The end of the prompt for a call that gets the real values of `keys` (Vault.origin reads each record). A
    value the person stored keeps the old request to check target and value; a value maisecrets masked by itself
    in a tool result is named with its origin, so the person can see that it is probably no secret."""
    meta = {k: vault.origin(k) for k in keys}
    own = [k for k, m in meta.items() if not m.get("found_in")]
    lines = []
    server = _server(tool)[0]
    for key, m in meta.items():
        src = str(m.get("found_in") or "")
        if not src:
            continue
        s_server, s_tool = _server(src)
        at = f"key {m['found_at']} in " if m.get("found_at") else ""
        where = f"{at}a result of {s_tool}" + (f" on {s_server}" if s_server else "")
        lines.append(f" You did not store ⟦{key}⟧: maisecrets masked it by itself, because it looked like a secret "
                     f"({where}).")
        if s_server and s_server == server:
            lines.append(" This call sends it back to the same server. If you do not know the value as a secret, it "
                         "is probably none, and you can allow the call.")
        else:
            lines.append(" This call sends it to another place than the one that sent it. Allow the call only if "
                         "that place may get the value.")
    if own:
        lines.append(" Check the target and the value before you allow it.")
    return "".join(lines)


def _ref_fields(node: Any, path: str = "") -> list[str]:
    """Paths of the string fields that hold a placeholder (`messages[0].text`), once each. A
    string that is itself a JSON object or array is walked too, so `{"params": "{\"text\": …}"}`
    names `params.text` (review, 2026-09-27: the list index cut the path to `messages`)."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(_ref_fields(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(_ref_fields(v, f"{path}[{i}]"))
    elif isinstance(node, str) and find_refs(node):
        inner = None
        if node.lstrip()[:1] in ("{", "["):
            try:
                inner = json.loads(node)
            except ValueError:
                inner = None
        nested = _ref_fields(inner, path) if isinstance(inner, (dict, list)) else []
        out.extend(nested or [path or "(input)"])
    return list(dict.fromkeys(out))
