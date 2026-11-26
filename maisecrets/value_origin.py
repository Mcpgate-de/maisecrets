"""Where a value that maisecrets masked by itself came from (#108): the tool whose result held it and the key it stood
after. The store keeps both on a new entry from a tool result (Entry.found_in, Entry.found_at); the permission prompt
of a call that gets the real value names them. A person who stored no value could not tell what "check the value"
asked for: the prompt said the same for an 8-digit token of a gateway answer as for a stored password. Also the
fields of a call that hold a placeholder (_ref_fields), for the same prompt."""
from __future__ import annotations

import json
import re
from typing import Any

from .placeholder import find_refs

# the key just before a value: `"grade_token": "`, `token=`, `api_key: '`. Not after `//` (the user part of a URL)
_KEY_BEFORE = re.compile(r"""(?<![/\w])["']?([A-Za-z_][A-Za-z0-9_]{0,40})["']?\s*(?:=>|:=|[:=])\s*["'`]?\s*\Z""")
_LOOK_BACK = 64
# a key is kept only when one of its words names a credential and every other word is one of these too or a neutral
# word: the index holds no other text of a tool result, so a name, a user, a domain or a random string that stands as a
# key (or in it, `<name>_password`) never gets there (review of #108: C10, C26)
_LABEL_WORDS = frozenset("token key secret password passwd pwd pass passphrase auth api apikey credential credentials "
                         "session cookie bearer access refresh client private signature sig hash code otp pin "
                         "grade nonce salt".split())
_NEUTRAL_WORDS = frozenset("id x type value header my new old".split())


def _label(key: str) -> str | None:
    words = [w.lower() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", key)]
    ok = words and all(w in _LABEL_WORDS or w in _NEUTRAL_WORDS for w in words) and \
        any(w in _LABEL_WORDS for w in words)
    return key if ok else None


def found(text: str, matches: list, tool: str) -> list[tuple[str, str | None]]:
    """(tool, key) for each match, in the order of `matches`: the key is the label word before the value, or None."""
    out = []
    for m in matches:
        k = _KEY_BEFORE.search(text[max(0, m.start - _LOOK_BACK):m.start])
        out.append((tool, _label(k.group(1)) if k else None))
    return out


def prompt_tail(vault, keys: list[str], tool: str) -> str:
    """The end of the prompt for a call that gets the real values of `keys` (Vault.origin reads each record). A
    value the person stored keeps the request to check target and value. For a value that maisecrets stored by itself
    from a tool result, the prompt names the origin and asks only about the target: it says facts and no verdict. One
    MCP server can serve many services (a gateway), so the same server is not the same destination (review of #108)."""
    lines = []
    own = []
    for key in keys:
        m = vault.origin(key)
        src = str(m.get("found_in") or "")
        if not src:
            own.append(f"⟦{key}⟧")
            continue
        at = f"key {m['found_at']} in " if m.get("found_at") else ""
        lines.append(f" maisecrets stored ⟦{key}⟧ by itself, because it looked like a secret ({at}a result of {src}).")
    if lines:
        lines.append(" Check that this call may get " + ("these values." if len(lines) > 1 else "this value."))
    if own and lines:
        lines.append(f" Check the target and {', '.join(own)} before you allow it.")
    elif own:
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
