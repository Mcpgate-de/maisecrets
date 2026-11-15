"""User names in prose after a user cue and in a user-id element (#51, the gap to Cloakroom 1.4.0 on the V3 samples:
Nemotron 82 values), read by key_values.hits in the tool channel. Kept out of personal.py, which is at the size limit
of a release file; it imports personal.py only when it runs."""
from __future__ import annotations

import re

# a handle: parts joined by . _ or -, letters with digits at the end, or a CamelCase pair; a word alone is no handle
_HANDLE = (r"(?:[A-Za-z][A-Za-z0-9]{1,20}(?:[._-][A-Za-z0-9]{1,20}){1,3}|[A-Za-z]{2,20}\d{1,6}"
           r"|[A-Z][a-z]{1,15}[A-Z][a-z0-9]{1,15})")
# the cues: `for user kalin.orbek`, `User kalin.orbek successfully logged in`, `Welcome, kalin_orb_42.`, and `my
# username is korbek` (a plain word too after `is`)
_CUE_RE = re.compile(
    r"(?:(?i:\b(?:for|by|from|the|a) user)|(?:^|(?<=[\n:]))[ \t]*User|(?i:\bwelcome),)[ \t]+(" + _HANDLE + r")"
    r"(?=[.,;:!?)\s]|$)", re.M)
_LOGIN_VERB_RE = re.compile(r"[ \t]+(?:successfully|logged|signed|accessed|failed|was|has|reported|attempted)\b")
_IS_RE = re.compile(r"(?i)\bmy user ?name is[ \t]+([A-Za-z][A-Za-z0-9._-]{1,30}?)(?=[.,;:!?)\s]|$)")
_WORDS = ("user", "welcome")


def user_names(text: str) -> list:
    """(start, end) of a user name after a cue in prose."""
    low = text.lower()
    if not any(w in low for w in _WORDS):
        return []
    from .core import _word_set
    from .personal import _username_value_ok
    out = []
    for m in _CUE_RE.finditer(text):
        v = m.group(1)
        cue = m.group(0)[:m.start(1) - m.start()].strip()
        # `User x` at the start of a line or after a colon names an account only before a verb of a login
        if cue == "User" and not _LOGIN_VERB_RE.match(text, m.end(1)):
            continue
        if _username_value_ok(v, False, " ") and _handle_ok(v, _word_set()):
            out.append((m.start(1), m.end(1)))
    for m in _IS_RE.finditer(text):
        v = m.group(1).rstrip("._-")
        # _username_value_ok refuses a word of the word list (`my username is visible`)
        if _username_value_ok(v, False, " "):
            out.append((m.start(1), m.start(1) + len(v)))
    return out


def _handle_ok(v: str, known) -> bool:
    """A person's handle, not a placeholder or words of the word list: one part of letters is no word of the list and
    longer than two letters (x86_64, v1.2.3, my_app and john.doe stay text)."""
    from .personal import PLACEHOLDER_NAMES
    parts = [p for p in re.split(r"[._-]|(?<=[a-z])(?=[A-Z])", v) if p]
    letters = [re.sub(r"\d+$", "", p) for p in parts if not p.isdigit()]
    if " ".join(letters).lower() in PLACEHOLDER_NAMES:
        return False
    return any(len(w) > 2 and w.lower() not in known for w in letters)


# a key whose value is a user name and that personal.py's username label does not read (#51)
USER_ID_KEYS = frozenset({"userid", "userlogin", "loginname", "loginid", "accountname", "screenname", "handle"})


def user_id_ok(v: str) -> bool:
    from .personal import _username_value_ok
    return bool(re.fullmatch(_HANDLE + r"|[A-Za-z][a-z]{2,20}", v)) and _username_value_ok(v, False, " ")
