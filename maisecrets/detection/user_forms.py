"""User names in prose after a user cue and in a user-id element (#51, the gap to Cloakroom 1.4.0 on the V3 samples:
Nemotron 82 values), read by key_values.hits in the tool channel. Kept out of personal.py, which is at the size limit
of a release file; it imports personal.py only when it runs."""
from __future__ import annotations

import re

# a handle: parts joined by . _ or -, or letters with digits at the end; a word alone is no handle
_HANDLE = r"(?:[A-Za-z][A-Za-z0-9]{1,20}(?:[._-][A-Za-z0-9]{1,20}){1,3}|[A-Za-z]{2,20}\d{1,6})"
# a CamelCase pair (KalinOrbek) names a person only before a login verb; else it is a class or a product name
_CAMEL = r"[A-Z][a-z]{1,15}[A-Z][a-z0-9]{1,15}"
# the cues: `for user kalin.orbek`, `for invalid user k.orbek` (sshd), `User kalin.orbek successfully logged in` (also
# after a log prefix), `Welcome, kalin_orb_42.` and `Welcome back, ...`
_CUE_RE = re.compile(
    r"(?:(?i:\b(?:for|by|from|the|a|invalid) user)|(?i:\buser)|(?i:\bwelcome(?: back)?),)[ \t]+(" + _HANDLE + "|"
    + _CAMEL + r")(?=[.,;:!?)\s]|$)")
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
        cue = m.group(0)[:m.start(1) - m.start()].strip().lower()
        login = bool(_LOGIN_VERB_RE.match(text, m.end(1)))
        # `user x` alone names an account only before a verb of a login (`User kalin.orbek logged in`)
        if cue == "user" and not login:
            continue
        if re.fullmatch(_CAMEL, v) and not login:
            continue
        if _username_value_ok(v, False, " ") and _handle_ok(v, _word_set()):
            out.append((m.start(1), m.end(1)))
    for m in _IS_RE.finditer(text):
        v = m.group(1).rstrip("._-")
        # _username_value_ok refuses a word of the word list of 3 letters or more (`my username is visible`)
        if len(v) > 2 and _username_value_ok(v, False, " "):
            out.append((m.start(1), m.start(1) + len(v)))
    return out


def _handle_ok(v: str, known) -> bool:
    """A person's handle, not a device, a hex id or words of the word list: each part is letters with digits at the
    end at most, a part of letters is not all capitals, longer than two letters and no word of the list, and one
    has four letters or more (x86_64, v1.2.3, my_app, django_app, john.doe, eth0, SAML2, utf-8 and
    pod-7f9c stay text)."""
    parts = [p for p in re.split(r"[._-]|(?<=[a-z])(?=[A-Z])", v) if p]
    if any(not re.fullmatch(r"[A-Za-z]+\d*|\d+", p) for p in parts):
        return False
    letters = [re.sub(r"\d+$", "", p) for p in parts if not p.isdigit()]
    if not letters or max(len(w) for w in letters) < 4:
        return False
    return all(len(w) > 2 and not w.isupper() and w.lower() not in known for w in letters)


# a key whose value is a user name and that personal.py's username label does not read (#51); not `handle` or
# `screenName`, which name product slugs and app screens as often
USER_ID_KEYS = frozenset({"userid", "userlogin", "loginname", "loginid"})


def user_id_ok(v: str) -> bool:
    from .core import _word_set
    return bool(re.fullmatch(_HANDLE, v)) and _handle_ok(v, _word_set())
