# Vendored from the phase6 ai-gateway, src/security/pii_display.py, blob
# fc6e2df22172ad5f7fad0f0e3b9a7bd44a35b9c7 (branch feat/1396-one-resolvable-token-with-a-display-level,
# commit 8b26ee76f, 2026-09-26). Kept byte-identical below this header so both sides render the
# same display for the same value; refresh by copying the file again and updating this header.
"""The reversible PII token and the display levels it can carry.

A value the gateway pseudonymises becomes ONE token, ``⟦EMAIL_1:ma•••@gmail.com⟧``:

* The KEY (``EMAIL_1``) is what resolves. It is minted per user and entity
  type from a counter and never derived from the value, so it does not link a
  person across users or days. It is always present.
* The DISPLAY (after the colon) is what the model and the reader can read.
  Its detail is the display LEVEL. The level never decides whether the token
  resolves; a token with its display changed or removed resolves the same.

Levels, from most to least readable: ``cleartext`` (no token at all),
``support``, ``standard``, ``minimal`` (key only). The ids are stable storage
values; the page names them separately.

The brackets are U+27E6/U+27E7 and the masking character is U+2022. Both were
measured against the syntaxes a token reaches without rehydration (Markdown,
HTML, Confluence storage format, Slack and Jira markup, URL, SQL ``LIKE``,
regex): ``<…>`` is a tag or a Slack control sequence, ``[…]`` a Jira link and a
regex class, ``*`` a regex quantifier, and ``x`` makes a display read as a real
address to the one-way scrubber.

Everything here is pure: no Redis, no config load. Callers pass the freemail
allowlist in.
"""

from __future__ import annotations

import re
from typing import FrozenSet, Optional, Tuple

OPEN = "⟦"
CLOSE = "⟧"
BULLET = "•"

CLEARTEXT = "cleartext"
SUPPORT = "support"
STANDARD = "standard"
MINIMAL = "minimal"

#: Most readable first. The page lists them in this order.
LEVELS: Tuple[str, ...] = (CLEARTEXT, SUPPORT, STANDARD, MINIMAL)

#: What an absent, unknown or malformed stored level means. The error case of
#: a guard must not be its loose case.
FAIL_SAFE_LEVEL = MINIMAL

#: Levels whose display shows part of the value. ``minimal`` shows nothing and
#: ``cleartext`` emits no token.
PARTIAL_LEVELS: Tuple[str, ...] = (SUPPORT, STANDARD)

KEY_PREFIX = {
    "email": "EMAIL",
    "phone": "PHONE",
    "credit_card": "CARD",
    "iban": "IBAN",
    "ip_address": "IP",
    "ip_address_v6": "IPV6",
}
ENTITY_BY_PREFIX = {prefix: entity for entity, prefix in KEY_PREFIX.items()}

# IPV6 before IP: the alternation takes the first branch that matches.
_PREFIX_ALT = "|".join(sorted(KEY_PREFIX.values(), key=len, reverse=True))

#: A key the gateway mints: ``EMAIL_1``. Counters start at 1. The number is
#: bounded: a key comes from text anybody can write, and an unbounded run of
#: digits would reach ``int()`` and its conversion limit.
GATEWAY_KEY_RE = re.compile(rf"(?:{_PREFIX_ALT})_[1-9][0-9]{{0,8}}")

#: The highest number a gateway key can spell.
MAX_KEY_NUMBER = 999_999_999

#: A key a client minted before the value reached the gateway (maisecrets):
#: ``EMAIL_c1``, ``DE_TAX_ID_c3``. The ``c`` keeps the two counters apart. The
#: gateway never resolves these — its mapping does not hold them — and a
#: write that needs the value is refused rather than sent with the reference.
CLIENT_KEY_RE = re.compile(r"[A-Z][A-Z_]{0,39}?_c[0-9]{1,9}")

#: Either kind of key.
KEY_RE = re.compile(rf"(?:{GATEWAY_KEY_RE.pattern}|{CLIENT_KEY_RE.pattern})")

#: A whole token as the gateway writes it. The display may not contain a
#: bracket or a line break, and is bounded so a stray opening bracket cannot
#: make one match run across a document.
TOKEN_RE = re.compile(
    rf"{OPEN}(?P<key>{KEY_RE.pattern})(?::(?P<display>[^{OPEN}{CLOSE}\r\n]{{0,256}}))?{CLOSE}"
)


def _alternatives(char: str, *extra: str) -> str:
    """``char`` as it may arrive: raw, percent-encoded UTF-8, a JSON or an HTML escape.

    Only the escape spellings are case-insensitive. The key itself is matched
    exactly: rehydration never guesses, so a token a model re-cased is left
    as written rather than resolved.
    """
    code = ord(char)
    pct = "".join(f"%{b:02X}" for b in char.encode("utf-8"))
    forms = [re.escape(char), f"(?i:{re.escape(pct)})", f"(?i:\\\\u{code:04x})",
             f"&#{code};", f"(?i:&#x{code:x};)", *extra]
    return "(?:" + "|".join(forms) + ")"


#: A token in any of the encodings a tool argument can carry: in a URL query
#: (``%E2%9F%A6EMAIL_1%3A…%E2%9F%A7``), a JSON string (``\u27e6EMAIL_1…``) or
#: an HTML body. Only the key is read; the display between the colon and the
#: closing bracket may be changed, re-encoded or missing.
_OPEN_ALT = _alternatives(OPEN)

#: The display may not run over another opening bracket: a token whose closing
#: bracket was lost must not swallow the next token and the text between.
ENCODED_TOKEN_RE = re.compile(
    _OPEN_ALT
    + rf"(?P<key>{KEY_RE.pattern})"
    + r"(?:(?::|(?i:%3A)|(?i:\\u003a))(?P<display>(?:(?!" + _OPEN_ALT + r")[^\r\n]){0,256}?))?"
    + _alternatives(CLOSE)
)

#: A display written without its key, for each entity type: what a model puts
#: in prose. Bounded candidate shapes; `is_display` decides.
BARE_DISPLAY_RE = {
    "phone": re.compile(rf"\+[0-9]{{1,3}}{BULLET}+[0-9]{{2,4}}"),
    "credit_card": re.compile(rf"[0-9{BULLET}]{{4}}(?:[ -]?[0-9{BULLET}]{{4}}){{2,3}}|[0-9{BULLET}]{{12,19}}"),
    "iban": re.compile(rf"[A-Z]{{2}}[0-9]{{2}}{BULLET}+[0-9A-Z]{{4}}"),
    "ip_address": re.compile(rf"[0-9]{{1,3}}\.[0-9]{{1,3}}\.(?:[0-9]{{1,3}}|{BULLET})\.{BULLET}"),
    "ip_address_v6": re.compile(rf"(?:[0-9a-fA-F]{{1,4}}:){{1,3}}{BULLET}{{3}}"),
}

#: The same, with the key matched case-insensitively. Only for refusing a
#: write: a token a model re-cased is never resolved, so it must still be
#: recognised as unresolved rather than stored as if it were a value.
ENCODED_TOKEN_RE_CI = re.compile(ENCODED_TOKEN_RE.pattern, re.IGNORECASE)

_CARD_KEEP_SUPPORT = (6, 4)  # PCI DSS v4.0 Req. 3.4.1: never more than BIN + last 4
_CARD_KEEP_STANDARD = (0, 4)


def is_client_key(key: str) -> bool:
    return bool(CLIENT_KEY_RE.fullmatch(key))


def entity_for_key(key: str) -> Optional[str]:
    """The entity type a key names, or ``None`` for a type the gateway has no
    display rules for (a client's ``DE_TAX_ID_c1``, ``SECRET_c2``)."""
    return ENTITY_BY_PREFIX.get(key.rsplit("_", 1)[0])


def render_token(key: str, display: str) -> str:
    return f"{OPEN}{key}:{display}{CLOSE}" if display else f"{OPEN}{key}{CLOSE}"


def normalise_level(raw: object) -> str:
    """A stored level as a known id, or the fail-safe for anything else.

    Exact match only. The writer stores exact ids, so a padded or re-cased
    value was put there by something else, and guessing what it meant is the
    loose direction.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    value = raw if isinstance(raw, str) else ""
    return value if value in LEVELS else FAIL_SAFE_LEVEL


# ---------------------------------------------------------------------------
# Display transforms
#
# Each one is a fixed point on its own output: displaying a display changes
# nothing. That property is how a display is recognised from the value alone
# (``is_display``), so every branch below keeps it — including inputs that
# already carry bullets.
# ---------------------------------------------------------------------------

def _email(value: str, level: str, freemail: FrozenSet[str]) -> str:
    if "@" not in value:
        return value
    local, domain = value.rsplit("@", 1)
    if not local:
        return value
    stripped = local.rstrip(BULLET)
    if stripped != local:
        # Already a display: keep what it shows, at most the two characters
        # a display ever shows.
        head = stripped[:2]
    else:
        # At least two characters stay hidden. "hr@" shows nothing of the
        # local part; "abc@" shows "a"; five or more show two.
        head = local[: max(0, min(2, len(local) - 2))]
    if level == STANDARD and domain.lower() not in freemail:
        tld = domain.rsplit(".", 1)[1] if "." in domain else ""
        domain = f"{BULLET * 3}.{tld}" if tld else BULLET * 3
    return f"{head}{BULLET * 3}@{domain}"


#: Characters a display always hides, at least. A value too short to hide
#: this many at the level asked for shows fewer, or nothing but the key.
MIN_HIDDEN = 3


def _phone(value: str, level: str) -> str:
    # The first two digits stand in for the country code. A number does not
    # say where its country code ends (+1 vs +49 vs +353), so the display
    # promises "first two digits", not "country code".
    digits = re.sub(r"[^0-9]", "", value)
    tail = 2 if level == STANDARD else 4
    if BULLET in value:
        # Already a display: re-render what it shows, never more than the tail.
        if len(digits) < 2:
            return value
        return f"+{digits[:2]}{BULLET * 6}{digits[2:][-tail:] if len(digits) > 2 else ''}"
    tail = min(tail, len(digits) - 2 - MIN_HIDDEN)
    if tail < 0:
        return value
    return f"+{digits[:2]}{BULLET * 6}{digits[-tail:] if tail else ''}"


def _card(value: str, level: str) -> str:
    chars = [c for c in value if c.isdigit() or c == BULLET]
    digits = [c for c in chars if c.isdigit()]
    first, last = _CARD_KEEP_SUPPORT if level == SUPPORT else _CARD_KEEP_STANDARD
    if len(chars) < 12 or len(digits) < first + last:
        return value
    # Depends only on the length, which a display keeps, so this stays a
    # fixed point: fewer leading digits when the number is short.
    first = max(0, min(first, len(chars) - last - MIN_HIDDEN))
    body = "".join(chars)
    masked = body[:first] + BULLET * (len(body) - first - last) + body[-last:]
    sep = "-" if "-" in value else (" " if " " in value else "")
    if not sep:
        return masked
    return sep.join(masked[i:i + 4] for i in range(0, len(masked), 4))


def _iban(value: str) -> str:
    compact = value.replace(" ", "").replace("-", "")
    if len(compact) < 8:
        return value
    return compact[:4] + BULLET * (len(compact) - 8) + compact[-4:]


def _ipv4(value: str, level: str) -> str:
    parts = value.split(".")
    if len(parts) != 4:
        return value
    keep = 3 if level == SUPPORT else 2
    return ".".join(parts[:keep] + [BULLET] * (4 - keep))


def _ipv6(value: str, level: str) -> str:
    keep = 3 if level == SUPPORT else 2
    # Only the hextets BEFORE a `::` are the routing prefix. After it comes
    # the host part, which must never show: `2a01::5` keeps `2a01`, not `5`.
    leading = value.split("::", 1)[0]
    head = [h for h in leading.split(":") if h and BULLET not in h][:keep]
    if not head:
        return BULLET * 3
    return ":".join(head) + ":" + BULLET * 3


def display(value: str, entity_type: str, level: str,
            freemail: FrozenSet[str] = frozenset()) -> str:
    """The display part for ``value`` at ``level``; ``""`` for ``minimal``.

    ``cleartext`` returns the value: at that level no token is written, and a
    caller that asks anyway gets the only honest answer.
    """
    level = normalise_level(level)
    if level == CLEARTEXT:
        return value
    if level == MINIMAL:
        return ""
    if entity_type == "email":
        shown = _email(value, level, freemail)
    elif entity_type == "phone":
        shown = _phone(value, level)
    elif entity_type == "credit_card":
        shown = _card(value, level)
    elif entity_type == "iban":
        shown = _iban(value)
    elif entity_type == "ip_address":
        shown = _ipv4(value, level)
    elif entity_type == "ip_address_v6":
        shown = _ipv6(value, level)
    else:
        return ""
    # Every transform returns an input it cannot parse unchanged — a phone
    # number in Arabic-Indic digits has too few ASCII digits for `_phone`. A
    # display that masked nothing would carry the detected value in full, so
    # the key alone is shown instead. The bullet is the mark that something
    # was masked.
    return shown if BULLET in shown else ""


def is_display(value: str, entity_type: str,
               freemail: FrozenSet[str] = frozenset()) -> bool:
    """True when ``value`` IS a display of some partial level, from the value alone.

    Level-agnostic on purpose: a display written at ``support`` for one
    service comes back through another service that runs ``standard``, and
    must still be recognised there.

    Both halves are required. The fixed point alone is not enough, because
    every transform returns a malformed input unchanged (no ``@``, too few
    digits); the bullet is the one mark a display always carries and a value
    the gateway did not write does not.
    """
    if entity_type not in KEY_PREFIX or BULLET not in value:
        return False
    return any(display(value, entity_type, lv, freemail) == value for lv in PARTIAL_LEVELS)


def token_is_ours(key: str, shown: Optional[str],
                  freemail: FrozenSet[str] = frozenset()) -> bool:
    """Whether a token found in text can be passed through unscrubbed.

    Only when its display is empty or is itself a display. Anything else in
    the display position is text somebody wrote into a token shape — a value
    such as ``⟦EMAIL_9:real.name@example.org⟧`` — and must be scrubbed like
    any other text. An exemption for "our tokens" that did not check the
    display would be an exemption anybody can type.
    """
    entity = entity_for_key(key)
    if not shown:
        return entity is not None or is_client_key(key)
    if entity is None:
        # A client's type without display rules carries no display; one that
        # does was written by somebody else and is scanned.
        return False
    return is_display(shown, entity, freemail)
