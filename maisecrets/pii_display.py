"""The human-readable display part of a PII placeholder, ``⟦EMAIL_c1:ma•••@example.org⟧``.

Written for maisecrets from the rules in ``docs/PROTOCOL.md`` §1 (this file replaces an
earlier copy of another project's implementation, 2026-09-26). The contract:

* The KEY (``EMAIL_c1``) is what resolves. The DISPLAY after the colon is for the
  reader only; a model may drop or change it and the key still resolves.
* A display always hides part of the value and marks the hidden part with the
  bullet U+2022. A value the rules cannot mask gets no display at all: the key
  alone is safer than a display that shows everything.
* Two levels: ``standard`` (the default; what the model sees) shows less,
  ``support`` shows a little more for a human on a support desk. ``minimal`` is
  the key alone. ``cleartext`` returns the value; nothing is masked at that level.
* Every rule is idempotent: masking a display again gives the same display, so a
  display is recognisable as one from the text alone.

The bullet and the brackets were chosen against the syntaxes a placeholder
travels through unresolved (Markdown, HTML, Slack and Jira markup, URL, SQL LIKE,
regex): ``<…>`` is a tag, ``[…]`` a link or a regex class, ``*`` a quantifier.
Everything here is pure; the freemail list is passed in by the caller.
"""
from __future__ import annotations

import re
from typing import FrozenSet

BULLET = "•"

CLEARTEXT = "cleartext"
SUPPORT = "support"
STANDARD = "standard"
MINIMAL = "minimal"
LEVELS = (CLEARTEXT, SUPPORT, STANDARD, MINIMAL)

_MIN_HIDDEN = 3          # a display hides at least this many characters
_DIGITS_RE = re.compile(r"\D+")


def normalise_level(raw: object) -> str:
    """A known level id, else ``standard`` (the safe direction for an unknown value)."""
    return raw if isinstance(raw, str) and raw in LEVELS else STANDARD


def _mask_email(value: str, level: str, freemail: FrozenSet[str]) -> str:
    local, sep, domain = value.rpartition("@")
    if not sep or not local:
        return value
    shown = local.rstrip(BULLET)
    if shown != local:
        head = shown[:2]                       # a display: keep what it shows, never more
    else:
        head = local[: max(0, min(2, len(local) - 2))]   # hr@ shows nothing, abc@ shows a, longer shows two
    if level == STANDARD and domain.lower() not in freemail:
        # a company domain names the customer; only the top-level label stays
        tld = domain.rpartition(".")[2] if "." in domain else ""
        domain = f"{BULLET * 3}.{tld}" if tld else BULLET * 3
    return f"{head}{BULLET * 3}@{domain}"


def _mask_phone(value: str, level: str) -> str:
    digits = _DIGITS_RE.sub("", value)
    tail = 2 if level == STANDARD else 4
    if BULLET in value:                        # a display: re-render, never widen the tail
        return value if len(digits) < 2 else f"+{digits[:2]}{BULLET * 6}{digits[2:][-tail:]}"
    tail = min(tail, len(digits) - 2 - _MIN_HIDDEN)
    if tail < 0:
        return value
    # the first two digits stand in for the country code; a number does not say where its
    # country code ends, so the display promises "first two digits", not "country code"
    return f"+{digits[:2]}{BULLET * 6}{digits[-tail:] if tail else ''}"


def _mask_card(value: str, level: str) -> str:
    chars = [c for c in value if c.isdigit() or c == BULLET]
    digits = [c for c in chars if c.isdigit()]
    first, last = (6, 4) if level == SUPPORT else (0, 4)
    if len(chars) < 12 or len(digits) < first + last:
        return value
    first = max(0, min(first, len(chars) - last - _MIN_HIDDEN))
    body = "".join(chars)
    masked = body[:first] + BULLET * (len(body) - first - last) + body[-last:]
    sep = "-" if "-" in value else (" " if " " in value else "")
    if not sep:
        return masked
    return sep.join(masked[i:i + 4] for i in range(0, len(masked), 4))


def _mask_iban(value: str) -> str:
    compact = value.replace(" ", "").replace("-", "")
    if len(compact) < 8:
        return value
    return compact[:4] + BULLET * (len(compact) - 8) + compact[-4:]


def _mask_ipv4(value: str, level: str) -> str:
    parts = value.split(".")
    if len(parts) != 4:
        return value
    keep = 3 if level == SUPPORT else 2
    return ".".join(parts[:keep] + [BULLET] * (4 - keep))


def _mask_ipv6(value: str, level: str) -> str:
    keep = 3 if level == SUPPORT else 2
    # only the hextets before a `::` are the routing prefix; the host part never shows
    if BULLET not in value:
        # a value that is only its prefix (`2a00:1450::`) would show whole: hide one hextet more
        keep = min(keep, len([h for h in value.split(":") if h]) - 1)
    head = [h for h in value.split("::", 1)[0].split(":") if h and BULLET not in h][:max(keep, 0)]
    return (":".join(head) + ":" + BULLET * 3) if head else BULLET * 3


_RULES = {
    "email": lambda v, level, fm: _mask_email(v, level, fm),
    "phone": lambda v, level, fm: _mask_phone(v, level),
    "credit_card": lambda v, level, fm: _mask_card(v, level),
    "iban": lambda v, level, fm: _mask_iban(v),
    "ip_address": lambda v, level, fm: _mask_ipv4(v, level),
    "ip_address_v6": lambda v, level, fm: _mask_ipv6(v, level),
}


def display(value: str, entity_type: str, level: str = STANDARD,
            freemail: FrozenSet[str] = frozenset()) -> str:
    """The display part for ``value`` at ``level``; ``""`` when nothing safe can be shown."""
    level = normalise_level(level)
    if level == CLEARTEXT:
        return value
    if level == MINIMAL:
        return ""
    rule = _RULES.get(entity_type)
    if rule is None:
        return ""
    shown = rule(value, level, freemail)
    # a rule returns an input it cannot parse unchanged; without a bullet nothing was hidden
    return shown if BULLET in shown else ""


def is_display(value: str, entity_type: str, freemail: FrozenSet[str] = frozenset()) -> bool:
    """True when ``value`` is a display at some level: masking it again changes nothing."""
    if BULLET not in value:
        return False
    return any(display(value, entity_type, level, freemail) == value for level in (STANDARD, SUPPORT))
