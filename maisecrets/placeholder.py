"""Placeholder tokens: key plus optional display part.

Form: ``⟦TYPE_cN⟧`` or ``⟦TYPE_cN:display⟧`` (U+27E6 / U+27E7, mask character
U+2022). The brackets and the mask were chosen by measurement against real
parsers in ai-gateway #1396: ``<…>`` vanishes in HTML and is a shell
redirection, ``[…]`` is a Jira link and a regex class, ``***`` is a regex
quantifier. ``⟦…⟧`` with ``•`` survives CommonMark, HTML, XHTML, URL query,
regex and SQL LIKE, and models copy it character by character.

The ``c`` marks a client-minted reference; a gateway mints ``⟦TYPE_N⟧`` without
it and never mints the ``c`` range, so the two never collide. Resolution
matches the KEY only; the display part is for humans and the model may drop
or change it. The earlier ``<TYPE_cN>`` form is still recognised for
rehydration, but never minted.
"""
from __future__ import annotations

import re

OPEN, CLOSE, MASK = "\u27e6", "\u27e7", "\u2022"
KEY_RE = r"(?P<type>[A-Z][A-Z_]*?)_(?P<key>c\d{1,9})"   # digits capped like the gateway
REF_RE = re.compile(
    rf"(?:{OPEN}{KEY_RE}(?::(?P<display>[^{OPEN}{CLOSE}]{{0,80}}))?{CLOSE})"
    rf"|(?:<(?P<ltype>[A-Z][A-Z_]*?)_(?P<lkey>c\d{{1,9}})(?::(?P<ldisplay>[^<>]{{0,80}}))?>)"
)


def make_ref(type_: str, n: int, display: str | None = None) -> str:
    key = f"{type_}_c{n}"
    return f"{OPEN}{key}:{display}{CLOSE}" if display else f"{OPEN}{key}{CLOSE}"


def _key(m: re.Match) -> str:
    if m.group("type"):
        return f"{m.group('type')}_{m.group('key')}"
    return f"{m.group('ltype')}_{m.group('lkey')}"


def key_of(ref: str) -> str | None:
    m = REF_RE.fullmatch(ref)
    return _key(m) if m else None


def find_refs(text: str) -> list[tuple[str, int, int]]:
    """Return (key, start, end) for every placeholder in text, new or legacy form."""
    return [(_key(m), m.start(), m.end()) for m in REF_RE.finditer(text)]


ENTITY_OF_TYPE = {"EMAIL": "email", "PHONE": "phone", "CARD": "credit_card", "IBAN": "iban",
                  "IP": "ip_address", "IPV6": "ip_address_v6"}
_FREEMAIL: frozenset[str] | None = None


def freemail_domains() -> frozenset[str]:
    global _FREEMAIL
    if _FREEMAIL is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent / "rules" / "freemail_domains.txt"
        _FREEMAIL = frozenset(line.strip().lower() for line in path.read_text().splitlines() if line.strip())
    return _FREEMAIL


def display_for(type_: str, value: str, level: str = "standard") -> str | None:
    """The display part, rendered by the gateway's own rules (pii_display.py, vendored).

    Same transformation on both sides, so the gateway recognises our display as a
    display. SECRET and the country-specific identifiers get no display.
    """
    from . import pii_display
    entity = ENTITY_OF_TYPE.get(type_)
    if entity is None:
        return None
    if type_ == "IP" and ":" in value:
        entity = "ip_address_v6"
    shown = pii_display.display(value, entity, level, freemail_domains())
    return shown or None
