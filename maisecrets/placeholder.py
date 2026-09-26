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
KEY_RE = r"(?P<type>[A-Z][A-Z_]*?)_(?P<key>c\d+)"
REF_RE = re.compile(
    rf"(?:{OPEN}{KEY_RE}(?::(?P<display>[^{OPEN}{CLOSE}]{{0,80}}))?{CLOSE})"
    rf"|(?:<(?P<ltype>[A-Z][A-Z_]*?)_(?P<lkey>c\d+)(?::(?P<ldisplay>[^<>]{{0,80}}))?>)"
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


def display_for(type_: str, value: str) -> str | None:
    """A human-readable hint that does not identify the value. Same rules as the gateway."""
    if type_ == "EMAIL" and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:2]}{MASK * 3}@{domain}"
    if type_ == "PHONE":
        digits = re.sub(r"\D", "", value)
        return f"{MASK * 3}{digits[-2:]}" if len(digits) >= 4 else None
    if type_ == "CARD":
        digits = re.sub(r"\D", "", value)
        return f"{MASK * 4}{digits[-4:]}"
    if type_ == "IBAN":
        s = value.replace(" ", "")
        return f"{s[:2]}{MASK * 2}{s[-4:]}"
    if type_ == "IP":
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.{MASK}.{MASK}"
    # SECRET and the country-specific identifiers: key only, no display
    return None
