"""Placeholder tokens: key plus optional display part.

Form: ``<TYPE_cN>`` or ``<TYPE_cN:display>``. The ``c`` marks a client-minted
reference; a gateway mints ``<TYPE_N>`` without it, so the two never collide
(ai-gateway #1396). Resolution matches the KEY only; the display part is for
humans and the model may drop or change it.
"""
from __future__ import annotations

import re

REF_RE = re.compile(r"<(?P<type>[A-Z]+)_(?P<key>c\d+)(?::(?P<display>[^<>]{0,80}))?>")


def make_ref(type_: str, n: int, display: str | None = None) -> str:
    key = f"{type_}_c{n}"
    return f"<{key}:{display}>" if display else f"<{key}>"


def key_of(ref: str) -> str | None:
    m = REF_RE.fullmatch(ref)
    return f"{m.group('type')}_{m.group('key')}" if m else None


def find_refs(text: str) -> list[tuple[str, int, int]]:
    """Return (key, start, end) for every placeholder in text."""
    return [(f"{m.group('type')}_{m.group('key')}", m.start(), m.end()) for m in REF_RE.finditer(text)]


def display_for(type_: str, value: str) -> str | None:
    """A human-readable hint that does not identify the value."""
    if type_ == "EMAIL" and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:2]}***@{domain}"
    if type_ == "PHONE":
        digits = re.sub(r"\D", "", value)
        return f"***{digits[-2:]}" if len(digits) >= 4 else None
    if type_ == "CARD":
        digits = re.sub(r"\D", "", value)
        return f"****{digits[-4:]}"
    if type_ == "IBAN":
        s = value.replace(" ", "")
        return f"{s[:2]}**{s[-4:]}"
    if type_ == "IP":
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.*.*"
    # SECRET: no display. A partial secret is still a hint.
    return None
