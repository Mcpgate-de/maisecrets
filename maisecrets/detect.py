"""Deterministic detection of secrets and PII in text.

One detector, shared by every hook and every direction. Two detectors with
slightly different rules is how a redaction leaks: a rule closed in one place
reopens a gap in the other.

The patterns come from the ai-gateway scrubber (src/security/pii_scrubber.py,
origin/main 1575685b4, 2026-09-26). They were copied, not re-invented, so a
value the gateway hides is a value this detector hides.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- secret shapes: an issuer prefix plus a fixed alphabet and length -------
SECRET_PATTERNS: dict[str, str] = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[puso]_[a-zA-Z0-9]{36}",
    "slack_token": r"xox[baprs]-\d[a-zA-Z0-9-]{20,}",
    "stripe_key": r"sk_live_[0-9a-zA-Z]{24}",
    "google_api_key": r"AIza[0-9A-Za-z-_]{35}",
    "gitlab_pat": r"glpat-[0-9A-Za-z_-]{20,}",
    # GitLab runner authentication token (`gitlab-runner list` prints it), deploy token, CI job token
    "gitlab_runner_token": r"glrt-[0-9A-Za-z_.-]{20,}",
    "gitlab_deploy_token": r"gldt-[0-9A-Za-z_-]{20,}",
    "openai_key": r"sk-[a-zA-Z0-9_-]{20,}",
    "google_oauth": r"ya29\.[a-zA-Z0-9_-]{20,}",
    "jwt": r"eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}",
    "private_key": (
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
        r"[\s\S]{0,8192}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    ),
    "bcrypt_hash": r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}",
    "argon2_hash": (
        r"\$argon2(?:id|i|d)\$v=\d{1,3}\$m=\d{1,8},t=\d{1,4},p=\d{1,3}"
        r"\$[A-Za-z0-9+/]{8,128}\$[A-Za-z0-9+/]{16,256}"
    ),
    "sha_crypt_hash": r"\$[56]\$(?:rounds=\d{1,9}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}",
    "pbkdf2_hash": r"pbkdf2_sha(?:1|256|512)\$\d{1,7}\$[A-Za-z0-9+/=.]{1,64}\$[A-Za-z0-9+/=]{20,128}",
    "ldap_ssha_hash": r"\{SSHA(?:256|512)?\}[A-Za-z0-9+/]{20,256}={0,2}",
    "phpass_hash": r"\$[PH]\$[./0-9A-Za-z]{31}",
    # A credential recognised by its position: a name says what the value is.
    # Group 2 is the value; the name stays in the text.
    "named_credential": (
        r"(?i)\b((?:[a-z0-9]{1,16}[_-])?(?:secret|passwo?rd|passwd|pwd|token"
        r"|api[_-]?key|apikey|client[_-]?secret|access[_-]?key|private[_-]?key"
        r"|auth[_-]?token))"
        r"(\s*[:=]\s*[\"']?)"
        r"([A-Za-z0-9_\-./+=~]{16,})"
    ),
    "auth_scheme": (
        r"(?i)\b(Bearer|Basic|Token|APIKey)"
        r"(\s+)([A-Za-z0-9._~+/=-]{16,})"
    ),
}

# --- PII shapes -------------------------------------------------------------
PII_PATTERNS: dict[str, str] = {
    "email": r"(?:\b[\w.+-]{1,64}|(?<![\w.+-])[\w.+-]{64,}|[\w.+-]{64})@[\w-]{1,63}\.[\w.-]{0,254}[\w-]",
    "iban": r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b",
    "credit_card": r"(?<!\w)(?<!\d{4}-)(?:\d{4}[\s-]?){3}\d{4}(?!-\d{4})(?!\w)",
    "ip": r"(?<!\w)(?<!\d\.)\d{1,3}(?:\.\d{1,3}){3}(?!\w)",
    "phone": r"(?<![\w+])\+\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}(?:[ \-]?\d{2,5}){1,4}(?!\w)",
}

# Which pattern names produce which placeholder type, and which are secrets.
TYPE_OF: dict[str, str] = {
    **{k: "SECRET" for k in SECRET_PATTERNS},
    "email": "EMAIL",
    "iban": "IBAN",
    "credit_card": "CARD",
    "ip": "IP",
    "phone": "PHONE",
}
SECRET_TYPES = frozenset({"SECRET"})

# The group that holds the value for patterns that also match a prefix.
VALUE_GROUP: dict[str, int] = {"named_credential": 3, "auth_scheme": 3}

_COMPILED: dict[str, re.Pattern[str]] = {
    name: re.compile(rx) for name, rx in {**SECRET_PATTERNS, **PII_PATTERNS}.items()
}

# Order matters: a longer, more specific shape must win over a generic one.
_ORDER = list(SECRET_PATTERNS) + list(PII_PATTERNS)


@dataclass(frozen=True)
class Match:
    kind: str      # pattern name, e.g. "gitlab_pat"
    type: str      # placeholder type, e.g. "SECRET"
    value: str     # the exact text to replace
    start: int
    end: int


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(num) % 97 == 1


def _private_ip(ip: str) -> bool:
    parts = ip.split(".")
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if any(int(p) > 255 for p in parts):
        return True  # not an IP at all
    return (
        a == 10 or a == 127 or a == 0
        or (a == 192 and b == 168)
        or (a == 172 and 16 <= b <= 31)
        or (a == 169 and b == 254)
    )


def _accept(kind: str, value: str) -> bool:
    if kind == "credit_card":
        return _luhn_ok(re.sub(r"\D", "", value))
    if kind == "iban":
        return _iban_ok(value)
    if kind == "ip":
        return not _private_ip(value)
    if kind == "named_credential":
        low = value.lower()
        return low not in {"placeholder", "changeme", "redacted", "example"} and not low.startswith("<")
    return True


def scan(text: str, enabled: set[str] | None = None) -> list[Match]:
    """Return non-overlapping matches, leftmost and longest first."""
    if not text:
        return []
    found: list[Match] = []
    taken: list[tuple[int, int]] = []
    for kind in _ORDER:
        if enabled is not None and kind not in enabled:
            continue
        rx = _COMPILED[kind]
        for m in rx.finditer(text):
            g = VALUE_GROUP.get(kind, 0)
            start, end = m.start(g), m.end(g)
            value = m.group(g)
            if end - start == 0:
                continue
            if any(s < end and start < e for s, e in taken):
                continue
            if not _accept(kind, value):
                continue
            # a placeholder we minted ourselves is never a hit
            if text[max(0, start - 1):start] == "<" and ":" in text[start:end + 40]:
                pass
            found.append(Match(kind, TYPE_OF[kind], value, start, end))
            taken.append((start, end))
    found.sort(key=lambda x: x.start)
    return found


def contains_secret(text: str) -> bool:
    return any(m.type in SECRET_TYPES for m in scan(text))
