"""Deterministic detection of secrets and PII in text.

Two rule sources, one scanner:

1. **gitleaks** (`rules/gitleaks.toml`, vendored, MIT, version in
   `rules/GITLEAKS_VERSION`): ~220 secret shapes with keywords, entropy
   thresholds and allowlists. Consumed as data; no gitleaks binary. Refresh
   with `scripts/sync_gitleaks.py vX.Y.Z`.
2. **Own rules** (`OWN_RULES` below): what gitleaks does not cover. PII with
   validators (email, IBAN mod-97, card Luhn, public IP, phone), credentials
   recognised by position (`password=…`, `Bearer …`, `user:pass@host`).

One detector, shared by every hook and every direction. Two detectors with
slightly different rules is how a redaction leaks.
"""
from __future__ import annotations

import math
import re
import tomllib
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass(frozen=True)
class Match:
    kind: str      # rule id, e.g. "gitlab-pat" or "email"
    type: str      # placeholder type: SECRET, EMAIL, IBAN, CARD, IP, PHONE
    value: str     # the exact text to replace
    start: int
    end: int


@dataclass(frozen=True)
class Rule:
    id: str
    type: str
    regex: re.Pattern[str]
    keywords: tuple[str, ...] = ()
    entropy: float = 0.0
    secret_group: int = 0
    allow_regexes: tuple[tuple[re.Pattern[str], str], ...] = ()   # (pattern, target: match|line)
    stopwords: tuple[str, ...] = ()
    validator: str | None = None


# ----------------------------------------------------------------- helpers --
def _re2_to_python(rx: str) -> str:
    """gitleaks regexes are RE2. Python differs in two spots we hit."""
    flags = ""
    if "(?i)" in rx:
        rx = rx.replace("(?i)", "")
        flags = "(?i)"
    return flags + rx.replace(r"\z", r"\Z")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


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
    return int("".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)) % 97 == 1


def _public_ip(ip: str) -> bool:
    parts = [int(p) for p in ip.split(".")]
    if any(p > 255 for p in parts):
        return False
    a, b = parts[0], parts[1]
    private = (a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
               or (a == 169 and b == 254))
    return not private


VALIDATORS = {
    "luhn": lambda v: _luhn_ok(re.sub(r"\D", "", v)),
    "iban": _iban_ok,
    "public_ip": _public_ip,
    "not_placeholder": lambda v: v.lower() not in {"placeholder", "changeme", "redacted", "example"}
    and not v.startswith("<"),
}


# --------------------------------------------------------------- own rules --
OWN_RULES: list[dict] = [
    {"id": "url-userinfo", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)\b[a-z][a-z0-9+.-]*://([^/\s:@]{1,128}):([^/\s@]{1,256})@"},
    # ?token=… / &api_key=… in a URL
    {"id": "url-query-secret", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)[?&]((?:access_?)?token|api[_-]?key|apikey|secret|password|sig|signature)=([^&\s#\"']{8,})"},
    {"id": "email", "type": "EMAIL",
     "regex": r"(?:\b[\w.+-]{1,64}|(?<![\w.+-])[\w.+-]{64,}|[\w.+-]{64})@[\w-]{1,63}\.[\w.-]{0,254}[\w-]"},
    {"id": "iban", "type": "IBAN", "validator": "iban",
     "regex": r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"},
    {"id": "credit-card", "type": "CARD", "validator": "luhn",
     "regex": r"(?<!\w)(?<!\d{4}-)(?:\d{4}[\s-]?){3}\d{4}(?!-\d{4})(?!\w)"},
    {"id": "ipv4", "type": "IP", "validator": "public_ip",
     "regex": r"(?<!\w)(?<!\d\.)\d{1,3}(?:\.\d{1,3}){3}(?!\w)"},
    {"id": "phone", "type": "PHONE",
     "regex": r"(?<![\w+])\+\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}(?:[ \-]?\d{2,5}){1,4}(?!\w)"},
    # full-length GitLab runner / deploy tokens; the gitleaks legacy shape stops after 20 chars
    {"id": "gitlab-runner-token", "type": "SECRET", "regex": r"glrt-[0-9A-Za-z_.-]{20,}"},
    {"id": "gitlab-deploy-token-any", "type": "SECRET", "regex": r"gldt-[0-9A-Za-z_-]{20,}"},
    # credentials recognised by POSITION, not shape: a name says what the value is
    {"id": "named-credential", "type": "SECRET", "secret_group": 3, "validator": "not_placeholder",
     "regex": (r"(?i)\b((?:[a-z0-9]{1,16}[_-])?(?:secret|passwo?rd|passwd|pwd|token|api[_-]?key|apikey"
               r"|client[_-]?secret|access[_-]?key|private[_-]?key|auth[_-]?token))"
               r"(\s*[:=]\s*[\"']?)([A-Za-z0-9_\-./+=~]{16,})")},
    {"id": "auth-scheme", "type": "SECRET", "secret_group": 3,
     "regex": r"(?i)\b(Bearer|Basic|Token|APIKey)(\s+)([A-Za-z0-9._~+/=-]{16,})"},
    # user:password@host in a URL; group 2 is the password
]


# ------------------------------------------------------------- rule loading --
def _load_gitleaks() -> list[Rule]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # "possible nested set" in two gitleaks regexes
        cfg = tomllib.loads((RULES_DIR / "gitleaks.toml").read_text())
        rules: list[Rule] = []
        for r in cfg.get("rules", []):
            if "regex" not in r:
                continue
            allow: list[tuple[re.Pattern[str], str]] = []
            stop: list[str] = []
            for al in r.get("allowlists", []) or []:
                target = al.get("regexTarget", "match")
                for arx in al.get("regexes", []) or []:
                    try:
                        allow.append((re.compile(_re2_to_python(arx)), target))
                    except re.error:
                        pass
                stop += [s.lower() for s in al.get("stopwords", []) or []]
            rules.append(Rule(
                id=r["id"], type="SECRET", regex=re.compile(_re2_to_python(r["regex"])),
                keywords=tuple(k.lower() for k in r.get("keywords", []) or ()),
                entropy=float(r.get("entropy", 0) or 0), secret_group=int(r.get("secretGroup", 0) or 0),
                allow_regexes=tuple(allow), stopwords=tuple(stop),
            ))
    return rules


def _load_own() -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=re.compile(d["regex"]),
                 secret_group=d.get("secret_group", 0), validator=d.get("validator"))
            for d in OWN_RULES]


_RULES: list[Rule] | None = None


def rules() -> list[Rule]:
    """Own secret rules first (longer shapes win the span), then gitleaks, then PII."""
    global _RULES
    if _RULES is None:
        own = _load_own()
        secrets = [r for r in own if r.type == "SECRET"]
        pii = [r for r in own if r.type != "SECRET"]
        _RULES = secrets + _load_gitleaks() + pii
    return _RULES


SECRET_TYPES = frozenset({"SECRET"})


# ------------------------------------------------------------------ scanner --
def _line_of(text: str, start: int, end: int) -> str:
    a = text.rfind("\n", 0, start) + 1
    b = text.find("\n", end)
    return text[a: b if b >= 0 else len(text)]


def _allowed(rule: Rule, text: str, m: re.Match, secret: str) -> bool:
    """True when an allowlist says this hit is fine (i.e. skip it)."""
    if rule.stopwords and any(s in secret.lower() for s in rule.stopwords):
        return True
    for rx, target in rule.allow_regexes:
        probe = _line_of(text, m.start(), m.end()) if target == "line" else secret
        if rx.search(probe):
            return True
    return False


def scan(text: str, enabled: set[str] | None = None) -> list[Match]:
    """Return non-overlapping matches, leftmost first; the first rule to claim a span wins."""
    if not text:
        return []
    low = text.lower()
    found: list[Match] = []
    taken: list[tuple[int, int]] = []
    for rule in rules():
        if enabled is not None and rule.id not in enabled:
            continue
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.regex.finditer(text):
            ngroups = m.re.groups or 0
            g = rule.secret_group if 0 < rule.secret_group <= ngroups else (1 if ngroups >= 1 and m.group(1) else 0)
            start, end = m.start(g), m.end(g)
            if end <= start:
                continue
            secret = m.group(g)
            if any(s < end and start < e for s, e in taken):
                continue
            if rule.entropy and shannon_entropy(secret) < rule.entropy:
                continue
            if rule.validator and not VALIDATORS[rule.validator](secret):
                continue
            if _allowed(rule, text, m, secret):
                continue
            # our own placeholders are never a hit
            if text[max(0, start - 1):start] == "<" and re.match(r"[A-Z]+_c\d+", secret):
                continue
            found.append(Match(rule.id, rule.type, secret, start, end))
            taken.append((start, end))
    found.sort(key=lambda x: x.start)
    return found


def contains_secret(text: str) -> bool:
    return any(m.type in SECRET_TYPES for m in scan(text))
