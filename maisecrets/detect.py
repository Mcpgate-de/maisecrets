"""Deterministic detection of secrets and PII in text.

Three rule sources, one scanner:

1. **gitleaks** (`rules/gitleaks.toml`, vendored, MIT, version in
   `rules/GITLEAKS_VERSION`): ~220 secret shapes with keywords, entropy
   thresholds and allowlists. Consumed as data; no gitleaks binary. Refresh
   with `scripts/sync_gitleaks.py vX.Y.Z`.
2. **Presidio** (`rules/presidio.json`, derived from Microsoft Presidio's
   pattern recognizers, MIT, version in `rules/PRESIDIO_VERSION`): country
   and generic PII shapes with scores and context words. Regions are
   opt-in (`pii_regions`, default `generic` + `de`). Checksum validators for
   the generic and the German types are ported below; the others keep
   their pattern score and need a context word. Refresh with
   `scripts/sync_presidio.py`.
3. **detect-secrets** (`rules/detect_secrets.json`, derived from Yelp
   detect-secrets' KeywordDetector and BasicAuthDetector, Apache-2.0, version
   in `rules/DETECT_SECRETS_VERSION`): credentials recognised by position
   (`password = …`, `api_key: "…"`, `user:pass@host`). Their heuristic
   filters (templated, indirect, sequential, dollar-prefixed) are ported.
4. **Own rules** (`OWN_RULES` below): what none of the three covers. Email
   stays ours (a bounded regex; the unbounded one took 11 s on an 80 KB
   dotted run), phone with a country code, `Bearer …` outside curl,
   `?api_key=…` in a URL, full-length GitLab runner and deploy tokens.

One detector, shared by every hook and every direction. Two detectors with
slightly different rules is how a redaction leaks.
"""
from __future__ import annotations

import json
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


class _Lazy:
    """A regex compiled on first use. Rule loading then costs a dict, not 265 compilations."""
    __slots__ = ("pattern", "flags", "_rx")

    def __init__(self, pattern: str, flags: int = 0) -> None:
        self.pattern, self.flags, self._rx = pattern, flags, None

    def _get(self) -> re.Pattern[str]:
        if self._rx is None:
            self._rx = re.compile(self.pattern, self.flags)
        return self._rx

    def finditer(self, text: str):
        return self._get().finditer(text)

    def search(self, text: str):
        return self._get().search(text)

    @property
    def groups(self) -> int:
        return self._get().groups


@dataclass(frozen=True)
class Rule:
    id: str
    type: str
    regex: _Lazy
    keywords: tuple[str, ...] = ()
    entropy: float = 0.0
    secret_group: int = 0
    allow_regexes: tuple[tuple[re.Pattern[str], str], ...] = ()   # (pattern, target: match|line)
    stopwords: tuple[str, ...] = ()
    validator: str | None = None
    score: float = 1.0                 # presidio pattern score; 1.0 = shape alone is enough
    context: tuple[str, ...] = ()      # presidio context words; a nearby one lifts a weak score
    require_context: bool = False      # weak shape: accept only with a context word nearby
    whole_match: bool = False          # presidio: the entity is the whole match, never a sub-group


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
    if ":" in ip:
        # IPv6: no private-range rule here, but "::", "::1" and "fe80:…" are not worth a placeholder
        return bool(re.fullmatch(r"[0-9A-Fa-f:.]{7,45}", ip)) and ip.count(":") >= 2 \
            and any(c in "123456789abcdefABCDEF" for c in ip) and not ip.lower().startswith(("::1", "fe80", "fc", "fd"))
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        return False   # e.g. a CIDR tail the upstream regex swallowed
    parts = [int(p) for p in ip.split(".")]
    if any(p > 255 for p in parts):
        return False
    a, b = parts[0], parts[1]
    private = (a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
               or (a == 169 and b == 254))
    return not private


def _de_tax_id_ok(v: str) -> bool:
    """Steuer-ID, ISO 7064 Mod 11,10 (BZSt), plus the digit-frequency rule."""
    if len(v) != 11 or not v.isdigit() or v[0] == "0":
        return False
    digits = [int(d) for d in v]
    if max(Counter(digits[:10]).values()) > 3:
        return False
    product = 10
    for i in range(10):
        total = (digits[i] + product) % 10 or 10
        product = (total * 2) % 11
    check = 11 - product
    return (0 if check == 10 else check) == digits[10]


def _de_social_security_ok(v: str) -> bool:
    """Rentenversicherungsnummer, VKVV § 4 checksum plus birth-date ranges."""
    v = v.upper().replace(" ", "")
    if not re.fullmatch(r"\d{8}[A-Z]\d{3}", v):
        return False
    day, month = int(v[2:4]), int(v[4:6])
    if not (1 <= day <= 31 or 51 <= day <= 81) or not 1 <= month <= 12:
        return False
    letter = str(ord(v[8]) - ord("A") + 1).zfill(2)
    effective = v[:8] + letter + v[9:11]
    weights = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1]
    total = 0
    for ch, w in zip(effective, weights):
        prod = int(ch) * w
        total += prod // 10 + prod % 10
    return total % 10 == int(v[11])


def _icao_check(v: str, forbidden: str = "") -> bool:
    """ICAO Doc 9303 check digit (weights 7,3,1) over 8 characters, digit at position 9."""
    v = v.upper().strip()
    if len(v) != 9 or not v[-1].isdigit():
        return False
    if any(c in forbidden for c in v[:-1]):
        return False
    total = 0
    for i, c in enumerate(v[:-1]):
        if c.isdigit():
            val = int(c)
        elif "A" <= c <= "Z":
            val = ord(c) - ord("A") + 10
        else:
            return False
        total += val * (7, 3, 1)[i % 3]
    return total % 10 == int(v[-1])


def _de_id_card_ok(v: str) -> bool:
    v = v.upper().strip()
    if len(v) == 9 and v[0] == "T" and v[1:].isdigit():
        return True   # legacy pre-2010 number, no check digit
    return _icao_check(v)


def _de_health_insurance_ok(v: str) -> bool:
    v = v.upper().strip()
    if not re.fullmatch(r"[A-Z]\d{9}", v):
        return False
    effective = str(ord(v[0]) - ord("A") + 1).zfill(2) + v[1:9]
    total = 0
    for ch, f in zip(effective, (1, 2) * 5):
        prod = int(ch) * f
        total += prod // 10 + prod % 10 if prod >= 10 else prod
    return total % 10 == int(v[9])


def _de_lanr_ok(v: str) -> bool:
    v = v.strip()
    if len(v) != 9 or not v.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(v[:6], (4, 9, 4, 9, 4, 9)))
    return int(v[6]) == (10 - total % 10) % 10


def _de_vat_id_ok(v: str) -> bool:
    n = re.sub(r"[\s.\-]", "", v.upper())
    return len(n) == 11 and n.startswith("DE") and n[2:].isdigit()


_DS_TEMPLATED = re.compile(r"^(\{\{.*\}\}|\$\{.*\}|<.*>|%.*%|\$[A-Za-z_][A-Za-z0-9_]*)$")
_DS_INDIRECT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\s*(\(.*\)|\[.*\])$")


def _ds_value_ok(v: str) -> bool:
    """Port of detect-secrets' heuristic filters for keyword hits."""
    v = v.strip()
    if len(v) < 8 or len(v) > 256:
        return False
    if _DS_TEMPLATED.match(v) or _DS_INDIRECT.match(v):
        return False
    if "(" in v or ")" in v:
        return False   # a call or an expression (`re.compile(r"…`), not a value
    if not any(c.isalnum() for c in v):
        return False
    if v.count(" ") >= 2:
        return False   # a sentence or an i18n label ("Add API key"), not a value
    if not any(c.isdigit() for c in v) and re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z]+)+", v):
        return False   # an identifier: secret_value, from-secret, NAME_OF_SECRET
    low = v.lower()
    if low in {"password", "changeme", "placeholder", "example", "none", "null", "true", "false", "redacted"}:
        return False
    # sequential or repeated strings (abcdef…, 123456…, aaaaaa…)
    if len(set(low)) <= 2:
        return False
    if all(ord(low[i + 1]) - ord(low[i]) == 1 for i in range(len(low) - 1)):
        return False
    if low.startswith(("\u27e6", "<")) and "_c" in low:
        return False
    return True


VALIDATORS = {
    "ds_value": _ds_value_ok,
    "de_tax_id": _de_tax_id_ok,
    "de_social_security": _de_social_security_ok,
    "de_id_card": _de_id_card_ok,
    "de_passport": lambda v: _icao_check(v, forbidden="ABDEIOQSU"),
    "de_health_insurance": _de_health_insurance_ok,
    "de_lanr": _de_lanr_ok,
    "de_bsnr": lambda v: len(v.strip()) == 9 and v.strip().isdigit() and v.strip() != "000000000",
    "de_vat_id": _de_vat_id_ok,
    "luhn": lambda v: _luhn_ok(re.sub(r"\D", "", v)),
    "iban": _iban_ok,
    "public_ip": _public_ip,
    "not_placeholder": lambda v: v.lower() not in {"placeholder", "changeme", "redacted", "example"}
    and not v.startswith("<"),
    "person_email": lambda v: v.split("@", 1)[0].lower() not in _SYSTEM_USERS,
}
_SYSTEM_USERS = frozenset({"git", "root", "ubuntu", "ec2-user", "admin", "noreply", "no-reply", "postmaster",
                           "hostmaster", "webmaster", "mailer-daemon", "bounce", "bounces"})


# --------------------------------------------------------------- own rules --
OWN_RULES: list[dict] = [
    # ?token=… / &api_key=… in a URL
    {"id": "url-query-secret", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)[?&]((?:access_?)?token|api[_-]?key|apikey|secret|password|sig|signature)=([^&\s#\"']{8,})"},
    {"id": "email", "type": "EMAIL", "validator": "person_email",
     "regex": r"(?:\b[\w.+-]{1,64}|(?<![\w.+-])[\w.+-]{64,}|[\w.+-]{64})@[\w-]{1,63}\.[\w.-]{0,254}[\w-]"},
    {"id": "phone", "type": "PHONE",
     "regex": r"(?<![\w+])\+\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}(?:[ \-]?\d{2,5}){1,4}(?!\w)"},
    # full-length GitLab runner / deploy tokens; the gitleaks legacy shape stops after 20 chars
    {"id": "gitlab-runner-token", "type": "SECRET", "regex": r"glrt-[0-9A-Za-z_.-]{20,}"},
    {"id": "gitlab-deploy-token-any", "type": "SECRET", "regex": r"gldt-[0-9A-Za-z_-]{20,}"},
    {"id": "auth-scheme", "type": "SECRET", "secret_group": 3,
     "regex": r"(?<![\w-])(Bearer|Basic)([ \t]+)([A-Za-z0-9._~+/=-]{16,})"},
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
                    allow.append((_Lazy(_re2_to_python(arx)), target))
                stop += [s.lower() for s in al.get("stopwords", []) or []]
            rules.append(Rule(
                id=r["id"], type="SECRET", regex=_Lazy(_re2_to_python(r["regex"])),
                keywords=tuple(k.lower() for k in r.get("keywords", []) or ()),
                entropy=float(r.get("entropy", 0) or 0), secret_group=int(r.get("secretGroup", 0) or 0),
                allow_regexes=tuple(allow), stopwords=tuple(stop),
            ))
    return rules


# entity -> placeholder type (short, stable); anything else keeps its entity name
ENTITY_TYPE = {"EMAIL_ADDRESS": "EMAIL", "IBAN_CODE": "IBAN", "CREDIT_CARD": "CARD",
               "IP_ADDRESS": "IP", "PHONE_NUMBER": "PHONE"}
# covered by OWN_RULES with bounded regexes and validators, or not PII worth a placeholder
PRESIDIO_SKIP = {"email", "url", "date", "mac-address", "uuid", "phone", "crypto"}
# validator id per presidio recognizer id; a recognizer with a validator we did not port
# keeps its pattern score and is treated as weak (context required)
PRESIDIO_VALIDATOR = {"iban": "iban", "credit-card": "luhn", "ip": "public_ip",
                      "de-tax-id": "de_tax_id", "de-social-security": "de_social_security",
                      "de-id-card": "de_id_card", "de-passport": "de_passport",
                      "de-health-insurance": "de_health_insurance", "de-lanr": "de_lanr",
                      "de-bsnr": "de_bsnr", "de-vat-id": "de_vat_id"}
# shapes that are plain digit runs: even with a valid checksum, ask for a context word
PRESIDIO_ALWAYS_CONTEXT = {"de-tax-id", "de-tax-number", "de-bsnr", "de-lanr", "de-plz", "de-kfz",
                           "de-handelsregister", "de-fuehrerschein", "nhs", "aba-routing", "medical-license"}
# Presidio tags every US/UK/IN/AU/… recognizer as language "en", so language is the wrong
# switch: an Indian PAN rule produced 290 false positives in one German transcript. The
# switch is the REGION, derived from the recognizer id; "generic" is always on.
REGION_OF_ID = {"nhs": "uk", "aba-routing": "us", "medical-license": "us"}
DEFAULT_PII_REGIONS = ("generic", "de")


def presidio_region(rec_id: str) -> str:
    if rec_id in REGION_OF_ID:
        return REGION_OF_ID[rec_id]
    head = rec_id.split("-", 1)[0]
    return head if len(head) == 2 and rec_id.count("-") >= 1 else "generic"


def _load_presidio(regions: tuple[str, ...] = DEFAULT_PII_REGIONS) -> list[Rule]:
    data = json.loads((RULES_DIR / "presidio.json").read_text())
    out: list[Rule] = []
    for rec in data["recognizers"]:
        if rec["id"] in PRESIDIO_SKIP or presidio_region(rec["id"]) not in regions:
            continue
        validator = PRESIDIO_VALIDATOR.get(rec["id"])
        weak = rec["id"] in PRESIDIO_ALWAYS_CONTEXT or (rec["validator"] and validator is None)
        for i, pat in enumerate(rec["patterns"]):
            out.append(Rule(
                id=f"{rec['id']}" if len(rec["patterns"]) == 1 else f"{rec['id']}#{i}",
                type=ENTITY_TYPE.get(rec["entity"], rec["entity"]), regex=_Lazy(_re2_to_python(pat["regex"])),
                validator=validator, score=float(pat["score"]),
                context=tuple(c.lower() for c in rec.get("context", [])), require_context=weak,
                whole_match=True,
            ))
    return out


def _load_detect_secrets() -> list[Rule]:
    data = json.loads((RULES_DIR / "detect_secrets.json").read_text())
    kws = tuple(sorted({"key", "pass", "pwd", "secret", "contrase"}))
    out: list[Rule] = []
    for r in data["rules"]:
        flags = re.IGNORECASE if r.get("ignorecase") else 0
        out.append(Rule(id=r["id"], type="SECRET", regex=_Lazy(r["regex"], flags),
                        keywords=() if r["id"] == "ds-basic-auth" else kws,
                        secret_group=int(r["group"]), validator="ds_value"))
    return out


def _load_own() -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=_Lazy(d["regex"]),
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
        _RULES = secrets + _load_detect_secrets() + _load_gitleaks() + _load_presidio(_pii_regions()) + pii
    return _RULES


def _pii_regions() -> tuple[str, ...]:
    try:
        from .vault import load_config
        regions = load_config().get("pii_regions")
        return tuple(regions) if regions else DEFAULT_PII_REGIONS
    except Exception:  # noqa: BLE001 - config is optional
        return DEFAULT_PII_REGIONS


SECRET_TYPES = frozenset({"SECRET"})
# a value that is obviously a placeholder is never a secret, whichever rule matched it
PLACEHOLDER_VALUES = frozenset({"changeme", "change_me", "password", "placeholder", "example", "redacted",
                                "secret", "your_api_key", "xxxxxxxx", "todo", "none", "null"})
PLACEHOLDER_PARTS = ("your_", "your-", "bogus", "dummy", "example", "sample", "placeholder", "changeme",
                     "xxxxxxxx", "test-token", "secure-token", "<redacted", "fake")
_TEMPLATE_NAME = re.compile(r"^[A-Z]+(?:_[A-Z]+)+$")   # YOUR_PORTKEY_API_KEY: words joined by underscores, no digits


def looks_like_placeholder(value: str) -> bool:
    v = value.strip("\"'` ")
    low = v.lower()
    return low in PLACEHOLDER_VALUES or any(p in low for p in PLACEHOLDER_PARTS) or bool(_TEMPLATE_NAME.match(v))


# ------------------------------------------------------------------ scanner --
_CTX_CACHE: dict[tuple[str, ...], re.Pattern[str]] = {}


def _has_context_word(window: str, context: tuple[str, ...]) -> bool:
    """A context word counts as a whole word: "ort" must not fire inside "report"."""
    if not context:
        return False
    rx = _CTX_CACHE.get(context)
    if rx is None:
        rx = re.compile(r"(?<![a-z0-9äöüß])(?:" + "|".join(re.escape(c) for c in context) + r")(?![a-z0-9äöüß])")
        _CTX_CACHE[context] = rx
    return rx.search(window) is not None


def _matches(rule: Rule, text: str):
    """detect-secrets keyword rules are line rules: run them per line, keep absolute offsets."""
    if not rule.id.startswith("ds-keyword") or "\n" not in text:
        yield from rule.regex.finditer(text)
        return
    pos = 0
    for line in text.split("\n"):
        for m in rule.regex.finditer(line):
            yield _Shifted(m, pos)
        pos += len(line) + 1


class _Shifted:
    """A match object whose offsets are shifted into the enclosing text."""
    __slots__ = ("_m", "_off")

    def __init__(self, m: re.Match, off: int) -> None:
        self._m, self._off = m, off

    def group(self, i: int = 0):
        return self._m.group(i)

    def start(self, i: int = 0) -> int:
        return self._m.start(i) + self._off

    def end(self, i: int = 0) -> int:
        return self._m.end(i) + self._off


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
        # a rule that cannot fire without a context word need not run its regex without one
        if rule.context and (rule.require_context or rule.score < 0.5) and not _has_context_word(low, rule.context):
            continue
        for m in _matches(rule, text):
            ngroups = rule.regex.groups or 0
            if rule.whole_match:
                g = 0
            elif 0 < rule.secret_group <= ngroups:
                g = rule.secret_group
            else:
                g = next((i for i in range(1, ngroups + 1) if m.group(i)), 0)
            start, end = m.start(g), m.end(g)
            if end <= start:
                continue
            secret = m.group(g)
            if any(s < end and start < e for s, e in taken):
                continue
            if rule.entropy and shannon_entropy(secret) < rule.entropy:
                continue
            if rule.validator:
                try:
                    ok = VALIDATORS[rule.validator](secret)
                except (ValueError, IndexError, TypeError):
                    ok = False   # a validator that cannot parse the value has not validated it
                if not ok:
                    continue
            if rule.type == "SECRET" and looks_like_placeholder(secret):
                continue
            if rule.score < 1.0 or rule.require_context:
                # presidio semantics: a weak shape passes only with a context WORD nearby
                window = low[max(0, start - 80):min(len(low), end + 40)]
                has_context = _has_context_word(window, rule.context)
                if rule.require_context and not has_context:
                    continue
                if rule.score < 0.5 and not has_context:
                    continue
            if _allowed(rule, text, m, secret):
                continue
            # our own placeholders are never a hit
            if text[max(0, start - 1):start] in ("<", "\u27e6") and re.match(r"[A-Z][A-Z_]*_c\d+", secret):
                continue
            found.append(Match(rule.id, rule.type, secret, start, end))
            taken.append((start, end))
    found.sort(key=lambda x: x.start)
    return found


def contains_secret(text: str) -> bool:
    return any(m.type in SECRET_TYPES for m in scan(text))
