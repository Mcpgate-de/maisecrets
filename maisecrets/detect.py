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

import ipaddress
import json
import math
import re
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
    allow_regexes: tuple[tuple[re.Pattern[str], str], ...] = ()   # (pattern, target: secret|match|line)
    stopwords: tuple[str, ...] = ()
    validator: str | None = None
    score: float = 1.0                 # presidio pattern score; 1.0 = shape alone is enough
    context: tuple[str, ...] = ()      # presidio context words; a nearby one lifts a weak score
    require_context: bool = False      # weak shape: accept only with a context word nearby
    whole_match: bool = False          # presidio: the entity is the whole match, never a sub-group
    quote_group: int = 0               # detect-secrets: group of the optional opening quote


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


# public resolvers: a server every network uses, never a person's address
_RESOLVER_IPS = frozenset({"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                           "208.67.222.222", "208.67.220.220", "2001:4860:4860::8888", "2001:4860:4860::8844",
                           "2606:4700:4700::1111", "2606:4700:4700::1001"})


def _public_ip(ip: str) -> bool:
    """An address that can name a person: global unicast. Private, loopback, link-local, shared (100.64/10), the
    documentation ranges (192.0.2.0/24, 2001:db8::/32 …), reserved, broadcast and multicast are not; the
    Python standard library's own docs and tests held 666 of them (measured 2026-09-29)."""
    if ":" in ip:
        if not (re.fullmatch(r"[0-9A-Fa-f:.]{7,45}", ip) and ip.count(":") >= 2):
            return False
    elif not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        return False   # e.g. a CIDR tail the upstream regex swallowed
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast and str(addr) not in _RESOLVER_IPS


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
# words joined by `.`, `_` or `-`, optionally ending where the regex cut the line (`:` of a
# condition, `;` of a statement, `[` before a quoted key): `settings.API_KEY`, `self._password`,
# `os.environ[`, `confirm_password:` were taken for values (false-positive corpus, 2026-09-27)
_DS_REFERENCE = re.compile(r"_*[A-Za-z]+(?:[._/:-]+[A-Za-z]+)+_*[:;\[]?")
_FORMAT_ONLY_RE = re.compile(r"(?:%[-+ #0]*\d*(?:\.\d+)?[sdifxXeEgGrcoba%]|\{[^{}]*\}|[^A-Za-z0-9])+")


# a short glued value that is a type or a keyword of code or config, or a camelCase identifier:
# password:string, {token:number}, secret=config, api_key=apiKey, auth_token=Bearer (final review,
# 2026-09-28: the 6-character floor for glued values took these for secrets)
_SHORT_WORDS = frozenset({
    "string", "number", "boolean", "object", "integer", "bigint", "symbol", "unknown", "config", "bearer", "secret",
    "tokens", "hidden", "masked", "optional", "default", "require", "undefined", "double", "decimal", "varchar",
    "binary", "buffer", "array", "values", "string[]", "never", "nullable", "boolean[]", "option", "settings",
    "private", "public", "enabled", "disabled", "secretstr", "secretbytes", "securestring"})
_CAMEL_RE = re.compile(r"^[a-z]+(?:[A-Z][a-z0-9]*)+$")
# the review of 2026-09-29 (679 snippets of normal work): the next label taken for the value (`DB_PASSWORD=` then
# `API_KEY=`), a generic type (`Option<String>`), a UUID, and a fixture that names itself (`testpass`, `secret123`,
# `Passw0rd!`: letters after undoing the digits and symbols people use for them)
_LABEL_SHAPE = re.compile(r"[A-Za-z_][\w.-]*[:=]")
_NAME_LABEL_RE = re.compile(r"(?:[A-Z][A-Z0-9_]*|[a-z][a-z0-9_]*|[A-Z][a-z]+(?:[ _-][A-Za-z][a-z]+)*)[.-]?[:=]")
_GENERIC_TYPE = re.compile(r"<[A-Za-z_][\w, ]*>")
_VERSION_RE = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+.]?[A-Za-z0-9]+)?")
_PART_TEMPLATE_RE = re.compile(r"\{[A-Za-z_][\w.]*(?:\[[^\]]*\]?)?\}?$|\{[A-Za-z_][\w.]*\}")
_SHELL_EXPANSION_RE = re.compile(r"[?:+=-]{1,2}[A-Z_][A-Z0-9_]*")
_YAML_REF_RE = re.compile(r"[&*][A-Za-z_][\w-]*")
_PATH_IN_VALUE_RE = re.compile(r"(?:^|\s)(?:~|\.{1,2})?/[\w.-]+/[\w.-]+")
_ESCAPED_TAIL_RE = re.compile(r"(?:\\[nrt])+$")
_SUBSCRIPT_RE = re.compile(r"[A-Za-z_][\w.]*\[[\w.,\s]*\]?")
_GLOB_RE = re.compile(r"[:/._-]\*$|^\*\.\w+$|/\*[/.]")   # token:*, *.py, logs/*.txt; a star inside a value stays
_NUMBER_RE = re.compile(r"\d{1,3}(?:_\d{3})+|\d+(?:_\d+)+")
_PRIVATE_NAME_RE = re.compile(r"_[A-Za-z][A-Za-z_]*")
_EMAIL_VALUE_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_FIXTURE_WORD = re.compile(r"passwor[dt]|passw|pass(?![a-z])|(?<![a-z])pass|secret|token|test|geheim|kennwort")
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a", "1": "i", "!": "i", "|": "l",
                       "7": "t"})


def _deleet(v: str) -> str:
    return v.lower().translate(_LEET)


# the words a fixture is made of around its fixture word: mypassword, wrongpassword, SuperSecret1, rootpass,
# sk_test_123. Longest first, so that `password` is taken before `pass`
_FIXTURE_PARTS = re.compile("|".join(sorted((
    "password", "passwort", "passwd", "passw", "pass", "secret", "token", "testing", "test", "geheim", "kennwort",
    "key", "my", "new", "old", "wrong", "bad", "top", "super", "very", "not", "so", "dummy", "fake", "default",
    "admin", "user", "root", "db", "dev", "local", "sample", "example", "secure", "strong", "weak", "correct",
    "valid", "invalid", "other", "some", "your", "the", "sk", "pk", "cs", "rk", "tok", "api", "app", "mock",
    "demo"), key=len, reverse=True)))


def _names_itself(v: str) -> bool:
    """testpass, secret123, Passw0rd!, wrongpassword, SuperSecret1: a fixture word, the words a fixture is made of,
    and at most one other letter. A real password that holds a fixture word keeps a word of its own: Contest-Winter,
    Passion, Latest, Geheimnis, Passatwagen (review, 2026-09-29). Only letters of the value count, not the letters
    that undoing 0, 1, 3 gave."""
    d = _deleet(v)
    if not _FIXTURE_WORD.search(d):
        return False
    covered = [False] * len(d)
    for m in _FIXTURE_PARTS.finditer(d):
        for i in range(m.start(), m.end()):
            covered[i] = True
    return sum(1 for i, c in enumerate(v) if c.isalpha() and not covered[i]) <= 1


def _short_word(v: str) -> bool:
    w = v.strip().rstrip(",;})]")
    return w.lower() in _SHORT_WORDS or bool(_CAMEL_RE.match(w))


def _ds_value_ok(v: str, min_len: int = 8) -> bool:
    """Port of detect-secrets' heuristic filters for keyword hits."""
    v = v.strip()
    if len(v) < min_len or len(v) > 256:
        return False
    if _DS_TEMPLATED.match(v) or _DS_INDIRECT.match(v):
        return False
    if _GENERIC_TYPE.search(v):
        return False   # a generic type: Option<String>, Secret<String>
    if _VERSION_RE.fullmatch(v):
        return False   # a version pin: tokenizers==0.20.3 (requirements.txt, renovate.json)
    if _PART_TEMPLATE_RE.search(v) and not any(c.isdigit() for c in _PART_TEMPLATE_RE.sub("", v)):
        return False   # a template with a name in it: mcp_{user}, {body['transfer_id']}
    if _SHELL_EXPANSION_RE.fullmatch(v) or _YAML_REF_RE.fullmatch(v) or _PATH_IN_VALUE_RE.search(v):
        return False   # ${REDIS_PASSWORD:?…} cut after its name, a YAML anchor, a command with a path
    if not any(c.isdigit() for c in v) and _DS_REFERENCE.fullmatch(_ESCAPED_TAIL_RE.sub("", v).rstrip("})],;")):
        return False   # process.env.NOTION_CLIENT_SECRET,\n in a JSON string
    if _SUBSCRIPT_RE.fullmatch(v) or _NUMBER_RE.fullmatch(v) or _GLOB_RE.search(v):
        return False   # list[str], 1_234_567, chatgpt_access_token:* (the ai-gateway repository, 2026-09-29)
    if not any(c.isdigit() for c in v) and _DS_REFERENCE.fullmatch(v.rstrip("})],;")):
        return False   # a reference before a closing bracket: no-check}
    if _PRIVATE_NAME_RE.fullmatch(v):
        return False   # a private name: security_token_cleanup = _cleanup_tokens
    if _EMAIL_VALUE_RE.fullmatch(v):
        return False   # an address after a label (user_tokens:<address>): the e-mail rule decides, not a secret
    if _names_itself(v):
        return False   # a value that names itself a password, a secret, a token or a test is a fixture
    if re.match(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(?![\w])", v):
        return False   # a shell variable: $PASSWORD, ${DB_PASSWORD}
    if "(" in v or ")" in v or "`" in v or "|" in v:
        return False   # a call, an expression or markdown (`re.compile(r"…`, "`/maisecrets:report` |"), not a value
    if not any(c.isalnum() for c in v):
        return False
    if "***" in v or "\u2022\u2022" in v:
        return False   # a mask as a prompt echoes it: "Password: *******" (Python standard library, 2026-09-29)
    if _FORMAT_ONLY_RE.fullmatch(v):
        return False   # a format string: token_range = "%d,%d-%d,%d:" (Python standard library, 2026-09-29)
    if v.count(" ") >= 2:
        return False   # a sentence or an i18n label ("Add API key"), not a value
    if " " in v and not any(c.isdigit() for c in v):
        return False   # two words of prose ("bad payload"), not a value
    if not any(c.isdigit() for c in v) and _DS_REFERENCE.fullmatch(v):
        return False   # an identifier or a reference to one: NAME_OF_SECRET, self._password, os.environ[
    if not any(c.isdigit() for c in v) and _short_word(v):
        return False   # a type, a keyword of code or a camelCase identifier, at any length (settings, tokenValue)
    low = v.lower().rstrip(";")
    if low in {"password", "changeme", "placeholder", "example", "none", "null", "true", "false", "redacted"}:
        return False
    # sequential strings (abcdef…, 123456…) and one repeated character (********, xxxxxxxx);
    # two distinct characters after a label are a value (`password:asasasas…`, field report,
    # 2026-09-27: `<= 2` dropped it as filler)
    if len(set(low)) <= 1:
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
    "person_email": lambda v: v.split("@", 1)[0].lower() not in _SYSTEM_USERS and not _reserved_domain(v),
}


_RESERVED_MAIL_DOMAINS = ("example.com", "example.net", "example.org")
_RESERVED_MAIL_TLDS = ("test", "example", "invalid", "localhost", "local", "internal")


def _reserved_domain(v: str) -> bool:
    """example.com/.net/.org, the TLDs .test .example .invalid .localhost (RFC 2606, RFC 6761), .local (RFC 6762)
    and .internal (ICANN, 2024): no mailbox of a person on the internet is there. Every README, git fixture and
    test used them (review, 2026-09-29)."""
    local, _, d = v.rpartition("@")
    d = d.lower()
    tld = d.rsplit(".", 1)[-1]
    if tld in ("local", "internal"):
        # hans.mueller@firma.local, jdoe@corp.internal: an Active Directory mailbox names a person (reviews,
        # 2026-09-29); only a system account there is no person
        return local.lower() in _SYSTEM_USERS or local.lower() in ("alerts", "alert", "monitoring", "backup", "ci")
    return (d in _RESERVED_MAIL_DOMAINS or d.endswith(tuple("." + x for x in _RESERVED_MAIL_DOMAINS))
            or tld in _RESERVED_MAIL_TLDS)


_SYSTEM_USERS = frozenset({"git", "root", "ubuntu", "ec2-user", "admin", "noreply", "no-reply", "postmaster",
                           "hostmaster", "webmaster", "mailer-daemon", "bounce", "bounces"})


# --------------------------------------------------------------- own rules --
OWN_RULES: list[dict] = [
    # ?token=… / &api_key=… in a URL
    {"id": "url-query-secret", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)[?&]((?:access_?)?token|api[_-]?key|apikey|secret|password|sig|signature)=([^&\s#\"']{8,})"},
    {"id": "email", "type": "EMAIL", "validator": "person_email",
     # the last label is alphabetic: `lodash@4.17.21`, `checkout@v4.1.1` and Homebrew's
     # `python@3.14/3.14.7` are version pins, not addresses (review, 2026-09-26)
     "regex": r"(?:\b[\w.+-]{1,64}|(?<![\w.+-])[\w.+-]{64,}|[\w.+-]{64})"
              r"@[\w-]{1,63}(?:\.[\w-]{1,63})*\.[A-Za-z]{2,63}(?![\w-])"},
    {"id": "phone", "type": "PHONE",
     "regex": r"(?<![\w+])\+(?!0)\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}(?:[ \-]?\d{2,5}){1,4}(?![\w.]\d|\w)"},
    # bare token prefixes newer than the vendored rulesets live in rules/prefixes.txt (see _load_prefixes)
    {"id": "auth-scheme", "type": "SECRET", "secret_group": 3,
     "regex": r"(?<![\w-])(Bearer|Basic)([ \t]+)([A-Za-z0-9._~+/=-]{16,})"},
    # the secret half of an AWS key pair has no prefix of its own; the console, a CSV export
    # and a chat paste show it within a few lines after the AKIA… id (field report, 2026-09-26)
    {"id": "aws-secret-after-access-key", "type": "SECRET", "secret_group": 1,
     "regex": r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])(?:[^\n]*\n){0,4}?[^\n]*?"
              r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"},
]


# ------------------------------------------------------------- rule loading --
def _load_gitleaks() -> list[Rule]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # "possible nested set" in two gitleaks regexes
        # gitleaks.json is the same rules as JSON, for a Python without tomllib; a test keeps the two equal
        cfg = json.loads((RULES_DIR / "gitleaks.json").read_text(encoding="utf-8"))
        rules: list[Rule] = []
        for r in cfg.get("rules", []):
            if "regex" not in r:
                continue
            allow: list[tuple[re.Pattern[str], str]] = []
            stop: list[str] = []
            for al in r.get("allowlists", []) or []:
                # gitleaks: no regexTarget means the secret, "match" the whole match, "line" the line
                target = al.get("regexTarget", "secret")
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
DEFAULT_PII_REGIONS = ("generic",)   # without a config: the rules of no country


def presidio_region(rec_id: str) -> str:
    if rec_id in REGION_OF_ID:
        return REGION_OF_ID[rec_id]
    head = rec_id.split("-", 1)[0]
    return head if len(head) == 2 and rec_id.count("-") >= 1 else "generic"


def _load_presidio(regions: tuple[str, ...] = DEFAULT_PII_REGIONS) -> list[Rule]:
    data = json.loads((RULES_DIR / "presidio.json").read_text(encoding="utf-8"))
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


# detect-secrets' denylist is English (plus Spanish contraseña). The labels it lacks, English
# ones such as `pass:` and `token:` and those of other languages such as `passwort:`, come from
# rules/labels/<language>.txt for each active label language (maisecrets/regions.py).
# The two keyword rules whose quote is optional, and the group of that quote. Their value class
# runs to the end of the line, spaces included, and the whole span was then judged: a password
# followed by "and" and an address was rejected as prose, so the password reached the model
# (field report, 2026-09-27). An unquoted value ends at the first whitespace; only a quoted one
# holds spaces. A cut value that is one capitalised word ("secret: Developers, Webhooks, …",
# "a secret: PostToolUse must …", both in this repository) is the start of a sentence.
_DS_QUOTE_GROUP = {"ds-keyword-colon": 3, "ds-keyword-equal-signs": 4}
# the end of the label in the vendored colon rules, and the same with up to three spaces, tabs,
# no-break or narrow no-break spaces before the colon
_COLON_AFTER_LABEL = "([]\\'\"]{0,2})?:"
_COLON_AFTER_LABEL_SPACED = "([]\\'\"]{0,2})?[ \\t\u00a0\u202f]{0,3}:"
_WHITESPACE_RE = re.compile(r"\s")
_CAPITALISED_WORD_RE = re.compile(r"(?:[A-Z][a-z]+)+")


def _load_detect_secrets(languages: tuple[str, ...] = ("en",)) -> list[Rule]:
    data = json.loads((RULES_DIR / "detect_secrets.json").read_text(encoding="utf-8"))
    from .regions import load_labels
    labels = [lab for lang in languages for lab in load_labels(lang)]
    # every denylist word contains one of these; each label adds its own literal
    kws = tuple(sorted({"key", "pass", "pwd", "secret", "contrase"} | {lab.prefilter for lab in labels}))
    denylist = "|".join(data["denylist"])
    out: list[Rule] = []
    for r in data["rules"]:
        flags = re.IGNORECASE if r.get("ignorecase") else 0
        # the product's own name carries "secret": `/maisecrets:shortcut` was stored as a secret
        # named "shortcut" (field report, 2026-09-27); "mai" + keyword is never a label
        keywords = "(?<!mai)(" + "|".join([denylist] + [lab.regex for lab in labels]) + ")"
        regex = r["regex"].replace("(" + denylist + ")", keywords, 1)
        # the vendored value group must start with a word character, so `$+4jJzBixvQD9#`,
        # `@f6a-VtyEOYr!` and `-NA#C-X-gb4T%` were never values (2026-09-27); any first character
        # a character a password starts with may start one (not {, [, (, \\, /, <: code and paths), and
        # _ds_value_ok refuses a shell variable ($VAR, ${VAR}) as before
        regex = regex.replace("(?=\\w+)", "(?=[\\w!#$%&*+\\-@^~?.])")
        # French typography puts a space (often a no-break space) before the colon, and people type
        # `password : x` in every language; the vendored colon rules allowed none, so
        # `mot de passe : <value>` and `password : <value>` were no hit (2026-09-28)
        regex = regex.replace(_COLON_AFTER_LABEL, _COLON_AFTER_LABEL_SPACED, 1)
        out.append(Rule(id=r["id"], type="SECRET", regex=_Lazy(regex, flags),
                        keywords=() if r["id"] == "ds-basic-auth" else kws,
                        secret_group=int(r["group"]), validator="ds_value",
                        quote_group=_DS_QUOTE_GROUP.get(r["id"], 0)))
    return out


def _load_prefixes() -> list[Rule]:
    """Bare token prefixes newer than the vendored rulesets: maisecrets/rules/prefixes.txt, one
    per line `id  regex`, extended by pull request. The whole match is the secret."""
    out: list[Rule] = []
    for line in (RULES_DIR / "prefixes.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rule_id, regex = line.split(None, 1)
        out.append(Rule(id=rule_id, type="SECRET", regex=_Lazy(regex.strip())))
    return out


def _load_own() -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=_Lazy(d["regex"]),
                 secret_group=d.get("secret_group", 0), validator=d.get("validator"))
            for d in OWN_RULES] + _load_prefixes()


_RULES: list[Rule] | None = None


def rules() -> list[Rule]:
    """Own secret rules first (longer shapes win the span), then gitleaks, then PII."""
    global _RULES
    if _RULES is None:
        own = _load_own()
        secrets = [r for r in own if r.type == "SECRET"]
        pii = [r for r in own if r.type != "SECRET"]
        active = active_regions()
        _RULES = (secrets + _load_detect_secrets(active.languages) + _load_gitleaks()
                  + _load_presidio(active.regions) + pii)
    return _RULES


def active_regions():
    """The regions and label languages of the config (maisecrets/regions.py)."""
    from . import regions
    try:
        from .vault import load_config
        cfg = load_config()
    except Exception:  # noqa: BLE001 - config is optional; a bad one is reported by the vault
        cfg = {}
    return regions.resolve(cfg)


def _pii_regions() -> tuple[str, ...]:
    return active_regions().regions


SECRET_TYPES = frozenset({"SECRET"})
# a value that is obviously a placeholder is never a secret, whichever rule matched it
PLACEHOLDER_VALUES = frozenset({"changeme", "change_me", "password", "placeholder", "example", "redacted",
                                "secret", "your_api_key", "xxxxxxxx", "todo", "none", "null"})
PLACEHOLDER_PARTS = ("your_", "your-", "bogus", "dummy", "example", "sample", "placeholder", "changeme",
                     "xxxxxxxx", "test-token", "secure-token", "<redacted", "fake")
_TEMPLATE_NAME = re.compile(r"^[A-Z]+(?:_[A-Z]+)+$")   # YOUR_PORTKEY_API_KEY: words joined by underscores, no digits


# a placeholder word counts at the start of the value, after a character that is not a letter or a
# digit (ghp_fake…, sk-dummy-key, <redacted>), or at the end (the AWS documentation key ends in
# EXAMPLE). Inside a run of letters and digits it is chance: a random GitHub token holds "fAKe" or
# "DuMmy" about once in 20,000, and it was then let through as a placeholder (found by a random
# test token on windows-latest, 2026-09-27)
_PARTS = "|".join(re.escape(p) for p in PLACEHOLDER_PARTS)
_PLACEHOLDER_PART_RE = re.compile(f"(?<![a-z0-9])(?:{_PARTS})|(?:{_PARTS})(?:key)?$")


def looks_like_placeholder(value: str) -> bool:
    v = value.strip("\"'` ")
    low = v.lower()
    return low in PLACEHOLDER_VALUES or bool(_PLACEHOLDER_PART_RE.search(low)) or bool(_TEMPLATE_NAME.match(v))


# ------------------------------------------------------------- test fixtures --
# A label rule finds a value by its label alone, so a test password looks like a real one: `PASSWD = '<word>'` in the
# tests of the Python standard library (2026-09-29). In test code the value is a fixture, and a
# block or a placeholder there only stops the work. A token shape (glpat-, AKIA, a PEM key) and personal data stay
# hits in test code too: a real token or a copy of customer data in a test is a leak.
LABEL_RULES = ("ds-keyword", "generic-api-key", "url-query-secret", "auth-scheme")
_TEST_PATH_RE = re.compile(r"(?:^|[/\\])(?i:tests?|__tests__|spec|testdata|test_data|e2e)[/\\]"
                           r"|(?:^|[/\\]|[a-z])Tests?\.\w+$"
                           r"|(?:^|[/\\])[^/\\]*[._-]e2e[._-][^/\\]*$"
                           r"|(?:^|[/\\])(?:test_[^/\\]*|[^/\\]*_test\.\w+|[^/\\]*\.(?:test|spec)\.\w+|conftest\.py)$")
# a file of real values even under tests/: an .env, a recorded HTTP cassette (review, 2026-09-29)
_REAL_VALUE_FILE_RE = re.compile(r"(?i)(?:^|[/\\])(?:\.env[^/\\]*|[^/\\]*\.env|cassettes?[/\\].*)$")
_TEST_MARKER_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\(|class[ \t]+Test\w*|@pytest\.|@Test\b|#\[test\]"
    r"|(?:import|from)[ \t]+(?:pytest|unittest)\b|func[ \t]+Test\w*\(|(?:describe|it|test|beforeEach)[ \t]*\()")
# `assert` alone is no marker: production code asserts too (review, 2026-09-29). A diff starts a new file here
_DIFF_FILE_RE = re.compile(r"(?m)^(?:diff --git |\+\+\+ |--- a/)")
_GREP_PATH_RE = re.compile(r"((?:[A-Za-z]:)?[^\s:]+):\d+[:-]")
_TEST_LOOKBACK_LINES = 40


def is_test_path(path: str) -> bool:
    return bool(path) and bool(_TEST_PATH_RE.search(path)) and not _REAL_VALUE_FILE_RE.search(path)


def in_test_code(text: str, start: int, path: str = "") -> bool:
    """Whether the hit at `start` sits in test code: the file is a test file, a grep line names one, or a test
    marker (`def test_`, `assert`, `describe(` …) stands in its line or in the 40 lines before it."""
    if is_test_path(path):
        return True
    line_start = text.rfind("\n", 0, start) + 1
    m = _GREP_PATH_RE.match(text, line_start)
    if m and is_test_path(m.group(1)):
        return True
    begin = line_start
    for _ in range(_TEST_LOOKBACK_LINES):
        if begin == 0:
            break
        begin = text.rfind("\n", 0, begin - 1) + 1
    for d in _DIFF_FILE_RE.finditer(text, begin, line_start):
        begin = d.start()          # a marker of another file in the same diff does not count
    end = text.find("\n", start)
    return bool(_TEST_MARKER_RE.search(text, begin, end if end >= 0 else len(text)))


def is_fixture(m: "Match", text: str, path: str = "") -> bool:
    """A label-rule hit in test code: not a secret the person typed (see LABEL_RULES). The first rule to claim a
    span wins, and the label rules run before the shape rules: `token = "<a JWT>"` got the kind of a label rule and
    was dropped with the fixtures (review, 2026-09-29). A value that a shape rule finds on its own stays a hit."""
    if not (m.type == "SECRET" and m.kind.startswith(LABEL_RULES) and in_test_code(text, m.start, path)):
        return False
    return not scan(m.value, enabled=_shape_rule_ids())


_SHAPE_IDS: list = []


def _shape_rule_ids() -> set:
    if not _SHAPE_IDS:
        _SHAPE_IDS.append({r.id for r in rules() if not r.id.startswith(LABEL_RULES)})
    return _SHAPE_IDS[0]


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


_LABEL_ONLY_RE = re.compile(r"[:=]\s*$")
# a line of code that ends in a colon is a condition, not a label: `if kind != "SECRET":` and
# `continue` on the next line was taken for a labelled secret (twice in this repository's own
# pre-commit check, 2026-09-27)
# Code syntax only: a comparison operator, or a line that opens a block with a keyword and has
# no space between the keyword and the rest of a sentence. "for the db, password:" and "if
# needed, passwort:" are labels in a sentence and must still take the next line (review,
# 2026-09-27: matching the bare words hid them).
_CODE_CONDITION_RE = re.compile(r"(?:==|!=|<=|>=|\bis not\b|^\s*(?:def|class)\s+\w+\s*[(:])")
# a keyword rule reads `if not token: <statement>` as label and value: the statement word went into the vault
# and every later text with that word was redacted, code included (field report, 2026-09-29). A statement
# keyword is never a value. A check of the whole line ("it opens a block") was tried and dropped: the colon
# of the label itself satisfied it, and `with password: <value>` went through (review, 2026-09-29)
_CODE_WORDS = frozenset({"break", "continue", "return", "pass", "raise", "throw", "yield", "await", "elif",
                         "else"})

# the word after a label in an error message or a log line: "pwd: expected bytes, got str" (Python standard library,
# 2026-09-29), "token: invalid", "password: required". None is a password anyone chooses
_MESSAGE_WORDS = frozenset({"expected", "invalid", "missing", "required", "incorrect", "wrong", "failed", "denied",
                            "unsupported", "mismatch", "rejected", "expired", "revoked", "unset", "empty", "unknown",
                            "must", "cannot", "should", "not", "no"})


def is_code_word(value: str) -> bool:
    """A statement keyword or a word of an error message: a keyword rule never takes it as a value."""
    w = value.strip().rstrip(";").lower()
    return w in _CODE_WORDS or w in _MESSAGE_WORDS


def code_word_spellings() -> list[str]:
    """The spellings of such a word that a keyword rule stored before 0.5.15. The vault finds a stored one by its
    fingerprint and reads no value (Vault.drop_code_words)."""
    return [s for w in sorted(_CODE_WORDS | _MESSAGE_WORDS) for b in (w, w.capitalize(), w.upper())
            for s in (b, b + ";")]


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LABEL_TAIL_RE = re.compile(r"([A-Za-z_][\w.]*)[\"']?\s*(?::=|=|:)\s*[\"'`]?$")
_OPERATOR_AFTER_RE = re.compile(r"[ \t]+[|&^*+][ \t]+[A-Za-z_(]")
_SELF_ATTR_RE = re.compile(r"(?:^|[\s,(])(?:self|this|cls)\.\w+$")


def value_is_code(text: str, start: int, end: int, secret: str) -> bool:
    """A keyword rule read `name = <expression>` in source code as label and value. Three forms, all measured in the
    Python standard library (2026-09-29): the same name on both sides (`authkey=authkey`), an unquoted name that an
    operator continues (`TOKEN_ENDS = TSPECIALS | WSP`), and an unquoted name given to an attribute of the object
    (`self.token = nextchar`). A quoted value, and `spring.datasource.password=<value>`, stay values."""
    v = secret.strip().strip("'\"`;,")
    line_start = text.rfind("\n", 0, start) + 1
    before = text[line_start:start]
    m = _LABEL_TAIL_RE.search(before)
    if not m:
        return False
    label = m.group(1)
    name = label.rsplit(".", 1)[-1].lower()
    if v.lower() == name or v.lower().startswith(name + "#"):
        return True   # also a documentation anchor: 'token': 'token#module-token'
    if before[-1:] in "'\"`" or not _IDENT_RE.fullmatch(v):
        return False
    if len(name) >= 3 and not any(c.isdigit() for c in v) and (v.lower().startswith(name) or v.lower().endswith(name)):
        return True   # a name made from the label: token = tokenizer, token = nexttoken
    if "=" in m.group(0) and _OPERATOR_AFTER_RE.match(text, end):
        return True   # an assignment only: `password: <value> | then log in` is prose
    return bool(_SELF_ATTR_RE.search(before[:m.start(1) + len(label)]))


# gitleaks' generic-api-key takes `key = "Europe/Dublin"`: words joined by `/` without a digit are a time zone or a
# path, never a key (Python standard library, 2026-09-29)
_WORD_PATH_RE = re.compile(r"[A-Z]?[a-z]+(?:_[A-Z]?[a-z]+)*(?:/[A-Z]?[a-z]+(?:_[A-Z]?[a-z]+)*)+")
# a signed number in code: `a = +4294967296`, `f(+12345678)`
_SECTION_BEFORE_RE = re.compile(r"(?i)(?:\bRFC[ -]?\d{3,5}|\bCore|\bsection|\bsec\.|\bchapter|\bKapitel|\bAbschnitt"
                                r"|\u00a7)[ ,:(]*\u00a7?[ ]*$")
_PHONE_LABEL_RE = re.compile(r"(?i)phone|tel|mobil|handy|fax|contact|kontakt|rufnummer|whatsapp|sms")
_NUMBER_BEFORE_RE = re.compile(r"(?:=\s+|[(\[]\s*|return\s+)$")   # not KEY=+49…, not a CSV column


def _phone_ok(text: str, start: int, secret: str) -> bool:
    """E.164 has at most 15 digits; a run of 0 and 1 is a binary number; a signed number without separators after
    `=`, `(` or `,` is a number in code (Python standard library, 2026-09-29)."""
    digits = re.sub(r"\D", "", secret)
    if len(digits) > 15 or set(digits) <= {"0", "1"}:
        return False
    if re.search(r"[ \-()]", secret) or not _NUMBER_BEFORE_RE.search(text, max(0, start - 8), start):
        return True
    return bool(_PHONE_LABEL_RE.search(_label_before(text, start)))   # CONTACT_PHONE = +49… (Codex review)


# gitleaks' generic-api-key starts with a lazy `[\w.-]{0,50}?` before its keyword, so the regex
# engine tries up to 50 prefixes at every position of the text: 80 % of a log scan's time
# (2026-09-27). Its keywords are found by a plain search first, and the rule runs only in a
# window around each: from 50 characters before the keyword (the prefix cannot cross a line) to
# the end of the 8th line after it (the separators may hold line breaks; the window ends after a
# newline, which the value's terminator class takes the same way as in the whole text).
_WINDOWED = {"generic-api-key": re.compile(r"(?i)access|auth|api|credential|creds|key|passw(?:or)?d|secret|token")}


def _windowed(rule: Rule, kw: re.Pattern, text: str):
    spans: list[list[int]] = []
    for k in kw.finditer(text):
        line_start = text.rfind("\n", 0, k.start()) + 1
        a = max(line_start, k.start() - 50)
        # the separators may hold several line breaks (`password for prod:` + blank line +
        # value, review 2026-09-27). The regex allows 3 whitespace characters before the separator
        # and 5 after it, so the value can start after 8 line breaks: the window runs to the end
        # of the 9th line (8 cut `password\n\n\n:\n\n\n\n\n<value>` off, differential test 2026-09-27)
        b = k.end()
        for _ in range(9):
            nxt = text.find("\n", b)
            if nxt < 0:
                b = len(text)
                break
            b = nxt + 1
        if spans and a <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], b)
        else:
            spans.append([a, b])
    last_end = -1
    for a, b in spans:
        for m in rule.regex.finditer(text[a:b]):
            if m.start() + a < last_end:
                continue
            last_end = m.end() + a
            yield _Shifted(m, a)


def _matches(rule: Rule, text: str):
    """detect-secrets keyword rules are line rules: run them per line, keep absolute offsets.

    A label that ends its line (``passwort:`` and the value on the next line, as a console
    or a chat renders it) is scanned together with the next non-empty line; only a hit whose
    value starts in that next line is taken from the pair (field report, 2026-09-26)."""
    kw = _WINDOWED.get(rule.id)
    if kw is not None and len(text) > 4096:
        yield from _windowed(rule, kw, text)
        return
    if not rule.id.startswith("ds-keyword") or "\n" not in text:
        yield from rule.regex.finditer(text)
        return
    pos = 0
    lines = text.split("\n")
    low = _lower(text).split("\n") if rule.keywords else None
    for i, line in enumerate(lines):
        # the regex needs one of the rule's keywords in this line (every denylist word contains
        # one); skipping the other lines cut a history scan from 71 s to a fraction (2026-09-27)
        if low is not None and len(low) == len(lines) and not any(k in low[i] for k in rule.keywords):
            pos += len(line) + 1
            continue
        for m in rule.regex.finditer(line):
            yield _Shifted(m, pos)
        if _LABEL_ONLY_RE.search(line) and not _CODE_CONDITION_RE.search(line):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                pair = "\n".join(lines[i:j + 1])
                for m in rule.regex.finditer(pair):
                    g = rule.secret_group if 0 < rule.secret_group <= (rule.regex.groups or 0) else 0
                    if m.start(g) > len(line):
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


def _names_its_label(text: str, start: int, secret: str) -> bool:
    """`POSTGRES_PASSWORD: postgres`, `password: password`: the value is a word of its own label, a default. With
    one label on the line the whole line counts (`ALTER USER postgres WITH PASSWORD 'postgres'`); with more, only
    the label of the value: in `smtp.host=mail.contoso.de smtp.password=contoso` the word is another value
    (review, 2026-09-29)."""
    before = text[text.rfind("\n", 0, start) + 1:start]
    m = _LABEL_TAIL_RE.search(before)
    if m and len(re.findall(r"[:=]", before[:m.start()])) > 0:
        before = m.group(1)
    words = set(re.findall(r"[a-z]+", before.lower()))
    v = secret.strip("\"'` ").rstrip(".,;:!?")
    if v.lower() in words:
        return True   # also at the end of a sentence
    parts = [p.lower() for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", v)]
    return len(parts) >= 2 and "".join(parts) == v.lower() and set(parts) <= words   # token_data: TokenData


# lookarounds, not ^: search(text, pos) anchors ^ at the start of the text, never at pos (a file's line 19 passed)
_MEASURE_LABEL_RE = re.compile(r"(?i)(?<![a-z])(?:ttl|timeout|expir\w*|lifetime|max|min|len|length|size|count|limit"
                               r"|port|age|seconds|minutes|hours|days|retries|interval)(?![a-z])")
# a label that names a secret: a UUID after it is one (Postmark server token, Scaleway secret key, a uuid4 API key)
_SECRET_LABEL_RE = re.compile(r"(?i)(?:token|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|password"
                              r"|passwd|pwd)[\"']?\s*(?::=|=>|[:=])\s*[\"'`]?$")
_ELISION_RE = re.compile(r"(?:\.\.\.|\u2026)$")
# a label that names a derived thing: secret_id, password_hash, token_type, hashed_secret. Anchored at the value: in
# `secret_name: x, password: <value>` the password stays a hit
_DERIVED_LABEL_RE = re.compile(
    r"(?i)(?:(?:secret|password|passwd|pwd|token|key)[_-]?(?:id|name|hash|hashed|len|length|path|file|arn|ref|url|uri"
    r"|version|type|policy|rules?)|hashed_(?:secret|password)|(?:secret|password|token|key)Id"
    r"|(?:secret|password|token)Name)[\"']?\s*(?::=|=>|[:=])\s*[\"'`]?$")


def _label_before(text: str, start: int) -> str:
    """The label of the value at `start`: `TTL_REFRESH_TOKEN` in `TTL_REFRESH_TOKEN = 15552000`."""
    m = _LABEL_TAIL_RE.search(text, max(0, text.rfind("\n", 0, start) + 1), start)
    return m.group(1) if m else ""


def _pass_equals_user(whole: str, secret: str) -> bool:
    """`postgres:postgres@`, `curl -u admin:admin`: a password equal to the user name is a default."""
    sec = secret.strip("\"' ")
    if ":" in sec:    # curl-auth-user: the secret group is user:pass
        u, _, pw = sec.partition(":")
        return u != "" and u.strip("\"' ").lower() == pw.strip("\"' ").lower()
    w = whole.strip("\"' ")
    head = w.split("://", 1)[1] if "://" in w else w
    user = head.split(":", 1)[0].strip("\"' ").rsplit(" ", 1)[-1]
    return user != "" and user.lower() == sec.lower()


def _line_of(text: str, start: int, end: int) -> str:
    a = text.rfind("\n", 0, start) + 1
    b = text.find("\n", end)
    return text[a: b if b >= 0 else len(text)]


def _allowed(rule: Rule, text: str, m: re.Match, secret: str) -> bool:
    """True when an allowlist says this hit is fine (i.e. skip it)."""
    if rule.stopwords and any(s in secret.lower() for s in rule.stopwords):
        return True
    for rx, target in rule.allow_regexes:
        # "match" is the whole match: `keyboard = …`, `public_key: …`, `api_version = …` are allowed
        # by their label, which the secret alone never shows (false-positive corpus, 2026-09-27)
        if target == "line":
            probe = _line_of(text, m.start(), m.end())
        else:
            probe = m.group(0) if target == "match" else secret
        if rx.search(probe):
            return True
    return False


_TOKEN_CHAR_RE = re.compile(r"[A-Za-z0-9_\-]")


def _lower(text: str) -> str:
    """Lower case for the prefilters and context words. The Turkish capital İ lowers to i plus a
    combining dot, so `ŞİFRE:` held no `ifre` (Codex review, 2026-09-28); the dot is dropped. The
    result is not the length of the input: never take an offset of the original into it."""
    return text.lower().replace("i\u0307", "i")


def scan(text: str, enabled: set[str] | None = None) -> list[Match]:
    """Return non-overlapping matches, leftmost first; the first rule to claim a span wins."""
    if not text:
        return []
    low = _lower(text)
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
            if rule.quote_group and not m.group(rule.quote_group):
                cut = _WHITESPACE_RE.search(secret)
                if cut:
                    # the regex never ends a value on a comma; the cut keeps that rule
                    secret = secret[:cut.start()].rstrip(",")
                    end = start + len(secret)
                    if _CAPITALISED_WORD_RE.fullmatch(secret):
                        continue
            if rule.id.startswith("ds-keyword") and (is_code_word(secret) or value_is_code(text, start, end, secret)):
                continue
            if rule.id == "generic-api-key" and _WORD_PATH_RE.fullmatch(secret.strip("'\"")):
                continue
            if rule.id.startswith("ds-keyword") and _names_its_label(text, start, secret):
                continue
            if (rule.id.startswith("ds-keyword") and _LABEL_SHAPE.fullmatch(secret.strip())
                    and _NAME_LABEL_RE.fullmatch(secret.strip()) and "\n" in text[m.start():start]):
                continue   # the next line is a label of its own: `DB_PASSWORD=\nAPI_KEY=`, `Zugangsdaten:\nBenutzer:`
            if (rule.id.startswith("ds-keyword") and secret.strip("\"' ").isdigit()
                    and _MEASURE_LABEL_RE.search(_label_before(text, start))):
                continue   # a limit or a duration: TTL_REFRESH_TOKEN = 2592000
            if rule.id == "url-query-secret" and secret.startswith("{"):
                continue   # a template: ?token={body['transfer_id']}, ?token={SLACK_AUTO_TOKEN}
            if (rule.id == "auth-scheme" and not any(c.isdigit() for c in secret)
                    and re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z]+)+", secret)):
                continue   # words, not a token: Bearer test_access_token
            if (rule.id.startswith("ds-keyword") or rule.id == "generic-api-key") and (
                    (_UUID_RE.fullmatch(secret.strip("\"'` ")) and not _SECRET_LABEL_RE.search(
                        text, max(0, text.rfind("\n", 0, start) + 1, start - 60), start))
                    or _ELISION_RE.search(secret)
                    or _DERIVED_LABEL_RE.search(text, max(0, text.rfind("\n", 0, start) + 1, start - 60), start)):
                continue   # a UUID, an elided value (sk-...), or a label that names a derived thing (secret_id)
            if rule.id in ("ds-basic-auth", "curl-auth-user") and _pass_equals_user(m.group(0), secret):
                continue
            if rule.id == "hashicorp-tf-password" and not _ds_value_ok(secret.strip("\"'")):
                continue
            if rule.id == "phone" and not _phone_ok(text, start, secret):
                continue
            if rule.type == "IP" and _SECTION_BEFORE_RE.search(text, max(0, start - 24), start):
                continue   # a section number: RFC 6749 4.1.2.1, OIDC Core 3.1.2.1, section 7.1.2.3
            if any(s < end and start < e for s, e in taken):
                continue
            if rule.entropy and shannon_entropy(secret) < rule.entropy:
                continue
            if rule.validator:
                try:
                    if (rule.validator == "ds_value" and 0 < start and text[start - 1] in ":="
                            and text.rfind("⟦", 0, start) <= text.rfind("⟧", 0, start)):   # not inside ⟦…⟧
                        # a value glued to its label, with no space after the colon, is typed on purpose: 6 characters
                        # count. With a space between them 8 stay the floor, against prose such as
                        # "password: string" (field report, 2026-09-27: a 7-letter password passed)
                        ok = _ds_value_ok(secret, min_len=6) and (len(secret.strip()) >= 8 or not _short_word(secret))
                    else:
                        ok = VALIDATORS[rule.validator](secret)
                except (ValueError, IndexError, TypeError):
                    ok = False   # a validator that cannot parse the value has not validated it
                if not ok:
                    continue
            if rule.type == "SECRET" and looks_like_placeholder(secret):
                continue
            if rule.type == "SECRET" and len(secret) >= 16 and len(set(secret[-12:])) <= 1:
                continue   # a prefix and one repeated character: glpat-AAAAAAAAAAAAAAAAAAAA is a placeholder
            if rule.score < 1.0 or rule.require_context:
                # presidio semantics: a weak shape passes only with a context WORD nearby
                # cut from the original text, then lowered: a lowered text is not the same length (the
                # Turkish İ lowers to two characters), so its offsets are not the original's
                window = _lower(text[max(0, start - 80):min(len(text), end + 40)])
                has_context = _has_context_word(window, rule.context)
                if rule.require_context and not has_context:
                    continue
                if rule.score < 0.5 and not has_context:
                    continue
            if _allowed(rule, text, m, secret):
                continue
            # our own placeholders are never a hit, alone or inside a larger span such as the
            # user:pass of `curl -u "app:⟦SECRET_c1⟧"` (the README example was flagged, 2026-09-26)
            if text[max(0, start - 1):start] in ("<", "\u27e6") and re.match(r"[A-Z][A-Z_]*_c\d+", secret):
                continue
            if "\u27e6" in secret or re.search(r"<[A-Z][A-Z_]*_c\d+>", secret):
                continue
            if rule.type == "SECRET":
                # a fixed-length shape (gitleaks: glpat-[\w-]{20}) stops inside a longer token and
                # the tail would stay in the clear (4 chars of a 24-char token, 2026-09-26): the
                # value runs to the end of the token characters
                end2 = end
                while end2 < len(text) and end2 - end < 128 and _TOKEN_CHAR_RE.match(text[end2]):
                    end2 += 1
                if end2 > end and _TOKEN_CHAR_RE.match(secret[-1]) and not any(s < end2 and end < e for s, e in taken):
                    end = end2
                    secret = text[start:end]
            found.append(Match(rule.id, rule.type, secret, start, end))
            taken.append((start, end))
    found.sort(key=lambda x: x.start)
    return found


def contains_secret(text: str) -> bool:
    return any(m.type in SECRET_TYPES for m in scan(text))
