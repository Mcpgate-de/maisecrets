"""Deterministic detection of secrets and PII in text.

Three rule sources, one scanner:

1. **betterleaks** (`rules/betterleaks.toml`, vendored, MIT, version in
   `rules/BETTERLEAKS_VERSION`): about 400 secret shapes with keywords and
   filters. Consumed as data; no betterleaks binary. The filters are Expr
   expressions, read by `rule_filter.py`; a rule whose filter is a program
   that module cannot read is left out. Refresh with
   `scripts/sync_betterleaks.py vX.Y.Z`. betterleaks is the successor of
   gitleaks.
2a. **Own secret rules** (`rules/own_secret_rules.json`, patterns derived from
   gitleaks v8.30.1, MIT): generic-api-key, to which the label filters below
   are tuned, and the token forms the betterleaks rules miss.
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

import bisect
import itertools
import hashlib
import ipaddress
import json
import math
import re
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from . import checksums

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
    drop: object = None                # betterleaks: the rule's filter and the global one; True drops the finding


# ----------------------------------------------------------------- helpers --
def _re2_to_python(rx: str) -> str:
    """betterleaks (and gitleaks) regexes are RE2. Python differs in two spots we hit."""
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


# IBAN length per country (SWIFT IBAN registry). Only an IBAN in lower case is held to it: a hex digest in lower case
# such as `de12…` passes mod 97 one time in 97; an IBAN in capitals keeps the vendored check alone
IBAN_LENGTH = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
    "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29,
    "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24,
    "SM": 27, "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").replace("-", "").upper()   # the vendored pattern takes a space or a hyphen between groups
    if not 15 <= len(s) <= 34 or not s.isalnum():
        return False
    if raw != raw.upper() and IBAN_LENGTH.get(s[:2]) != len(s):
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
    if ":" not in ip:
        ip = ".".join(str(int(o)) for o in ip.split("."))   # 085.214.132.005 (final review, 2026-09-30)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    inner = getattr(addr, "sixtofour", None)
    if inner is not None:
        addr = inner    # 2002:55d6:8405::1 carries 85.214.132.5
    return addr.is_global and not addr.is_multicast and str(addr) not in _RESOLVER_IPS


def _de_tax_id_ok(v: str) -> bool:
    """Steuer-ID (IdNr, § 139b AO): eleven digits, the first never 0. In the first ten, exactly one digit occurs twice
    or three times and every other digit once at most; a digit that occurs three times never stands at three places
    in a row. The eleventh is the check digit, ISO 7064 MOD 11,10. Source: ITZBund, "KONZEPT Steueridentifikationsnummer
    (IdNr) nach § 139b AO", version 2.3 of 2016-03-01, section 1, and ELSTER, "Prüfung der Steuer- und
    Steueridentifikationsnummer", 2026-09-02, section 2.2. Presidio's "no digit more than three times" passed 8.7 % of
    random numbers; this rule passes 0.4 % (0.6.19)."""
    if len(v) != 11 or not v.isdigit() or v[0] == "0":
        return False
    digits = [int(d) for d in v]
    repeated = [(d, n) for d, n in Counter(digits[:10]).items() if n > 1]
    if len(repeated) != 1 or repeated[0][1] not in (2, 3):
        return False
    if repeated[0][1] == 3 and any(digits[i] == digits[i + 1] == digits[i + 2] for i in range(8)):
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


def _us_ssn_ok(v: str) -> bool:
    """Presidio's UsSsnRecognizer.invalidate_result (microsoft/presidio 8c98180a46, the last change of
    us_ssn_recognizer.py on main as of 2026-10-11), ported: mixed delimiters,
    one digit repeated, a group of zeros, area 000 or 666, or one of the published sample numbers is no SSN. The
    vendored rule had no validator, so `000-00-0000` in a form was a hit (public benchmark, 2026-10-11)."""
    if len({c for c in v if c in ".- "}) > 1:
        return False
    d = "".join(c for c in v if c.isdigit())
    if not d or len(set(d)) == 1:
        return False
    if d[3:5] == "00" or d[5:] == "0000" or d[:3] in ("000", "666"):
        return False
    return d not in ("1234" + "56789", "9876" + "54320", "0780" + "51120")


_DS_TEMPLATED = re.compile(r"^(\{\{.*\}\}|\$\{.*\}|<.*>|%.*%|\$[A-Za-z_][A-Za-z0-9_]*)$")
_DS_INDIRECT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\s*(\(.*\)|\[.*\])$")
# words joined by `.`, `_` or `-`, optionally ending where the regex cut the line (`:` of a
# condition, `;` of a statement, `[` before a quoted key): `settings.API_KEY`, `self._password`,
# `os.environ[`, `confirm_password:` were taken for values (false-positive corpus, 2026-09-27)
_DS_REFERENCE = re.compile(r"_*[A-Za-z]+(?:(?:\?\.|[._/:-]+)#?[A-Za-z]+)+_*\??[:;\[]?")
_FORMAT_ONLY_RE = re.compile(r"(?:%[-+ #0]*\d*(?:\.\d+)?[sdifxXeEgGrcoba%]|\{[^{}]*\}|[^A-Za-z0-9%{])+")


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
_NAME_LABEL_RE = re.compile(r"(?:[A-Z][A-Z0-9_]*|[a-z][a-z0-9_]*|[A-Z][a-z]+(?:[ _-][A-Za-z][a-z]+)*"
                            r"|[a-z]{2,}(?:[A-Z][a-z]{2,})+|[A-Za-z][a-z0-9]+(?:[A-Z][a-z0-9]{2,})*(?:[A-Z][a-z0-9]{2,}|[A-Z]{2,}|[A-Z][a-z0-9]))[.-]?[:=]")
_GENERIC_TYPE = re.compile(r"<[A-Za-z_][\w, ]*>")
_VERSION_RE = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+.]?[A-Za-z0-9]+)?")
_PART_TEMPLATE_RE = re.compile(r"\{[A-Za-z_][\w.]*(?:\[[^\]]*\]?)?\}?$|\{[A-Za-z_][\w.]*\}")
_SHELL_EXPANSION_RE = re.compile(r"[?:+=-]{1,2}[A-Z_][A-Z0-9_]*")
# the names of anchors and tags are lower case (&creds_2024, &gitlab_token_fields, !vault, !!str); a value with
# capitals after & or ! is a password (&Xk9v2Qm7…, !Passw0rd…; review of b4a7c54)
_ANCHOR_OR_TAG_RE = re.compile(r"[&*][a-z_][a-z0-9_-]*|!!?[a-z][a-z0-9_/-]*")
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


_IDENT_WORDS = frozenset({"password", "passwort", "token", "secret", "key", "value", "default", "config", "env",
                          "setting", "settings", "credential", "credentials", "auth", "api", "get", "set", "new", "old",
                          "user", "admin", "current", "stored", "hashed", "encrypted", "load", "read", "fetch",
                          "extract", "parse", "resolve", "build", "create", "from", "to", "with", "vault", "request",
                          "header", "environment", "variable", "store"})


def _short_word(v: str) -> bool:
    w = v.strip().rstrip(",;})]")
    if w.lower() in _SHORT_WORDS:
        return True
    if not _CAMEL_RE.match(w):
        return False
    words = [x.lower() for x in re.findall(r"[A-Z]?[a-z0-9]+", w)]
    # correctHorseBatteryStaple is a passphrase (final review, 2026-09-30)
    return len(words) <= 3 or any(x in _IDENT_WORDS for x in words)


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
    if _SHELL_EXPANSION_RE.fullmatch(v) or _PATH_IN_VALUE_RE.search(v):
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
    if re.match(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(?![\w])|\$\$\{?[A-Z_][A-Z0-9_]*\}?(?![\w])", v):
        return False   # a shell variable: $PASSWORD, ${DB_PASSWORD}; $$NAME in docker compose (upper case only)
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
    if not any(c.isdigit() for c in v) and (_DS_REFERENCE.fullmatch(v) or (
            v.rstrip(";").endswith("!") and "." in v and _DS_REFERENCE.fullmatch(v.rstrip(";")[:-1]))):
        return False   # a reference: NAME_OF_SECRET, self._password, os.environ[, opts.password! (TypeScript)
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


_LOWER_WORDS_RE = re.compile(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*")


_MARKER_RE = re.compile(r"\[[^\]]*\]|<[^>]*>|\{[^}]*\}")
# values the new label paths of 0.6.15 read that hold no password (release review of 0.6.15, Gate B): a date or a
# timestamp (passwordLastChanged, AUTH 2024-10-13), a file a tool reads (--password @/run/secrets/pw), a template
# variable a build fills (-p@MYSQL_PWD@), a placeholder to replace (CHANGE_ME_2024). The ds rules keep their own filter
_LABEL_NOT_A_VALUE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
    r"|@[~.]?/[^\s]*|@[A-Za-z_][A-Za-z0-9_]*@"
    r"|(?i:change[_-]?me)(?:[_-]?[A-Za-z0-9]+)*")


def _label_value_ok(v: str) -> bool:
    # the whole value, its last character too: `2024-10-13!` is a password, no date (codex, verification of 0.6.15).
    # The prose rule ends its value before the punctuation of the sentence, so it needs no strip here
    return not _LABEL_NOT_A_VALUE_RE.fullmatch(v.strip())


def _word_value_ok(v: str, min_len: int = 8, prose_punct: bool = False) -> bool:
    """A value after a label with no `=` or `:` (a CLI flag, Redis AUTH, netrc): as _ds_value_ok, and not letters
    only. Docs write `--password argument`, `AUTH LOGIN`, `--password PASSWORD`; a password of letters alone after such
    a label stays a gap, as it is after the colon forms below 8 characters. A marker a log wrote (`[REDACTED]`,
    `<pw>`, `{password}`) and a Windows path (a backslash) are no value (round 2 of 0.6.15). With prose_punct (the CLI
    flag in a typed sentence) the punctuation after a word is no part of it: "give --password explicitly?" is a
    question (Gate B of 0.6.15); after AUTH or in a netrc, `Sommerurlaub!` stays a value."""
    w = v.strip()
    if _MARKER_RE.fullmatch(w) or w[:1] in "[{<" or "\\" in w:   # the flag regex ends a value at ]: [REDACTED
        return False
    if not _label_value_ok(w):
        return False
    core = w.rstrip(".,;:!?)") if prose_punct else w
    return _ds_value_ok(v, min_len=min_len) and not core.isalpha()


# prose about a password, not one: a hyphen compound whose last part says what was done to it (SHA256-hashed,
# AES-256-encrypted, 1Password-managed, OWASP-ASVS-4.0-compliant), and names of algorithms, encodings and standards
# with their numbers and versions (PBKDF2-SHA256, ISO-8859-1, UTF-16LE, WPA2-PSK, Argon2id-v19, RFC-7617, ARGON2ID).
# A compound with a word of its own stays a value: Xk9-q2-secret, Winter-2024-berlin, Sha256-2024! (round 2)
_PROSE_LAST = frozenset({
    "hashed", "encrypted", "encoded", "decoded", "managed", "protected", "enabled", "disabled", "signed", "salted",
    "compliant", "based", "derived", "generated", "stored", "secured", "wrapped", "rotated", "required", "enforced",
    "backed", "verified", "validated", "compatible", "formatted", "only", "free", "safe", "aware", "style", "format",
    "encryption", "hashing", "encoding"})
_VERSION_PART_RE = re.compile(r"v?\d+(?:\.\d+)*")
_ALGORITHM_PARTS = frozenset({
    "md5", "sha1", "sha2", "sha3", "sha224", "sha256", "sha384", "sha512", "pbkdf2", "bcrypt", "scrypt", "argon2",
    "argon2i", "argon2d", "argon2id", "aes", "aes128", "aes192", "aes256", "gcm", "cbc", "ctr", "rsa", "hmac", "des",
    "3des", "blake2b", "blake2s", "blake3", "sha", "crypt", "ntlm", "ntlmv2", "chacha20", "poly1305", "ecdsa",
    "ed25519", "x25519", "pkcs1", "pkcs5", "pkcs8", "pkcs12", "oaep", "pss",
    "iso", "utf", "utf8", "utf16", "utf16le", "utf16be", "utf32", "16le", "16be", "latin1", "cp1252", "ascii",
    "base64", "base32", "hex", "wpa", "wpa2", "wpa3", "psk", "sae", "eap", "tls", "ssl", "rfc", "owasp", "asvs", "nist",
    "fips", "scram", "chap", "totp", "hotp", "kerberos", "x509", "plus", "jwt", "jwe", "jws", "oauth", "oauth2"})


def _prose_word(v: str) -> bool:
    parts = v.lower().split("-")
    if len(parts) >= 2 and parts[-1] in _PROSE_LAST:
        return True
    names = [x for x in parts if not _VERSION_PART_RE.fullmatch(x)]
    return bool(names) and all(x in _ALGORITHM_PARTS for x in names)


def _prose_value_ok(v: str) -> bool:
    """`my password is <value>`: no word of a sentence. A letter and a digit must be in it, and a capital or a
    symbol beyond - _ .: `incorrect`, `base64-encoded`, `hunter2`, `valid.\\n@param` (an escaped line break in
    generated docs) are prose; the shapes `Aa9#aA9a` and `aAA%aAA9A` are values."""
    v = v.strip()
    return (_word_value_ok(v) and not _LOWER_WORDS_RE.fullmatch(v) and "\\" not in v and not _prose_word(v)
            and any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


_DIGEST_PREFIX_RE = re.compile(r"(?i)(?:sha\d*|md5|blake\w*|h1)[-:]")
# words and numbers run together: ProdDbPassword2024Rotated, Authentication123, SECRET_NAME_2024. A word has two
# letters at least; a random key has a lone letter (a capital before a digit, a small letter between digits) in it
_WORDS_RUN_RE = re.compile(r"(?:[A-Z][a-z]+|[a-z]{2,}|[A-Z]{2,}(?![a-z])|\d+|[_.-])+")


def _keylike(v: str) -> bool:
    """A capital, a small letter and a digit, and not words run together."""
    return (any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v)
            and not _WORDS_RUN_RE.fullmatch(v))


# values in a list of secrets that are no key: a password hash, a name with a scheme (arn:aws:…, urn:…)
# ($2b$…, $argon2id$…), an Ethereum address (0x and 40 hex), an id with a type prefix (pm_…, sess_…, cus_…). Hex
# alone and base58 stay values here: every label of label-secret-list names secrets (a commit, an ObjectId or a
# Solana mint sits in a list of tokens or ids, which the rule does not read; a base58 check lost 12 % of random keys)
_LIST_NOT_A_KEY_RE = re.compile(r"\$[\w-]+\$.*|[a-z][\w+.-]*:.*|0x[0-9a-fA-F]+|[a-z]{2,6}_[A-Za-z0-9_-]+")
# a path has a segment of small letters between slashes (base64 has a slash too, but rarely a word between two)
_PATH_SEGMENT_RE = re.compile(r"(?:^|/)[a-z][a-z_.-]{2,}/")
# a word part: two small letters or more after an optional capital, or three capitals or more; it counts as a word
# when it has a vowel (and three letters, unless all small)
_WORD_PART_RE = re.compile(r"[A-Z]?[a-z]{2,}|[A-Z]{3,}")
_VOWEL_RE = re.compile(r"[aeiouyAEIOUY]")


def _word_shaped(v: str) -> bool:
    """Words make up 60 % of the value or more: TokenizerPiece2024X, iPhone15ProMax, convertToUTF8String. Measured on
    random keys of 16 to 64 characters (base64): 2.6 % are word-shaped by this test."""
    words = (w for w in _WORD_PART_RE.findall(v) if _VOWEL_RE.search(w) and (len(w) >= 3 or w.islower()))
    return sum(len(w) for w in words) >= 0.6 * len(v)


def _list_value_ok(v: str) -> bool:
    """A value in a list after a secret label (label-secret-list): hex of 16 or more with a letter and a digit, or 16
    or more characters that _keylike takes and that are not word-shaped. A path, a password hash, a name with a
    scheme, an address, a typed id, a digest with its algorithm and a filler are no key. Cheap
    checks first: this runs on each value of a list before the filters of scan()."""
    v = v.strip()
    if len(v) < 16 or " " in v or _LIST_NOT_A_KEY_RE.fullmatch(v) or _DIGEST_PREFIX_RE.match(v):
        return False
    if _PATH_SEGMENT_RE.search(v):   # projects/p/secrets/db, secret/data/app, /run/secrets/x
        return False
    if shannon_entropy(v) < 2.5:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", v):
        ok = any(c.isdigit() for c in v) and any(c.isalpha() for c in v)
    else:
        ok = _keylike(v) and not _word_shaped(v)
    return ok and _ds_value_ok(v, min_len=16)


def _apikey_value_ok(v: str) -> bool:
    """The value after `Authorization: ApiKey`: base64 or base64url (Elasticsearch, Kibana) that decodes to `id:key`,
    both parts not empty and printable. Docs write `ApiKey <base64-encoded id:key>`, `ApiKey ${ES_API_KEY}` and
    `ApiKey YOUR_ENCODED_API_KEY`, which decode to nothing of that form."""
    import base64
    import binascii
    raw = v.strip()
    padded = raw + "=" * (-len(raw) % 4)
    for alt in (None, b"-_"):
        try:
            dec = base64.b64decode(padded, altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            txt = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        ident, sep, key = txt.partition(":")
        if sep and ident and key and txt.isprintable() and " " not in txt:
            return True
    return False


# ------------------------------------------------------- label and literal value --
# A password label and a literal value that is no word: `db_password = "<value>"`, `<password><value></password>`,
# `?pwd=<value>`, `IDENTIFIED BY '<value>'`, `ConvertTo-SecureString '<value>'`. The label is read from a frozen list
# of label words; the value must be no word of English or of developer text after undoing leet (P4ssw0rd is a word),
# which keeps `password = "changeme"`, `password: hunter`, `password = os.environ[...]` and `password: ${DB_PASS}`
# text. Word-likeness and the label word classes follow Dan Szymkowiak's backlog ideas (TASK-11.22, TASK-11.23).
# Measured on CredData without repository 2ba83c6a (split by repository: discovery half, validation half).
_WORDS_FILE = "words_en.txt"   # SCOWL en_US 60, 4 to 8 letters (rules/LICENSE-scowl, scripts/sync_words.py)
_WORDS: list = []
# words that the English list lacks: short words, code identifiers, algorithm names, German words of developer prose
# "password" in other languages: the whole value of a locale key (`"password": "Senha"`) is a label text, not a
# password (Opus Gate B of 0.6.17). An exact value only: as words they made Senha123 a word with a number, and 0.6.16
# took it (Gate B round 2)
_PW_TRANSLATIONS = frozenset({
    "senha", "heslo", "geslo", "lozinka", "sifre", "haslo", "parola", "parool", "salasana", "jelszo", "losenord",
    "passord", "adgangskode", "wachtwoord", "kennwort", "passwort", "contrasena", "motdepasse", "sifra", "parole"})
_EXTRA_WORDS = frozenset({
    "api", "key", "id", "db", "url", "uri", "app", "dev", "prod", "test", "user", "pass", "pwd", "sql", "web",
    "admin", "root", "my", "new", "old", "the", "and", "for", "get", "set", "put", "add", "max", "min", "log",
    "tmp", "env", "var", "val", "str", "int", "num", "src", "dst", "cfg", "conf", "auth", "oauth", "jwt", "aws",
    "gcp", "ssh", "rsa", "pem", "http", "https", "www", "com", "org", "net", "io", "js", "py", "go", "is", "on",
    "of", "to", "in", "at", "by", "no", "ok", "yes", "let", "me", "foo", "bar", "baz", "abc", "xyz", "qwerty", "pw",
    "secret", "token", "hello", "world", "demo", "mock", "fake", "dummy", "sample", "example", "default",
    "kwargs", "args", "argv", "self", "this", "opts", "params", "nil", "none", "null", "undefined",
    "md5", "sha1", "sha2", "sha3", "sha224", "sha256", "sha384", "sha512", "pbkdf2", "bcrypt", "scrypt", "argon2",
    "argon2i", "argon2d", "argon2id", "aes", "aes128", "aes192", "aes256", "gcm", "cbc", "ctr", "hmac", "des",
    "blake2b", "blake2s", "blake3", "sha", "crypt", "ntlm", "ntlmv2", "chacha20", "poly1305", "ecdsa", "ed25519",
    "x25519", "pkcs1", "pkcs5", "pkcs8", "pkcs12", "oaep", "pss", "utf8", "utf16", "latin1", "ascii", "base64",
    "base32", "hex", "wpa", "wpa2", "psk", "tls", "ssl", "totp", "hotp", "jwe", "jws", "oauth2", "varchar",
    "bigint", "secretstr", "securestring", "bool", "float", "char", "byte", "bytes", "uuid", "json",
    "yaml", "html", "xml", "csv", "ldap", "smtp", "imap", "ftp", "sftp", "redis", "mysql", "postgres",
    "psql", "mongo", "mongodb", "sqlite", "oracle", "guest", "anon", "localhost",
    "siehe", "geheim", "kennwort", "passwort", "benutzer", "zugang", "zugangsdaten", "anmeldung", "nutzer", "wird",
    "nicht", "oder", "und", "mit", "ohne", "bitte", "hier", "dort", "neu", "alt", "leer", "fehlt", "falsch",
    "richtig", "geheimnis", "schluessel", "sommer", "winter", "herbst", "fruehling", "schl\u00fcssel",
    "fr\u00fchling",
})


def _word_set() -> frozenset:
    """The word list, read on the first password label (about 3 ms). A file that is missing, unreadable, not UTF-8 or
    not a list of words (fewer than 1,000 entries of small ASCII letters, or more than 1 % other lines) counts as no
    list: _WORDS_OK turns false, and the password rule then takes no value of letters only (_pw_literal_ok)."""
    if not _WORDS:
        words: set = set()
        ok = True
        try:
            entries = (RULES_DIR / _WORDS_FILE).read_text(encoding="utf-8").split()
            words = {w for w in entries if w.isascii() and w.isalpha() and w.islower() and len(w) <= 20}
            ok = len(words) >= 1000 and len(entries) - len(words) <= len(entries) // 100
        except (OSError, UnicodeError, ValueError):
            ok = False
        if not ok:
            words = set()
        _WORDS_OK[:] = [ok]
        _WORDS.append(frozenset(words | _EXTRA_WORDS))
    return _WORDS[0]


_WORDS_OK: list = [True]
_CHANNEL: list = ["prompt"]


_COVER_CACHE: dict = {}


def _cover(run: str) -> int:
    """The most letters of `run` that words of the list cover (dynamic programming over words of 2 to 20 letters)."""
    got = _COVER_CACHE.get(run)
    if got is None:
        words = _word_set()
        n = len(run)
        best = [0] * (n + 1)
        for i in range(1, n + 1):
            best[i] = best[i - 1]
            for j in range(max(0, i - 20), i - 1):
                if run[j:i] in words:
                    best[i] = max(best[i], best[j] + (i - j))
        got = best[n]
        if len(_COVER_CACHE) > 20000:
            _COVER_CACHE.clear()
        _COVER_CACHE[run] = got
    return got


_WORD_RUN_RE = re.compile(r"[A-Z\u00c4\u00d6\u00dc]?[a-z\u00e4\u00f6\u00fc\u00df]+|[A-Z\u00c4\u00d6\u00dc]+"
                          r"(?![a-z\u00e4\u00f6\u00fc\u00df])|[0-9]+")


def _wordlike(v: str) -> float:
    """The share of the letters of `v` that words cover, after an identifier split (0 to 1)."""
    letters = sum(c.isalpha() for c in v)
    if not letters:
        return 0.0
    words = _word_set()
    covered = 0
    for part in _WORD_RUN_RE.findall(v):
        if part.isalpha():
            low = part.lower()
            covered += len(low) if low in words else _cover(low)
    return covered / letters


def _charset(v: str) -> str:
    if v.isdigit() and v.isascii():
        return "digits"
    if re.fullmatch(r"[0-9a-f]+|[0-9A-F]+", v):
        return "hex"
    if re.fullmatch(r"[A-Za-z]+", v):
        return "alpha"
    if re.fullmatch(r"[A-Za-z0-9]+", v):
        return "alnum"
    return "other"


# a value that says it is no value: a mask, a template, a reference, a word of a form
_LITERAL_PLACEHOLDER_RE = re.compile(
    r"(?i)x{3,}|\*{3,}|\.{3}|<[^>]*>|\{\{|\}\}|\$\{|%\(|%s|\$[A-Za-z_]|your[_-]?|example|sample|dummy|placeholder|"
    r"changeme|change_me|redacted|replace|insert|enter[_-]|todo|fixme|foobar|lorem|secret_here|here$|^test|test$|"
    r"^fake|^mock|^none$|^null$|^true$|^false$|^undefined$|^password$|^secret$|^token$|^string$|^empty$|^default$")
_DOTTED_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_CLOSED_TEMPLATE_RE = re.compile(r"\{[A-Za-z_][\w.]*(?:\[[^\]{}]*\])?\}")   # {pw}, {cfg.pw}, {row['pw']}; not a lone {
_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _norm_label(name: str) -> list:
    """`dbPassword`, `DB_PASSWORD`, `db.password`, `db-password`, `db:Password` -> ["db", "password"]."""
    name = _CAMEL_SPLIT_RE.sub("_", name.lstrip("$@-"))
    return [t for t in re.split(r"[._:\-]+", name.lower()) if t]


# the last word of a password label, and the words before it that make the label name something else
_PW_LAST = frozenset({"password", "passwd", "passphrase", "passwort", "pwd", "userpwd", "pass", "pw", "passcode",
                      "passw", "pword", "pswd", "psw"})
# the label words of a language that is on (regions.py): Kennwort is a label only with German on, as for the keyword
# rules; passwort counts always, as the English `pass` label allows letters after it
_PW_LAST_OF = {"de": frozenset({"kennwort"})}
_PW_LAST_ON: list = [_PW_LAST]
_PASS_NEG_PREV = frozenset({"two", "one", "single", "multi", "first", "second", "third", "by", "no", "skip", "sur",
                            "over", "under", "compass", "render", "shader", "high", "low", "band", "all", "each",
                            "next", "last", "test", "tests"})
_LABEL_NEG_WORDS = frozenset({
    "hint", "label", "title", "text", "message", "msg", "error", "err", "prompt", "placeholder", "field", "policy",
    "length", "len", "min", "max", "required", "confirm", "confirmation", "reset", "forgot", "invalid", "incorrect",
    "wrong", "strength", "rule", "rules", "regex", "pattern", "hash", "hashed", "salt", "file", "path", "env", "var",
    "type", "mode", "enabled", "expire", "expires", "expiry", "changed", "change", "validation", "valid", "show",
    "hide", "toggle", "visible", "icon", "button", "btn", "no", "without", "skip", "ask", "input", "form", "dialog",
    "tooltip", "description", "desc", "help", "name", "id", "count", "cmd", "command", "url", "uri", "key", "column",
    "col", "header", "param", "arg", "option", "opt", "flag", "set", "get", "update", "lbl", "str", "string", "i18n",
    "translation", "not", "missing", "empty", "format", "fmt", "encoder", "encoded", "encrypted", "digest",
    "algorithm", "manager", "provider", "store", "storage", "service", "handler", "callback", "validator", "widget"})


def _pw_label(toks: list) -> bool:
    if not toks:
        return False
    last = toks[-1].rstrip("0123456789") or toks[-1]
    if last not in _PW_LAST_ON[0]:
        return False
    if last in ("pass", "pw") and len(toks) > 1 and toks[-2] in _PASS_NEG_PREV:
        return False
    return not any(t in _LABEL_NEG_WORDS for t in toks[:-1])


def _sequential(low: str) -> bool:
    return len(low) > 2 and (all(ord(low[i + 1]) - ord(low[i]) == 1 for i in range(len(low) - 1))
                             or all(ord(low[i]) - ord(low[i + 1]) == 1 for i in range(len(low) - 1)))


# what a value after a password label is when it is no password: a number, a ratio, a percentage, a range, a time, a
# duration or a size with its unit (95.2%, 118/124, 8-64, 12:30, ~30d, 24h/7d, 14C/27, 2025/26), a section (§3.2), a
# dotted abbreviation (s.o., z.B.), and a word with a number (Seite#3, Gate-12)
_MEASURE_VALUE_RE = re.compile(r"[~<>=+\u00a7#-]?\d+(?:[.,:/-]\d+)*(?:[a-z]{1,3}|[A-Z]{1,2})?"
                               r"(?:[/ -]\d+(?:[.,:]\d+)*(?:[a-z]{1,3}|[A-Z]{1,2})?)*%?")
_ABBREVIATION_RE = re.compile(r"(?:[A-Za-z\u00c0-\u024f]{1,4}\.)+[A-Za-z\u00c0-\u024f]{0,4}")
# a path or a reference after a password label names where the password lives: /run/secrets/db, ../x/y, ~/.pw,
# C:\keys\db.pw, \\server\share, file:///etc/pw, vault:secret/db#pw, env:DB_PASSWORD
_PATH_REFERENCE_RE = re.compile(r"(?:[/~]|\.{1,2}[/\\]|[A-Za-z]:[/\\]|\\\\)\S*"
                                r"|[A-Za-z][A-Za-z0-9+.-]{2,15}:(?://|[A-Za-z_$])\S*")
_ISO_DURATION_RE = re.compile(r"P(?:\d+[YMWD])*(?:T(?:\d+[HMS])+)?")   # P90D, PT15M
_WORD_NUMBER_RE = re.compile(r"[A-Za-z\u00c0-\u024f]{2,}[#_. :/-]\d{1,4}|\d{1,4}[#_. :/-][A-Za-z\u00c0-\u024f]{2,}")


def _random_evidence(v: str, tool: bool = False) -> bool:
    """A value that no word covers is a password only with evidence of chance (codex and Opus Gate A/B of 0.6.16): a
    letter, and a digit or a sign beside it, or (letters only) few vowels or a mix of cases that no word boundary
    explains. A word of another language (senhaAtual, wachtwoord) and a measure (95.2%, 12:30, ~30d) stay text."""
    if not any(c.isalpha() for c in v):
        return False
    if (_MEASURE_VALUE_RE.fullmatch(v) or _ABBREVIATION_RE.fullmatch(v) or _WORD_NUMBER_RE.fullmatch(v)
            or _ISO_DURATION_RE.fullmatch(v)):
        return False
    if any(c.isdigit() for c in v) or any(_is_sign(c) and c not in "_-." for c in v):
        return True   # a digit, or a sign that no identifier uses (_ - . join the words of a name: senha_atual)
    parts = [part for part in re.split(r"[_.-]+", v) if part]
    if not v.isascii():
        # another script or accents: a word (a UI string) unless scripts mix or the cases change at random
        return _scripts_mix(v) or any(_case_flips(part) >= 2 for part in parts)
    if tool:
        return True   # a tool result or a file: ASCII letters that no word covers are a password there
    # ASCII letters joined at most by _ - .: one part with a mix of cases that no word boundary explains
    return any(_random_letters(part) for part in parts)


def _is_sign(c: str) -> bool:
    """Punctuation or a symbol. A combining vowel sign of Devanagari or Thai is part of a word, not a sign."""
    import unicodedata
    return unicodedata.category(c)[0] in "PS"


def _case_flips(v: str) -> int:
    """How often a small letter is followed by a capital: once in a camelCase name, often in a random value."""
    return sum(1 for x, y in zip(v, v[1:]) if x.islower() and y.isupper())


def _scripts_mix(v: str) -> bool:
    """Letters of two scripts with case in one value (Latin and Cyrillic, Greek and Latin): no word is written so.
    Scripts without case mix in ordinary words (Japanese kanji and kana) and do not count."""
    import unicodedata
    scripts = {unicodedata.name(c, "?").split(" ")[0].split("-")[0]
               for c in v if c.isalpha() and c.upper() != c.lower()}
    return len(scripts) > 1


def _random_letters(v: str) -> bool:
    """ASCII letters that no word explains: capitals inside short runs (xKqTzLmP)."""
    # a long run of letters with few vowels (a keyboard run, xkcdqwrtzp), counted per word of a camelCase or snake_case
    # name: ctxPtr, grpcSrv and the words of other languages (Pflicht, Svensk) are short or have more vowels
    if len(v) >= 9 and sum(c in "aeiouyAEIOUY" for c in v) < 0.15 * len(v) and v.isalpha() and v[1:].islower():
        return True
    upper = sum(c.isupper() for c in v)
    parts = _WORD_RUN_RE.findall(v)
    return upper >= 2 and len(v) - upper >= 2 and len(parts) >= 3 and len(v) <= 3 * len(parts)


def _pw_strong_evidence(v: str) -> bool:
    """After the weak label `pass` (a boarding pass, a test pass, a season pass): 8 characters and more of three of
    the four classes (small, capital, digit, sign)."""
    classes = (any(c.islower() for c in v) + any(c.isupper() for c in v) + any(c.isdigit() for c in v)
               + any(not c.isalnum() for c in v))
    return len(v) >= 8 and classes >= 3


def _pw_literal_ok(v: str) -> bool:
    """A password value: 4 to 64 characters, no word after undoing leet (or a word with a number and a sign), not
    digits only, 3 distinct characters or more, no run such as abcd, no placeholder, no space, no dotted reference, no
    fixture word (testpass), no version."""
    if not 4 <= len(v) <= 64 or any(c.isspace() for c in v) or _charset(v) == "digits" or len(set(v)) < 3:
        return False
    if v.lower() in _PW_TRANSLATIONS and v in (v.lower(), v.capitalize(), v.upper()):
        return False   # the word for password in another language: a locale value (SeNhA stays a hit, as in 0.6.16)
    if _sequential(v.lower()) or _LITERAL_PLACEHOLDER_RE.search(v) or _DOTTED_RE.fullmatch(v) or _names_itself(v):
        return False
    if _CLOSED_TEMPLATE_RE.search(v) or _looks_like_regex(v):
        return False   # a template of a format string or a pattern: f'pwd = "{pw}"', "password: {password}"
    if _VERSION_RE.fullmatch(v):
        return False   # a version: v1.2.3-rc1 (undoing leet makes it letters)
    if _PATH_REFERENCE_RE.fullmatch(v):
        return False   # a path or a reference: /run/secrets/db, ./secrets/pw.txt, C:\\keys\\db.pw, vault:…, file:///…
    if _wordlike(_deleet(v)) < 0.3:
        if not _WORDS_OK[0] and v.isalpha():
            return False   # without a word list, a value of letters only may be any word
        if _CHANNEL[0] == "tool":
            return _random_evidence(v, tool=True)   # a false hit in a tool result masks a value, it blocks no prompt
        return _random_evidence(v)
    # a password made of a word, a number and a sign: Sommer2024!, Herbst2025#, Welcome1! (the form people choose).
    # A word with a number alone (Winter2023, postgres15) stays text here; the keyword rules judge it. So does a name
    # joined by _ - . (ABC_123_DEF) and a reference with : / or \ (b64:!!notbase64, vault:db/pw1!)
    return (len(v) >= 8 and any(c.isalpha() for c in v) and any(c.isdigit() for c in v)
            and any(not c.isalnum() and c not in "_-." for c in v) and not any(c in ":/\\" for c in v)
            and _ds_value_ok(v))


# the forms of label and literal value. A label, then = => := == : , or ( and a quoted value (also inside a wrapper
# such as SecretStr("…")); a label, then = or : and an unquoted value to the end of the line; a query parameter; an
# XML element; SQL's IDENTIFIED BY '…' and PowerShell's ConvertTo-SecureString '…'
_LIT_WRAP = (r"(?:(?:Some|Ok|String::from|str|bytes|SecretString::new|Secret::new|SecretStr|SecretBytes|Optional\.of"
             r"|Box::new|Sensitive|new[ \t]+String)[ \t]*\([ \t]*)?")
# a label starts after no word character, no path or flag part and no `=`: `--password-file=/etc/app/pw` holds no
# label pw, and `pw=pw=pw=…` (1 MB took 5.5 s) starts one label only
_LIT_LABEL = r"(?<![\w.\-$@/\\=])([A-Za-z_$@][\w.\-]{0,60})[\"'\]]?[ \t]*"
# the quoted forms end at the opening quote: _read_quoted reads the literal to its real closing quote
_LIT_QUOTED = re.compile(_LIT_LABEL + r"(?<![=!<>])(?:=>|:=|=(?!=)|:|,|\()[ \t]*" + _LIT_WRAP + r"([\"'`])")
_LIT_FORMS = (
    (re.compile(r"(?m)" + _LIT_LABEL + r"(?:=|:)[ \t]*([^\s\"'`,()\[\]{}<>]{3,299}[^\s\"'`,;()\[\]{}<>]);?"
                r"(?:[ \t]+(?:#|//|;).*|[ \t]*(?:#|//).*)?[ \t]*$"), 1, 2),
    (re.compile(r"[?&;]([\w.\-\[\]]{1,60})=([^&\s\"'#<>]{4,400})"), 1, 2),
    (re.compile(r"<([\w:.-]{1,60})(?:\s[^<>]{0,200})?>([^<>\s]{4,400})</"), 1, 2),
)
# SQL's IDENTIFIED BY '…' (a doubled quote and MySQL's backslash escape are part of the value) and PowerShell's
# ConvertTo-SecureString '…' (single quotes: a doubled quote; double quotes: a doubled quote and the backtick escape)
_LIT_SQL = re.compile(r"(?i)\bidentified[ \t]+(?:with[ \t]+\w+[ \t]+)?by[ \t]*(?:password[ \t]*)?([\"'])")
_LIT_PS = re.compile(r"(?i)ConvertTo-SecureString[ \t]+(?:-String[ \t]+)?([\"'])")
_LIT_BOUND = 300   # a literal longer than this, or one that its line ends, is taken to the bound: never a prefix
_BACKSLASH_ESCAPE_RE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(.))", re.S)
_ESCAPED_CHAR = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}


def _unquote(raw: str, quote: str, backslash: bool, backtick: bool) -> str:
    """The value a literal stands for, for the judgement only (the span stays the raw text): `\u00fc` is ü, `\"` is ",
    a doubled quote is one quote, PowerShell's backtick escapes the next character."""
    v = raw.replace(quote + quote, quote)
    if backslash and "\\" in v:
        v = _BACKSLASH_ESCAPE_RE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)) if (m.group(1) or m.group(2))
                                     else _ESCAPED_CHAR.get(m.group(3), m.group(3)), v)
    if backtick and "`" in v:
        v = re.sub(r"`(.)", lambda m: _ESCAPED_CHAR.get(m.group(1), m.group(1)), v, flags=re.S)
    return v


def _read_quoted(text: str, i: int, quote: str, backslash: bool = True, backtick: bool = False) -> tuple:
    """Read a quoted literal whose content starts at `i`: (end of the content, closed). A backslash (C, Python, JSON,
    JavaScript, MySQL) or a backtick (PowerShell) escapes the next character, and a doubled quote (SQL, PowerShell, YAML
    single quotes) is one quote of the content, so an escaped quote never ends the value early. Without a closing quote
    on the line within _LIT_BOUND characters the content runs to the line end or the bound."""
    n = len(text)
    stop = min(n, i + _LIT_BOUND)
    j = i
    while j < stop:
        c = text[j]
        if c == "\n" or c == "\r":
            return j, False
        if (backslash and c == "\\") or (backtick and c == "`"):
            j += 2
            continue
        if c == quote:
            if j + 1 < n and text[j + 1] == quote:
                j += 2   # a doubled quote is one quote of the value, also as its first character
                continue
            return j, True
        j += 1
    return min(j, stop), False


# a label that names a secret by its whole tail (`client_secret`, `apiKey`, `x-auth-token`), and a weak label that may
# name one (`key`, `hmac`, `session`, `cookie`). A word before the tail can make it name something else: password_hint,
# public_key, cache_key, primary_key, csrf_token, next_page_token
_SECRET_TAIL_RE = re.compile(r"(?:^|_)(?:secret|token|apikey|api_key|access_key|secret_key|private_key|client_secret"
                             r"|auth_token|access_token|refresh_token|session_token|bearer|credentials?|app_secret"
                             r"|consumer_secret|signing_key|encryption_key|master_key|auth_key)$")
_WEAK_TAIL_RE = re.compile(r"(?:^|_)(?:key|auth|salt|seed|otp|totp|cred|cookie|session|hmac|psk)$")
_WEAK_NEG_WORDS = frozenset({
    "public", "pub", "primary", "foreign", "sort", "partition", "cache", "idempotency", "row", "map", "lookup",
    "cursor", "object", "s3", "dedup", "dedupe", "routing", "shard", "group", "sequence", "index", "composite",
    "unique", "natural", "surrogate", "react", "list", "item", "translation", "i18n", "locale", "storage", "redis",
    "memcache", "query", "license", "licence", "product", "registry", "gpg", "pgp", "ssh", "host", "known",
    "fingerprint", "csrf", "xsrf", "anti", "forgery", "verification", "page", "next", "continuation", "pagination",
    "sync", "lexer", "tokenizer", "parser", "cancellation", "captcha", "recaptcha"})


# a TOTP or HOTP seed: base32 of 10 to 40 bytes after a one-time-password label (otpauth://… carries it as secret=)
_OTP_WORDS = frozenset({"totp", "hotp", "otp", "mfa", "2fa", "otpauth", "authenticator"})
_OTP_SEED_RE = re.compile(r"[A-Z2-7]{16,64}={0,6}")


def _alphabet_size(v: str) -> int:
    if v.isdigit():
        return 10
    if re.fullmatch(r"[0-9a-f]+|[0-9A-F]+", v):
        return 16
    size = 26 * (any(c.islower() for c in v) + any(c.isupper() for c in v)) + 10 * any(c.isdigit() for c in v)
    if any(not c.isalnum() for c in v):
        size += 2 if re.fullmatch(r"[A-Za-z0-9+/=_-]+", v) else 32
    return max(size, 2)


def _norm_entropy(v: str) -> float:
    """Shannon entropy over the most the value's alphabet and length allow (0 to 1): a charset-normalised entropy
    after Dan Szymkowiak's backlog idea (TASK-11.21)."""
    return shannon_entropy(v) / math.log2(max(2, min(_alphabet_size(v), len(v))))


# a value that is a pattern, not a key: a character class with a quantifier, a counted repeat, an escape class, a group
# (`token: '[A-Za-z0-9_-]{20,}'`, `secret: '[a-f0-9]{64}'`, `^\d{6}$`; Opus verification of 0.6.16)
_REGEX_LIKE_RE = re.compile(r"\[[^\]]{1,60}\](?:[*+?]|\{\d+(?:,\d*)?\})|\{\d+(?:,\d*)?\}|\\[dwsDWSbB]"
                            r"|\(\?[:=!<]|\.[*+]")


def _looks_like_regex(v: str) -> bool:
    """The whole value is a pattern: it starts with ^ [ ( or \\ , ends with $ ] ) } or a quantifier, and holds a
    pattern part. A password with \\d or .* inside it is no pattern (codex, final round of 0.6.16)."""
    return (len(v) >= 3 and v[0] in "^[(\\" and (v[-1] in "$])}*+?" or v[-2:] in ("\\b", "\\B"))
            and _REGEX_LIKE_RE.search(v) is not None)


def _key_literal_ok(v: str, lo: int, hi: int, words: float, entropy: float) -> bool:
    """A key after a secret or a weak label: ASCII, no space, no placeholder, few word letters, a high normalised
    entropy, and detect-secrets' filters (templates, references, sequences)."""
    if _looks_like_regex(v):
        return False
    if not lo <= len(v) <= hi or not v.isascii() or any(c.isspace() for c in v) or _LITERAL_PLACEHOLDER_RE.search(v):
        return False   # a key is ASCII: a value with § or an umlaut is a split test value or a word
    return _norm_entropy(v) >= entropy and _ds_value_ok(v, 4) and _wordlike(_deleet(v)) < words


_LABEL_CLASS: dict = {}


def _label_class(label: str) -> tuple:
    """(password label, secret label, weak label, OTP label, last word) of a label, computed once per label: a list of
    70,000 words reads each word as the label of the next one."""
    got = _LABEL_CLASS.get(label)
    if got is None:
        toks = _norm_label(label)
        full = "_".join(toks)
        before = toks[:-1]
        # an AWS signature or the key id in a SigV4 scope is no secret value of its own
        # (the session token, x-amz-security-token, is a secret: the rule label-aws-session-token takes it)
        amz = (full.startswith("x_amz") and full != "x_amz_security_token") or bool(
            toks and toks[-1] in ("credential", "signature"))
        named = bool(full) and not amz
        other = any(t in _LABEL_NEG_WORDS or t in _WEAK_NEG_WORDS for t in before)
        secret = named and bool(_SECRET_TAIL_RE.search(full)) and not other
        weak = named and bool(_WEAK_TAIL_RE.search(full)) and not other
        otp = named and bool(set(toks) & _OTP_WORDS)
        got = (_pw_label(toks), secret, weak, otp, toks[-1] if toks else "")
        if len(_LABEL_CLASS) > 50000:
            _LABEL_CLASS.clear()
        _LABEL_CLASS[label] = got
    return got


_COMMON_PAIRS: list = []


def _common_pairs() -> frozenset:
    """The letter pairs that occur 20 times or more in the word list (about 370 of 676). Empty without a word list."""
    if not _COMMON_PAIRS:
        count: dict = {}
        if _word_set() and _WORDS_OK[0]:
            for w in _WORDS[0]:
                for i in range(len(w) - 1):
                    count[w[i:i + 2]] = count.get(w[i:i + 2], 0) + 1
        _COMMON_PAIRS.append(frozenset(p for p, n in count.items() if n >= 20))
    return _COMMON_PAIRS[0]


def reads_as_word(value: str) -> bool:
    """Whether a value reads as a word of some language: letters only (parts joined by _ - .), no evidence of chance,
    and in ASCII at most one rare letter pair in ten. Wartungsfenster, senha_atual and Пароль are words; xqzvbnmq,
    Kx7QpZr9 and qwmzpl are not. The store keeps a word that a label rule took in a tool result quiet (vault.is_quiet):
    masked in later tool results, never looked for in a typed prompt, where it would block every prompt that uses
    the word (field report, 2026-10-14)."""
    parts = [p for p in re.split(r"[_.-]+", value) if p]
    if not parts or not all(p.isalpha() for p in parts) or _random_evidence(value):
        return False
    if not value.isascii():
        return True   # another script or accents, and no mix of scripts or cases (_random_evidence)
    common = _common_pairs()
    if not common:
        return False   # no word list: hunt the value, as 0.6.16 did
    pairs = [p[i:i + 2] for p in (x.lower() for x in parts) for i in range(len(p) - 1)]
    if not pairs:
        return False   # single letters: no evidence of a word
    return sum(q not in common for q in pairs) <= 0.1 * len(pairs)


def _judge_literal(label: str, v: str, quoted: bool = True) -> str:
    """The rule a label and its literal value fall under, or ""."""
    pw, secret, weak, otp, last = _label_class(label)
    if pw and _pw_literal_ok(v) and (last.rstrip("0123456789") != "pass" or _pw_strong_evidence(v)):
        return "label-pw-literal"
    if secret and _key_literal_ok(v, 8, 200, 0.3, 0.8):
        return "label-secret-literal"
    if (quoted and weak and _key_literal_ok(v, 12, 300, 0.2, 0.85) and not (len(v) == 64 and _charset(v) == "hex")
            and not (last == "key" and _charset(v) == "hex")):
        return "label-weak-key"
    if otp and _OTP_SEED_RE.fullmatch(v) and _wordlike(v) < 0.3:
        return "label-otp-seed"
    return ""


def _literal_hits(text: str) -> list:
    """(rule id, start of the label, start and end of the value) of each label and literal value of `text`, computed
    once per text for all the rules that read them."""
    _newlines(text)
    cache = _INDEX[1]
    if ("literal", _CHANNEL[0]) not in cache:
        hits = []
        pos = 0
        while True:
            m = _LIT_QUOTED.search(text, pos)
            if m is None:
                break
            a = m.end()
            q = m.group(2)
            lq = text[m.start(1) - 1:m.start(1)]
            if "," in text[m.end(1):m.start(2)] and not (lq in ("'", '"') and text[m.end(1):m.end(1) + 1] == lq):
                pos = m.start(2)   # f(password, "…"): the next argument; ("password", "…") is a pair of label and value
                continue
            # PowerShell escapes with a backtick in double quotes, after a $ label only: $pw = "…`"…"
            tick = q == '"' and m.group(1).startswith("$")
            end, closed = _read_quoted(text, a, q, backtick=tick)
            raw = text[a:end]
            # past a literal that is a value
            pos = end + 1 if closed else max(end, a)
            if closed and re.match(r"[ \t]*\+", text[end + 1:end + 40]):
                continue   # a string that + continues is an expression
            rid = _judge_literal(m.group(1), _unquote(raw, q, True, tick), quoted=True)
            if rid:
                hits.append((rid, m.start(), a, end))
            else:
                pos = a   # a literal that is no value may be a label itself: f("password", "…"), or hold a JSON text
        for n, (rx, gl, gv) in enumerate(_LIT_FORMS):
            for m in rx.finditer(text):
                rid = _judge_literal(m.group(gl), m.group(gv), quoted=n != 0)
                if rid:
                    hits.append((rid, m.start(), m.start(gv), m.end(gv)))
        for rx, backslash in ((_LIT_SQL, True), (_LIT_PS, False)):
            for m in rx.finditer(text):
                q = m.group(1)
                tick = not backslash and q == '"'
                end, _closed = _read_quoted(text, m.end(), q, backslash=backslash, backtick=tick)
                if _pw_literal_ok(_unquote(text[m.end():end], q, backslash, tick)):
                    hits.append(("label-pw-literal", m.start(), m.end(), end))
        hits.sort(key=lambda h: h[2])
        cache["literal", _CHANNEL[0]] = hits   # the tool channel takes more values
    return cache["literal", _CHANNEL[0]]


class _Literal:
    """A match of a label and literal rule: group 0 runs from the label to the end of the value, group 1 is the
    value."""
    __slots__ = ("_text", "_a", "_s", "_e")

    def __init__(self, text: str, a: int, s: int, e: int) -> None:
        self._text, self._a, self._s, self._e = text, a, s, e

    def group(self, i: int = 0):
        return self._text[self._a if i == 0 else self._s:self._e]

    def start(self, i: int = 0) -> int:
        return self._a if i == 0 else self._s

    def end(self, i: int = 0) -> int:
        return self._e


def _literal_matches(rule_id: str, text: str):
    for rid, a, s, e in _literal_hits(text):
        if rid == rule_id:
            yield _Literal(text, a, s, e)


# the rules that read labels and literal values; they run after every other rule and take only a span no other rule
# took. The keywords skip a text without the label words
LITERAL_RULES = (
    {"id": "label-pw-literal", "keywords": ("pass", "pw", "pwd", "kennwort", "psw", "identified", "securestring")},
    {"id": "label-secret-literal", "keywords": ("secret", "token", "key", "bearer", "credential")},
    {"id": "label-otp-seed", "keywords": ("otp", "mfa", "2fa", "authenticator")},
    {"id": "label-weak-key", "keywords": ("key", "auth", "salt", "seed", "otp", "cred", "cookie", "session", "hmac",
                                          "psk")},
)
_LITERAL_IDS = frozenset(d["id"] for d in LITERAL_RULES)


VALIDATORS = {
    "ds_value": _ds_value_ok,
    "apikey_value": _apikey_value_ok,
    "word_value": _word_value_ok,
    "flag_value": lambda v: _word_value_ok(v, prose_punct=True),
    "glued_value": lambda v: _word_value_ok(v, min_len=6),
    "prose_value": _prose_value_ok,
    "de_tax_id": _de_tax_id_ok,
    "de_social_security": _de_social_security_ok,
    "de_social_security_spaced": lambda v: _de_social_security_ok(v.replace("\u00a0", " ")),
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
    # name%40firma.de in a URL query, a form body or an access log: the same address, percent-encoded
    "person_email_encoded": lambda v: VALIDATORS["person_email"](v.replace("%40", "@")),
    "us_ssn": _us_ssn_ok,
    # checksums.py: ports of Presidio validators that were missing and the German document number
    "de_document": checksums.de_document_ok,
    "de_tax_id_spaced": lambda v: _de_tax_id_ok(re.sub(r"[ \u00a0]", "", v)),
    "pl_pesel": checksums.pl_pesel_ok,
    "es_nif": checksums.es_nif_ok,
    "es_nie": checksums.es_nie_ok,
    "uk_nhs": checksums.uk_nhs_ok,
    "us_aba": checksums.us_aba_ok,
    "it_fiscal_code": checksums.it_fiscal_code_ok,
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
        # a bot or a pipeline is no person either: a CI file that names renovate@repo.local was blocked in Codex,
        # which cannot rewrite a prompt (2026-10-06)
        local = local.lower()
        return (local in _SYSTEM_USERS or local in _SERVICE_MAILBOXES
                or local.endswith(("-bot", "_bot")))
    return (d in _RESERVED_MAIL_DOMAINS or d.endswith(tuple("." + x for x in _RESERVED_MAIL_DOMAINS))
            or tld in _RESERVED_MAIL_TLDS)


_SERVICE_MAILBOXES = frozenset({"alerts", "alert", "monitoring", "backup", "ci", "bot", "renovate", "dependabot",
                                "release", "deploy", "build", "jenkins", "gitlab-runner", "github-actions"})
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
    # an IBAN in lower case, plain or in groups of four; its validator also wants the country's length
    {"id": "iban-lowercase", "type": "IBAN", "validator": "iban",
     "regex": r"(?<![A-Za-z0-9])[a-z]{2}[0-9]{2}(?:[a-z0-9]{11,30}|(?:[ -][a-z0-9]{4}){2,7}(?:[ -][a-z0-9]{1,3})?)"
              r"(?![A-Za-z0-9])"},
    {"id": "email-percent-encoded", "type": "EMAIL", "validator": "person_email_encoded",
     # the @ as %40 in a query string, a form body, an access log (public benchmark, 2026-10-11: 7 addresses
     # passed); scan() keeps it only where an address is expected (_ENCODED_MAIL_CONTEXT_RE)
     "regex": r"(?:(?<![\w.+%-])|(?<=(?i:mailto%3a))|(?<=%3[Dd]))[\w.+-]{1,64}%40"
              r"[\w-]{1,63}(?:\.[\w-]{1,63})*\.[A-Za-z]{2,63}(?![\w-])"},
    {"id": "phone", "type": "PHONE",
     "regex": r"(?<![\w+])\+(?!0)\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}(?:[ \-]?\d{2,5}){1,4}(?![\w.]\d|\w)"},
    # bare token prefixes newer than the vendored rulesets live in rules/prefixes.txt (see _load_prefixes)
    {"id": "auth-scheme", "type": "SECRET", "secret_group": 3,
     "regex": r"(?<![\w-])(Bearer|Basic)([ \t]+)([A-Za-z0-9._~+/=-]{16,})"},
    # a password with no user in a URL: redis://:pw@host, the form Redis and some brokers use. ds-basic-auth needs a
    # user before the colon; same characters and the same value filter otherwise (corpus of 0.6.7)
    {"id": "url-password-no-user", "type": "SECRET", "secret_group": 1, "validator": "ds_value",
     "regex": r"://:([^:/?#\[\]@!$&'()*+,;=\s]+)@"},
    # the secret half of an AWS key pair has no prefix of its own; the console, a CSV export
    # and a chat paste show it within a few lines after the AKIA… id (field report, 2026-09-26). Each line part is
    # bounded at 400 characters: unbounded, each id scanned the rest of its line, and a line of ids took O(n^2)
    # (32K: 2.3 s, 256K: 97 s, past the client's timeout). The longest field form, the console's credentials CSV
    # row (user, password, id, secret, console link), puts about 150 characters around the secret.
    {"id": "aws-secret-after-access-key", "type": "SECRET", "secret_group": 1,
     "regex": r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])(?:[^\n]{0,400}\n){0,4}?[^\n]{0,400}?"
              r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"},
    # a password with no shape where no `=` or `:` stands between label and value (public benchmark holdout v7,
    # 2026-10-12: all ten leaked passwords had one of these five forms). They are label rules (LABEL_RULES): the
    # keyword filters of scan() and the test-code rule apply as to `password=<value>`.
    # `pg_dump --password '<value>'`, `--db-password <value>`, PowerShell `-Password <value>`; the `=` form is
    # ds-keyword-equal-signs. A flag before a space, so `--password-stdin` and `--password-file` stay options
    {"id": "label-cli-password", "type": "SECRET", "secret_group": 2, "validator": "flag_value",
     "regex": r"(?<![\w-])--?(?!(?i:no|ask|skip|prompt|without|one|two|single|multi|first|second)[-_])"
              r"(?:[A-Za-z][A-Za-z0-9]*[-_])*"
              r"(?i:password|passwd|passphrase|pass|pwd)[ \t]+"
              r"(['\"]?)(?!-|(?:file|env|fd):|stdin(?![\w-]))(?:pass:)?([^\s'\"<>]{1,256}?)\1(?=$|[\s;|&)\]\\])"},
    # `mysql -u app -p'<value>' db`: the value glued to -p (a space after -p asks for it; -P is the port)
    {"id": "label-mysql-p", "type": "SECRET", "secret_group": 2, "validator": "glued_value",
     "regex": r"(?<![\w-])(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mariadb"
              r"|mariadb-dump|mariadb-admin)(?:\.exe)?(?![\w-])[^\n|;&]{0,400}?[ \t]-p(['\"]?)([^\s'\"<>]{1,256}?)\1"
              r"(?=$|[\s;|&)\]])"},
    # redis-cli: `127.0.0.1:6379> AUTH <value>` (or AUTH <user> <value>) at a prompt or the start of a line, and
    # `redis-cli -a <value>`. AUTH in capitals, as Redis documents it; `auth token expired` is prose
    {"id": "label-redis-auth", "type": "SECRET", "secret_group": 2, "validator": "word_value",
     "regex": r"(?m)(?:^[ \t]*|>[ \t]?)AUTH[ \t]+(?![=:]|LOGIN[ \t])(?:[^\s'\"]+[ \t]+)?"
              r"(?!(?:CRAM-MD5|DIGEST-MD5|SCRAM-SHA-[0-9]+(?:-PLUS)?|XOAUTH2|OAUTHBEARER|GSSAPI|NTLM|EXTERNAL"
              r"|ANONYMOUS|PLAIN|LOGIN)[ \t]*$)"   # an SMTP or IMAP AUTH names a SASL mechanism (Gate B of 0.6.15)
              r"(['\"]?)([^\s'\"<>]{1,256})\1[ \t]*$"},
    {"id": "label-redis-cli-a", "type": "SECRET", "secret_group": 2, "validator": "word_value",
     "regex": r"(?<![\w-])redis-cli(?![\w-])[^\n|;&]{0,400}?[ \t]-a[ \t]+"
              r"(['\"]?)([^\s'\"<>]{1,256}?)\1(?=$|[\s;|&)\]])"},
    # .netrc: `machine <host> login <user> password <value>`, on one line or on several. The host has a dot, a colon
    # or a digit (or is localhost): "on my dev machine the password changed" is prose. `default` starts an entry at a
    # line start, or anywhere before `login` (a second entry on the line, a grep prefix); "the default password
    # policy_v2" is prose (round 2 of 0.6.15)
    {"id": "label-netrc-password", "type": "SECRET", "secret_group": 1, "validator": "word_value",
     "regex": r"(?:(?<![\w-])machine[ \t]+(?:[^\s]*[.:0-9][^\s]*|localhost)"
              r"|(?<![^\n])[ \t]*default|(?<![\w-])default(?=[ \t]+login[ \t]))"
              r"(?:\s+(?:login|account|port)[ \t]+[^\s]+)*"
              r"\s+password[ \t]+([^\s]{1,256})"},
    # prose: "my password is <value>". Only a value that is no word of a sentence: it holds a capital or a symbol
    # beyond - _ . and a digit or a symbol ("the password is incorrect" stays prose). English only: the German
    # sentence of tests/fp_corpus.py (`Das Passwort ist` and a season and a year) is kept silent
    {"id": "label-prose-password", "type": "SECRET", "secret_group": 1, "validator": "prose_value",
     "regex": r"(?i)(?<![\w-])(?:password|passwd|passphrase)[ \t]+(?:is|was)[ \t]*:?[ \t]+"
              r"[\"'„“]?([^\s\"'“”]{0,255}[^\s\"'“”.,;:!?)])[\"'“”]?(?=[.,;:!?)]*(?:[\s\"'<\\]|$))"},
    # each quoted value of a list after a label that names secrets: `"api_keys": ["<v1>", "<v2>"]`,
    # `passwords = ['<v1>']`, Go `Secrets: []string{"<v1>"}`. The label rules took no value that starts with a
    # bracket, so a whole list of keys stayed in the clear. Only a label that names secrets and nothing else: a bare
    # `tokens` is the output of a tokenizer, and code_tokens, cache_tokens or revokedTokens name no secret (Gate B of
    # 0.6.16: 30 false alarms in developer text). The regex finds the label and the opening bracket; _list_matches
    # reads the values and keeps only those that look like a key (_list_value_ok). No tuple: the Elasticsearch client
    # takes api_key=("<id>", "<key>"), and the id is public
    {"id": "label-secret-list", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)(?<![\w$.-])[\"']?(passwords?|passwd|secrets?|api[_-]?(?:keys?|tokens?|secrets?)"
              r"|(?:access|auth|refresh|bearer)[_-]?tokens?|client[_-]?secrets?|private[_-]?keys?|secret[_-]?keys?"
              r"|credentials)[\"']?[ \t]*(?::=|=>|[:=])[ \t]*(\[\][\w.]*[ \t]*\{|[\w.]*\[\][ \t]*\{|\[)"},
    # four token formats with a public prefix and no rule in the vendored sets (0.6.16). The third NTLMSSP message in
    # base64 (`Authorization: NTLM TlRMTVNTUAAD…`: its response is derived from the password hash; the negotiate and
    # challenge messages carry none); a
    # NATS nkey seed (S, the key type, 56 base32 characters; the public key starts with N, U, A … and stays text);
    # a PASERK secret, local or wrapped key (k1. to k4.; k4.public., k4.lid. and the other ids stay text); a PASETO
    # token (v1. to v4., local or public: a bearer token as a JWT is one)
    {"id": "ntlmssp-message", "type": "SECRET",
     "regex": r"(?<![A-Za-z0-9+/])TlRMTVNTUAAD[A-Za-z0-9+/]{30,}={0,2}"},
    {"id": "nats-nkey-seed", "type": "SECRET",
     "regex": r"(?<![A-Za-z0-9])S[UNOACXP][A-Z2-7]{56}(?![A-Za-z0-9])"},
    {"id": "paserk-secret-key", "type": "SECRET",
     "regex": r"(?<![\w.])k[1-4]\.(?:local|secret|local-wrap|secret-wrap|local-pw|secret-pw|seal)\."
              r"(?:[A-Za-z0-9_-]+\.){0,3}[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"},   # dot-separated parts, no end dot
    {"id": "paseto-token", "type": "SECRET",
     "regex": r"(?<![\w.])v[1-4]\.(?:local|public)\.[A-Za-z0-9_-]{30,}(?:\.[A-Za-z0-9_-]+)?"},
    # the STS session token of temporary AWS credentials: a presigned URL carries it as the query parameter
    # X-Amz-Security-Token (percent-encoded), a request as the header of that name. The other X-Amz- parameters (the
    # key id in X-Amz-Credential, X-Amz-Signature, X-Amz-Date) stay text; the session token grants access until it
    # expires. 100 to 4096 characters: real tokens have several hundred
    {"id": "label-aws-session-token", "type": "SECRET", "secret_group": 1,
     "regex": r"(?i)(?<![\w-])x-amz-security-token(?:[\"']?[ \t]*[:=][ \t]*[\"']?)([A-Za-z0-9%+/=_-]{100,4096})"
              r"(?![A-Za-z0-9%+/=_-])"},
    # Elasticsearch's API key in an Authorization header: `Authorization: ApiKey <base64 of id:key>`, as a header
    # line, in curl -H, or as the key of a header object (`authorization: 'ApiKey <value>'`). Only after the header
    # name: prose names the scheme ("send ApiKey followed by …", Gate B of 0.6.16)
    {"id": "auth-scheme-apikey", "type": "SECRET", "secret_group": 1, "validator": "apikey_value",
     "regex": r"(?i:authorization)[\"']?\]?[ \t]*[:=][ \t]*[\"'`]?ApiKey[ \t]+([A-Za-z0-9+/_-]{8,1024}={0,2})"
              r"(?![\w+/=-])"},
]


# ------------------------------------------------------------- rule loading --
# betterleaks rules left out: a filter that is a program (let bindings; rule_filter.Unsupported) would run without
# it, and maisecrets' own label rules cover these shapes (ds-keyword, url-query-secret, the email rule)
BETTERLEAKS_SKIP_UNSUPPORTED = True


def _load_own_secret_rules() -> list[Rule]:
    """maisecrets' own secret rules (rules/own_secret_rules.json; patterns derived from gitleaks v8.30.1, MIT), with
    their entropy and allowlists: generic-api-key, to which the keyword window (_WINDOWED) and the label filters of
    scan() are tuned, and the token forms the betterleaks rules miss (etsy, jfrog, a bare Fly.io token, a labelled
    Atlassian token, a legacy Vault token, …). They run after betterleaks, so they only fill its gaps."""
    cfg = json.loads((RULES_DIR / "own_secret_rules.json").read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for r in cfg["rules"]:
        allow: list[tuple[re.Pattern[str], str]] = []
        stop: list[str] = []
        for al in r.get("allowlists", []) or []:
            # as in gitleaks: no regexTarget means the secret, "match" the whole match, "line" the line
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


def _load_betterleaks() -> list[Rule]:
    """The vendored betterleaks rules (rules/betterleaks.json, synced by scripts/sync_betterleaks.py). A rule with
    skipReport is a component that betterleaks never reports alone (a client id beside its secret); a rule without a
    regex matches by file path only. Each filter, and the global one, is read by rule_filter; a filter that module
    cannot read leaves its rule out."""
    from . import rule_filter
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # "possible nested set" in some regexes
        # betterleaks.json is the same rules as JSON, for a Python without tomllib; a test keeps the two equal
        cfg = json.loads((RULES_DIR / "betterleaks.json").read_text(encoding="utf-8"))
        global_drop = rule_filter.compile_filter(cfg["filter"]) if cfg.get("filter") else None
        rules: list[Rule] = []
        for r in cfg.get("rules", []):
            if "regex" not in r or r.get("skipReport"):
                continue
            own = None
            if r.get("filter"):
                try:
                    own = rule_filter.compile_filter(r["filter"])
                except rule_filter.Unsupported:
                    if BETTERLEAKS_SKIP_UNSUPPORTED:
                        continue
            drop = _combine_drops(own, global_drop)
            rules.append(Rule(
                id=r["id"], type="SECRET", regex=_Lazy(_re2_to_python(r["regex"])),
                keywords=tuple(k.lower() for k in r.get("keywords", []) or ()),
                secret_group=int(r.get("secretGroup", 0) or 0), drop=drop,
            ))
    return rules


def _combine_drops(*drops):
    live = [d for d in drops if d is not None]
    if not live:
        return None
    return lambda env: any(d(env) for d in live)


# entity -> placeholder type (short, stable); anything else keeps its entity name
ENTITY_TYPE = {"EMAIL_ADDRESS": "EMAIL", "IBAN_CODE": "IBAN", "CREDIT_CARD": "CARD",
               "IP_ADDRESS": "IP", "PHONE_NUMBER": "PHONE"}
# covered by OWN_RULES with bounded regexes and validators, or not PII worth a placeholder. The German ID card and
# passport are REGIONAL_RULES: Presidio reads the 9th character as an ICAO check digit over the first 8, but the card
# prints the 9-character number without its check digit (it stands in the machine-readable zone only), so 37 of 40
# real-shaped numbers and the number of the official specimen card were missed (survey of other detectors, 0.6.19).
# de-handelsregister: a company's register number, public in the Handelsregister and no personal data
PRESIDIO_SKIP = {"email", "url", "date", "mac-address", "uuid", "phone", "de-id-card", "de-passport",
                 "crypto", "de-handelsregister"}
# validator id per presidio recognizer id; a recognizer with a validator we did not port
# keeps its pattern score and is treated as weak (context required)
PRESIDIO_VALIDATOR = {"iban": "iban", "credit-card": "luhn", "ip": "public_ip",
                      "de-tax-id": "de_tax_id", "de-social-security": "de_social_security",
                      "de-health-insurance": "de_health_insurance", "de-lanr": "de_lanr",
                      "de-bsnr": "de_bsnr", "de-vat-id": "de_vat_id", "us-ssn": "us_ssn",
                      # 0.6.19: with the context word alone a value with a wrong check digit was a hit
                      "pl-pesel": "pl_pesel", "es-nif": "es_nif", "es-nie": "es_nie", "nhs": "uk_nhs",
                      "aba-routing": "us_aba", "it-fiscal-code": "it_fiscal_code"}
# shapes that are plain digit runs: even with a valid checksum, ask for a context word. The validators ported in
# 0.6.19 keep the context word they needed before: a check digit alone passes one value in 10 to 26
PRESIDIO_ALWAYS_CONTEXT = {"de-tax-id", "de-tax-number", "de-bsnr", "de-lanr", "de-plz", "de-kfz",
                           "de-fuehrerschein", "nhs", "aba-routing", "medical-license", "pl-pesel", "es-nif",
                           "es-nie", "it-fiscal-code"}
# a Presidio pattern with no boundary: PESEL's eleven digits matched inside a longer digit run
PRESIDIO_DIGIT_BOUNDED = {"pl-pesel"}
# single patterns that need a context word although their recognizer does not: DE and nine digits that pass the
# checksum are also FIX tags and XML identifiers; a real VAT ID stands next to USt-IdNr or VAT. The spaced form
# (de-vat-id#1) has a low score and needs its word already
PRESIDIO_PATTERN_CONTEXT = {"de-vat-id#0"}
# card words the vendored recognizer lacks: its words are English, so a card number after "Karte" in a German bank
# statement reached the model. The number must still pass Luhn. A short word that means something else in a
# neighbour language (kort: short in Danish and Dutch) stays out
PRESIDIO_EXTRA_CONTEXT = {
    "credit-card": ("karte", "kreditkarte", "kartennummer", "kartennr", "debitkarte", "bankkarte", "ec-karte",
                    "girocard", "carte", "cartes", "carta", "tarjeta", "creditcard", "kaart", "cart\u00e3o", "karta"),
}
# Presidio tags every US/UK/IN/AU/… recognizer as language "en", so language is the wrong
# switch: an Indian PAN rule produced 290 false positives in one German transcript. The
# switch is the REGION, derived from the recognizer id; "generic" is always on.
REGION_OF_ID = {"nhs": "uk", "aba-routing": "us", "medical-license": "us"}
DEFAULT_PII_REGIONS = ("generic",)   # without a config: the rules of no country

# country rules of our own (0.6.19): forms Presidio has no pattern for. The design follows a fork of this project
# (Apache-2.0, see NOTICE). Each rule names its region; a rule
# with require_context needs one of its context words within 80 characters before or 40 after the value.
_DE_TAX_ID_CONTEXT = ("steueridentifikationsnummer", "steuer-id", "steuerid", "steuerliche identifikationsnummer",
                      "steuerliche identifikation", "persönliche identifikationsnummer", "steuer identifikation",
                      "idnr", "steuer-idnr", "identifikationsnummer", "bzst")
_DE_ID_CARD_CONTEXT = ("personalausweis", "ausweis", "personalausweisnummer", "ausweisnummer", "ausweis-nr",
                       "ausweisnr", "personalausweisnr", "dokumentennummer", "ausweisdokument", "npa",
                       "neuer personalausweis", "bundespersonalausweis", "identity card", "id card", "id-card",
                       "national id", "mrz")
_DE_PASSPORT_CONTEXT = ("reisepass", "passnummer", "reisepassnummer", "reisepass-nr", "pass-nr", "passnr",
                        "reisepassnr", "dokumentennummer", "passport", "passport number", "mrz")
_DOC = "CFGHJKLMNPRTVWXYZ"
REGIONAL_RULES: list = [
    # the German ID card and passport: 9 characters as printed on the card, or 10 with the ICAO check digit as in the
    # machine-readable zone. BSI TR-03123-2 v1.8.2, 3.2.1, and the BMI sheet "Die Dokumentennummer in deutschen
    # Ausweisen und Pässen" (2023-11-01): the consonants C F G H J K L M N P R T V W X Y Z and the digits (0 only before
    # 2021-11), the first a letter since 2023-11 (the specimens of 2010, 2019 and 2021 start with one too)
    {"id": "de-id-card", "region": "de", "type": "DE_ID_CARD", "validator": "de_document",
     "context": _DE_ID_CARD_CONTEXT, "require_context": True,
     "regex": rf"(?<![A-Za-z0-9])[{_DOC}][{_DOC}0-9]{{8}}[0-9]?(?![A-Za-z0-9])"},
    {"id": "de-passport", "region": "de", "type": "DE_PASSPORT", "validator": "de_document",
     "context": _DE_PASSPORT_CONTEXT, "require_context": True,
     "regex": rf"(?<![A-Za-z0-9])[{_DOC}][{_DOC}0-9]{{8}}[0-9]?(?![A-Za-z0-9])"},
    # the Steuer-ID as the tax office prints it, 2-3-3-3 digits; the 11 digits in one run are Presidio's de-tax-id
    {"id": "de-tax-id-spaced", "region": "de", "type": "DE_TAX_ID", "validator": "de_tax_id_spaced",
     "context": _DE_TAX_ID_CONTEXT, "require_context": True,
     "regex": r"(?<![\d.,/-])(?<!\d[ \u00a0])[1-9][0-9][ \u00a0][0-9]{3}[ \u00a0][0-9]{3}[ \u00a0][0-9]{3}"
              r"(?![0-9]|[ \u00a0][0-9])"},
    # the Rentenversicherungsnummer as the SV-Ausweis prints it: 2, 6 (birth date), 1 letter, 3, with spaces; the run
    # without spaces is Presidio's de-social-security, which needs no context word in the same date-checked form
    {"id": "de-social-security-spaced", "region": "de", "type": "DE_SOCIAL_SECURITY",
     "validator": "de_social_security_spaced",
     "regex": r"(?<![\w.,/-])[0-9]{2}[ \u00a0](?:0[1-9]|[12][0-9]|3[01]|5[1-9]|[67][0-9]|8[01])(?:0[1-9]|1[0-2])"
              r"[0-9]{2}[ \u00a0][A-Z][ \u00a0][0-9]{3}(?![\w])"},
]


def _load_regional(regions: tuple[str, ...] = DEFAULT_PII_REGIONS) -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=_Lazy(d["regex"]), validator=d["validator"],
                 context=tuple(d.get("context", ())), require_context=d.get("require_context", False),
                 whole_match=True)
            for d in REGIONAL_RULES if d["region"] in regions]


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
            rule_id = rec["id"] if len(rec["patterns"]) == 1 else f"{rec['id']}#{i}"
            out.append(Rule(
                id=rule_id,
                type=ENTITY_TYPE.get(rec["entity"], rec["entity"]),
                regex=_Lazy(rf"(?<!\d)(?:{_re2_to_python(pat['regex'])})(?!\d)" if rec["id"] in PRESIDIO_DIGIT_BOUNDED
                            else _re2_to_python(pat["regex"])),
                validator=validator, score=float(pat["score"]),
                context=tuple(c.lower() for c in rec.get("context", [])) + PRESIDIO_EXTRA_CONTEXT.get(rec["id"], ()),
                require_context=weak or rule_id in PRESIDIO_PATTERN_CONTEXT,
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
# and with a backslash before each quote: a JSON object inside a string, as a log line, an HTTP body in a test or a
# tool output shows it (`{\"password\":\"<value>\"}`). The label's quotes were no closer, so no value was read
# (Samsung CredData, line by line: 62 such credentials missed, 2026-10-12). The backslash before the value's opening
# quote is skipped only before a quote; the one before its closing quote is cut in scan()
_COLON_AFTER_LABEL_ESCAPED = "((?:\\\\?[]'\"]){0,2})?[ \\t\u00a0\u202f]{0,3}:"
_ESCAPABLE_COLON_RULES = ("ds-keyword-colon", "ds-keyword-colon-quotes-required")   # group 2: the label's quote
_COLON_THEN_QUOTE = (":\\s*([\\'\"`]?)", ":(\\s*)([\\'\"`])")
_ESCAPED_QUOTE_SKIP = "(?:\\\\(?=[\"']))?"
_WHITESPACE_RE = re.compile(r"\s")
# the label tail of the vendored keyword rules: `<keyword>\w*` and then a separator. On `password=` and a long run of
# letters with no space, each keyword inside the run (pwd, key) took the rest of the run and gave it back one character
# at a time (the rule with a quote and a semicolon tried 50 more characters each time): quadratic, 320 KB took 10 s,
# also in 0.6.15. What follows `\w*` in these rules never starts with a word character (a quote, ], a space, a colon,
# =, or `[^\s]{0,50}?` that a shorter run can only reach less far with), so the regex matches only where `\w*` takes
# the whole run. _KeywordTail finds each keyword, jumps to the end of its word run with an index of the runs, and runs
# the rest of the regex once per run end: the same matches, in linear time. tests/test_scan_bounds.py compares it
# with the vendored regex on runs of 0 to 5000 characters
class _KeywordTail:
    r"""A vendored keyword regex `(<alternatives>)\w*<tail>` matched without backtracking into the word run."""
    __slots__ = ("pattern", "flags", "_prefix", "_alts", "_any", "_tail", "_heads", "_cross", "_rx")

    def __init__(self, pattern: str, keywords_prefix: str, alts: list, flags: int) -> None:
        self.pattern, self.flags, self._prefix, self._alts = pattern, flags, keywords_prefix, alts
        self._any = self._tail = None
        self._heads: list = []

    def _compile(self) -> None:
        if self._any is not None:
            return
        tail = self.pattern[len(self._prefix) + len("\\w*"):]
        self._rx = re.compile(self.pattern, self.flags)
        self._any = re.compile(self._prefix, self.flags)
        groups = self._any.groups
        # one head per alternative, in the regex's order; the others never match but keep their group numbers
        self._heads = [re.compile("(?<!mai)(" + "|".join(a if j == i else "(?!)" + a for j, a in enumerate(self._alts))
                                  + ")", self.flags) for i in range(len(self._alts))]
        self._tail = re.compile("()" * groups + tail, self.flags)   # empty groups keep the numbers of backreferences
        # the alternatives that can match a character outside a word (mot de passe): only they can start inside a
        # word run and end past it. Every other one ends inside the run, at the run's end once \w* has run
        cross = [a for a in self._alts if _CROSS_CHARS_RE.search(_LOOKAROUND_RE.sub("", a))]
        self._cross = re.compile("(?<!mai)(?:" + "|".join(cross) + ")", self.flags) if cross else None

    def finditer(self, text: str):
        self._compile()
        if _LONG_WORD_RUN_RE.search(text) is None:
            # no word run of 200 characters: the vendored regex backtracks at most that far per keyword, and its C
            # loop is faster than this one on ordinary lines
            yield from self._rx.finditer(text)
            return
        tails: dict = {}
        word = _WORD_RUN_ANY_RE
        pos, n = 0, len(text)
        while pos <= n:
            m = self._any.search(text, pos)
            if m is None:
                return
            p = m.start()
            w = word.match(text, m.end())
            if w is None or w.end() - m.end() < 200:
                # a short word run after the keyword: the vendored regex at p backtracks at most that far, and it is
                # the same regex. Only a keyword before a long run takes the loop below (codex verification of 0.6.16:
                # one long word made the whole text slow)
                r = self._rx.match(text, p)
                if r is not None:
                    yield r
                    pos = r.end() if r.end() > p else p + 1
                else:
                    pos = p + 1
                continue
            hit = None
            e = -1
            # the first alternative that matches at p is the one the regex tries first: the search found it already
            for h in itertools.chain((m,), (head.match(text, p) for head in self._heads)):
                if h is None:
                    continue
                q = h.end()
                w = word.match(text, q)
                e = w.end() if w is not None else q     # \w* takes the whole run after the keyword
                if e not in tails:
                    tails[e] = self._tail.match(text, e)
                t = tails[e]
                if t is not None:
                    hit = _HeadTail(text, h, t)
                    break
            if hit is None:
                pos = p + 1
                run = word.match(text, p)
                if run is not None and run.end() == e and e > pos:
                    # p starts a word run whose rest failed: a keyword later in the run that stays in it fails too.
                    # Only an alternative that leaves the run can start a match before its end
                    c = self._cross.search(text, pos, e + 256) if self._cross is not None else None
                    pos = c.start() if c is not None and c.start() < e else e
                continue
            yield hit
            pos = hit.end() if hit.end() > p else p + 1

    def search(self, text: str):
        return next(self.finditer(text), None)

    @property
    def groups(self) -> int:
        self._compile()
        return self._tail.groups


class _HeadTail:
    """A match of _KeywordTail: the groups of the keyword from the head, the rest from the tail."""
    __slots__ = ("_text", "_h", "_t", "_n")

    def __init__(self, text: str, h, t) -> None:
        self._text, self._h, self._t, self._n = text, h, t, h.re.groups

    def group(self, i: int = 0):
        if i == 0:
            return self._text[self._h.start():self._t.end()]
        return self._h.group(i) if i <= self._n else self._t.group(i)

    def start(self, i: int = 0) -> int:
        if i == 0:
            return self._h.start()
        return self._h.start(i) if i <= self._n else self._t.start(i)

    def end(self, i: int = 0) -> int:
        if i == 0:
            return self._t.end()
        return self._h.end(i) if i <= self._n else self._t.end(i)

    def span(self, i: int = 0) -> tuple:
        return self.start(i), self.end(i)


_WORD_RUN_ANY_RE = re.compile(r"\w+")
_LONG_WORD_RUN_RE = re.compile(r"\w{200}")
_LOOKAROUND_RE = re.compile(r"\(\?<?[=!][^()]*\)")
_CROSS_CHARS_RE = re.compile(r"[ .\[-]|\\[sWdbBSD]")   # a space, a dot, a class, a hyphen or a non-word escape
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

        if _COLON_AFTER_LABEL_SPACED in regex:
            regex = regex.replace(_COLON_AFTER_LABEL_SPACED, _COLON_AFTER_LABEL_ESCAPED, 1)
            for q in _COLON_THEN_QUOTE:   # the skip goes right before the group of the opening quote
                at = q.rindex("([")
                regex = regex.replace(q, q[:at] + _ESCAPED_QUOTE_SKIP + q[at:], 1)
        if regex.startswith(keywords + "\\w*") and len(regex) > len(keywords) + 3:
            rx = _KeywordTail(regex, keywords, list(data["denylist"]) + [lab.regex for lab in labels], flags)
        else:
            rx = _Lazy(regex, flags)
        out.append(Rule(id=r["id"], type="SECRET", regex=rx,
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


def _load_literal(languages: tuple[str, ...] = ("en",)) -> list[Rule]:
    _LABEL_CLASS.clear()   # the password label words depend on the languages
    _PW_LAST_ON[0] = _PW_LAST.union(*(_PW_LAST_OF.get(lang, ()) for lang in languages))
    return [Rule(id=d["id"], type="SECRET", regex=_Lazy(r"(?!)()"), secret_group=1, keywords=d["keywords"])
            for d in LITERAL_RULES]


def _load_own() -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=_Lazy(d["regex"]),
                 secret_group=d.get("secret_group", 0), validator=d.get("validator"))
            for d in OWN_RULES] + _load_prefixes()


_RULES: list[Rule] | None = None


def rules() -> list[Rule]:
    """Own secret rules first (longer shapes win the span), then betterleaks and the own rules of
    own_secret_rules.json, then PII."""
    global _RULES
    if _RULES is None:
        own = _load_own()
        secrets = [r for r in own if r.type == "SECRET"]
        pii = [r for r in own if r.type != "SECRET"]
        active = active_regions()
        _RULES = (secrets + _load_detect_secrets(active.languages) + _load_betterleaks() + _load_own_secret_rules()
                  + _load_regional(active.regions) + _load_presidio(active.regions) + pii
                  + _load_literal(active.languages))
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


_PUBLIC_TEST_VALUES: list = []
# an encoded address is an address after `=` (email=, to=, login=), after mailto%3A, or after a mail word; elsewhere
# name%40version.com is a package, a git ref or an asset name (codex review)
_ENCODED_MAIL_CONTEXT_RE = re.compile(
    r"(?i)(?:=|%3d|mailto(?::|%3a)"
    r"|\b(?:to|from|cc|bcc)[ \t]*[:=][ \t]*"   # `to` and `from` alone are paths and imports: path/to/pkg%40v.com
    r"|\b(?:e-?mail|mail|sender|recipient|bounce|reply-to|contact|login|users?|username)[ \t]*[:=/]?[ \t]*)$")
_DIGITS_ONLY_RE = re.compile(r"\+?[\d\s().-]+")


def is_public_test_value(value: str, kind: str) -> bool:
    """A value that vendor documentation publishes for tests, for one placeholder type (rules/public_test_values.txt):
    a payment test card is no CARD, the Stripe API reference key and the jwt.io example are no SECRET, a Twilio test
    number is no PHONE. The same digits under another type stay a hit: a bank account that happens to equal a test
    card is still a bank account (codex review). 18 of 21 false alarms of a public benchmark were such values
    (2026-10-11). The file holds full sha256 digests, never the values."""
    if not _PUBLIC_TEST_VALUES:
        entries = set()
        for line in (RULES_DIR / "public_test_values.txt").read_text(encoding="utf-8").splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) == 2:   # digest and type; a malformed line must not break every scan
                entries.add((fields[1], fields[0]))
        _PUBLIC_TEST_VALUES.append(frozenset(entries))
    v = value.strip("\"'` ")
    if _DIGITS_ONLY_RE.fullmatch(v):
        v = re.sub(r"\D", "", v)
    return (kind, hashlib.sha256(v.encode("utf-8")).hexdigest()) in _PUBLIC_TEST_VALUES[0]


def looks_like_placeholder(value: str) -> bool:
    v = value.strip("\"'` ")
    low = v.lower()
    return low in PLACEHOLDER_VALUES or bool(_PLACEHOLDER_PART_RE.search(low)) or bool(_TEMPLATE_NAME.match(v))


# ------------------------------------------------------------- test fixtures --
# A label rule finds a value by its label alone, so a test password looks like a real one: `PASSWD = '<word>'` in the
# tests of the Python standard library (2026-09-29). In test code the value is a fixture, and a
# block or a placeholder there only stops the work. A token shape (glpat-, AKIA, a PEM key) and personal data stay
# hits in test code too: a real token or a copy of customer data in a test is a leak.
LABEL_RULES = ("ds-keyword", "label-", "generic-api-key", "url-query-secret", "auth-scheme")
# the keyword rules: the detect-secrets ones and maisecrets' own label rules with no `=` or `:` (OWN_RULES)
KEYWORD_RULES = ("ds-keyword", "label-")
_TEST_PATH_RE = re.compile(r"(?:^|[/\\])(?i:tests?|__tests__|spec|testdata|test_data|e2e)[/\\]"
                           r"|(?:^|[/\\]|[a-z])Tests?\.\w+$"
                           r"|(?:^|[/\\])[^/\\]*[._-]e2e[._-][^/\\]*$"
                           r"|(?:^|[/\\])(?:test_[^/\\]*|[^/\\]*_test\.\w+|[^/\\]*\.(?:test|spec)\.\w+|conftest\.py)$")
# a file of real values even under tests/: an .env, a recorded HTTP cassette (review, 2026-09-29)
_REAL_VALUE_FILE_RE = re.compile(r"(?i)(?:^|[/\\])(?:\.env[^/\\]*|[^/\\]*\.env(?:\.[^/\\]*)?|[^/\\]*\.har"
                                 r"|[^/\\]*\.har\.\w+|(?:cassettes?|(?:__)?recordings?(?:__)?|recorded|tapes|vcr"
                                 r"|__nock-fixtures__)[/\\].*)$")
_TEST_MARKER_RE = re.compile(
    r"(?m)^(?:(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\(|[ \t]*class[ \t]+Tests?(?:[A-Z_(:]|$)|[ \t]*@pytest\."
    r"|[ \t]*@Test\b|[ \t]*#\[test\]"
    r"|[ \t]*(?:import|from)[ \t]+(?:pytest|unittest)\b|[ \t]*func[ \t]+Test\w*\("
    r"|[ \t]*(?:describe|it|test|beforeEach)[ \t]*\()")
_TEST_METHOD_RE = re.compile(r"(?m)^[ \t+-]+(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\([ \t]*self\b")
_CLASS_LINE_RE = re.compile(r"(?m)^[ \t+-]*class[ \t]+\w|^@@[^\n]*\bclass[ \t]+\w")
_TEST_CLASS_LINE_RE = re.compile(r"[ \t+-]*class[ \t]+Tests?(?:[A-Z_(:]|$)|@@[^\n]*\bclass[ \t]+Tests?(?:[A-Z_(:]|\b)")
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
    line_start = _line_start(text, start)
    m = _GREP_PATH_RE.match(text, line_start)
    if m and is_test_path(m.group(1)):
        return True
    nl = _newlines(text)
    i = bisect.bisect_left(nl, line_start)       # the line of the hit is line i
    begin = nl[i - _TEST_LOOKBACK_LINES - 1] + 1 if i > _TEST_LOOKBACK_LINES else 0
    diffs = _positions(text, "diff", _DIFF_FILE_RE)
    j = bisect.bisect_left(diffs, line_start)
    if j and diffs[j - 1] >= begin:
        begin = diffs[j - 1]      # a marker of another file in the same diff does not count
    end = _line_end(text, start)
    markers = _positions(text, "marker", _TEST_MARKER_RE)
    k = bisect.bisect_left(markers, begin)
    if k < len(markers) and markers[k] < end:
        return True
    # an indented `def test_…(self` counts when no class other than a test class stands nearer above it: a test
    # method in a diff hunk or a paste, but not `def test_connection(self)` in class Db (reviews, 2026-09-30)
    defs = _positions(text, "defs", _TEST_METHOD_RE)
    k = bisect.bisect_left(defs, end) - 1
    if k < 0 or defs[k] < begin:
        return False
    classes = _positions(text, "classes", _CLASS_LINE_RE)
    c = bisect.bisect_left(classes, end) - 1   # the class nearest above the hit, also one after the method
    if c < 0 or classes[c] < begin:
        return True
    return bool(_TEST_CLASS_LINE_RE.match(text, classes[c]))


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
                            "must", "cannot", "should", "not", "no", "abgelaufen", "unbekannt", "erforderlich",
                            "vergessen", "unver\u00e4ndert", "ung\u00fcltig", "ungueltig", "gesperrt",
                            "ge\u00e4ndert", "widerrufen", "zur\u00fcckgesetzt"})


def is_code_word(value: str) -> bool:
    """A statement keyword or a word of an error message: a keyword rule never takes it as a value."""
    w = value.strip().rstrip(";").lower()
    return w in _CODE_WORDS or w in _MESSAGE_WORDS


def code_word_spellings() -> list[str]:
    """The spellings of such a word that a keyword rule stored before 0.5.15. The vault finds a stored one by its
    fingerprint and reads no value (Vault.drop_code_words)."""
    return [s for w in sorted(_CODE_WORDS | _MESSAGE_WORDS) for b in (w, w.capitalize(), w.upper())
            for s in (b, b + ";")]


_NL_RE = re.compile("\n")
_INDEX: list = [None, None]   # the last text and its line index: scan() and is_fixture() ask about one text


def _newlines(text: str) -> list:
    """The offsets of the line breaks of `text`, computed once per text. A search for the start or the end of a line
    at each keyword hit was one pass over the line, and a one-line text of 2 MB took 14.5 s (review of 3e5d53e,
    2026-09-30)."""
    if _INDEX[0] is not text:
        _INDEX[0], _INDEX[1] = text, {"nl": [m.start() for m in _NL_RE.finditer(text)]}
    return _INDEX[1]["nl"]


def _line_start(text: str, pos: int) -> int:
    nl = _newlines(text)
    i = bisect.bisect_left(nl, pos)
    return nl[i - 1] + 1 if i else 0


def _line_end(text: str, pos: int) -> int:
    nl = _newlines(text)
    i = bisect.bisect_left(nl, pos)
    return nl[i] if i < len(nl) else len(text)


def _split_lines(text: str) -> tuple:
    """The lines of `text` and of its lower-case form, split once per text: the seven keyword rules each split a
    megabyte again (review of 3e5d53e, 2026-09-30)."""
    _newlines(text)
    cache = _INDEX[1]
    if "lines" not in cache:
        cache["lines"] = (text.split("\n"), _lower(text).split("\n"))
    return cache["lines"]


def _positions(text: str, name: str, rx: re.Pattern) -> list:
    """The start offsets of the matches of `rx` in `text`, computed once per text (see _newlines)."""
    _newlines(text)
    cache = _INDEX[1]
    if name not in cache:
        cache[name] = [m.start() for m in rx.finditer(text)]
    return cache[name]


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LABEL_WINDOW = 200   # characters before a value in which its label is looked for


def _before_value(text: str, start: int) -> str:
    """The text of the value's line before it, at most _LABEL_WINDOW characters."""
    return text[max(_line_start(text, start), start - _LABEL_WINDOW):start]
_LABEL_TAIL_RE = re.compile(r"([A-Za-z_][\w.]*)\\?[\"']?\s*(?::=|=|:)\s*\\?[\"'`]?$")   # \" in JSON in a string
_OPERATOR_AFTER_RE = re.compile(r"[ \t]+[|&^*+][ \t]+[A-Za-z_(]")
_SELF_ATTR_RE = re.compile(r"(?:^|[\s,(])(?:self|this|cls)\.\w+$")


def value_is_code(text: str, start: int, end: int, secret: str) -> bool:
    """A keyword rule read `name = <expression>` in source code as label and value. Three forms, all measured in the
    Python standard library (2026-09-29): the same name on both sides (`authkey=authkey`), an unquoted name that an
    operator continues (`TOKEN_ENDS = TSPECIALS | WSP`), and an unquoted name given to an attribute of the object
    (`self.token = nextchar`). A quoted value, and `spring.datasource.password=<value>`, stay values."""
    v = secret.strip().strip("'\"`;,")
    before = _before_value(text, start)
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
# whole words of the label: TELEMETRY_OFFSET is no telephone (Codex review, 2026-09-30)
_PHONE_LABEL_RE = re.compile(r"(?i)phone|(?<![a-z])(?:telefon|mobil|handy(?!man)|fax|contact|kontakt|rufnummer|whatsapp"
                             r"|msisdn|festnetz|hotline|durchwahl)|(?<![a-z])(?:tel|cell|sms)(?![a-z])")
_NUMBER_BEFORE_RE = re.compile(r"(?:=\s+|[(\[]\s*|return\s+)$")   # not KEY=+49…, not a CSV column


def _phone_ok(text: str, start: int, secret: str) -> bool:
    """E.164 has at most 15 digits; a run of 0 and 1 is a binary number; a signed number without separators after
    `=`, `(` or `,` is a number in code (Python standard library, 2026-09-29)."""
    digits = re.sub(r"\D", "", secret)
    if len(digits) > 15 or set(digits) <= {"0", "1"}:
        return False
    if re.search(r"[ \-()]", secret) or not _NUMBER_BEFORE_RE.search(text, max(0, start - 8), start):
        return True
    # CONTACT_PHONE = +49… (Codex review), phone(+49…), [+49…] after a phone word (final review, 2026-09-30)
    return bool(_PHONE_LABEL_RE.search(_label_before(text, start)) or _PHONE_LABEL_RE.search(
        text, max(0, start - 24), start))


# gitleaks' generic-api-key starts with a lazy `[\w.-]{0,50}?` before its keyword, so the regex
# engine tries up to 50 prefixes at every position of the text: 80 % of a log scan's time
# (2026-09-27). Its keywords are found by a plain search first, and the rule runs only in a
# window around each: from 50 characters before the keyword (the prefix cannot cross a line) to
# the end of the 8th line after it (the separators may hold line breaks; the window ends after a
# newline, which the value's terminator class takes the same way as in the whole text).
_WINDOWED = {"generic-api-key": re.compile(r"(?i)access|auth|api|credential|creds|key|passw(?:or)?d|secret|token")}


def _windowed(rule: Rule, kw: re.Pattern, text: str):
    spans: list[list[int]] = []
    nl = _newlines(text)
    for k in kw.finditer(text):
        a = max(_line_start(text, k.start()), k.start() - 50)
        # the separators may hold several line breaks (`password for prod:` + blank line +
        # value, review 2026-09-27). The regex allows 3 whitespace characters before the separator
        # and 5 after it, so the value can start after 8 line breaks: the window runs to the end
        # of the 9th line (8 cut `password\n\n\n:\n\n\n\n\n<value>` off, differential test 2026-09-27)
        i = bisect.bisect_left(nl, k.end()) + 8
        b = nl[i] + 1 if i < len(nl) else len(text)
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
    curl = _curl_parts(rule)
    if curl is not None:
        yield from _curl_matches(curl, text)
        return
    if rule.id == "label-secret-list":
        yield from _list_matches(rule, text)
        return
    if rule.id in _LITERAL_IDS:
        yield from _literal_matches(rule.id, text)
        return
    kw = _WINDOWED.get(rule.id)
    if kw is not None and len(text) > 4096:
        yield from _windowed(rule, kw, text)
        return
    if not rule.id.startswith("ds-keyword") or not _newlines(text):
        yield from rule.regex.finditer(text)
        return
    pos = 0
    lines, low = _split_lines(text)
    low = low if rule.keywords else None
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


# betterleaks' two curl rules start with `\bcurl\b` and then `.*` (or `.*?`) over up to 5 more lines before the -H or
# -u part. RE2 runs that in linear time; Python's `re` scans the rest of the line again from each `curl`, and a line
# with many of them took O(n^2) (32K characters: 10 s, past the hook's time limit). Here the -H/-u part (the tail)
# is found on its own, and the nearest `curl` before it must stand within the same line breaks as the regex allows.
_CURL_HEADS = (r"\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})", r"\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})")
_CURL_PARTS: dict = {}


def _curl_parts(rule: Rule):
    """(curl regex, tail regex) of a curl rule whose regex starts with a known head; None for any other rule, and
    for a curl rule whose regex a sync changed (it then runs as it is: correct, only slower)."""
    if not rule.id.startswith("curl-"):
        return None
    if rule.id not in _CURL_PARTS:
        p = rule.regex.pattern
        flags = "(?i)" if p.startswith("(?i)") else ""
        body = p[len(flags):]
        head = next((h for h in _CURL_HEADS if body.startswith(h)), None)
        tail = body[len(head):] if head else ""
        if tail.endswith(r"(?:\s|\Z)"):
            # the space after a credential was part of the match, so finditer skipped a credential that started
            # right after it: `-u a:x --user b:y` lost b:y (Gate B of 0.6.15); a lookahead keeps it
            tail = tail[:-len(r"(?:\s|\Z)")] + r"(?=\s|\Z)"
        _CURL_PARTS[rule.id] = None if head is None else (re.compile(flags + r"\bcurl\b"), re.compile(flags + tail))
    return _CURL_PARTS[rule.id]


def _curl_matches(parts, text: str):
    """The matches of a curl rule in linear time. A match takes each -H/-u part whose nearest `curl` before it is
    at most 5 line breaks away (`[\\r\\n]{1,2}` is one break, so a blank line counts once); its group 0 starts at
    that `curl`. The regex took only the first (-H, lazy) or the last (-u, greedy) part after one `curl`; this
    takes each one."""
    head, tail = parts
    starts: list[int] = []
    ends: list[int] = []
    for c in head.finditer(text):
        starts.append(c.start())
        ends.append(c.end())
    if not starts:
        return
    nl = _newlines(text)
    for t in tail.finditer(text):
        i = bisect.bisect_right(ends, t.start()) - 1
        if i < 0:
            continue
        lo, hi = bisect.bisect_left(nl, ends[i]), bisect.bisect_left(nl, t.start())
        if hi - lo > 10:
            continue
        breaks = run = 0
        for j in range(lo, hi):
            run = run + 1 if j > lo and nl[j] == nl[j - 1] + 1 else 1
            breaks += run % 2                    # two line feeds in a row are one `[\r\n]{1,2}`
        if breaks <= 5:
            yield _Spanned(t, starts[i], text)


# one quoted value of a list and what follows it: a comma (the next value) or the closing bracket. Up to two line
# breaks around it: a list written one value per line
_LIST_ITEM_RE = re.compile(r"[ \t]*(?:\r?\n[ \t]*){0,2}([\"'`])([^\"'`\\\n]{1,256})\1"
                           r"[ \t]*(?:\r?\n[ \t]*){0,2}(,|[\]})])")


def _list_matches(rule: Rule, text: str):
    """Each quoted value of the list that starts after a label of label-secret-list and that looks like a key
    (_list_value_ok), as group 2 of a match whose group 0 starts at the label. The values are checked here, before
    the filters of scan(): a list of 10,000 words cost each word the whole chain. The list ends at its closing
    bracket or at a value that is not a quoted string, at any length: a cut at 1 MB left the keys after it in the
    clear (codex Gate A of 0.6.16). A label inside a list already read is skipped, so each character is read once."""
    done = -1
    for lab in rule.regex.finditer(text):
        if lab.start() < done:
            continue
        pos = lab.end()
        while True:
            it = _LIST_ITEM_RE.match(text, pos)
            if it is None:
                break
            if _list_value_ok(it.group(2)):
                yield _Spanned(it, lab.start(), text)
            if it.group(3) != ",":
                break
            pos = it.end()
        done = pos


class _Spanned:
    """A tail match whose group 0 starts earlier, at its `curl`."""
    __slots__ = ("_m", "_start", "_text")

    def __init__(self, m: re.Match, start: int, text: str) -> None:
        self._m, self._start, self._text = m, start, text

    def group(self, i: int = 0):
        return self._text[self._start:self._m.end()] if i == 0 else self._m.group(i)

    def start(self, i: int = 0) -> int:
        return self._start if i == 0 else self._m.start(i)

    def end(self, i: int = 0) -> int:
        return self._m.end(i)


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
    before = _before_value(text, start)
    m = _LABEL_TAIL_RE.search(before)
    # another label on the line, also one before the window: then only the value's own label counts (an earlier
    # smtp.user= label, 225 characters of prose, then the password label and a word of the prose; review of 3e5d53e)
    wide = text[max(_line_start(text, start), start - 1000):start]
    if m and (len(re.findall(r"[:=]", before[:m.start()])) > 0 or len(re.findall(r"[:=]", wide)) > 1):
        before = m.group(1)
    words = set(re.findall(r"[a-z]+", before.lower()))
    v = secret.strip("\"'` ").rstrip(".,;:!?")
    if v.lower() in words:
        return True   # also at the end of a sentence
    parts = [p.lower() for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", v)]
    return len(parts) >= 2 and "".join(parts) == v.lower() and set(parts) <= words   # token_data: TokenData


# lookarounds, not ^: search(text, pos) anchors ^ at the start of the text, never at pos (a file's line 19 passed)
_MEASURE_LABEL_RE = re.compile(r"(?i)(?<![a-z])(?:ttl|timeout|expir\w*|lifetime|max|min|len|length|size|count|limit"
                               r"|port|age|seconds|minutes|hours|days|retries|interval|ms|budget|refresh|rotation|cost"
                               r"|price|quota|window|delay|offset|threshold|rate|bytes|exp|iat|nbf|at|counter|index"
                               r"|generation)(?![a-z])")
# a label that names a secret: a UUID after it is one (Postmark server token, Scaleway secret key, a uuid4 API key)
_SECRET_LABEL_RE = re.compile(r"(?i)(?:token|secret[_-]?key|secret|secret[_-]?value|api[_-]?key|apikey|access[_-]?key"
                              r"|auth[_-]?key|\w+[_-]key|password|passwd|pwd|passphrase)\\?[\"']?\s*(?::=|=>|[:=])\s*\\?[\"'`]?$")
_ELISION_RE = re.compile(r"(?:\.\.\.|\u2026)$")
# a label that names a derived thing: secret_id, password_hash, token_type, hashed_secret. Anchored at the value: in
# `secret_name: x, password: <value>` the password stays a hit
_DERIVED_LABEL_RE = re.compile(
    r"(?i)(?:(?:secret|password|passwd|pwd|token|key)[_-]?(?:id|name|hash|hashed|len|length|path|file|arn|ref|url|uri"
    r"|version|type|policy|rules?|last(?:_\w+)?)|hashed_(?:secret|password|token)|(?:secret|password|token|key)Id"
    r"|(?:secret|password|token)Name)\\?[\"']?\s*(?::=|=>|[:=])\s*\\?[\"'`]?$")


def _label_before(text: str, start: int) -> str:
    """The label of the value at `start`: `TTL_REFRESH_TOKEN` in `TTL_REFRESH_TOKEN = 15552000`."""
    m = _LABEL_TAIL_RE.search(_before_value(text, start))
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
# GitLab's routable token: payload, ".", version (2 base36), ".", length (2) and CRC32 (7) in base36: 9 characters;
# the older form has one dot: payload, ".", 9 characters (lib/authn/token_field/generator/routable_token.rb)
_ROUTABLE_TAIL_RE = re.compile(r"\.(?:[0-9a-z]{2}\.)?[0-9a-z]{9}(?![0-9A-Za-z_-])")
_GITLAB_PREFIX_RE = re.compile(r"gl[a-z]+-")


def _lower(text: str) -> str:
    """Lower case for the prefilters and context words. The Turkish capital İ lowers to i plus a
    combining dot, so `ŞİFRE:` held no `ifre` (Codex review, 2026-09-28); the dot is dropped. The
    result is not the length of the input: never take an offset of the original into it."""
    return text.lower().replace("i\u0307", "i")


# X-Amz-Credential=AKIA…/20261008/eu-central-1/s3/aws4_request: the access key id names the key, it is not the
# secret half; a presigned URL carries it in the clear by design (corpus of 0.6.7: 142 such hits in tool output)
_SIGV4_CREDENTIAL_RE = re.compile(r"\b(?i:x-amz-credential|credential)(?:=|%3[Dd])$")
# and the scope that must follow it: /date/region/service/aws4_request, plain or percent-encoded. A bare
# Credential=AKIA… is no SigV4 scope and stays a hit (codex review of 0.6.8)
_SIGV4_SCOPE_RE = re.compile(r"(?:/|%2[Ff])\d{8}(?:/|%2[Ff])[a-z0-9-]+(?:/|%2[Ff])[a-z0-9-]+(?:/|%2[Ff])aws4_request"
                             r"(?=$|[\s&,;\"'#])")    # then a query or header separator: not aws4_requestX (codex)
# a whole reference or a whole date in the password place of a URL: redis://:%24%7BREDIS_PASSWORD%7D@…,
# redis://:2026-10-08@…; an encoded $ or { inside a real password stays a value (codex, Opus review of 0.6.8)
_URL_PASSWORD_NOT_A_VALUE_RE = re.compile(r"%24[A-Za-z_][A-Za-z0-9_]*|%24%7[Bb][A-Za-z_][A-Za-z0-9_]*%7[Dd]"
                                          r"|\d{4}-\d{2}-\d{2}")    # a time has a colon, which this rule never takes


def _url_password_not_a_value(v: str) -> bool:
    """A whole encoded reference, or a date the calendar has (2026-02-31 is a value: codex review of 0.6.8)."""
    if not _URL_PASSWORD_NOT_A_VALUE_RE.fullmatch(v):
        return False
    if v.startswith("%"):
        return True
    import datetime
    try:
        datetime.date.fromisoformat(v)
    except ValueError:
        return False
    return True


# PostgreSQL's tools take --password (-W) as a switch with no value (Gate B of 0.6.15)
_PG_TOOL_RE = re.compile(r"(?<![\w-])(?:psql|pg_dump|pg_dumpall|pg_restore|pg_basebackup|createdb|dropdb|createuser"
                         r"|dropuser|vacuumdb|reindexdb|clusterdb|pgbench)(?:\.exe)?(?![\w-])")


def _command_start(text: str, pos: int) -> int:
    """The start of the shell command that holds pos: after the last | ; & on its line (round 2 of 0.6.15)."""
    a = _line_start(text, pos)
    cut = max(text.rfind(c, a, pos) for c in "|;&")
    return cut + 1 if cut >= a else a


def scan(text: str, enabled: set[str] | None = None, channel: str = "prompt", path: str = "") -> list[Match]:
    """Return non-overlapping matches, leftmost first; the first rule to claim a span wins. channel "tool" (a tool
    result or a file) takes a password after a password label without evidence of chance, and the cells of a
    password export (path: the file the text came from, if any)."""
    outer, _CHANNEL[0] = _CHANNEL[0], channel if channel == "tool" else "prompt"
    outer_path, _PATH[0] = _PATH[0], path or ""
    try:
        return _scan(text, enabled)
    finally:
        _CHANNEL[0] = outer   # the channel of an outer scan comes back after a nested one (is_fixture)
        _PATH[0] = outer_path


_PATH: list = [""]
# a label rule (LABEL_RULES): its header labels the cell, so a word in it is stored quiet and a fixture in test code
# is dropped, as after `password:`
EXPORT_RULE = "label-password-export"
# the file names of password exports: a browser's (Chrome, Edge, Firefox, Safari), Bitwarden, 1Password, LastPass,
# KeePass and KeePassXC, Dashlane, and any table whose name says passwords
_EXPORT_NAME_RE = re.compile(r"(?i)(?:passw|kennw|logins?\b|bitwarden|1password|lastpass|keepass|dashlane|enpass"
                             r"|nordpass|roboform)[^/\\]*\.(?:csv|tsv|txt)$")
# a header names what its cells hold by its words (camelCase, _ - . and spaces split them): the last word, or the
# last two together. A flag (is_secret, has_password) holds no value; `token` alone is often an NLP column
_HEADER_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_EXPORT_SECRET_WORDS = frozenset({"password", "passwd", "pwd", "passphrase", "passwort", "kennwort", "secret", "totp",
                                  "hotp", "otp", "otpauth"})
_EXPORT_SECRET_PAIRS = frozenset({"apikey", "secretkey", "privatekey", "accesstoken", "otpauth", "otpsecret",
                                  "mfasecret"})
_EXPORT_ID_WORDS = frozenset({"username", "user", "login", "loginname", "email", "mail", "url", "uri", "website",
                              "site", "web", "origin", "hostname", "host", "title", "name", "account", "benutzer",
                              "benutzername"})
_EXPORT_DELIMITERS = (",", ";", "\t")


def _header_words(cell: str) -> list:
    return [w.lower() for w in _HEADER_WORD_RE.findall(cell.strip().strip("\"'"))]


def _export_column(cell: str) -> str:
    """SECRET for a header whose cells are passwords, TOTP seeds or keys; ID for one that names an entry or its
    login; "" for any other."""
    w = _header_words(cell)
    if not w or w[0] in ("is", "has"):
        return ""
    if w[-1] in _EXPORT_SECRET_WORDS or "".join(w[-2:]) in _EXPORT_SECRET_PAIRS:
        return "SECRET"
    if w[-1] in _EXPORT_ID_WORDS or "".join(w[-2:]) in _EXPORT_ID_WORDS:
        return "ID"
    return ""


_CELL_MAX = 8192   # a quote that no quote closes within this many characters opens no cell: the cell ends its line


def _csv_cells(text: str, pos: int, delim: str):
    """The cells of the CSV row that starts at pos, as (start, end) of each cell's content (its quotes excluded), and
    the start of the next row. A quoted cell may hold the delimiter, a doubled quote and a line break."""
    cells = []
    n = len(text)
    i = pos
    while True:
        q = -1
        if i < n and text[i] == '"':
            j = i + 1
            limit = min(n, i + _CELL_MAX)
            while True:
                q = text.find('"', j, limit)
                if q < 0 or not text.startswith('""', q):
                    break
                j = q + 2
            if q >= 0 and q + 1 < n and text[q + 1] not in delim + "\r\n":
                q = -1   # no cell ends so: the quote opened no cell, and the cell ends its line
        if q >= 0:
            cells.append((i + 1, q))
            i = q + 1
        else:
            j = i
            while j < n and text[j] not in delim + "\r\n":
                j += 1
            cells.append((i, j))
            i = j
        if i < n and text[i] == delim:
            i += 1
            continue
        if i < n and text[i] == "\r":
            i += 1
        if i < n and text[i] == "\n":
            i += 1
        return cells, i


_PLACEHOLDER_IN_CELL_RE = re.compile("\u27e6[A-Z][A-Z_]*_c\\d+(?::[^\u27e7\n]*)?\u27e7")
# what a cell of a schema, a form or a masked export holds instead of a password
_NOT_A_CELL_VALUE = frozenset({"true", "false", "null", "none", "nil", "undefined", "string", "str", "text", "int",
                               "integer", "bool", "boolean", "varchar", "yes", "no", "n/a", "na", "-", "--", "*",
                               "required", "optional", "hidden", "redacted", "masked", "empty", "password", "passwort",
                               "secret", "totp", "otp"})


def _outside_placeholders(text: str, a: int, b: int) -> list:
    """The parts of text[a:b] outside complete maisecrets placeholders, each trimmed: a placeholder is no value."""
    parts, pos = [], a
    for m in _PLACEHOLDER_IN_CELL_RE.finditer(text, a, b):
        parts.append((pos, m.start()))
        pos = m.end()
    parts.append((pos, b))
    out = []
    for pa, pb in parts:
        while pa < pb and text[pa] in " \t":
            pa += 1
        while pb > pa and text[pb - 1] in " \t":
            pb -= 1
        if pb > pa:
            out.append((pa, pb))
    return out


def _not_a_cell_value(v: str) -> bool:
    low = v.strip().lower()
    return low in _NOT_A_CELL_VALUE or (len(set(low)) == 1 and low[0] in "*\u2022x#.")


# a header row starts at the start of its line (code is indented) and each cell is a column name: up to four words,
# no brackets, operators or colons (a signature `def login(user, password):`, a call, a list line ending in a comma)
_HEADER_LINE_RE = re.compile(r"[\"'\w]")
_HEADER_CELL_RE = re.compile(r"[ \t]*\"?[A-Za-z][\w.#/-]*(?: [\w.#/-]+){0,3}\"?[ \t]*")
_NAME_RE = re.compile(r"\"?[A-Za-z][\w.-]*\"?")
_EXPORT_HINT_RE = re.compile(r"pass|pwd|kennw|totp|otp|secret|apikey|api_key|private_?key|access_?token")


def _export_hits(text: str, low: str) -> list:
    """The values in the password, TOTP and secret columns of a password export: a table whose header row names a
    secret column and an entry column (url, username, name, title, ...), or a secret column alone when the file name
    is an export's (passwords.csv, bitwarden_export.csv, ...). No rule finds a bare password in a cell: an export read
    whole put every password in front of the model."""
    if not _EXPORT_HINT_RE.search(low):
        return []
    by_name = bool(_PATH[0]) and _EXPORT_NAME_RE.search(_PATH[0]) is not None
    out = []
    pos = 0
    n = len(text)
    while pos < n:
        end = text.find("\n", pos)
        end = n if end < 0 else end
        line = text[pos:end].lower()   # not low: a lowered text can be longer than the original (Turkish I)
        header = None
        if _EXPORT_HINT_RE.search(line) and _HEADER_LINE_RE.match(line):
            best = None
            for delim in _EXPORT_DELIMITERS:
                if delim not in line:
                    continue
                cells, nxt = _csv_cells(text, pos, delim)
                if len(cells) < 2 or not all(_HEADER_CELL_RE.fullmatch(text[a:b]) and (
                        text[a - 1:a] == '"' or " " not in text[a:b].strip()) for a, b in cells):
                    continue   # each cell a column name, of several words only when quoted: code, SQL, prose and
                    # a test table are no header
                if len(cells) == 2 and not by_name and not all(_NAME_RE.fullmatch(text[a:b]) for a, b in cells):
                    continue   # two columns: names without a space (user_name,password), never `user, password`
                kinds = [_export_column(text[a:b]) for a, b in cells]
                if "SECRET" in kinds and ("ID" in kinds or by_name) and (best is None or len(cells) > len(best[1])):
                    best = (delim, cells, kinds, nxt)
            header = best
        if header is None:
            pos = end + 1
            continue
        delim, cells, kinds, pos = header
        secret_cols = [i for i, k in enumerate(kinds) if k == "SECRET"]
        width = len(cells)
        weak = width == 2 and not by_name
        while pos < n:
            if text.startswith(("\n", "\r\n"), pos):
                break   # an empty line ends the table
            row, nxt = _csv_cells(text, pos, delim)
            if len(row) != width:
                break   # no longer a row of this table: an export's rows all have the header's width
            for i in secret_cols:
                if i < len(row):
                    a, b = row[i]
                    while a < b and text[a] in " \t":
                        a += 1
                    while b > a and text[b - 1] in " \t":
                        b -= 1
                    if b <= a or _not_a_cell_value(text[a:b]) or (weak and _WHITESPACE_RE.search(text, a, b)):
                        continue   # a two-column table is a weaker sign: a cell with a space there is prose
                    for pa, pb in _outside_placeholders(text, a, b):
                        out.append(Match(EXPORT_RULE, "SECRET", text[pa:pb], pa, pb))
            pos = nxt
    return out


def _scan(text: str, enabled: set[str] | None = None, _copy: bool = False) -> list[Match]:
    """_copy: the text is the normaliser's cleaned copy of a tool result, which is not cleaned again."""
    if not text:
        return []
    low = _lower(text)
    found: list[Match] = []
    taken_starts: list[int] = []
    taken_ends: list[int] = []

    def overlaps(a: int, b: int) -> bool:
        """Whether [a, b) overlaps a span already taken. The spans never overlap each other, so only the two
        neighbours by start can; a scan over all of them was quadratic in the hits (review of b4a7c54)."""
        i = bisect.bisect_left(taken_starts, a)
        return (i > 0 and taken_ends[i - 1] > a) or (i < len(taken_starts) and taken_starts[i] < b)
    if _CHANNEL[0] == "tool" and not _copy and (enabled is None or EXPORT_RULE in enabled):
        # first: a cell of a password export is a value as a whole, and no other rule claims a part of it
        for m in _export_hits(text, low):
            found.append(m)
            taken_starts.append(m.start)
            taken_ends.append(m.end)
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
            if (rule.id in _ESCAPABLE_COLON_RULES and "\\" in (m.group(2) or "")
                    and text[start - 2:start] not in ('\\"', "\\'")):
                # the label's quote is escaped: JSON inside a string, whose values are escaped strings. A value without
                # an escaped quote is code or a literal: `\"access_token\": finding[\"secret\"]` (19 hits in the
                # vendored rules file, Gate A of 0.6.15), an escaped null (Gate B)
                continue
            if secret.endswith("\\") and text[end:end + 1] in ("\"", "'") and rule.id.startswith("ds-keyword"):
                secret, end = secret[:-1], end - 1   # {\"password\":\"<value>\"}: the backslash escapes the quote
            if (rule.id in _ESCAPABLE_COLON_RULES and "\\" in (m.group(2) or "")
                    and not _label_value_ok(secret)):
                continue   # {\"passwordLastChanged\":\"2024-10-01T12:00:00Z\"}: the new escaped path, no password
            if rule.quote_group and not m.group(rule.quote_group):
                cut = _WHITESPACE_RE.search(secret)
                if cut:
                    # the regex never ends a value on a comma; the cut keeps that rule
                    secret = secret[:cut.start()].rstrip(",")
                    end = start + len(secret)
                    if _CAPITALISED_WORD_RE.fullmatch(secret):
                        continue
            if rule.id.startswith(KEYWORD_RULES) and _ANCHOR_OR_TAG_RE.fullmatch(secret.strip()):
                # a quoted scalar is never an anchor: the colon must stand right before it (review of b4a7c54)
                nxt = re.match(r"[ \t]+([^\s#]+)", text[end:end + 300])
                if nxt:
                    # password: &pw <value>, password: !vault <value>: the value follows the anchor or the tag
                    # (review of 3e5d53e: the value after it was never scanned); its quotes are no part of it
                    a, b = end + nxt.start(1), end + nxt.end(1)
                    if b - a >= 2 and text[a] == text[b - 1] and text[a] in "'\"":
                        a, b = a + 1, b - 1
                    start, end = a, b
                    secret = text[start:end]
                elif _before_value(text, start).rstrip(" \t").endswith(":"):
                    continue   # a YAML anchor or alias alone after a colon label: &gitlab_token_fields
            if rule.id.startswith(KEYWORD_RULES) and (is_code_word(secret) or value_is_code(text, start, end, secret)):
                continue
            if rule.id == "generic-api-key" and _WORD_PATH_RE.fullmatch(secret.strip("'\"")):
                continue
            if rule.id.startswith(KEYWORD_RULES) and _names_its_label(text, start, secret):
                continue
            if (rule.id.startswith(KEYWORD_RULES) and _LABEL_SHAPE.fullmatch(secret.strip())
                    and _NAME_LABEL_RE.fullmatch(secret.strip()) and "\n" in text[m.start():start]):
                continue   # the next line is a label of its own: `DB_PASSWORD=\nAPI_KEY=`, `Zugangsdaten:\nBenutzer:`
            if (rule.id.startswith(KEYWORD_RULES) and secret.strip("\"' ").isdigit()
                    and _MEASURE_LABEL_RE.search(_label_before(text, start))):
                continue   # a limit or a duration: TTL_REFRESH_TOKEN = 2592000
            if rule.id == "url-query-secret" and secret.startswith("{"):
                continue   # a template: ?token={body['transfer_id']}, ?token={SLACK_AUTO_TOKEN}
            if (rule.id == "auth-scheme" and not any(c.isdigit() for c in secret)
                    and re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z]+)+", secret)):
                continue   # words, not a token: Bearer test_access_token
            if (rule.id.startswith(KEYWORD_RULES) or rule.id == "generic-api-key") and (
                    (_UUID_RE.fullmatch(secret.strip("\"'` ")) and not _SECRET_LABEL_RE.search(
                        text, max(_line_start(text, start), start - 60), start))
                    or (_ELISION_RE.search(secret) and len(secret.rstrip(".\u2026")) < 20)
                    or _DERIVED_LABEL_RE.search(text, max(_line_start(text, start), start - 60), start)):
                continue   # a UUID, an elided value (sk-...), or a label that names a derived thing (secret_id)
            if rule.id in ("ds-basic-auth", "curl-auth-user") and _pass_equals_user(m.group(0), secret):
                continue
            if (rule.id == "aws-access-token" and _SIGV4_CREDENTIAL_RE.search(text, max(0, start - 24), start)
                    and _SIGV4_SCOPE_RE.match(text, end)):
                continue   # the key id in a SigV4 credential scope (a presigned URL, an Authorization header)
            if (rule.id == "label-cli-password" and text[start - 1:start] not in "'\""
                    and _PG_TOOL_RE.search(text, _command_start(text, start), start)):
                continue   # `psql --password app_db`: a switch that asks for the password, then the database
            if rule.id == "url-password-no-user" and _url_password_not_a_value(secret):
                continue
            if rule.id == "hashicorp-tf-password" and not _ds_value_ok(secret.strip("\"'")):
                continue
            if rule.id == "email-percent-encoded" and not _ENCODED_MAIL_CONTEXT_RE.search(
                    text, max(_line_start(text, start), start - 40), start):
                continue
            if rule.id == "phone" and not _phone_ok(text, start, secret):
                continue
            if rule.type == "IP" and _SECTION_BEFORE_RE.search(text, max(0, start - 24), start):
                continue   # a section number: RFC 6749 4.1.2.1, OIDC Core 3.1.2.1, section 7.1.2.3
            if overlaps(start, end):
                continue
            if rule.entropy and shannon_entropy(secret) < rule.entropy:
                continue
            if rule.drop is not None and rule.drop({"secret": secret, "match": m.group(0), "path": "",
                                                    "line": text[_line_start(text, start):_line_end(text, end)]}):
                continue                     # the betterleaks filter of the rule, or the global one
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
            labelled = rule.type == "SECRET" and rule.id.startswith(LABEL_RULES)
            if is_public_test_value(secret, rule.type) and not labelled:
                # a documented test card, key or number that a shape rule found. A published key that a label assigns
                # (PROD_PASSWORD=<the Stripe docs key>) is used as a credential and stays a hit: being public does not
                # make the same bytes no secret there (review of 0.6.12). The label rules run first, so no later rule
                # claims a span around a skipped key; a value of another type around a test card stays its own hit
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
                # a fixed-length shape (betterleaks: glpat-[\w-]{20}) stops inside a longer token and
                # the tail would stay in the clear (4 chars of a 24-char token, 2026-09-26): the
                # value runs to the end of the token characters
                end2 = end
                while end2 < len(text) and end2 - end < 128 and _TOKEN_CHAR_RE.match(text[end2]):
                    end2 += 1
                if end2 > end and _TOKEN_CHAR_RE.match(secret[-1]) and not overlaps(end, end2):
                    end = end2
                    secret = text[start:end]
                # a routable GitLab token ends in ".<version>.<id>" (glpat-...CA.01.0y0znlm9w): the token
                # characters stop at the dot, and the tail stayed in the clear (field report, 2026-10-06)
                tail = _ROUTABLE_TAIL_RE.match(text, end) if _GITLAB_PREFIX_RE.match(secret) else None
                if tail and not overlaps(end, tail.end()):
                    end = tail.end()
                    secret = text[start:end]
            found.append(Match(rule.id, rule.type, secret, start, end))
            i = bisect.bisect_left(taken_starts, start)
            taken_starts.insert(i, start)
            taken_ends.insert(i, end)
    if _CHANNEL[0] == "tool" and not _copy:
        _scan_cleaned_copy(text, enabled, found, taken_starts, taken_ends)
    found.sort(key=lambda x: x.start)
    return found


_WINDOW_BEFORE = 2048  # context a rule may read before a value: a label 200, a context word 80, an AWS key id up to
_WINDOW_AFTER = 512    # four lines of 400 before its secret (aws-secret-after-access-key); after it: a context word 40


def _changed_windows_scan(text: str, norm, enabled) -> list:
    """The hits of the cleaned copy, scanned only around its changed lines: each changed line with the whole lines
    that hold the _WINDOW_BEFORE characters before it and the _WINDOW_AFTER characters after it, windows that touch
    merged. A line the stages left alone holds the hits the raw scan already has, and a rescan of the whole text
    doubled the time of a 70 KB tool result with one coloured line or one JWT."""
    copy, starts, ends = norm.text, norm.starts, norm.ends
    windows: list = []
    a = 0
    n = len(copy)
    while a <= n:
        b = copy.find("\n", a)
        b = n if b < 0 else b
        # the original range of this line, from after the previous line break to this one: deleted characters at
        # its edges and a line that only deleted characters held count as a change (Gate A, round 2)
        oa = ends[a - 1] if a > 0 else 0
        ob = starts[b] if b < n else len(text)
        if ob - oa != b - a or text[oa:ob] != copy[a:b]:
            wa = copy.rfind("\n", 0, max(0, a - _WINDOW_BEFORE)) + 1 if a > _WINDOW_BEFORE else 0
            wb = copy.find("\n", min(n, b + _WINDOW_AFTER))
            wb = n if wb < 0 else wb
            if windows and wa <= windows[-1][1] + 1:
                windows[-1][1] = max(windows[-1][1], wb)
            else:
                windows.append([wa, wb])
        a = b + 1
    out = []
    for wa, wb in windows:
        for m in _scan(copy[wa:wb], enabled, _copy=True):
            out.append(Match(m.kind, m.type, m.value, m.start + wa, m.end + wa))
    return out


def _scan_cleaned_copy(text: str, enabled, found: list, taken_starts: list, taken_ends: list) -> None:
    """The tool channel also scans a copy of the text without terminal and encoding disguises (ANSI codes, zero-width
    characters, HTML entities, fullwidth letters, base64 and hex runs: maisecrets/normalise.py). A hit of the copy
    redacts its original range, hidden characters included. The raw text's own hits came first and keep their spans,
    except a part of a value that the copy sees whole: the whole replaces the part, or the rest reaches the model."""
    try:
        from .normalise import normalise
    except ImportError:   # a copy of detect.py without its sibling modules: the raw scan alone
        return
    norm = normalise(text)
    if norm.text is text:
        return
    by_start = {f.start: f for f in found}   # the taken spans never overlap, so a start names one
    copy_hits = _changed_windows_scan(text, norm, enabled)
    if enabled is None or EXPORT_RULE in enabled:
        # a header in colour or in entities: the table is read whole in the copy, not only around changed lines
        copy_hits = _export_hits(norm.text, _lower(norm.text)) + copy_hits
    for m in copy_hits:
        start, end = norm.span(m.start, m.end)
        lo = bisect.bisect_left(taken_starts, start)
        if lo > 0 and taken_ends[lo - 1] > start:
            lo -= 1
        inside = [by_start[a] for a in taken_starts[lo:bisect.bisect_left(taken_starts, end)]]
        if inside:
            if not all(start <= f.start and f.end <= end for f in inside) or \
                    all((f.start, f.end) == (start, end) for f in inside):
                continue
            for f in inside:
                found.remove(f)
                del by_start[f.start]
                i = bisect.bisect_left(taken_starts, f.start)
                del taken_starts[i], taken_ends[i]
        found.append(Match(m.kind, m.type, text[start:end], start, end))
        by_start[start] = found[-1]
        i = bisect.bisect_left(taken_starts, start)
        taken_starts.insert(i, start)
        taken_ends.insert(i, end)


def contains_secret(text: str) -> bool:
    return any(m.type in SECRET_TYPES for m in scan(text))
