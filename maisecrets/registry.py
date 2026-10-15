"""The rule registry: where each detection rule comes from, its rank, its channel, its region and its class, as data.

detect.rules() was a sum of loaders in a fixed order, and the first rule to claim a span wins: the order decided which
rule id a hit gets, and the id decides what scan() and the vault do with it (a label rule in test code is a fixture, a
label hit is stored quiet). A measurement of the order (2026-10-15) found ten such dependencies between the sources.
Here each rule gets a RuleSpec with an explicit rank, `priority = (phase, band, seq)`, and detect.rules() sorts by it.

- `phase` orders the passes of a scan: 0 the password export, 1 the rule list, 2 the personal-data step and the
  cleaned copy of a tool result, 3 the rules of your own, 4 the extra matchers.
- `band` is the source inside the rule list (BANDS), with gaps for a source to come.
- `seq` is the position in the source file.

The rule id (`Match.kind`) stays what it was: the vault index and the event log store it. Three ids are loaded twice
(mailchimp-api-key, new-relic-insert-key, flutterwave-secret-key), so each spec also gets a unique `key`
(`<source>:<id>`). Standard library only; Python 3.9.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

# the bands of the rule list, in scan order. The order between them is measured, not chosen (docs/BENCHMARKS.md,
# "Rule order"): a label rule before a shape rule, detect-secrets before generic-api-key, the literal rules last.
BANDS = {
    "own-secret": 100,       # OWN_RULES of type SECRET
    "prefixes": 150,         # rules/prefixes.txt
    "detect-secrets": 200,   # rules/detect_secrets.json, rewritten at load
    "betterleaks": 300,      # rules/betterleaks.json
    "own-json": 400,         # rules/own_secret_rules.json
    "fallback": 450,         # FALLBACK_RULES: forms of a key whose vendored rule fixes one length
    "regional": 500,         # REGIONAL_RULES
    "presidio": 600,         # rules/presidio.json
    "own-pii": 700,          # OWN_RULES of any other type
    "literal": 800,          # LITERAL_RULES
    "user": 900,             # the rules of your own (maisecrets/user_rules.py)
}
SOURCES = tuple(BANDS)
PHASES = {"export": 0, "rules": 1, "personal": 2, "user": 3, "extra": 4}
VENDORED = frozenset({"detect-secrets", "betterleaks", "presidio"})   # synced from upstream by scripts/sync_*.py
OWN_SPECIAL = {"fallback": "fallback", "user": "user"}

# a label rule finds a value by its label alone; a keyword rule is a label rule with no `=` or `:` of its own. Until
# the registry these were id prefixes (detect.LABEL_RULES, detect.KEYWORD_RULES), and a stored kind still is one
LABEL_PREFIXES = ("ds-keyword", "label-", "generic-api-key", "url-query-secret", "auth-scheme")
KEYWORD_PREFIXES = ("ds-keyword", "label-")


@dataclass(frozen=True)
class Upstream:
    source: str          # betterleaks | detect-secrets | presidio
    version: str         # rules/<SOURCE>_VERSION
    upstream_id: str     # the id of the rule upstream (a Presidio recognizer for each of its patterns)
    sha256: str          # of the upstream rule as canonical JSON: a re-sync that changes it shows in `rules list`
    license: str         # the licence file in rules/


@dataclass(frozen=True)
class Patch:
    rule_key: str        # the spec it changes; "detect-secrets:*" for every rule of that source
    field: str           # regex | keywords | validator | context | ...
    op: str              # replace | add | set
    value: str           # what the patch puts there, short
    reason: str          # why, in one line
    upstream_sha256: str = ""   # the upstream rule the patch was written against; "" when it applies to a source


@dataclass(frozen=True)
class RuleSpec:
    key: str             # unique: "<source>:<id>"
    id: str              # Match.kind as before; stored data in the vault index
    source: str          # one of SOURCES
    origin: str          # vendored | patched | own | fallback | user
    priority: tuple      # (phase, band, seq)
    channel: str         # prompt | tool | both
    region: str          # "generic" or a country code
    type: str            # the placeholder type: SECRET, EMAIL, IBAN, DE_ID_CARD, ...
    rule_class: str      # what it finds: "provider:github", "label:keyword", "pii:email", ...
    form: str            # keyword | label | shape
    language: str = ""   # the label languages of a label source ("en,de"), else ""
    upstream: Upstream | None = None
    patches: tuple = field(default=())


def form_of(rule_id: str) -> str:
    """keyword, label or shape, by the id: the kind of a stored hit has no spec, so this stays readable from the id."""
    if rule_id.startswith(KEYWORD_PREFIXES):
        return "keyword"
    if rule_id.startswith(LABEL_PREFIXES):
        return "label"
    return "shape"


def canonical_sha256(rule: dict) -> str:
    return hashlib.sha256(json.dumps(rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


def _provider(rule_id: str) -> str:
    head = rule_id.split("#", 1)[0].split(".", 1)[0]
    return head.split("-", 1)[0]


def rule_class(source: str, rule_id: str, type_: str) -> str:
    """The class a rule belongs to, for `maisecrets rules list` and scripts/measure_rule_classes.py."""
    form = form_of(rule_id)
    if source == "user":
        return "user"
    if source == "literal":
        return "label:literal"
    if form == "keyword":
        return "label:keyword"
    if form == "label":
        return "label:" + rule_id.split("#", 1)[0]
    if type_ != "SECRET":
        return "pii:" + type_.lower()
    if source == "fallback":
        return "provider:" + _provider(rule_id)
    return "provider:" + _provider(rule_id)


def coarse_class(spec: RuleSpec) -> str:
    """A class of a few dozen members: the source for a token rule, the class for label and PII rules."""
    if spec.rule_class.startswith("provider:"):
        return "token:" + spec.source
    if spec.rule_class.startswith("pii:"):
        return spec.rule_class + ("" if spec.region == "generic" else "@" + spec.region)
    return spec.rule_class


def make(source: str, rule_id: str, type_: str, seq: int, *, region: str = "generic", channel: str = "both",
         language: str = "", upstream: Upstream | None = None, patches: tuple = ()) -> RuleSpec:
    origin = "vendored" if source in VENDORED else OWN_SPECIAL.get(source, "own")
    if origin == "vendored" and patches:
        origin = "patched"
    phase = PHASES["user"] if source == "user" else PHASES["rules"]
    key = rule_id if source == "user" else f"{source}:{rule_id}"    # a user rule id has its own prefix, `user:`
    return RuleSpec(key=key, id=rule_id, source=source, origin=origin,
                    priority=(phase, BANDS[source], seq), channel=channel, region=region, type=type_,
                    rule_class=rule_class(source, rule_id, type_), form=form_of(rule_id), language=language,
                    upstream=upstream, patches=tuple(patches))
