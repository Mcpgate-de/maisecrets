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

# the bands of the rule list, in scan order. The order between them was measured, not chosen (2026-10-15, every
# CredData line with the sources moved): a label rule before a shape rule, detect-secrets before generic-api-key, the
# own SECRET rules before the vendored ones, the literal rules last.
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
# The passes of a scan outside the rule list, as sources of their own. Each runs where its phase says: the password
# export before every rule (a cell is a value as a whole), the personal-data rules (maisecrets/personal.py) and the
# cleaned copy of a tool result after every built-in rule and before the rules of your own, the extra matchers last.
# The cleaned copy has no rule of its own: it runs every rule again on a cleaned text.
PASSES = {"export": PHASES["export"], "personal": PHASES["personal"]}
# the channels a source runs in. Every rule of the rule list runs in both; the literal rules judge a value by the
# channel (detect._pw_literal_ok: a tool result takes a password without evidence of chance), which is a rule of
# their own, not a channel switch
CHANNEL = {source: "both" for source in BANDS}
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
    field: str           # regex | keywords | validator | context | context_rule | region | load
    op: str              # replace | add | set | wrap | skip
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
    matcher: str = "regex"   # matcher_of
    filters: frozenset = frozenset()   # filters_of
    language: str = ""   # the label languages of a label source ("en,de"), else ""
    upstream: Upstream | None = None
    patches: tuple = field(default=())


# The upstream state each correction of a vendored betterleaks rule (detect.BETTERLEAKS_PATCHES) was written
# against: canonical_sha256 of the rule in rules/betterleaks.json, kept in rules/patched_upstream.txt (a digest in
# the tree outside rules/ reads as a secret to the tree scan). After a sync that changes one of these rules,
# tests/test_registry.py goes red: check the correction against the new rule, then update the digest or drop it.
UPSTREAM_FILE = "patched_upstream.txt"


def patched_upstream(rules_dir) -> dict:
    """{"<source>:<id>": sha256} from rules/patched_upstream.txt."""
    out = {}
    for line in (rules_dir / UPSTREAM_FILE).read_text(encoding="utf-8").splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) == 2:
            out[fields[1]] = fields[0]
    return out


_BETTERLEAKS_REASONS = {
    "add_keywords": "the keyword list named only the provider; the token's own prefix is a keyword too (0.6.20)",
    "regex": "the key is waka_ and a UUID; the upstream regex took no hyphen (0.6.20)",
}
# What detect._load_detect_secrets changes in each vendored detect-secrets rule. The loader applies them; these records
# say what and why, for `maisecrets rules list`
DETECT_SECRETS_PATCHES = (
    Patch("detect-secrets:*", "regex", "replace", "denylist + the label words of the active languages",
          "the labels detect-secrets lacks (pass:, token:, passwort:) and the product's own name (mai-secrets)"),
    Patch("detect-secrets:*", "regex", "replace", "a value may start with ! # $ % & * + - @ ^ ~ ? .",
          "a value had to start with a word character, so $+4j... was never a value (2026-09-27)"),
    Patch("detect-secrets:*", "regex", "replace", "up to three spaces before the colon",
          "`mot de passe : x` and `password : x` (2026-09-28)"),
    Patch("detect-secrets:*", "regex", "replace", "an escaped quote around the label and before the value",
          "JSON inside a string, as a log line shows it (CredData, 2026-10-12)"),
    Patch("detect-secrets:*", "regex", "replace", "_KeywordTail: the same matches in linear time",
          "a long word run after a keyword was quadratic (0.6.15)"),
    Patch("detect-secrets:*", "validator", "set", "ds_value", "detect-secrets' own value check, ported"),
    Patch("detect-secrets:ds-basic-auth", "keywords", "set", "none", "a URL with user and password has no label"),
)


def betterleaks_patches(table: dict, upstream: dict) -> dict:
    """{rule id: (Patch, ...)} from detect.BETTERLEAKS_PATCHES; upstream is patched_upstream()."""
    out = {}
    for rule_id, patch in table.items():
        recs = []
        if patch.get("add_keywords"):
            recs.append(Patch("betterleaks:" + rule_id, "keywords", "add", " ".join(patch["add_keywords"]),
                              _BETTERLEAKS_REASONS["add_keywords"], upstream.get("betterleaks:" + rule_id, "")))
        if patch.get("regex"):
            recs.append(Patch("betterleaks:" + rule_id, "regex", "replace", patch["regex"],
                              _BETTERLEAKS_REASONS["regex"], upstream.get("betterleaks:" + rule_id, "")))
        out[rule_id] = tuple(recs)
    return out


def presidio_patches(detect) -> dict:
    """{recognizer id or pattern id: (Patch, ...)} from the six Presidio tables of detect.py, which the loader
    applies."""
    out: dict = {}

    def add(rid, *a):
        out.setdefault(rid, []).append(Patch("presidio:" + rid, *a))
    for rid in sorted(detect.PRESIDIO_SKIP):
        add(rid, "load", "skip", "", "an own rule covers it, or it is no personal data worth a placeholder")
    for rid, v in sorted(detect.PRESIDIO_VALIDATOR.items()):
        add(rid, "validator", "set", v, "a check digit Presidio does not run here")
    for rid in sorted(detect.PRESIDIO_ALWAYS_CONTEXT):
        add(rid, "context_rule", "set", "required", "a plain digit run: a check digit alone passes 1 in 10 to 26")
    for rid in sorted(detect.PRESIDIO_DIGIT_BOUNDED):
        add(rid, "regex", "wrap", "(?<!\\d)...(?!\\d)", "the pattern matched inside a longer digit run")
    for rid in sorted(detect.PRESIDIO_PATTERN_CONTEXT):
        add(rid, "context_rule", "set", "required", "the same digits are also FIX tags and XML identifiers")
    for rid, words in sorted(detect.PRESIDIO_EXTRA_CONTEXT.items()):
        add(rid, "context", "add", " ".join(words), "the vendored context words are English only")
    for rid, region in sorted(detect.REGION_OF_ID.items()):
        add(rid, "region", "set", region, "the id names no country")
    return {k: tuple(v) for k, v in out.items()}


def form_of(rule_id: str) -> str:
    """keyword, label or shape, by the id: the kind of a stored hit has no spec, so this stays readable from the id."""
    if rule_id.startswith(KEYWORD_PREFIXES):
        return "keyword"
    if rule_id.startswith(LABEL_PREFIXES):
        return "label"
    return "shape"


def is_label(kind: str) -> bool:
    """Whether a hit of this kind (a rule id, also one read from the vault index) came from a label rule."""
    return str(kind).startswith(LABEL_PREFIXES)


# The checks scan() runs on a hit of these rules, by name (detect._scan). Until the registry each was a test of the id.
FILTERS = {
    "private-key-base64": ("base64-wrapped-end",),             # the further lines of a wrapped value
    "ds-keyword-colon": ("escaped-label-quote",),               # JSON inside a string: the value must be escaped too
    "ds-keyword-colon-quotes-required": ("escaped-label-quote",),
    "generic-api-key": ("word-path", "derived-label"),
    "url-query-secret": ("template-value",),                    # ?token={...}
    "auth-scheme": ("words-not-token",),                        # Bearer and words joined by - or _
    "ds-basic-auth": ("user-equals-password",),
    "curl-auth-user": ("user-equals-password",),
    "aws-access-token": ("sigv4-scope",),                       # the key id of a SigV4 credential scope
    "label-cli-password": ("pg-password-switch",),              # psql --password <database>
    "url-password-no-user": ("url-password-value",),
    "hashicorp-tf-password": ("password-value",),               # detect-secrets' value check
    "email-percent-encoded": ("encoded-mail-context",),         # name%40host only where an address is expected
    "phone": ("phone-shape",),
    "crypto-seed-phrase": ("seed-phrase",),                     # no placeholder check; compared as single-spaced words
}
# the filters of every rule whose id starts so: a value that ends in a backslash before its quote
PREFIX_FILTERS = (("ds-keyword", ("escaped-value-quote",)),)


def filters_of(rule_id: str) -> frozenset:
    """The named checks of a rule: FILTERS, PREFIX_FILTERS, and `derived-label` for every keyword rule (a UUID, an
    elided value, or a label that names a derived thing such as secret_id is no value)."""
    out = set(FILTERS.get(rule_id, ()))
    for prefix, names in PREFIX_FILTERS:
        if rule_id.startswith(prefix):
            out.update(names)
    if form_of(rule_id) == "keyword":
        out.add("derived-label")
    return frozenset(out)


def matcher_of(rule_id: str, source: str = "") -> str:
    """How scan() runs a rule: `regex` (finditer), `lines` (the detect-secrets keyword rules, per line, a label at the
    end of a line with the next line), `windowed` (generic-api-key on a long text: windows around its keywords),
    `curl` (a curl command, split at its head), `list` (the values of a labelled list), `literal` (a password after a
    password label, judged by detect._judge_literal), `seed` (a BIP39 seed phrase by its checksum)."""
    if rule_id.startswith("curl-"):
        return "curl"
    if rule_id == "label-secret-list":
        return "list"
    if source == "literal":
        return "literal"
    if rule_id == "crypto-seed-phrase":
        return "seed"
    if rule_id == "generic-api-key":
        return "windowed"
    if rule_id.startswith("ds-keyword"):
        return "lines"
    return "regex"


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


def pass_specs(export_rule: str, export_type: str, personal_rules: tuple, prompt_rules: frozenset,
               personal_types: dict) -> list:
    """The specs of the passes outside the rule list: the password export (tool channel only) and the personal-data
    rules (tool channel; the ones in personal.PROMPT_RULES in both)."""
    out = [make("export", export_rule, export_type, 0, channel="tool")]
    for seq, rid in enumerate(personal_rules):
        out.append(make("personal", rid, personal_types.get(rid, "PERSON"), seq,
                        channel="both" if rid in prompt_rules else "tool"))
    return out


def coarse_class(spec: RuleSpec) -> str:
    """A class of a few dozen members: the source for a token rule, the class for label and PII rules."""
    if spec.rule_class.startswith("provider:"):
        return "token:" + spec.source
    if spec.rule_class.startswith("pii:"):
        return spec.rule_class + ("" if spec.region == "generic" else "@" + spec.region)
    return spec.rule_class


def key_of(source: str, rule_id: str) -> str:
    """The unique key of a rule: `<source>:<id>`; a rule of your own keeps its id, which has its own prefix `user:`."""
    return rule_id if source == "user" else source + ":" + rule_id


def make(source: str, rule_id: str, type_: str, seq: int, *, region: str = "generic", channel: str = "both",
         language: str = "", upstream: Upstream | None = None, patches: tuple = ()) -> RuleSpec:
    origin = "vendored" if source in VENDORED else OWN_SPECIAL.get(source, "own")
    if source in PASSES:
        origin = "own"
    if origin == "vendored" and patches:
        origin = "patched"
    phase = PHASES["user"] if source == "user" else PASSES.get(source, PHASES["rules"])
    return RuleSpec(key=key_of(source, rule_id), id=rule_id, source=source, origin=origin,
                    priority=(phase, BANDS.get(source, 0), seq), channel=channel, region=region, type=type_,
                    rule_class=rule_class(source, rule_id, type_), form=form_of(rule_id),
                    matcher=matcher_of(rule_id, source), filters=filters_of(rule_id), language=language,
                    upstream=upstream, patches=tuple(patches))
