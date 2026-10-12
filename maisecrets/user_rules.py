"""Rules of your own: detection rules from folders, and an allow list (README "Rules of your own", C25).

The sources, read once per process (detect.rules() keeps the result):

- `~/.maisecrets/rules.d`, the person's own folder. The agent cannot write there (C8).
- each folder of the setting `rule_dirs`; only a prompt the person typed adds or removes one (C22).
- each folder of `rule_dirs` in the machine policy; the person cannot remove those.

A folder holds `*.json` (the gitleaks form of rules/own_secret_rules.json) and `*.prefixes` (the line form of
rules/prefixes.txt, `id  regex`). Nothing else in it is read: no code, no word lists, no allow list. A folder is data
that a hook reads in every call, so each rule passes static checks at load; a rule that fails one is QUARANTINED: it is
left out, and /maisecrets:rules, the status and events.log name it with its reason. A broken rule file never stops a
hook. A broken machine policy still does (vault.load_config).

The allow list only loosens, so only the person (`~/.maisecrets/allow.txt`) and the administrator (`allow` in the
policy) write it: one exact value per line, or `rule: <id>` to switch a rule off. Never a pattern: a pattern in an allow
list lets through values nobody looked at. A folder of rule_dirs carries no allow list: an agent can write a shared
checkout, and an agent may only make detection stricter.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from . import detect
from .vault import HOME

try:   # the regex parser of the standard library: re._parser from 3.11, sre_parse before
    from re import _parser as _sre
except ImportError:   # pragma: no cover - Python 3.9 and 3.10
    import sre_parse as _sre

OWN_DIR = HOME / "rules.d"
ALLOW_FILE = HOME / "allow.txt"
STATE_FILE = HOME / ".rules-state"
ID_PREFIX = "user:"                  # every user rule id gets it: no user id can take the name of a built-in rule
MAX_RULES_PER_FOLDER = 500
MAX_FILE_BYTES = 64 * 1024
MAX_REGEX = 300
MIN_LITERAL = 4
TYPES = ("SECRET", "NAME", "EMAIL", "PHONE", "IBAN", "CARD", "IP")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT} | {getattr(_sre, "POSSESSIVE_REPEAT", _sre.MAX_REPEAT)}   # 3.11+


@dataclass(frozen=True)
class Quarantined:
    folder: str     # as configured, `~` kept
    file: str       # the file name in the folder; "" for the whole folder
    rule: str       # the rule id; "" for the whole file
    reason: str     # fixed text, never a regex or a value


@dataclass(frozen=True)
class Folder:
    shown: str      # as configured
    path: Path
    source: str     # own | setting | policy
    state: str = "ok"            # ok | missing | refused: <why>
    rules: int = 0
    digest: str = ""
    commit: str = ""


@dataclass
class Loaded:
    rules: list = field(default_factory=list)          # detect.Rule
    quarantined: list = field(default_factory=list)    # Quarantined
    folders: list = field(default_factory=list)        # Folder


# ------------------------------------------------------------------- checks --
def _children(op, av) -> list:
    if op in _REPEATS:
        return [av[2]]
    if op == _sre.SUBPATTERN:
        return [av[-1]]
    if op == _sre.BRANCH:
        return list(av[1])
    if op in (_sre.ASSERT, _sre.ASSERT_NOT):
        return [av[1]]
    if op == _sre.GROUPREF_EXISTS:
        return [x for x in av[1:] if x is not None]
    if op == getattr(_sre, "ATOMIC_GROUP", None):
        return [av]
    return []


def _nested(items, outer: int = 0) -> bool:
    """A repeat inside a repeat, with one of them unbounded: `(a+)+`, `(?:\\.[a-z]+)+`. That is the shape of
    catastrophic backtracking; `(?:-[a-z0-9]{4}){3}` and `(?:\\.[a-z]{1,63}){1,5}` stay bounded and pass."""
    for op, av in items:
        hi = av[1] if op in _REPEATS else 0
        if op in _REPEATS and hi > 1 and outer > 1 and _sre.MAXREPEAT in (hi, outer):
            return True
        inner = hi if hi > 1 else outer
        if any(_nested(child, inner) for child in _children(op, av)):
            return True
    return False


def _leading_repeat(items) -> bool:
    """The pattern starts with a quantifier of variable length (`.*`, `\\w+`, `[\\w.-]{0,50}`): the engine then tries
    it at every position of the text. generic-api-key started so and took 80 % of a scan (detect._WINDOWED)."""
    for op, av in items:
        if op in (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT):
            continue     # an anchor or a lookaround consumes nothing
        if op in _REPEATS:
            return av[1] > 1 and av[0] != av[1]
        if op == _sre.SUBPATTERN:
            return _leading_repeat(av[-1])
        if op == _sre.BRANCH:
            return any(_leading_repeat(b) for b in av[1])
        return False
    return False


def _literal(items) -> str:
    """The longest run of plain characters the pattern always needs (descending into plain groups)."""
    best, run = "", ""
    for op, av in items:
        if op == _sre.LITERAL:
            run += chr(av)
            continue
        best, run = max(best, run, key=len), ""
        if op == _sre.SUBPATTERN:
            best = max(best, _literal(av[-1]), key=len)
    return max(best, run, key=len)


def check_regex(rx: str, keywords: tuple = (), allowlist: bool = False):
    """(reason, compiled, prefilter keywords). A reason means the rule is refused; it names the check, never the
    regex. The prefilter: the rule's own keywords when each has MIN_LITERAL characters, else the longest literal of
    the regex. An allowlist regex needs no literal: it runs only on a hit."""
    if not isinstance(rx, str) or not rx:
        return "no regex", None, ()
    if len(rx) > MAX_REGEX:
        return f"a regex longer than {MAX_REGEX} characters", None, ()
    rx = detect._re2_to_python(rx)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            parsed = _sre.parse(rx)
            compiled = re.compile(rx)
    except (re.error, RecursionError, OverflowError, ValueError):
        return "a regex that does not compile", None, ()
    items = list(parsed)
    if _nested(items):
        return "a nested quantifier (a repeat inside a repeat)", None, ()
    if allowlist:
        return None, compiled, ()
    if _leading_repeat(items):
        return "a regex that starts with a quantifier", None, ()
    kws = tuple(k.lower() for k in keywords if isinstance(k, str))
    if kws and all(len(k) >= MIN_LITERAL for k in kws):
        return None, compiled, kws
    lit = _literal(items)
    if len(lit) >= MIN_LITERAL:
        return None, compiled, (lit.lower(),)
    return f"no keyword or literal of {MIN_LITERAL} characters", None, ()


def _lazy(compiled: re.Pattern) -> "detect._Lazy":
    lazy = detect._Lazy(compiled.pattern, compiled.flags)
    lazy._rx = compiled
    return lazy


def _json_rules(data, kept, refuse):
    """The rules of one *.json file in the gitleaks form; kept(id, rule) and refuse(id, reason)."""
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        refuse("", "not the rules form (an object with a rules list)")
        return
    for r in data["rules"]:
        rid = r.get("id") if isinstance(r, dict) else None
        if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
            refuse("?", "an id that is not 1 to 64 letters, digits, '.', '_' or '-'")
            continue
        type_ = r.get("type", "SECRET")
        if type_ not in TYPES:
            refuse(rid, "a type that is not one of " + ", ".join(TYPES))
            continue
        keywords = r.get("keywords") or ()
        if not isinstance(keywords, (list, tuple)):
            refuse(rid, "keywords that are not a list")
            continue
        why, compiled, prefilter = check_regex(r.get("regex"), tuple(keywords))
        if why:
            refuse(rid, why)
            continue
        allow: list = []
        stop: list = []
        for al in r.get("allowlists") if isinstance(r.get("allowlists"), list) else ():
            if why or not isinstance(al, dict):
                continue
            target = al.get("regexTarget", "secret")
            for arx in al.get("regexes") if isinstance(al.get("regexes"), list) else ():
                awhy, acompiled, _ = check_regex(arx, allowlist=True)
                if awhy:
                    why = "in an allowlist: " + awhy
                    break
                allow.append((_lazy(acompiled), target))
            stop += [s.lower() for s in (al.get("stopwords") if isinstance(al.get("stopwords"), list) else ())
                     if isinstance(s, str)]
        if why:
            refuse(rid, why)
            continue
        try:
            entropy = float(r.get("entropy", 0) or 0)
            group = int(r.get("secretGroup", 0) or 0)
        except (TypeError, ValueError):
            refuse(rid, "an entropy or secretGroup that is not a number")
            continue
        kept(rid, detect.Rule(id=ID_PREFIX + rid, type=type_, regex=_lazy(compiled), keywords=prefilter,
                              entropy=entropy, secret_group=group, allow_regexes=tuple(allow),
                              stopwords=tuple(stop)))


def _prefix_rules(text, kept, refuse):
    """The rules of one *.prefixes file: `id  regex` per line, `#` comments; the whole match is the secret."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        rid = parts[0]
        if not _ID_RE.fullmatch(rid):
            refuse("?", "an id that is not 1 to 64 letters, digits, '.', '_' or '-'")
            continue
        if len(parts) < 2:
            refuse(rid, "a line without a regex")
            continue
        why, compiled, prefilter = check_regex(parts[1].strip())
        if why:
            refuse(rid, why)
            continue
        kept(rid, detect.Rule(id=ID_PREFIX + rid, type="SECRET", regex=_lazy(compiled), keywords=prefilter))


def load_folder(path: Path, shown: str, taken: set | None = None) -> tuple[list, list, str]:
    """(rules, quarantined, digest) of one folder. `taken` holds the ids of earlier folders: a second rule with the
    same id is quarantined, so an id names one rule (the allow list switches rules off by id)."""
    taken = set() if taken is None else taken
    rules: list = []
    quarantined: list = []
    digest = hashlib.sha256()
    names = sorted(p.name for p in path.iterdir() if p.suffix in (".json", ".prefixes") and p.is_file())
    over = 0
    for name in names:
        f = path / name
        digest.update(name.encode("utf-8") + b"\0")

        def refuse(rid: str, reason: str, name: str = name) -> None:
            quarantined.append(Quarantined(shown, name, rid, reason))

        def kept(rid: str, rule) -> None:
            nonlocal over
            if rid in taken:
                refuse(rid, "an id that an earlier rule has")
            elif len(rules) >= MAX_RULES_PER_FOLDER:
                over += 1
            else:
                taken.add(rid)
                rules.append(rule)
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                refuse("", f"a file larger than {MAX_FILE_BYTES // 1024} KB")
                continue
            raw = f.read_bytes()
            digest.update(raw)
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            refuse("", "a file that cannot be read as UTF-8")
            continue
        if name.endswith(".json"):
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                refuse("", "not valid JSON")
                continue
            _json_rules(data, kept, refuse)
        else:
            _prefix_rules(text, kept, refuse)
    if over:
        quarantined.append(Quarantined(shown, "", "", f"{over} rule(s) past the limit of {MAX_RULES_PER_FOLDER} "
                                                      "per folder"))
    return rules, quarantined, digest.hexdigest()[:12]


# ------------------------------------------------------------------ folders --
def expand(shown: str) -> Path:
    return Path(os.path.expanduser(shown.strip()))


def refused_folder(path: Path) -> str:
    """Why a folder is not read, or "". The maisecrets home holds config.json and index.json, which are *.json too;
    rules.d is read as the person's own folder anyway."""
    if not path.is_absolute():
        return "refused: not an absolute path"
    try:
        real, home = path.resolve(), HOME.resolve()
    except (OSError, RuntimeError):
        return "refused: the path cannot be resolved"
    if real == home or home in real.parents:
        return "refused: inside the maisecrets folder"
    return ""


def folders(cfg: dict) -> list[tuple[str, Path, str]]:
    """(shown, path, source) of every folder, policy first: on a duplicate id the administrator's rule stays."""
    out = [(d, expand(d), "policy") for d in cfg.get("policy_rule_dirs") or [] if isinstance(d, str) and d.strip()]
    out.append(("~/.maisecrets/rules.d" if HOME == Path.home() / ".maisecrets" else str(OWN_DIR), OWN_DIR, "own"))
    out += [(d, expand(d), "setting") for d in cfg.get("rule_dirs") or [] if isinstance(d, str) and d.strip()]
    seen: set = set()
    unique = []
    for shown, path, source in out:
        key = os.path.normcase(os.path.abspath(path)) if path.is_absolute() else shown
        if key not in seen:
            seen.add(key)
            unique.append((shown, path, source))
    return unique


def _commit(path: Path) -> str:
    """The checked-out commit of a git folder (the folder or its parent), when a plain file says it; else ""."""
    for top in (path, path.parent):
        head = top / ".git" / "HEAD"
        try:
            text = head.read_text(encoding="utf-8").strip()
            if text.startswith("ref: "):
                text = (top / ".git" / text[5:]).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        return text[:12] if re.fullmatch(r"[0-9a-f]{40,64}", text) else ""
    return ""


def _config() -> dict:
    from .vault import load_config
    try:
        return load_config()
    except Exception:  # noqa: BLE001 - a broken policy fails closed in the hook itself; here it means no folder
        return {}


_LOADED: list = []


def load(cfg: dict | None = None) -> Loaded:
    """Every folder, read once per process. Never raises: a folder that fails is named, not fatal."""
    if cfg is None and _LOADED:
        return _LOADED[0]
    cache = cfg is None
    cfg = _config() if cfg is None else cfg
    out = Loaded()
    taken: set = set()
    for shown, path, source in folders(cfg):
        why = refused_folder(path) if source != "own" else ""
        if why:
            out.folders.append(Folder(shown, path, source, why))
            continue
        if not path.is_dir():
            out.folders.append(Folder(shown, path, source, "missing"))
            continue
        try:
            rules, quarantined, digest = load_folder(path, shown, taken)
        except OSError:
            out.folders.append(Folder(shown, path, source, "refused: the folder cannot be read"))
            continue
        out.rules += rules
        out.quarantined += quarantined
        out.folders.append(Folder(shown, path, source, "ok", len(rules), digest, _commit(path)))
    if cache:
        _LOADED[:] = [out]
    return out


# --------------------------------------------------------------- allow list --
def _allow_lines(lines) -> tuple[frozenset, frozenset]:
    values, ids = set(), set()
    for line in lines:
        line = line.rstrip("\r\n").strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("rule:"):
            rid = line[5:].strip()
            if rid:
                ids.add(rid)
        else:
            values.add(line)
    return frozenset(values), frozenset(ids)


def allow_list(cfg: dict | None = None) -> tuple[frozenset, frozenset]:
    """(exact values, rule ids) from ~/.maisecrets/allow.txt and the policy's `allow`. A file that cannot be read
    allows nothing: the stricter side."""
    try:
        own = ALLOW_FILE.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        own = []
    cfg = _config() if cfg is None else cfg
    policy = [x for x in cfg.get("policy_allow") or [] if isinstance(x, str)]
    return _allow_lines(own + policy)


def switched_off(rule_id: str, ids: frozenset) -> bool:
    """A rule id on the allow list, also with the `#n` of one of several patterns of a Presidio rule."""
    return rule_id in ids or rule_id.split("#", 1)[0] in ids


def reset() -> None:
    """Forget what this process read (tests, and `rules check` of another folder)."""
    _LOADED.clear()


# ------------------------------------------------------------ session start --
def session_note() -> str | None:
    """At session start: when the set of quarantined rules changed since the last start, one events.log line and
    one sentence for the person. Unchanged, it says nothing again."""
    loaded = load()
    names = sorted(f"{q.folder}/{q.file}:{q.rule}:{q.reason}" for q in loaded.quarantined)
    digest = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:16]
    try:
        before = STATE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        before = ""
    if digest == before:
        return None
    try:
        from .vault import atomic_write
        atomic_write(STATE_FILE, digest + "\n")
    except OSError:
        return None    # a state that cannot be written would repeat the sentence at every start
    if not loaded.quarantined:
        return None
    from types import SimpleNamespace
    from . import events
    events.record("SessionStart", "-", [SimpleNamespace(key="", type="RULE", kind=ID_PREFIX + (q.rule or "?"))
                                        for q in loaded.quarantined[:20]],
                  outcome="quarantined: " + "; ".join(sorted({q.reason for q in loaded.quarantined}))[:300])
    return (f"{len(loaded.quarantined)} rule(s) of your own were left out because they fail a check; "
            "/maisecrets:rules says which and why.")
