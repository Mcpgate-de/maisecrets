"""Values from your own tools: imports of found values, masked wherever they appear (README "Values from your own
tools", C26, #19 part 3).

A tool the person runs (a NER, an export, a script) writes JSON lines:

    {"value": "Jan Kowalski", "type": "NAME"}
    {"value": "jan.kowalski@example.org", "type": "EMAIL"}
    {"value": "A value without a shape"}            # type SECRET when it is missing

`maisecrets values import FILE`, or a file of the setting `value_files` at session start, adds them to an import:
`~/.maisecrets/imports/<id>.jsonl`, written by maisecrets alone (value_files.py). The registry pass `imports`
(registry phase 5, after the terms) finds every imported value as a phrase of whole words, in any case, NFC and
without format characters, with the matcher of the terms (terms.Matcher): one index of every import, never a regex
per value. A hit is a detect.Match of kind `import:<import id>:<value id>`, so it names its import.

Mask only, as the terms: the store keeps `maisecrets-import:<ids>`, never the value, and the placeholder is never
put back into a command or a file. An imported value that a rule finds, or that the store holds already, keeps
that rule's or that entry's placeholder (detect._import_hits, hooks._longest_wins): an import only adds masking
where nothing else masks, and never changes how another value is masked or resolved.

The trust rule: the agent can only make detection stricter. An import only adds. Nothing in a line can loosen
anything: only `value` and `type` are read, and a type only names the placeholder. A new import of the same file
merges into its import and never drops a value; only the person removes an import, by a typed prompt
(/maisecrets:forget import:ID, hooks.user_prompt). What an agent can still do is mask too much, and these hold it:

- a floor per value (_reason): at least MIN_LEN characters, a number at least MIN_DIGITS digits, no ordinary word
  (one word of lower-case letters, or only words of the stop list of the team terms), no text of maisecrets itself.
- caps: MAX_PER_IMPORT values in one import, MAX_VALUES in all, of which the imports that no value file names hold
  at most MAX_RUN_VALUES, so the person's value files always have room; MAX_IMPORTS imports.
- each new import is named at the next session start, by id and count, and /maisecrets:list shows every import.
"""
from __future__ import annotations

import errno
import hashlib
import json
import marshal
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import terms, value_files
from .vault import HOME, ConfigError

TYPES = terms.TYPES
IMPORTS = value_files.IMPORTS
SUFFIX = value_files.SUFFIX
CACHE_FILE = value_files.CACHE_FILE
STATE_FILE = value_files.STATE_FILE

MAX_FILE_BYTES = 8 << 20       # about 150,000 lines of a name and a type
MAX_PER_IMPORT = 100_000
MAX_VALUES = 150_000           # as terms.MAX_TEAM_ENTITIES: the index stays within one build of about 2 s
MAX_RUN_VALUES = 100_000       # of MAX_VALUES: the imports that no value file names
MAX_IMPORTS = 50
MAX_FILES_PER_START = 20       # value files one session start reads
MIN_LEN = 4
MIN_DIGITS = 6                 # a value of digits only: 2024 or 10115 would mask years and postcodes everywhere
MAX_LEN = 200
MAX_WORDS = terms.MAX_WORDS
_FORMAT = 1
_CONTROL_TEXT = ("⟦", "⟧", "maisecrets", "import:")
_LOWER_WORD = re.compile(r"[a-zß-ÿ]+")
_WORD_RE = re.compile(r"\w+")


class ValuesError(ConfigError):
    """A ConfigError: every hook fails closed on it. The message names the import, never a value."""


@dataclass
class Result:
    id: str = ""
    new: dict = field(default_factory=dict)          # type -> values added now
    known: int = 0                                    # values this import or another one held already
    duplicates: int = 0                               # the same value twice in the file
    refused: list = field(default_factory=list)       # (line number, reason), never the text
    stopped: str = ""                                 # why the import stopped before the end, or ""
    merged: bool = False                              # the file had an import already

    @property
    def added(self) -> int:
        return sum(self.new.values())


# ----------------------------------------------------------------- parsing --
def _norm(value: str) -> str:
    """A value as the index holds it: NFC, without format characters, white space runs as one space."""
    return " ".join(terms._norm(value).split())


def _reason(value: str) -> str:
    """Why a value is refused, or "". Fixed text, never the value."""
    if len(value) < MIN_LEN:
        return f"too short (at least {MIN_LEN} characters)"
    if len(value) > MAX_LEN:
        return f"too long (at most {MAX_LEN} characters)"
    if any(ord(c) < 32 for c in value):
        return "holds a control character or a line break"
    words = _WORD_RE.findall(terms._lower(value))
    if not words:
        return "holds no letter or digit"
    if len(words) > MAX_WORDS:
        return f"more than {MAX_WORDS} words"
    folded = value.casefold()
    if any(t in folded for t in _CONTROL_TEXT):
        # a value with one of them would mask the person's own controls (/maisecrets:forget import:ID) and the
        # placeholders (review of block 3, Opus H1)
        return "holds text of maisecrets itself (a placeholder bracket, maisecrets or import:)"
    if _LOWER_WORD.fullmatch(value):
        return "an ordinary word (one word of lower-case letters)"
    stop = terms.stoplist()
    if all(w in stop for w in words):
        return "only common words (the stop list of the team terms)"
    digits = sum(c.isdigit() for c in value)
    if not any(c.isalpha() for c in value) and digits < MIN_DIGITS:
        return f"a number of fewer than {MIN_DIGITS} digits"
    return ""


def parse(text: str) -> tuple[list, list, int]:
    """(values as (value, type, line), refused lines as (line, reason), duplicates). Blank lines and lines that start
    with `#` are skipped. Only `value` and `type` are read; any other field is ignored, so no field can loosen."""
    items: list = []
    refused: list = []
    seen: set = set()
    duplicates = 0
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            refused.append((n, "not JSON (a line that a writer has not finished is one too)"))
            continue
        if not isinstance(obj, dict):
            refused.append((n, "not a JSON object"))
            continue
        value = obj.get("value")
        if not isinstance(value, str) or not value.strip():
            refused.append((n, "no \"value\" text"))
            continue
        type_ = obj.get("type", "SECRET")
        if not isinstance(type_, str) or type_.upper() not in TYPES:
            refused.append((n, f"unknown type (one of {', '.join(TYPES)})"))
            continue
        value = _norm(value)
        why = _reason(value)
        if why:
            refused.append((n, why))
            continue
        low = terms._lower(value)
        if low in seen:
            duplicates += 1
            continue
        seen.add(low)
        items.append((value, type_.upper(), n))
    return items, refused, duplicates


# ------------------------------------------------------------------ sources --
def read_source(path: Path) -> bytes:
    """The bytes of a file to import, or ValueError with a reason for the person (never the file name).

    One open without following a link at the end of the path and without blocking, then every check on the open
    descriptor: a regular file (a FIFO, a device or a folder is refused), owned by the person or root, not writable by
    every user; then one read with a byte bound. So a file swapped after a check (TOCTOU), a FIFO that would hold the
    session start, and a file that grows while it is read all fail or stop at the bound."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("a symbolic link (name the file it points to)") from None
        raise ValueError(f"cannot be read ({type(exc).__name__})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        if os.name != "nt":
            if st.st_uid not in (0, os.getuid()):
                raise ValueError("owned by another user")
            if st.st_mode & stat.S_IWOTH:
                raise ValueError("every user can write it")
        chunks, size = [], 0
        while size <= MAX_FILE_BYTES:
            chunk = os.read(fd, min(1 << 20, MAX_FILE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise ValueError(f"cannot be read ({type(exc).__name__})") from None
    finally:
        os.close(fd)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"larger than {MAX_FILE_BYTES >> 20} MB; split it")
    return b"".join(chunks)


def _path_key(path: Path) -> str:
    """The same file gives the same key, so a new import of it merges. A hash: the state names no file."""
    try:
        real = os.path.realpath(str(path))
    except (OSError, ValueError):
        real = str(path)
    return hashlib.sha256(os.path.normcase(real).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _lock():
    """One lock for every write of the imports and the state: two imports at once lost one (review of block 3)."""
    from .vault import _lock_for
    return _lock_for(HOME / ".values.lock")


def _import_files() -> list:
    """(id, path) of every import, sorted by id. A folder that cannot be read raises ValuesError."""
    try:
        with os.scandir(IMPORTS) as entries:
            names = sorted(e.name for e in entries if e.name.endswith(SUFFIX))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ValuesError(f"{IMPORTS}: cannot be read ({type(exc).__name__})") from None
    return [(n[:-len(SUFFIX)], IMPORTS / n) for n in names if value_files.ID_RE.fullmatch(n[:-len(SUFFIX)])]


def _read_import(iid: str, path: Path) -> tuple[dict, list]:
    """(header, [(value, type)]) of one import. A damaged file raises ValuesError: the hooks fail closed, since the
    alternative is a silent leak of exactly the values the import lists."""
    try:
        raw = terms._read_bounded(path, MAX_FILE_BYTES * 2)
        if raw is None:
            raise ValueError
        lines = raw.decode("utf-8").splitlines()
        head = json.loads(lines[0])
        if not isinstance(head, dict) or head.get("import") != iid:
            raise ValueError
        items = []
        for line in lines[1:]:
            obj = json.loads(line)
            v, t = obj["v"], obj["t"]
            if not isinstance(v, str) or t not in TYPES:
                raise ValueError
            items.append((v, t))
    except (OSError, ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError):
        raise ValuesError(f"import:{iid} is damaged, so its values cannot be masked. Your prompt /maisecrets:forget "
                          f"import:{iid} removes it.") from None
    return head, items


def _write_import(iid: str, head: dict, items: list) -> None:
    from .vault import atomic_write
    IMPORTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = [json.dumps(head, sort_keys=True)] + [json.dumps({"v": v, "t": t}, ensure_ascii=False) for v, t in items]
    atomic_write(IMPORTS / f"{iid}{SUFFIX}", "\n".join(body) + "\n")


def _load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    from .vault import atomic_write
    try:
        atomic_write(STATE_FILE, json.dumps(state, sort_keys=True))
    except OSError:
        pass


# ------------------------------------------------------------------- import --
def import_bytes(raw: bytes, key: str, origin: str = "run") -> Result:
    """Add the values of one file to its import (the import of `key`, or a new one). Raises ValueError with a
    message for the person when the file itself cannot be used. Never removes a value."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("not UTF-8 text") from None
    items, refused, duplicates = parse(text)
    result = Result(refused=refused, duplicates=duplicates)
    with _lock():
        every = [(iid, path) + _read_import(iid, path) for iid, path in _import_files()]
        mine = next((x for x in every if x[2].get("key") == key), None)
        if mine is None and len(every) >= MAX_IMPORTS:
            raise ValueError(f"maisecrets holds {MAX_IMPORTS} imports, the limit; /maisecrets:list names them, and "
                             "your prompt /maisecrets:forget import:ID removes one")
        held = {terms._lower(v) for x in every for v, _t in x[3]}
        total = sum(len(x[3]) for x in every)
        runs = sum(len(x[3]) for x in every if x[2].get("origin") != "file")
        if mine is None:
            iid = "v" + secrets.token_hex(4)
            while any(x[0] == iid for x in every):
                iid = "v" + secrets.token_hex(4)
            head = {"import": iid, "key": key, "origin": origin, "at": time.time()}
            values: list = []
        else:
            iid, head, values = mine[0], dict(mine[2]), list(mine[3])
            result.merged = True
            if origin == "file":
                head["origin"] = "file"     # a value file that the person set names it from now on
        result.id = iid
        file_origin = head.get("origin") == "file"
        for value, type_, n in items:
            if terms._lower(value) in held:
                result.known += 1
                continue
            if len(values) >= MAX_PER_IMPORT:
                why = f"at most {MAX_PER_IMPORT:,} values in one import"
            elif total >= MAX_VALUES:
                why = f"maisecrets holds {MAX_VALUES:,} imported values, the limit"
            elif not file_origin and runs >= MAX_RUN_VALUES:
                why = (f"the imports that no value file names hold {MAX_RUN_VALUES:,} values, their limit (the rest "
                       "is kept for your value files)")
            else:
                why = ""
            if why:
                result.stopped = (f"line {n} and later not imported: {why}; /maisecrets:list names the imports, and "
                                  "your prompt /maisecrets:forget import:ID removes one")
                break
            values.append((value, type_))
            held.add(terms._lower(value))
            result.new[type_] = result.new.get(type_, 0) + 1
            total += 1
            runs += not file_origin
        if result.added or mine is None:
            if not values:
                result.id = ""        # nothing to keep: no empty import
                return result
            head["at"] = time.time()
            _write_import(iid, head, values)
    reset()
    if result.added:
        prebuild()
        _log(result, origin)
    return result


def import_file(path, origin: str = "run") -> Result:
    path = Path(os.path.expanduser(str(path)))
    return import_bytes(read_source(path), _path_key(path), origin)


def _log(result: Result, origin: str) -> None:
    """One events.log line per import: its id, origin and counts per type, no value (review of block 3, Fable M2:
    an agent's import masked text and left no trace)."""
    from types import SimpleNamespace
    from . import events
    events.record("ValueImport", origin, [SimpleNamespace(key="import:" + result.id, type=t, kind=f"import:{n}")
                                          for t, n in sorted(result.new.items())],
                  outcome=f"added {result.added}, known {result.known}, refused {len(result.refused)}")


def type_text(counts: dict) -> str:
    return ", ".join(f"{t} {counts[t]}" for t in TYPES if counts.get(t))


def summary(result: Result) -> str:
    """The line a person reads: counts, refused line numbers with reasons. No value, no file name."""
    if not result.id:
        head = "imported nothing"
    else:
        head = (f"import:{result.id}: {'added' if result.merged else 'imported'} {result.added} value(s)"
                + (f" ({type_text(result.new)})" if result.added else ""))
    parts = [head]
    if result.known:
        parts.append(f"{result.known} held already")
    if result.duplicates:
        parts.append(f"{result.duplicates} duplicate line(s) skipped")
    if result.refused:
        shown = "; ".join(f"line {n} {why}" for n, why in result.refused[:5])
        more = f"; and {len(result.refused) - 5} more" if len(result.refused) > 5 else ""
        parts.append(f"{len(result.refused)} line(s) refused: {shown}{more}")
    if result.stopped:
        parts.append(result.stopped)
    return ", ".join(parts) + "."


def rows() -> list:
    """Every import: id, count, counts per type, when, origin. Never a value."""
    out = []
    for iid, path in _import_files():
        try:
            head, items = _read_import(iid, path)
        except ValuesError:
            out.append({"id": iid, "count": 0, "types": {}, "at": 0.0, "origin": "damaged"})
            continue
        counts: dict = {}
        for _v, t in items:
            counts[t] = counts.get(t, 0) + 1
        at = head.get("at")
        out.append({"id": iid, "count": len(items), "types": counts,
                    "at": float(at) if isinstance(at, (int, float)) else 0.0, "origin": head.get("origin", "run")})
    return out


def remove_typed(ids: list) -> str:
    """Remove imports. Only the prompt hook calls this, for a prompt the person typed (hooks.user_prompt): the one way
    an import is removed. A value file's next import then reads the file as it is."""
    said = []
    with _lock():
        state = _load_state()
        for iid in ids:
            if not value_files.ID_RE.fullmatch(iid):
                said.append(f"import:{iid[:20]} is no import id (/maisecrets:list shows them)")
                continue
            path = IMPORTS / f"{iid}{SUFFIX}"
            try:
                head = json.loads(terms._read_bounded(path, MAX_FILE_BYTES * 2).decode("utf-8").split("\n", 1)[0])
            except (OSError, ValueError, AttributeError, UnicodeDecodeError):
                head = {}
            try:
                path.unlink()
            except FileNotFoundError:
                said.append(f"import:{iid} not found (/maisecrets:list shows the imports)")
                continue
            except OSError as exc:
                said.append(f"import:{iid} could not be removed ({type(exc).__name__}); nothing was changed")
                continue
            files = state.get("files")
            if isinstance(files, dict) and isinstance(head, dict):
                for k in [k for k, rec in files.items() if isinstance(rec, dict) and rec.get("key") == head.get("key")]:
                    files.pop(k, None)
            said.append(f"import:{iid} removed; its values are no longer masked")
            from . import events
            events.record_weakening("value-import", "import:" + iid, "typed prompt")
        _save_state(state)
    reset()
    prebuild()
    return "maisecrets: " + "; ".join(said) + "."


# ---------------------------------------------------------------- matcher --
_CACHE: list = []    # [Matcher] or [ValuesError]


def _stat_key(files: list) -> str:
    """The key of the index: the format, the Python version and each import file's id, size, time and inode. Only
    maisecrets writes these files, each with an atomic rename, so a change gives a new key."""
    h = hashlib.sha256(f"{_FORMAT} {sys.version_info[0]}.{sys.version_info[1]}".encode())
    for iid, path in files:
        try:
            st = os.stat(path)
        except OSError as exc:
            raise ValuesError(f"import:{iid} cannot be read ({type(exc).__name__})") from None
        h.update(f"{iid}\0{st.st_size}\0{st.st_mtime_ns}\0{st.st_ino}\n".encode())
    return h.hexdigest()


def _entities(files: list) -> list:
    out = []
    seen: set = set()
    for iid, path in files:
        _head, items = _read_import(iid, path)
        for n, (value, type_) in enumerate(items, 2):
            low = terms._lower(value)
            if low in seen:
                continue          # the first import keeps a value two imports list
            seen.add(low)
            out.append(terms.Entity(type_, (terms.Variant(value, terms.WORD),), n, "import:" + iid))
    return out


def _cached(key: str):
    try:
        fmt, k, data = marshal.loads(CACHE_FILE.read_bytes())
        if fmt == _FORMAT and k == key and isinstance(data, tuple) and len(data) == 8:
            return terms.Matcher(data=data)
    except (OSError, ValueError, EOFError, TypeError):
        pass
    return None


def _store(key: str, m) -> None:
    tmp = CACHE_FILE.with_name(CACHE_FILE.name + f".{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(marshal.dumps((_FORMAT, key, m.data())))
        os.replace(tmp, CACHE_FILE)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _build():
    files = _import_files()
    if not files:
        return terms.Matcher()
    key = _stat_key(files)
    m = _cached(key)
    if m is None:
        m = terms.Matcher(_entities(files))
        _store(key, m)
    return m


def matcher():
    """The matcher of every import, built once per process. A damaged import raises at every call."""
    if not _CACHE:
        try:
            _CACHE.append(_build())
        except ValuesError as exc:
            _CACHE.append(exc)
    if isinstance(_CACHE[0], ValuesError):
        raise _CACHE[0]
    return _CACHE[0]


def reset() -> None:
    _CACHE.clear()
    value_files.forget()


def prebuild() -> None:
    """Build the index now and cache it (after an import, at session start), so a tool hook only loads it."""
    reset()
    try:
        matcher()
    except ValuesError:
        pass


def matches(text: str) -> list:
    """The hits of the imports pass (detect._import_hits, registry phase "imports"): one Match per run, of kind
    `import:<import id>:<value id>`."""
    from .detect import Match
    return [Match(f"{ent.source}:{ent.id}", ent.type, text[s:e], s, e) for s, e, ent in matcher().find(text)]


# ------------------------------------------------------------ session start --
def _sync(cfg: dict, state: dict, deadline: float) -> list:
    """Import each file of `value_files` whose content changed since its last import. Notes for the person; a file
    is named by its place in the setting, never by its name."""
    files = [f for f in cfg.get("value_files") or [] if isinstance(f, str) and f.strip()]
    notes = []
    known = state.setdefault("files", {})
    for number, shown in enumerate(files[:MAX_FILES_PER_START], 1):
        label = f"value file {number}"
        if time.time() > deadline:
            notes.append(f"{label} and later follow at the next session start")
            break
        path = Path(os.path.expanduser(shown.strip()))
        slot = _path_key(path)
        try:
            raw = read_source(path)
        except ValueError as exc:
            said = f"{label}: {exc}"
            if (known.get(slot) or {}).get("said") != said:
                notes.append(said)
                known[slot] = {"said": said}
            continue
        digest = hashlib.sha256(raw).hexdigest()[:16]
        if (known.get(slot) or {}).get("digest") == digest:
            continue
        try:
            result = import_bytes(raw, slot, "file")
        except ValueError as exc:
            notes.append(f"{label}: {exc}")
            continue
        known[slot] = {"digest": digest, "key": slot}
        if result.added or result.refused or result.stopped:
            notes.append(f"{label}: " + summary(result).rstrip("."))
    if len(files) > MAX_FILES_PER_START:
        notes.append(f"only the first {MAX_FILES_PER_START} value files are read")
    return notes


def session_note(cfg: dict, started: float | None = None) -> str | None:
    """At session start: import the value files that changed, then name each import that is new since the last
    start (an import an agent ran is seen), and an import that is damaged. Unchanged, it says nothing."""
    deadline = (started if started is not None else time.time()) + 8.0
    with _lock():
        state = _load_state()
    notes = _sync(cfg, state, deadline)
    every = rows()
    ids = sorted(r["id"] for r in every)
    before = state.get("announced")
    new = [r for r in every if r["id"] not in set(before or [])]
    parts = []
    if notes:
        parts.append("value files: " + "; ".join(notes) + ".")
    if before is None or set(before) != set(ids):
        if new:
            shown = ", ".join(f"import:{r['id']} ({r['count']} value(s))" for r in new[:5])
            more = f" and {len(new) - 5} more" if len(new) > 5 else ""
            parts.append(f"from now on maisecrets masks the values of {shown}{more}. /maisecrets:list shows each "
                         "import; your prompt /maisecrets:forget import:ID removes one.")
    damaged = [r["id"] for r in every if r["origin"] == "damaged"]
    if damaged:
        parts.append(f"import:{damaged[0]} is damaged, so maisecrets withholds every tool result until your prompt "
                     f"/maisecrets:forget import:{damaged[0]} removes it.")
    with _lock():
        fresh = _load_state()
        fresh["files"] = state.get("files", {})
        fresh["announced"] = ids
        _save_state(fresh)
    prebuild()
    return ("maisecrets: " + " ".join(parts)) if parts else None


def summary_line() -> str:
    """One line for /maisecrets:status and /maisecrets:rules: imports and values, no value."""
    try:
        every = rows()
    except ValuesError as exc:
        return f"imported values: unusable ({exc})"
    return f"imported values: {sum(r['count'] for r in every)} in {len(every)} import(s)"
