"""Values from your own tools: `values import FILE` through the plugin's launcher (`command()`) and the setting
`value_files` (README "Values from your own tools", C26).

A tool the person runs (an export of the team's names, a password manager's list, a script) writes JSON lines:

    {"value": "Jan Example", "type": "NAME"}
    {"value": "A value without a shape"}            # type SECRET when it is missing

Each value goes into the vault with its type, so the exact match of the hooks (C2) masks it in every tool result and
every prompt from then on; a value of 2 to 6 words is found as a phrase. Nothing is printed but counts and line
numbers: a refused line is named by its number and the reason, never by its text.

An import only adds. It never deletes a value and never changes a stored one (an import the agent runs never changes a
lifetime), so the agent may run it: it can only make detection stricter. What could still hurt is volume and shape, and
the caps hold that:

- only a regular file, checked on the open descriptor before a byte is read, of at most MAX_FILE_BYTES, and at most
  MAX_VALUES_PER_FILE values per import; at most MAX_IMPORTED imported values in the vault at once, of which an import
  that no value file names fills at most RUN_SHARE of them. Past a cap the import stops and says so; the vault
  evicts nothing to make room. The index grows by about 450 bytes per value, and each hook reads it: with 6000
  imported names, Vault() and the exact match of a 40-line text took 15 to 35 ms (fastest of 20 calls in one
  process, Python 3.9 and 3.14, 2026-10-13; up to 90 ms at a load average of 35).
- a value of 8 to MAX_VALUE_LEN characters on one line: shorter values are not hunted in other texts anyway (the
  8-character floor of hooks._EXACT_MIN_LEN). Refused as ordinary text, which an agent could import to mask what the
  person writes: a single word of lower-case letters, and a SECRET without an upper-case letter, a digit or a symbol.
  Refused as text of maisecrets itself: a placeholder bracket, "maisecrets", "import:" (the person's controls).
- the import writes BATCH values per hold of the vault lock: a hook in another session waits for one batch, never for
  the whole file (a keychain write takes tens of milliseconds, and a hook waits at most 6 s for the lock).
- each import writes one events.log line, and the next session start names an import that is new (imports_note).

Imported values live max_ttl_seconds (30 days unless the person set less): an import is the person's list, not a value
from one tool result. An import of a file of `value_files` that lists a stored imported value again renews it to
max_ttl_seconds from then, never longer; an import the agent runs renews nothing. A file of `value_files` is imported
again at session start when it is due (_due). The person sees each import with its counts in /maisecrets:list and
removes one with `/maisecrets:forget import:NAME`; a value another import lists stays.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .vault import HOME, atomic_write

TYPES = ("SECRET", "NAME", "EMAIL", "PHONE", "IBAN", "CARD", "IP")
MAX_FILE_BYTES = 1024 * 1024
MAX_VALUES_PER_FILE = 2000
MAX_IMPORTED = 5000
MAX_VALUE_LEN = 512
MIN_VALUE_LEN = 8          # hooks._EXACT_MIN_LEN: a shorter stored value is never hunted in another text
BATCH = 25
RUN_SHARE = 0.6            # of MAX_IMPORTED: the imports that no value file names (an agent's) hold at most this share
EXPIRE_PER_IMPORT = 200     # expired values one import deletes; a keychain delete costs about 10 ms
FORGET_BATCH = 200          # values one hold of the lock forgets when an import is removed
REIMPORT_AFTER = 86400     # a value file is imported again after a day, which renews its values
SESSION_BUDGET = 8.0       # seconds of a session start for value_files; the rest follows at the next start
STATE_FILE = HOME / ".values-state"
KIND = "import"
_PLAIN_WORD = re.compile(r"[a-zß-ÿ]+")


@dataclass
class Result:
    source: str = ""
    new: dict = field(default_factory=dict)          # type -> values stored now
    known: int = 0                                    # values the vault held already (their lifetime stays)
    duplicates: int = 0                               # the same value twice in the file
    refused: list = field(default_factory=list)       # (line number, reason)
    stopped: str = ""                                 # why the import stopped before the end, or ""
    pending: int = 0                                  # values not written because the time ran out

    @property
    def stored(self) -> int:
        return sum(self.new.values())


# text of maisecrets itself: a placeholder bracket, the plugin's name (each control prompt and command holds it) and the
# form that names an import. A value with one of them stored by an agent blocked the person's own /maisecrets:forget,
# /maisecrets:send and every Codex settings prompt, and an imported placeholder made the person's one resolve to the
# agent's value (review of block 3, Opus H1)
_CONTROL_TEXT = ("\u27e6", "\u27e7", "maisecrets", "import:")


def _reason_for(value: str, type_: str = "SECRET") -> str:
    if len(value) < MIN_VALUE_LEN:
        return f"too short (at least {MIN_VALUE_LEN} characters)"
    if len(value) > MAX_VALUE_LEN:
        return f"too long (at most {MAX_VALUE_LEN} characters)"
    if any(ch in value for ch in "\n\r\0"):
        return "holds a line break"
    if _PLAIN_WORD.fullmatch(value):
        return "an ordinary word (lower-case letters only)"
    folded = value.casefold()
    if any(t in folded for t in _CONTROL_TEXT):
        return "holds text of maisecrets itself (a placeholder bracket, maisecrets or import:)"
    if type_ == "SECRET" and not any(c.isupper() or c.isdigit() or not (c.isalpha() or c.isspace()) for c in value):
        # lower-case words and spaces are ordinary text: an agent could mask any sentence of the person's prompts
        return "ordinary text (a SECRET needs an upper-case letter, a digit or a symbol)"
    return ""


def parse(text: str) -> tuple[list[tuple[str, str, int]], list[tuple[int, str]], int]:
    """(values as (value, type, line), refused lines as (line, reason), duplicates). Blank lines and lines that start
    with `#` are skipped. A reason never holds the value or the line."""
    items: list[tuple[str, str, int]] = []
    refused: list[tuple[int, str]] = []
    seen: set[str] = set()
    duplicates = 0
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            refused.append((n, "not JSON"))
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
            # the type is not echoed either: a name put into the wrong field would be printed
            refused.append((n, f"unknown type (one of {', '.join(TYPES)})"))
            continue
        type_ = type_.upper()
        value = value.strip()
        if type_ != "SECRET":
            # a name broken over two spaces is the same name, and one typed in decomposed form (NFD) too: the hooks
            # compare the NFC form of the text (hooks._phrase_spans)
            value = unicodedata.normalize("NFC", " ".join(value.split()))
        why = _reason_for(value, type_)
        if why:
            refused.append((n, why))
            continue
        if value in seen:
            duplicates += 1
            continue
        seen.add(value)
        items.append((value, type_, n))
    return items, refused, duplicates


# ------------------------------------------------------------------ sources --
def _load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    try:
        atomic_write(STATE_FILE, json.dumps(state, indent=1))
    except OSError:
        pass


def source_name(path: Path, state: dict | None = None) -> str:
    """The name of an import: the file name, plus a short tag when another file of that name came first."""
    state = _load_state() if state is None else state
    real = str(path.resolve())
    for name, rec in state.get("sources", {}).items():
        if rec.get("path") == real:
            return name
    base = re.sub(r"[^\w.-]", "_", path.name)[:48] or "values"
    taken = set(state.get("sources", {}))
    return base if base not in taken else f"{base}~{hashlib.sha256(real.encode()).hexdigest()[:6]}"


def _names(meta: dict) -> list[str]:
    """The imports that list one index entry: its first source and the others (Entry.also)."""
    first = meta.get("source")
    return ([first] + [n for n in meta.get("also") or [] if isinstance(n, str)]) if first else []


def counts_by_source(vault) -> dict[str, dict[str, int]]:
    """source -> type -> live values, from the index (no value is read). A value two imports list counts in both."""
    out: dict[str, dict[str, int]] = {}
    for meta in vault._index["entries"].values():
        if meta.get("purged"):
            continue
        for src in _names(meta):
            by_type = out.setdefault(src, {})
            by_type[meta["type"]] = by_type.get(meta["type"], 0) + 1
    return out


def sources(vault) -> list[dict]:
    """Every import the vault or the state knows: name, path, when, live counts per type, soonest expiry."""
    state = _load_state().get("sources", {})
    live = counts_by_source(vault)
    expiry: dict[str, float] = {}
    for meta in vault._index["entries"].values():
        if meta.get("purged"):
            continue
        for src in _names(meta):
            expiry[src] = min(expiry.get(src, meta["expires"]), meta["expires"])
    rows = []
    for name in sorted(set(state) | set(live)):
        rec = state.get(name, {})
        rows.append({"name": name, "path": rec.get("path", ""), "at": rec.get("at", 0.0),
                     "counts": live.get(name, {}), "expires": expiry.get(name), "origin": rec.get("origin", "run")})
    return rows


def _room(vault, origin: str, source: str) -> tuple[int, int, str]:
    """(room, cap, the other import that holds the most of the limited pool) for an import of ``origin``.

    The invariant: imports that no value file lists (an agent's, or one the person ran) hold at most RUN_SHARE of
    MAX_IMPORTED, so value files always have the rest; value files may fill the whole cap. A value that a value file
    lists counts as the file's. The room of a run import is the smaller of the room in its share and the room in the
    whole cap (round-2 review of block 3: a run import after the files had filled the cap still found room)."""
    files = {n for n, rec in _load_state().get("sources", {}).items() if rec.get("origin") == "file"}
    total = run_only = 0
    every: dict[str, int] = {}
    runs: dict[str, int] = {}
    now = time.time()
    for meta in vault._index["entries"].values():
        names = _names(meta)
        if not names or meta.get("purged") or meta["expires"] < now:
            continue
        total += 1
        run = not files.intersection(names)
        run_only += run
        for n in names:
            every[n] = every.get(n, 0) + 1
            if run:
                runs[n] = runs.get(n, 0) + 1

    def most(counts: dict[str, int]) -> str:
        counts = {n: c for n, c in counts.items() if n != source}
        return max(counts, key=lambda n: (counts[n], n)) if counts else ""
    run_cap = int(MAX_IMPORTED * RUN_SHARE)
    if origin != "file" and run_cap - run_only <= MAX_IMPORTED - total:
        return run_cap - run_only, run_cap, most(runs)
    return MAX_IMPORTED - total, MAX_IMPORTED, most(every)


def command(rest: str) -> str:
    """The line a person types in a terminal for `values REST`: the plugin's launcher by its absolute path, as other
    printed commands give it (hooks._run_sh). No `maisecrets` command is on the PATH (review of block 3, LOW)."""
    name = "run.cmd" if os.name == "nt" else "run.sh"
    launcher = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks", name)
    if os.name == "nt":
        launcher = f'"{launcher}"' if " " in launcher else launcher
    else:
        import shlex
        launcher = shlex.quote(launcher)     # a home with a space (/Users/Jan Example/...) runs as printed
    return launcher + " values " + rest


def type_text(counts: dict[str, int]) -> str:
    return ", ".join(f"{t} {counts[t]}" for t in TYPES if counts.get(t))


# ------------------------------------------------------------------- import --
def read_capped(path: Path) -> bytes:
    """The bytes of a regular file of at most MAX_FILE_BYTES; ValueError with a message for the person otherwise.

    The file is opened without blocking and checked on the open descriptor before a byte is read: a FIFO in value_files
    held every session start until the client's timeout, and a sparse file of 400 MB cost 427 MB of memory (review of
    block 3, Fable H1). The read stops at MAX_FILE_BYTES + 1 bytes, so a file that grows after the check costs no more.
    """
    import stat
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise ValueError(f"{path.name}: cannot be read ({type(exc).__name__})") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{path.name}: not a file")
        if info.st_size > MAX_FILE_BYTES:
            raise ValueError(f"{path.name}: {info.st_size:,} bytes, over the limit of {MAX_FILE_BYTES:,}; split it")
        chunks, left = [], MAX_FILE_BYTES + 1
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
    except OSError as exc:
        raise ValueError(f"{path.name}: cannot be read ({type(exc).__name__})") from None
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"{path.name}: over the limit of {MAX_FILE_BYTES:,} bytes; split it")
    return raw


def import_file(path: str | Path, vault=None, deadline: float | None = None, raw: bytes | None = None,
                origin: str = "run") -> Result:
    """Import one file. Raises ValueError with a message for the person when the file itself cannot be used."""
    from .vault import Vault
    path = Path(os.path.expanduser(str(path)))
    raw = read_capped(path) if raw is None else raw
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{path.name}: not UTF-8 text") from None
    vault = vault or Vault()
    state = _load_state()
    result = Result(source=source_name(path, state))
    items, result.refused, result.duplicates = parse(text)
    if len(items) > MAX_VALUES_PER_FILE:
        result.stopped = (f"line {items[MAX_VALUES_PER_FILE][2]} and later not read: at most "
                          f"{MAX_VALUES_PER_FILE} values per import")
        items = items[:MAX_VALUES_PER_FILE]
    vault.expire(limit=EXPIRE_PER_IMPORT)
    # a run import (an agent's) may fill RUN_SHARE of the cap; the rest stays for the person's value files, so an agent
    # cannot fill the vault and have the person's names refused (review of block 3, Opus M1)
    room, cap, biggest = _room(vault, origin, result.source)
    for i in range(0, len(items), BATCH):
        if deadline is not None and time.time() > deadline:
            result.pending = len(items) - i
            break
        batch = items[i:i + BATCH]
        out = vault.put_many([(v, t, KIND) for v, t, _n in batch], cap=max(room, 0), source=result.source,
                             ttl=int(vault.cfg.get("max_ttl_seconds", 30 * 86400)), renew=origin == "file")
        for (value, type_, n), entry in zip(batch, out):
            if entry is None:
                if not result.stopped:
                    result.stopped = (f"line {n} and later not stored: the vault holds {cap} imported values, the "
                                      "limit" + ("" if cap == MAX_IMPORTED else " of imports that are no value file")
                                      + (f"; import:{biggest} holds the most of them, /maisecrets:forget "
                                         f"import:{biggest} removes it" if biggest else
                                         "; /maisecrets:forget import:NAME removes an import"))
                continue
            if entry.uses == 0:          # made now; a value the vault held was touched (uses went up)
                result.new[type_] = result.new.get(type_, 0) + 1
                room -= 1
            else:
                result.known += 1
    real = str(path.resolve())
    rec = state.setdefault("sources", {}).setdefault(result.source, {})
    # count: the live values that carry this import's name, the number _due compares with; a value the vault held
    # from elsewhere (a /maisecrets:put) carries none, and counting it made every start import again (round 2)
    rec.update({"path": real, "at": time.time(), "origin": "file" if origin == "file" or rec.get("origin") == "file"
                else "run", "count": sum(counts_by_source(vault).get(result.source, {}).values())})
    if not result.pending:
        rec["hash"] = hashlib.sha256(raw).hexdigest()[:16]
    _save_state(state)
    _log(result, origin)
    return result


def _log(result: Result, origin: str) -> None:
    """One events.log line per import: its name, origin and counts per type, no value (review of block 3, Fable M2:
    an agent's import masked text and left no trace)."""
    from types import SimpleNamespace
    from . import events
    events.record("ValueImport", origin, [SimpleNamespace(key="import:" + result.source, type=t, kind=f"{KIND}:{n}")
                                          for t, n in sorted(result.new.items())] or
                  [SimpleNamespace(key="import:" + result.source, type="-", kind=f"{KIND}:0")],
                  outcome=f"stored {result.stored}, known {result.known}, refused {len(result.refused)}")


def summary(result: Result) -> str:
    """The one line a person reads: counts, refused line numbers with reasons, what to do next. No value."""
    parts = [f"imported {result.stored} value(s) from {result.source}"
             + (f" ({type_text(result.new)})" if result.stored else "")]
    if result.known:
        parts.append(f"{result.known} already stored")
    if result.duplicates:
        parts.append(f"{result.duplicates} duplicate line(s) skipped")
    if result.refused:
        shown = "; ".join(f"line {n} {why}" for n, why in result.refused[:5])
        more = f"; and {len(result.refused) - 5} more" if len(result.refused) > 5 else ""
        parts.append(f"{len(result.refused)} line(s) refused: {shown}{more}")
    if result.stopped:
        parts.append(result.stopped)
    if result.pending:
        parts.append(f"{result.pending} more follow at the next session start")
    return ", ".join(parts) + "."


def remove(vault, name: str) -> tuple[int, int, dict]:
    """Forget every value of one import: (deleted, refused by the store, kept: other import -> values it keeps). A value
    another import lists too stays and loses only this name (review of block 3, Opus M2). The values are deleted
    FORGET_BATCH per hold of the lock and index write (Opus M3: one write per value took 58.8 s for 2,000). The state
    then forgets the import."""
    kept: dict[str, int] = {}
    with vault._exclusive():
        for meta in vault._index["entries"].values():
            names = _names(meta)
            if name in names and len(names) > 1:
                if not meta.get("purged"):
                    for other in names:
                        if other != name:
                            kept[other] = kept.get(other, 0) + 1
                rest = [n for n in names if n != name]
                meta["source"], meta["also"] = rest[0], rest[1:]
        keys = [k for k, m in vault._index["entries"].items() if m.get("source") == name and not m.get("also")]
        vault._drop_derived()
    deleted = refused = 0
    for i in range(0, len(keys), FORGET_BATCH):
        for status in vault.forget_many(keys[i:i + FORGET_BATCH]).values():
            deleted += status == "ok"
            refused += status == "store"
    if not refused:
        state = _load_state()
        if state.get("sources", {}).pop(name, None) is not None:
            _save_state(state)
    return deleted, refused, kept


# ------------------------------------------------------------ session start --
def _due(rec: dict, digest: str, live: int, soonest: float | None, max_ttl: int) -> bool:
    """Import a value file again: its content changed, its last import is a day old, a value of it expires within the
    renewal window, or fewer of its values live than the last import left (one was forgotten or expired). The window is
    two days, or half of max_ttl_seconds when that is shorter: with a lifetime of one day, a window of two days made
    every session start import the file again (round-2 review of block 3)."""
    now = time.time()
    window = min(2 * REIMPORT_AFTER, max_ttl / 2)
    return (rec.get("hash") != digest or now - float(rec.get("at", 0)) >= REIMPORT_AFTER
            or (soonest is not None and soonest < now + window) or live < int(rec.get("count", 0)))


def session_import(cfg: dict, vault=None) -> str | None:
    """Import each file of `value_files` that is due (_due), within SESSION_BUDGET seconds; then say once when the set
    of imports changed since the last start (imports_note). One text for the person, or None."""
    files = [f for f in cfg.get("value_files") or [] if isinstance(f, str) and f.strip()]
    from .vault import Vault
    vault = vault or Vault(cfg)
    notes: list[str] = []
    if files:
        notes = _import_files(files, vault)
    text = ("maisecrets value files: " + "; ".join(notes) + ". /maisecrets:list shows each import.") if notes else ""
    note = imports_note(vault)
    return " ".join(t for t in (text, note) if t) or None


def _import_files(files: list[str], vault) -> list[str]:
    state = _load_state()
    deadline = time.time() + SESSION_BUDGET
    live = counts_by_source(vault)
    soonest = {r["name"]: r["expires"] for r in sources(vault)}
    notes: list[str] = []
    for shown in files:
        path = Path(os.path.expanduser(shown.strip()))
        try:
            raw = read_capped(path)
            digest = hashlib.sha256(raw).hexdigest()[:16]
            name = source_name(path, state)
            rec = state.get("sources", {}).get(name, {})
            if not _due(rec, digest, sum(live.get(name, {}).values()), soonest.get(name),
                        int(vault.cfg.get("max_ttl_seconds", 30 * 86400))):
                continue
            result = import_file(path, vault, deadline=deadline, raw=raw, origin="file")
        except ValueError as exc:
            # a file that cannot be used is said once, not at every start (review of block 3, LOW)
            state = _load_state()
            if state.setdefault("refused", {}).get(shown) != str(exc):
                state["refused"][shown] = str(exc)
                _save_state(state)
                notes.append(str(exc))
            continue
        state = _load_state()
        if state.get("refused", {}).pop(shown, None) is not None:
            _save_state(state)
        if result.stored or result.refused or result.stopped or result.pending:
            notes.append(summary(result).rstrip("."))
    return notes


def imports_note(vault) -> str | None:
    """At session start: when the set of imports changed since the last start, one sentence that names each new import
    and its counts, so an import an agent ran is seen (review of block 3, Fable M2). Unchanged, it says nothing."""
    rows = sources(vault)
    names = sorted(r["name"] for r in rows if sum(r["counts"].values()))
    state = _load_state()
    before = state.get("announced")
    if before is not None and set(before) == set(names):
        return None
    state["announced"] = names
    _save_state(state)
    new = [r for r in rows if r["name"] in set(names) - set(before or [])]
    if not new:
        return None
    shown = ", ".join(f"import:{r['name']} ({type_text(r['counts'])})" for r in new[:5])
    more = f" and {len(new) - 5} more" if len(new) > 5 else ""
    return (f"maisecrets masks the values of {shown}{more} in every text from now on. /maisecrets:list shows each "
            "import; /maisecrets:forget import:NAME removes one.")
