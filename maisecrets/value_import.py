"""Values from your own tools: `maisecrets values import FILE` and the setting `value_files` (README "Values from your
own tools", C26).

A tool the person runs (an export of the team's names, a password manager's list, a script) writes JSON lines:

    {"value": "Jan Example", "type": "NAME"}
    {"value": "a value without a shape"}            # type SECRET when it is missing

Each value goes into the vault with its type, so the exact match of the hooks (C2) masks it in every tool result and
every prompt from then on; a value of 2 to 6 words is found as a phrase. Nothing is printed but counts and line
numbers: a refused line is named by its number and the reason, never by its text.

An import only adds. It never deletes a value, never changes a stored one and never shortens a lifetime, so the agent
may run it: it can only make detection stricter. What could still hurt is volume and shape, and the caps hold that:

- at most MAX_FILE_BYTES per file and MAX_VALUES_PER_FILE values per import, at most MAX_IMPORTED imported values in
  the vault at once; past a cap the import stops and says so. The vault evicts nothing to make room: a full vault
  refuses the import, never the person's values. The index grows by about 450 bytes per value, and each hook reads it
  (measured in tests/test_value_import.py, the timing note in the README).
- a value of 8 to MAX_VALUE_LEN characters on one line: shorter values are not hunted in other texts anyway (the
  8-character floor of hooks._EXACT_MIN_LEN), and a single word of lower-case letters is an ordinary word, which an
  agent could import to mask every text that uses it.
- the import writes BATCH values per hold of the vault lock: a hook in another session waits for one batch, never for
  the whole file (a keychain write takes tens of milliseconds, and a hook waits at most 6 s for the lock).

Imported values live max_ttl_seconds (30 days unless the person set less): an import is the person's list, not a
value from one tool result. A file of `value_files` is imported again at session start when its content changed or a
day passed, which renews its values. The person sees each import with its counts in /maisecrets:list and removes one
with `/maisecrets:forget import:NAME`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
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


def _reason_for(value: str) -> str:
    if len(value) < MIN_VALUE_LEN:
        return f"too short (at least {MIN_VALUE_LEN} characters)"
    if len(value) > MAX_VALUE_LEN:
        return f"too long (at most {MAX_VALUE_LEN} characters)"
    if any(ch in value for ch in "\n\r\0"):
        return "holds a line break"
    if _PLAIN_WORD.fullmatch(value):
        return "an ordinary word (lower-case letters only)"
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
            value = " ".join(value.split())     # a name broken over two spaces is the same name
        why = _reason_for(value)
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


def counts_by_source(vault) -> dict[str, dict[str, int]]:
    """source -> type -> live values, from the index (no value is read)."""
    out: dict[str, dict[str, int]] = {}
    for meta in vault._index["entries"].values():
        src = meta.get("source")
        if src and not meta.get("purged"):
            by_type = out.setdefault(src, {})
            by_type[meta["type"]] = by_type.get(meta["type"], 0) + 1
    return out


def sources(vault) -> list[dict]:
    """Every import the vault or the state knows: name, path, when, live counts per type, soonest expiry."""
    state = _load_state().get("sources", {})
    live = counts_by_source(vault)
    expiry: dict[str, float] = {}
    for meta in vault._index["entries"].values():
        src = meta.get("source")
        if src and not meta.get("purged"):
            expiry[src] = min(expiry.get(src, meta["expires"]), meta["expires"])
    rows = []
    for name in sorted(set(state) | set(live)):
        rec = state.get(name, {})
        rows.append({"name": name, "path": rec.get("path", ""), "at": rec.get("at", 0.0),
                     "counts": live.get(name, {}), "expires": expiry.get(name)})
    return rows


def type_text(counts: dict[str, int]) -> str:
    return ", ".join(f"{t} {counts[t]}" for t in TYPES if counts.get(t))


# ------------------------------------------------------------------- import --
def import_file(path: str | Path, vault=None, deadline: float | None = None) -> Result:
    """Import one file. Raises ValueError with a message for the person when the file itself cannot be used."""
    from .vault import Vault
    path = Path(os.path.expanduser(str(path)))
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"{path.name}: cannot be read ({type(exc).__name__})") from None
    if not path.is_file():
        raise ValueError(f"{path.name}: not a file")
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{path.name}: {size:,} bytes, over the limit of {MAX_FILE_BYTES:,}; split it")
    raw = path.read_bytes()
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
    vault.expire(limit=None)
    imported = sum(1 for m in vault._index["entries"].values() if m.get("source") and not m.get("purged"))
    room = MAX_IMPORTED - imported
    for i in range(0, len(items), BATCH):
        if deadline is not None and time.time() > deadline:
            result.pending = len(items) - i
            break
        batch = items[i:i + BATCH]
        out = vault.put_many([(v, t, KIND) for v, t, _n in batch], cap=max(room, 0), source=result.source,
                             ttl=int(vault.cfg.get("max_ttl_seconds", 30 * 86400)))
        for (value, type_, n), entry in zip(batch, out):
            if entry is None:
                if not result.stopped:
                    result.stopped = (f"line {n} and later not stored: the vault holds {MAX_IMPORTED} imported "
                                      "values, the limit; /maisecrets:forget import:NAME removes an import")
                continue
            if entry.uses == 0:          # made now; a value the vault held was touched (uses went up)
                result.new[type_] = result.new.get(type_, 0) + 1
                room -= 1
            else:
                result.known += 1
    real = str(path.resolve())
    rec = state.setdefault("sources", {}).setdefault(result.source, {})
    rec.update({"path": real, "at": time.time()})
    if not result.pending:
        rec["hash"] = hashlib.sha256(raw).hexdigest()[:16]
    _save_state(state)
    return result


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


def remove(vault, name: str) -> tuple[int, int]:
    """Forget every value of one import: (deleted, refused by the store). The state keeps no record of it."""
    keys = [k for k, m in vault._index["entries"].items() if m.get("source") == name]
    deleted = refused = 0
    for k in keys:
        status = vault.forget(k)
        if status == "ok":
            deleted += 1
        elif status == "store":
            refused += 1
    if not refused:
        state = _load_state()
        if state.get("sources", {}).pop(name, None) is not None:
            _save_state(state)
    return deleted, refused


# ------------------------------------------------------------ session start --
def session_import(cfg: dict, vault=None) -> str | None:
    """Import each file of `value_files` whose content changed or whose last import is a day old, within
    SESSION_BUDGET seconds. One sentence for the person when something new was stored or a file failed, else None."""
    files = [f for f in cfg.get("value_files") or [] if isinstance(f, str) and f.strip()]
    if not files:
        return None
    from .vault import Vault
    vault = vault or Vault(cfg)
    state = _load_state()
    deadline = time.time() + SESSION_BUDGET
    notes: list[str] = []
    for shown in files:
        path = Path(os.path.expanduser(shown.strip()))
        try:
            digest = hashlib.sha256(path.read_bytes()[:MAX_FILE_BYTES + 1]).hexdigest()[:16]
        except OSError:
            notes.append(f"{path.name}: cannot be read")
            continue
        rec = state.get("sources", {}).get(source_name(path, state), {})
        if rec.get("hash") == digest and time.time() - float(rec.get("at", 0)) < REIMPORT_AFTER:
            continue
        try:
            result = import_file(path, vault, deadline=deadline)
        except ValueError as exc:
            notes.append(str(exc))
            continue
        state = _load_state()
        if result.stored or result.refused or result.stopped or result.pending:
            notes.append(summary(result).rstrip("."))
    if not notes:
        return None
    return "maisecrets value files: " + "; ".join(notes) + ". /maisecrets:list shows each import."
