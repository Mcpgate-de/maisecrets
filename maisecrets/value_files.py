"""Where the imported values live (maisecrets/values.py, C26), and whether any import is there.

A hook reads this module alone while no import exists: maisecrets/values.py loads the term matcher (about 13 ms at
import), and every hook call is a new process. values.py reads its files through these names, so the check and the
matcher cannot disagree about a source.

An import is one file `~/.maisecrets/imports/<id>.jsonl` that maisecrets writes itself (0600, in the maisecrets
folder, which the agent cannot read or write: C8). The id is opaque (`v` and 8 hex digits), never the name of the
file it came from: a file named like one of its values would print that value.
"""
from __future__ import annotations

import os
import re

from .vault import HOME

IMPORTS = HOME / "imports"
SUFFIX = ".jsonl"
CACHE_FILE = HOME / ".values-cache"
STATE_FILE = HOME / ".values-state"     # what the last session start said about the imports
KIND_PREFIX = "import:"
STORE_PREFIX = "maisecrets-import:"     # the store value of an import hit: its ids, never the value
ID_RE = re.compile(r"v[0-9a-f]{8}")


def _any_import() -> bool:
    """An import file is there, or the folder cannot be read: values.py then reads it, and a folder it cannot read
    stops the hooks (fail closed). Only a folder that is not there, or holds no import, is no source."""
    try:
        with os.scandir(IMPORTS) as entries:
            return any(e.name.endswith(SUFFIX) for e in entries)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True


_THERE: list = []    # [bool] of present(), once per process until forget()


def present() -> bool:
    """Whether an import is there, once per process. values.reset() and detect.reset_rules() forget it."""
    if not _THERE:
        _THERE.append(_any_import())
    return _THERE[0]


def forget() -> None:
    _THERE.clear()


def start_note_due(cfg: dict) -> bool:
    """Whether the session start has to load values.py: an import is there, a value file is set, or the last start
    saw an import (an import that went away is said once)."""
    files = cfg.get("value_files")
    return present() or bool(isinstance(files, list) and files) or STATE_FILE.exists()


# ------------------------------------------- what a hook asks without the matcher --
def is_import_kind(kind) -> bool:
    return isinstance(kind, str) and kind.startswith(KIND_PREFIX)


def is_mask_only(kind) -> bool:
    """A hit whose placeholder is never resolved: a term (term_files) or an imported value."""
    return isinstance(kind, str) and kind.startswith(("term:", KIND_PREFIX))


def store_value(kind: str) -> str:
    """What the store keeps for an import hit: the import id and the value id, never the value."""
    return STORE_PREFIX + kind[len(KIND_PREFIX):]


def import_of(kind: str) -> str:
    """The import id of an import hit (`import:<id>:<value id>`)."""
    return kind[len(KIND_PREFIX):].split(":", 1)[0]


# the person's prompt that removes imports: /maisecrets:forget import:ID [import:ID ...], in Codex
# `maisecrets: forget import:ID`. The whole prompt, nothing else
_REMOVAL_RE = re.compile(r"\A\s*(?:/maisecrets:forget|maisecrets:[ \t]*forget)\s+((?:import:\S+\s*)+)\Z", re.I)


def parse_removal(prompt) -> list | None:
    """The import ids of a removal prompt, or None when the prompt is no removal."""
    if not isinstance(prompt, str):
        return None
    m = _REMOVAL_RE.match(prompt)
    if not m:
        return None
    return [w[len(KIND_PREFIX):] for w in m.group(1).split()]


# the same removal in a tool call: the prompt typed by a nested client, the CLI form, or the remover called by name.
# A text match (the C22 class): a name built at run time is not seen, which README "Values from your own tools" says
IN_A_COMMAND_RE = re.compile(
    r"(?:/maisecrets:forget|maisecrets:[ \t]*forget)\s[^\n]*import:"
    r"|\bvalues[\s\"']+(?:remove|forget|delete)\b"
    r"|\b(?:remove_typed|_remove_import)\b", re.I)
IN_A_COMMAND = ("maisecrets: this command removes an import of values, which makes detection weaker; only the person "
                "removes one, as their own prompt (/maisecrets:forget import:ID, in Codex: maisecrets: forget "
                "import:ID). The command did not run. Tell the user the prompt to send.")
