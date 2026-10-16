"""Where the terms live (maisecrets/terms.py, C26), and whether any list is there.

A hook reads this module alone while no list exists: maisecrets/terms.py costs about 13 ms at import (measured with
`python3 -X importtime` on Python 3.14), and every hook call is a new process. terms.py reads its files through the
same functions, so the check and the matcher cannot disagree about a source.
"""
from __future__ import annotations

import os
from pathlib import Path

from .vault import HOME

PERSONAL = HOME / "terms.txt"
MARKED = HOME / "terms.marked.json"
STATE_FILE = HOME / ".terms-state"     # what the last session start said about the team lists
SUFFIX = ".terms"
MAX_ENTRIES = 2000      # entries looked at per team folder, as user_rules.MAX_ENTRIES


def _there(path: Path) -> bool:
    """A file that exists, or one whose state cannot be read: terms.py then reads it, and a file it cannot read
    stops the hooks (fail closed). Only a file that is not there is no source."""
    try:
        os.stat(path)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True
    return True


def team_folders(cfg: dict) -> list:
    """(shown, folder) of each folder of `rule_dirs` (the setting and the policy) that holds team lists: its
    subfolder `rules/` when it has one, as for the rules of your own (user_rules.rule_folder). Not rules.d, the
    person's own folder: their list is terms.txt."""
    from . import user_rules
    out = []
    for shown, path, src in user_rules.folders(cfg):
        if src == "own" or user_rules.refused_folder(path):
            continue
        target = user_rules.rule_folder(path)
        if target.is_dir():
            out.append((shown, target))
    return out


def team_files(cfg: dict) -> list:
    """(source, path) of each `*.terms` file in the team folders, sorted by name within a folder."""
    out = []
    for shown, folder in team_folders(cfg):
        try:
            with os.scandir(folder) as entries:
                names = []
                for n, e in enumerate(entries):
                    if n >= MAX_ENTRIES:
                        break
                    if e.name.endswith(SUFFIX) and e.is_file():
                        names.append(e.name)
        except OSError:
            continue
        out += [(f"{shown.rstrip('/')}/{name}", folder / name) for name in sorted(names)]
    return out


def any_terms(cfg: dict) -> bool:
    """Whether a term source is there: terms.txt, the marked names, or a team list."""
    return _there(PERSONAL) or _there(MARKED) or bool(team_files(cfg))


_THERE: list = []    # [bool] of present(), once per process until forget()


def present() -> bool:
    """any_terms() of the config, once per process. terms.reset() and detect.reset_rules() forget it: a name marked
    or added in this process is masked in its next scan."""
    if not _THERE:
        from .user_rules import _config
        _THERE.append(any_terms(_config()))
    return _THERE[0]


def forget() -> None:
    _THERE.clear()


def start_note_due(cfg: dict) -> bool:
    """Whether the session start has to ask terms.session_note: a list is there, or the last start saw one (a team
    list that went away is said once)."""
    return any_terms(cfg) or _there(STATE_FILE)


# ------------------------------------------- what a hook asks without the matcher --
STORE_PREFIX = "maisecrets-term:"   # the store value of a term entry: the id, never the term


def is_term_kind(kind) -> bool:
    return isinstance(kind, str) and kind.startswith("term:")


def store_value(kind: str) -> str:
    """What the store keeps for a term hit: the entity id, never the term. One entry per entity, so every spelling
    of it gets the same placeholder."""
    return STORE_PREFIX + kind[5:]


def parse_command(prompt):
    """terms.parse_command, for a prompt that can be a term command at all: both of its forms start with
    `/maisecrets` or `maisecrets` after white space (any case), so a prompt without `ecret` near its start is none."""
    if not isinstance(prompt, str) or "ecret" not in prompt.lstrip()[:32].lower():
        return None
    from . import terms
    return terms.parse_command(prompt)


def take_markers(prompt: str, ttl: int) -> tuple:
    """terms.take_markers, for a prompt that can hold a marker at all (`{{`)."""
    if "{{" not in prompt:
        return prompt, 0
    from . import terms
    return terms.take_markers(prompt, ttl)
