"""Cowork (the Claude desktop app's Cowork tab) runs Claude Code in a Linux VM and marks it with
CLAUDE_CODE_ENTRYPOINT=remote_cowork (measured 2026-11-21, desktop 6.28899.6, Claude Code 2.1.330). Two things differ
there: Cowork knows a plugin's commands by their short name only (`/status`; `/maisecrets:status` is an "unknown
skill"), and it draws no panel, no row above the prompt and no dropped-prompt line, so a command the mod ran itself
showed nothing."""
from __future__ import annotations

import os
import re

ENTRYPOINT = "remote_cowork"
_LONG = re.compile(r"/maisecrets:(?=[a-z])")


def active() -> bool:
    """Whether this process serves a Cowork session."""
    return os.environ.get("CLAUDE_CODE_ENTRYPOINT") == ENTRYPOINT


def short(text: str) -> str:
    """A text for the person, with each `/maisecrets:NAME` as the `/NAME` that Cowork knows."""
    return _LONG.sub("/", text)


class ShortNames:
    """A stream that writes the short command names (in Cowork only, set up by hooks/dispatch.py)."""

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        self._stream.write(short(text))
        return len(text)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)
