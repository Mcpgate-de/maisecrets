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


# what the model gets in place of a command the hook answered: the answer only, never the typed command (it can carry
# a name or a value), and no `maisecrets:` at the start, so the prompt hook reads no command in it
_SHOW = ("The person ran a maisecrets command, and maisecrets carried it out. Show the person this answer exactly as "
         "it is, in a code block, and add nothing:\n\n")


def show_answer(payload: dict, answer: str) -> dict:
    """The mod's answer in Cowork for a command the prompt hook answered: the prompt becomes a request to show the
    answer, with each value in it masked as in any prompt the mod passes on."""
    from . import hooks
    text = _SHOW + short(answer)
    masked = hooks.rewrite_prompt({**payload, "prompt": text, "origin": None})
    return {"text": masked.get("text", text) if isinstance(masked.get("text"), str) else text}
