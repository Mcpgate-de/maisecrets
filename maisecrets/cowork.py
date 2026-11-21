"""Cowork (the Claude desktop app's Cowork tab) runs Claude Code in a Linux VM and marks it with
CLAUDE_CODE_ENTRYPOINT=remote_cowork (measured 2026-11-21, desktop 6.28899.6, Claude Code 2.1.330). Cowork knows a
plugin's commands by their short name only (`/maisecrets`, the entry), and it draws no panel, no row above the prompt
and no dropped or blocked prompt: an answer the mod drops, or the prompt hook's block, is not seen there. The mod's
answer to a command the prompt hook answers goes to the model as a request to show it (show_answer), and the hints
name such a command in its text form, `maisecrets: term add NAME` (forms.cowork)."""
from __future__ import annotations

import os

ENTRYPOINT = "remote_cowork"


def active() -> bool:
    """Whether this process serves a Cowork session."""
    return os.environ.get("CLAUDE_CODE_ENTRYPOINT") == ENTRYPOINT


# what the model gets in place of a command the hook answered: the answer only, never the typed command (it can carry
# a name or a value), and no `maisecrets:` at the start, so the prompt hook reads no command in it
_SHOW = ("The person ran a maisecrets command, and maisecrets carried it out. Show the person this answer exactly as "
         "it is, in a code block, and add nothing:\n\n")


def show_answer(payload: dict, answer: str) -> dict:
    """The mod's answer in Cowork for a command the prompt hook answered: the prompt becomes a request to show the
    answer, with each value in it masked as in any prompt the mod passes on."""
    from . import forms, hooks
    text = _SHOW + forms.cowork(answer)
    masked = hooks.rewrite_prompt({**payload, "prompt": text, "origin": None})
    return {"text": masked.get("text", text) if isinstance(masked.get("text"), str) else text}
