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


# the request when the answer could not be checked: nothing of the answer goes to the model
UNCHECKED = (_SHOW + "maisecrets: the command was carried out, but its answer could not be checked, so it is not "
             "shown here.")


def show_answer(payload: dict, answer: str) -> dict:
    """The mod's answer in Cowork for a command the prompt hook answered: the prompt becomes a request to show the
    answer, with each value in it masked as in any prompt the mod passes on. A placeholder in the answer reaches the
    prompt hook as plain brackets, so it never counts as one the person typed (C4). When the rewrite was not possible
    (no valid session, the rewrite off), the request is a fixed line."""
    from . import forms, hooks
    from .placeholder import CLOSE, OPEN
    text = _SHOW + forms.cowork(answer).replace(OPEN, "[").replace(CLOSE, "]")
    masked = hooks.rewrite_prompt({**payload, "prompt": text, "origin": None})
    if isinstance(masked.get("text"), str):
        return {"text": masked["text"]}
    session = payload.get("session_id")
    # {} from a rewrite that ran: no value in the text. {} before it ran: unknown, so nothing of it is sent
    ran = (isinstance(session, str) and hooks._SESSION_ID_RE.fullmatch(session) is not None
           and hooks.load_config().get("rewrite_prompts", True))
    return {"text": text} if masked == {} and ran else {"text": UNCHECKED}
