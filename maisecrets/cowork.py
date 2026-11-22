"""Cowork (the Claude desktop app's Cowork tab) runs Claude Code in a Linux VM and marks it with
CLAUDE_CODE_ENTRYPOINT=remote_cowork (measured 2026-11-21, desktop 6.28899.6, Claude Code 2.1.330). Cowork knows a
plugin's commands by their short name only (`/maisecrets`, the entry), and it draws no panel, no row above the prompt
and no dropped or blocked prompt: an answer the mod drops, or the prompt hook's block, is not seen there. The mod's
answer to a command the prompt hook answers goes to the model as a request to show it (show_answer), and the hints
name such a command in its text form, `maisecrets: term add NAME` (forms.cowork)."""
from __future__ import annotations

import os

ENTRYPOINT = "remote_cowork"
# the Cowork cloud entry points: Claude Code's own list of them is remote_cowork and remote_cowork_trigger (desktop app
# 6.28899.6, app.asar)
ENTRYPOINTS = frozenset({ENTRYPOINT, "remote_cowork_trigger"})


def active() -> bool:
    """Whether this process serves a Cowork session."""
    return os.environ.get("CLAUDE_CODE_ENTRYPOINT") in ENTRYPOINTS


def names_off(cfg) -> bool:
    """Whether names are off in this Cowork task: Cowork, and no name source set. Measured on 0.9.22: the name service
    on the person's computer (127.0.0.1) is not reachable from the VM, and a gateway in Cowork is a claude.ai
    connector, not an MCP server of the VM's configuration, so `ner gateway NAME` cannot name it."""
    if not active():
        return False
    conf = cfg.get("remote_detector") if isinstance(cfg, dict) else None
    return not (isinstance(conf, dict) and conf.get("url"))


# why names are off in Cowork, for the person (the status) and for the model (the session start)
NAMES_WHY = ("a name service on your computer is not reachable from Cowork, and a gateway name service is not "
             "available in Cowork yet")


# what the model gets in place of a command the hook answered: the answer only, never the typed command (it can carry
# a name or a value), and no `maisecrets:` at the start, so the prompt hook reads no command in it
_SHOW = ("The person ran a maisecrets command, and maisecrets carried it out. Show the person this answer exactly as "
         "it is, in a code block, and add nothing:\n\n")


# the request when the answer could not be checked: nothing of the answer goes to the model
UNCHECKED = (_SHOW + "maisecrets: the command was carried out, but its answer could not be checked, so it is not "
             "shown here.")


def _masked_request(payload: dict, answer: str) -> str | None:
    """The request to show `answer`: its commands in their Cowork form (forms.cowork), then each value masked as in
    any prompt the mod passes on. A placeholder in the answer reaches the prompt hook as plain brackets, so it never
    counts as one the person typed (C4). None when the rewrite was not possible (no valid session, the rewrite off)."""
    from . import forms, hooks
    from .placeholder import CLOSE, OPEN
    text = _SHOW + forms.cowork(answer).replace(OPEN, "[").replace(CLOSE, "]")
    masked = hooks.rewrite_prompt({**payload, "prompt": text, "origin": None})
    if isinstance(masked.get("text"), str):
        return masked["text"]
    session = payload.get("session_id")
    # {} from a rewrite that ran: no value in the text. {} before it ran: unknown, so nothing of it is sent
    ran = (isinstance(session, str) and hooks._SESSION_ID_RE.fullmatch(session) is not None
           and hooks.load_config().get("rewrite_prompts", True))
    return text if masked == {} and ran else None


def show_answer(payload: dict, answer: str) -> dict:
    """The mod's answer in Cowork for a command the prompt hook answered: the prompt becomes a request to show the
    answer, with each value in it masked (_masked_request). When the rewrite was not possible, the request is a fixed
    line, also on any error (a lock that timed out, a store that cannot be read)."""
    try:
        text = _masked_request(payload, answer)
    except Exception:  # noqa: BLE001 - the answer cannot be checked: the fixed line instead
        text = None
    return {"text": text if text is not None else UNCHECKED}


# the output in a demo answer when it could not be checked: nothing of it
OUTPUT_UNCHECKED = "maisecrets: the command was carried out, but its output could not be checked, so it is not shown."


def masked_output(payload: dict, output: str) -> str:
    """A command's output for the demo answer in Cowork (demo.cowork_own), which enters the transcript: masked as in
    show_answer, or OUTPUT_UNCHECKED when the rewrite was not possible. No prompt hook reads a demo answer, so a text
    the rewrite left to that hook (an @mention) is shown only when the rules and the store find no value in it. The
    caller keeps the demo's own step out of this rewrite (demo._INSIDE). Any error (a lock that timed out, a store
    that cannot be read) gives OUTPUT_UNCHECKED."""
    try:
        text = _masked_request(payload, output)
        if text is None or not text.startswith(_SHOW):
            return OUTPUT_UNCHECKED
        text = text[len(_SHOW):]
        from . import hooks
        from .demo import _has_value
        if _has_value(text, hooks.load_config()):
            return OUTPUT_UNCHECKED
        return text
    except Exception:  # noqa: BLE001 - the output cannot be checked: it is not shown
        return OUTPUT_UNCHECKED
