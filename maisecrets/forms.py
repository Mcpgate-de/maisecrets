"""The forms of a maisecrets command in a text for the person. The texts name the entry form, `/maisecrets status`
(commands/maisecrets.md). Codex has no slash commands: there a command is the prompt `maisecrets: status`. Cowork shows
no answer of the prompt hook to a slash command (it shows no dropped or blocked prompt), but it shows it for the text
form, which the mod answers there (cowork.show_answer): a command that the prompt hook answers is named as text in
Cowork. Light: no import of the hooks."""
from __future__ import annotations

import re

from .lazy_regex import LazyRx

# every slash form of a command in a text: the colon form and the entry forms (prompt_commands.canonical), for the
# patterns that refuse a tool call carrying a command only the person may give. Followed by the command name
SLASH = r"(?:/maisecrets:(?:(?:maisecrets|ms)[ \t]+)?|/maisecrets[ \t]+|(?<![\w./-])/ms[ \t]+)"
_NAMES = ("audit", "demo", "forget", "guard", "list", "ner", "not-a-secret", "put", "report", "rules", "send",
          "settings", "shortcut", "sref", "status", "term")
_ENTRY_RX = LazyRx(r"/maisecrets[: ](?=(?:" + "|".join(re.escape(n) for n in sorted(_NAMES, key=len, reverse=True))
                       + r")(?![\w-]))")
# the commands the prompt hook answers, and their text form (the parsers: terms, not_a_secret, demo, settings,
# ner_setup, value_files). Most specific first
_TYPED = [
    (LazyRx(r"/maisecrets term (add|remove)\b"), r"maisecrets: term \1"),
    (LazyRx(r"/maisecrets not-a-secret undo\b"), "maisecrets: undo not a secret"),
    (LazyRx(r"/maisecrets not-a-secret\b"), "maisecrets: not a secret"),
    (LazyRx(r"/maisecrets demo\b"), "maisecrets: demo"),
    (LazyRx(r"/maisecrets settings hints reset\b"), "maisecrets: reset hints"),
    (LazyRx(r"/maisecrets settings ssh_autonomous_hosts add\b"), "maisecrets: ssh autonomous"),
    (LazyRx(r"/maisecrets settings ssh_autonomous_hosts remove\b"), "maisecrets: ssh ask"),
    # a change has a key and a value; `/maisecrets settings` and `settings all` only show, through the command file
    (LazyRx(r"/maisecrets settings (?!all\b|--all\b)([a-z_]+)(?= \S)"), r"maisecrets: set \1"),
    (LazyRx(r"/maisecrets forget import:"), "maisecrets: forget import:"),
    (LazyRx(r"/maisecrets ner (?=off\b|local\b|on\b|url\b|gateway\b|fallback\b|updates\b|unavailable\b)"),
     "maisecrets: ner "),
]


def codex(text: str) -> str:
    """Each `/maisecrets NAME` (or the colon form) as Codex's `maisecrets: NAME`."""
    return _ENTRY_RX.sub("maisecrets: ", text)


def cowork(text: str) -> str:
    """Each command that the prompt hook answers as its text form, which Cowork shows an answer for; every other
    command keeps its slash form, whose command file shows its output there."""
    for rx, form in _TYPED:
        text = rx.sub(form, text)
    return text


def for_this_client(text: str) -> str:
    """The text for the person of this process: the Cowork forms in Cowork, else as it is."""
    from . import cowork as cw
    return cowork(text) if cw.active() else text
