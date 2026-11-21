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
    # a change has a key and a value word (_settings_change); `/maisecrets settings`, `settings all` and a sentence
    # such as "/maisecrets settings clean_dirs shows which" only show, through the command file
    (LazyRx(r"/maisecrets settings (?!all\b|--all\b)([A-Za-z_]+) ([A-Za-z0-9_-]+)(?![\w-])"), None),
    (LazyRx(r"/maisecrets forget import:"), "maisecrets: forget import:"),
    (LazyRx(r"/maisecrets report incident\b"), "maisecrets: report incident"),
    (LazyRx(r"/maisecrets ner (?=off\b|local\b|on\b|url\b|gateway\b|fallback\b|updates\b|unavailable\b)"),
     "maisecrets: ner "),
]


def codex(text: str) -> str:
    """Each `/maisecrets NAME` (or the colon form) as Codex's `maisecrets: NAME`."""
    return _ENTRY_RX.sub("maisecrets: ", text)


# a placeholder of a hint in capitals: `/maisecrets settings KEY VALUE`, `max_keys_per_session NUMBER`
_PLACEHOLDERS = frozenset({"VALUE", "NUMBER", "HOST", "DIR", "FILE"})


def _value_words() -> frozenset:
    """The words a settings change takes as its value (settings.py): on and off, each choice, a lifetime, a region,
    default, add and remove for a list."""
    from . import settings
    words = set(settings._BOOL_WORDS) | set(settings.TTL_WORDS) | {"default", "add", "remove", "auto"}
    words.update(settings.region_codes())
    for choices in settings._CHOICES.values():
        words.update(choices)
    return frozenset(words)


def _settings_change(m) -> str:
    """`maisecrets: set KEY VALUE` for a change: a value word, a whole number or a placeholder in capitals; the text
    as it is for anything else (a sentence after the command)."""
    word = m.group(2)
    if word.lower() in _value_words() or word.isdigit() or word in _PLACEHOLDERS:
        return f"maisecrets: set {m.group(1)} {word}"
    return m.group(0)


# Cowork has no /clear ("Unknown skill", measured 2026-11-21): a new task starts a new session there
_CLEAR = [
    (LazyRx(r"/clear to switch it off"), "Start a new task to switch it off"),
    (LazyRx(r"/clear (switches it off|ends the demo|starts a new)"), r"A new task \1"),
    (LazyRx(r"(?<![\w/])/clear\b"), "a new task"),
]


def cowork(text: str) -> str:
    """Each command that the prompt hook answers as its text form, which Cowork shows an answer for; every other
    command keeps its slash form, whose command file shows its output there. /clear, which Cowork does not have, is a
    new task."""
    for rx, form in _TYPED:
        text = rx.sub(form if form is not None else _settings_change, text)
    for rx, form in _CLEAR:
        text = rx.sub(form, text)
    return text


def for_this_client(text: str) -> str:
    """The text for the person of this process: the Cowork forms in Cowork, else as it is."""
    from . import cowork as cw
    return cowork(text) if cw.active() else text
