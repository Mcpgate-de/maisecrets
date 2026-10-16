"""ms:(…) - the person checks whether maisecrets would catch a value, and the value never reaches the model.

A typed prompt that starts with `ms:(` is always blocked (hooks.user_prompt; the mod leaves it to that hook). The
value is the text between `ms:(` and the last `)`, or up to the end when the `)` is missing. The verdict comes from
the same calls as for a normal prompt with that value (hooks._prompt_hits and hooks._take_values_out). The answer
goes to the person only, in the block reason, and names types and rule ids, never the value (README "Check a value
first").
"""
from __future__ import annotations

import re

# `Ms:(` too: a phone keyboard in Remote Control writes the first letter in capitals, and that prompt would go out.
# The near forms of the same trigger count too, because a miss sends a value without a shape to the model: blanks
# around the colon (`ms: (`), and the full-width colon and bracket of an input method (`ms：（`). Before it, every
# blank that the mod's `\s` takes (JavaScript counts U+FEFF, Python does not) and the zero-width characters: a prompt
# that the mod passes on as a check must be a check here too, or the hook would send it (claude-mod CHECK)
_BLANK = r"[\s\ufeff\u200b-\u200d\u2060]*"
TRIGGER_RE = re.compile(r"\A" + _BLANK + "ms" + _BLANK + "[:\uff1a]" + _BLANK + "[(\uff08]", re.I)
# the start as the README writes it: only this one stores a value no rule caught. A near form is blocked as a check, but
# `MS: (Microsoft Teams) the sync fails` would else put a product name into the store for good (Gate B, round 2)
EXACT_RE = re.compile(r"\A" + _BLANK + r"ms:\(", re.I)
# one blank at most on each side: `ms:( value )` and a key on its own lines between `ms:(` and `)`
_EDGES = ("\r\n", "\n", " ", "\t")

TIP_CLAUDE = "Tip: check a value first with ms:(…)"
TIP_CODEX = ("maisecrets: check a value first: send ms:(your value) alone as your prompt. maisecrets says whether it "
             "would mask the value, and the value does not reach the AI.")
NOT_SENT = "This prompt was not sent. The value did not reach the AI."
USAGE = ("maisecrets: put the value between the brackets, for example ms:(my-value). maisecrets then says whether it "
         "would mask it. " + NOT_SENT)
A_PLACEHOLDER = ("maisecrets: this is a maisecrets placeholder, not a value. Put the value itself between the "
                 "brackets. " + NOT_SENT)
NOT_CAUGHT = "⚠ maisecrets would NOT have caught this."


def exact(prompt) -> bool:
    return isinstance(prompt, str) and EXACT_RE.match(prompt) is not None


def parse(prompt) -> str | None:
    """The value of a check prompt, or None when the prompt is no check. An empty value is "" (the prompt is still
    a check and is blocked)."""
    if not isinstance(prompt, str):
        return None
    m = TRIGGER_RE.match(prompt)
    if not m:
        return None
    rest = prompt[m.end():]
    close = max(rest.rfind(")"), rest.rfind("\uff09"))
    value = rest[:close] if close >= 0 else rest
    for edge in _EDGES:
        if value.startswith(edge):
            value = value[len(edge):]
            break
    for edge in _EDGES:
        if value.endswith(edge):
            value = value[:-len(edge)]
            break
    return value


_KEY_LIKE_RE = re.compile(r"[A-Za-z_]+")


def scrub_forms(prompt: str, value: str) -> list[str]:
    """The texts of a check to mask in the transcript: the prompt as typed and without its outer blanks, and the value
    alone. The value alone only from 8 characters on and when it is not letters only: a short value or a word such as
    `true` or `content` would be masked in every record and break the JSON of the transcript (Gate B, round 1); the
    prompt as typed covers it."""
    forms = [prompt, prompt.strip()]
    if len(value) >= 8 and not _KEY_LIKE_RE.fullmatch(value):
        forms.append(value)
    return [f for f in dict.fromkeys(forms) if f]


def only_placeholders(value: str, refs: list) -> bool:
    """The value is placeholders and blanks only: nothing to check."""
    rest, last = [], 0
    for _key, a, b in refs:
        rest.append(value[last:a])
        last = b
    rest.append(value[last:])
    return bool(refs) and not "".join(rest).strip()


def hit_label(type_: str, kind: str, stored: bool = False) -> str:
    """One hit as the person reads it: the type and the rule id. A term names no entity, a stored value no key."""
    if stored:
        return f"{type_} (stored value)"
    if kind.startswith("term:"):
        return f"{type_} (term)"
    return f"{type_} ({kind})"


def caught(labels: list[str]) -> str:
    return f"✓ maisecrets would mask this: {', '.join(dict.fromkeys(labels))}\n\n{NOT_SENT}"


def not_caught(why: str) -> str:
    return f"{NOT_CAUGHT} {why}\n\n{NOT_SENT}"


def stored_text(ref: str, alone: bool, in_text: bool) -> str:
    if alone and in_text:
        return not_caught(f"It is now stored ({ref}). From now on it is masked wherever it stands as a word of its "
                          "own.")
    if alone:
        return not_caught(f"It is now stored ({ref}). From now on it is masked where it stands alone on a line or "
                          "after a colon or an equals sign (password: …). Inside a sentence maisecrets does not find "
                          "it, because it has spaces.")
    return not_caught(f"It is now stored ({ref}), but maisecrets does not find it again in a prompt. Please report "
                      "this with /maisecrets:report bug (the report holds no value).")
