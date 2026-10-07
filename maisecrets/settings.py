"""The settings a person sees and changes, and the hint that names one at the moment it matters.

A setting changes only from a prompt the person typed, which the UserPromptSubmit hook reads
(`/maisecrets:settings KEY VALUE`, or `maisecrets: set KEY VALUE` alone as the prompt): a tool call of
the model never writes one, also not a stricter value (a prompt injection could set it for good). The
CLI only shows them. A key the user wrote is a decision; a missing key is "not decided" and reads the
default. A hint goes to the model once, when the case it is about first happens.
"""
from __future__ import annotations

import json
import re
import time

from .vault import (CONFIG, DEFAULT_CONFIG, HOME, ConfigError, LockTimeout, _check_types, _lock_for, atomic_write,
                    load_config)

# Every key of the config is in exactly one class (a test holds it): a new key without one is a test failure.
DISCOVERABLE = ("ssh_consent", "rehydration")
ADVANCED = ("ssh_host_groups", "ssh_approval", "resolve_in_files", "ssh_via_sandbox", "block_at_mentions",
            "rewrite_prompts", "scrub_transcript", "strip_hidden_characters", "regions", "ttl_seconds",
            "renew_on_use", "tips", "shortcut", "guard", "pass_agent_reports", "gateway_servers")
INTERNAL = ("backend", "allow_plaintext_store", "report_url", "max_ttl_seconds", "max_new_entries_per_result",
            "max_keys_per_session", "max_resolves_per_hour", "keep_purged_days", "audit_max_lines", "pii_regions")

MEANING = {
    "ssh_consent": "ask once per host before an ssh command that changes something",
    "rehydration": "put a stored value into a call: automatic, confirm (ask each time) or block",
    "ssh_host_groups": "hosts that one ssh consent covers together (edit config.json)",
    "ssh_approval": "under rehydration confirm: per-command, or per-session for the ssh route",
    "resolve_in_files": "a placeholder in Write/Edit content gets its value",
    "ssh_via_sandbox": "a value may go to ssh on stdin inside the Claude Code sandbox",
    "block_at_mentions": "block an @file mention in a prompt (the file would skip the scan)",
    "rewrite_prompts": "Claude Code with mods: send a prompt with placeholders instead of blocking it",
    "scrub_transcript": "remove a value from the session transcript on disk",
    "strip_hidden_characters": "remove invisible characters from tool results",
    "regions": "countries for the personal-data rules (edit config.json)",
    "ttl_seconds": "how long a stored value lives (edit config.json)",
    "renew_on_use": "a use of a value extends its life",
    "tips": "a short tip at session start, and the hints at the moment they matter",
    "shortcut": "the first session start names /maisecrets:shortcut once",
    "guard": "a synced install registers the guard outside its folder",
    "pass_agent_reports": "a subagent's report is not blocked",
    "gateway_servers": "MCP servers that resolve placeholders themselves (edit config.json)",
}

# what a prompt may set; any other key is edited in config.json by hand
_BOOL_WORDS = {"on": True, "true": True, "off": False, "false": False}
_CHOICES = {"rehydration": ("automatic", "confirm", "block"), "ssh_approval": ("per-command", "per-session")}
_BOOL_KEYS = tuple(k for k in DISCOVERABLE + ADVANCED if isinstance(DEFAULT_CONFIG.get(k), bool))

# the whole prompt, nothing else: a sentence inside a longer prompt is text for the model, not an order
_PROMPT_RE = re.compile(r"\A\s*(?:/maisecrets:settings|maisecrets:\s*set)\s+([a-z_]+)\s+([a-z-]+)\s*\Z", re.I)
# the same sentence anywhere in a tool call: a nested client (`codex exec 'maisecrets: set …'`, `claude -p`) would
# type it for the model, and the writer called by name would skip the prompt (review of C22). A text match: a
# sentence or a name built at run time is not seen
IN_A_COMMAND_RE = re.compile(r"(?:/maisecrets:settings|maisecrets:\s*set)\s+[a-z_]+\s+[a-z-]+|\bapply_typed\b", re.I)
# who wrote the prompt (Claude Code 2.1.292 UserPromptSubmit `source`): only the person at the composer. A scheduled
# task, a loop wakeup, a system or poll prompt can carry text the model chose (CronCreate, ScheduleWakeup), and an
# `sdk` prompt can come from a program a tool started (codex review round 2), so none of them changes anything. A
# client without the field is taken as the person
TYPED_SOURCES = (None, "user")
_LOCK = HOME / ".settings.lock"


def state(key: str, cfg: dict) -> str:
    if key in (cfg.get("policy_keys") or []):
        return "managed by policy"
    if key not in (cfg.get("user_keys") or []):
        return "default (not decided)"
    value = cfg.get(key)
    if isinstance(value, bool):
        return "explicitly enabled" if value else "explicitly disabled"
    return "explicitly set"


def _shown(value) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))[:40]
    return str(value)


def render(show_all: bool = False, cfg: dict | None = None) -> str:
    cfg = cfg if cfg is not None else load_config()
    keys = DISCOVERABLE + (ADVANCED if show_all else ())
    rows = [(k, _shown(cfg.get(k)), state(k, cfg), MEANING[k]) for k in keys]
    w = [max(len(r[i]) for r in rows) for i in range(3)]
    lines = [f"{k:<{w[0]}}  {v:<{w[1]}}  {s:<{w[2]}}  {m}" for k, v, s, m in rows]
    lines += ["",
              "To change one, send it as your own prompt: /maisecrets:settings KEY VALUE "
              "(in Codex: maisecrets: set KEY VALUE).",
              "VALUE is on or off, a choice the line names, or default. default removes your decision: "
              "the setting reads the default again, and its hint may come once more."]
    if not show_all:
        lines.append("/maisecrets:settings --all shows the advanced settings too.")
    if cfg.get("config_warning"):
        lines.append(f"WARNING: {cfg['config_warning']}")
    return "\n".join(lines)


def parse_prompt(prompt) -> tuple[str, str] | None:
    """(key, value word) when the whole prompt is a settings change, else None."""
    if not isinstance(prompt, str):
        return None
    m = _PROMPT_RE.match(prompt)
    return (m.group(1).lower(), m.group(2).lower()) if m else None


def apply_typed(key: str, word: str) -> str:
    """Write one change the person typed into config.json, keep every other key, and say what happened. Only the
    prompt hook calls this, for a prompt whose source is the person (TYPED_SOURCES)."""
    cfg = load_config()
    if key in (cfg.get("policy_keys") or []):
        return f"maisecrets: {key} is managed by a machine policy; it cannot be changed here."
    if key not in _BOOL_KEYS and key not in _CHOICES:
        if key in MEANING:
            return f"maisecrets: {key} is not changed by a prompt; edit {CONFIG} by hand."
        return f"maisecrets: {key} is no setting this command changes. /maisecrets:settings --all lists them."
    if word != "default":
        if key in _BOOL_KEYS and word not in _BOOL_WORDS:
            return f"maisecrets: {key} takes on, off or default."
        if key in _CHOICES and word not in _CHOICES[key]:
            return f"maisecrets: {key} takes {', '.join(_CHOICES[key])} or default."
    # a symlinked config.json (dotfiles) keeps its link: the new file replaces the target
    target = CONFIG.resolve() if CONFIG.is_symlink() else CONFIG
    try:
        # read, change and write under one lock: two prompts at once must not drop each other's change
        with _lock_for(_LOCK):
            try:
                text = target.read_text(encoding="utf-8")
            except FileNotFoundError:
                text = "{}"
            try:
                user = json.loads(text)
            except ValueError:
                user = None
            if not isinstance(user, dict):
                # rewriting a file that does not parse would drop what the person wrote in it
                return f"maisecrets: {CONFIG} is not one valid JSON object; fix it first. Nothing was changed."
            try:
                _check_types(user, CONFIG.name)
            except ConfigError as exc:
                # load_config ignores the whole file then: the change would be written and still not count
                return f"maisecrets: {exc}; fix it first. Nothing was changed."
            if word == "default":
                user.pop(key, None)
            else:
                user[key] = _BOOL_WORDS[word] if key in _BOOL_KEYS else word
            atomic_write(target, json.dumps(user, indent=2) + "\n")
    except (OSError, LockTimeout) as exc:
        return f"maisecrets: {CONFIG} cannot be written ({type(exc).__name__}); nothing was changed."
    after = load_config()
    return (f"maisecrets: {key} is {_shown(after.get(key))} ({state(key, after)}). "
            "This prompt was not sent to the model.")


# ------------------------------------------------------------------ hints --
# A hint is a sentence for the model, once. REVISION goes up only when the feature changes in a way that
# matters: then the hint comes once more. A hint never comes again because time passed.
HINTS = {
    "ssh_consent": {
        "revision": 1,
        "claude": ("maisecrets can ask the user once per host before an ssh command that changes something "
                   "(setting ssh_consent; it is off, and the user has not decided). Mention this once, in one "
                   "sentence, after your answer. If the user wants it, tell them to send this as their own prompt: "
                   "/maisecrets:settings ssh_consent on (or off, so the question does not come again). "
                   "Do not change settings yourself."),
        "codex": ("maisecrets can ask the user once per host before an ssh command that changes something "
                  "(setting ssh_consent; it is off, and the user has not decided). Mention this once, in one "
                  "sentence, after your answer. If the user wants it, tell them to send this alone as their own "
                  "prompt: maisecrets: set ssh_consent on (or off, so the question does not come again). "
                  "Do not change settings yourself."),
    },
}
_HINTS_FILE = HOME / "hints.json"


def _given() -> dict:
    try:
        given = json.loads(_HINTS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return given if isinstance(given, dict) else {}


def _given_this_revision(feature: str, given: dict) -> bool:
    seen = given.get(feature)
    return isinstance(seen, dict) and isinstance(seen.get("revision"), int) and \
        seen["revision"] >= HINTS[feature]["revision"]


def hint_due(feature: str, cfg: dict) -> bool:
    """The setting is undecided (not in config.json, not in a policy, still the default) and this revision
    of its hint was never given. `tips: false` silences every hint."""
    if cfg.get("tips", True) is False:
        return False
    if feature in (cfg.get("policy_keys") or []) or feature in (cfg.get("user_keys") or []):
        return False
    if cfg.get(feature) != DEFAULT_CONFIG.get(feature):
        return False      # a file that was ignored as a whole still turned it on (vault._keep_the_stricter)
    return not _given_this_revision(feature, _given())


def claim_hint(feature: str) -> bool:
    """Record this revision of the hint as given, and say whether this process may give it: only the one that
    wrote the record. Two hooks at once give it once; a record that cannot be written gives no hint, so an
    unwritable home never makes it nag."""
    try:
        with _lock_for(_LOCK):
            given = _given()
            if _given_this_revision(feature, given):
                return False
            given[feature] = {"revision": HINTS[feature]["revision"], "given": time.strftime("%Y-%m-%d")}
            atomic_write(_HINTS_FILE, json.dumps(given, indent=2) + "\n")
            return True
    except (OSError, LockTimeout):
        return False
