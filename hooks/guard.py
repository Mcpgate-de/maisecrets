#!/usr/bin/env python3
"""The maisecrets guard: a hook that lives outside the plugin folder.

A Claude Code update of a synced plugin rewrites its folder, and a session whose plugin was loaded
from it then runs none of its hooks, silently (anthropics/claude-code#97847; measured 2026-09-29:
the session that started the sync ran no maisecrets hook either, while /plugin showed the new
version). Nothing inside the plugin can see that. This script is copied to ~/.claude by
`maisecrets guard install` and registered in ~/.claude/settings.json with the plugin's matchers.

For each prompt and tool call it waits a moment for the heartbeat that every maisecrets hook writes
when it starts (~/.maisecrets/alive/<hash of session, event and id>). No heartbeat means maisecrets
did not run for this call: the prompt is blocked, the tool call denied, a tool result withheld, and
the message names /reload-plugins. It stays silent where maisecrets is not meant to run: another
account without maisecrets, a plugin the user disabled, Codex. Standard library only, and no import
from the plugin: the plugin folder is exactly what may be missing.
"""
import hashlib
import json
import os
import sys
import time

EVENTS = {"UserPromptSubmit": "user-prompt", "PreToolUse": "pre-tool", "PostToolUse": "post-tool"}
MESSAGE = ("maisecrets did not run in this session: a plugin update replaced its folder. Run /reload-plugins, "
           "then try again. Until then the maisecrets guard blocks this.")


def _home() -> str:
    return os.environ.get("MAISECRETS_HOME") or os.path.join(os.path.expanduser("~"), ".maisecrets")


def _claude_dir() -> str:
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def expected() -> bool:
    """Whether maisecrets is meant to run for the account Claude Code runs as now."""
    mode = _load(os.path.join(_home(), "guard.json")).get("expect", "synced")
    if mode == "always":
        return True
    if mode != "synced":
        return False
    claude = _claude_dir()
    settings = _load(os.path.join(claude, "settings.json")).get("enabledPlugins") or {}
    if any("maisecrets" in k and v is False for k, v in settings.items()):
        return False            # the user switched it off
    # the account file sits next to ~/.claude, or inside CLAUDE_CONFIG_DIR when that is set
    account_file = (os.path.join(claude, ".claude.json") if os.environ.get("CLAUDE_CONFIG_DIR")
                    else os.path.join(os.path.expanduser("~"), ".claude.json"))
    account = _load(account_file).get("oauthAccount") or {}
    org, acc = account.get("organizationUuid"), account.get("accountUuid")
    if org and acc and os.path.isfile(os.path.join(claude, "plugins", "synced", f"{org}_{acc}", "maisecrets",
                                                   ".claude-plugin", "plugin.json")):
        return True
    installed = _load(os.path.join(claude, "plugins", "installed_plugins.json")).get("plugins") or {}
    return any(k.startswith("maisecrets@") for k in installed)


def heartbeat_name(session: str, event: str, ident: str) -> str:
    """The same name maisecrets.hooks._heartbeat writes; the tests hold both to it."""
    return hashlib.sha256(f"{session}\0{event}\0{ident}".encode()).hexdigest()[:32]


def _refusal(hook_event: str) -> dict:
    if hook_event == "UserPromptSubmit":
        return {"decision": "block", "reason": MESSAGE}
    if hook_event == "PreToolUse":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": MESSAGE}}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "updatedToolOutput": f"[{MESSAGE} The tool ran; its output is withheld.]"}}


def decide(payload: dict, wait: float) -> dict:
    hook_event = payload.get("hook_event_name", "")
    event = EVENTS.get(hook_event)
    if event is None or "turn_id" in payload or "prompt_id" not in payload:
        return {}               # not an event maisecrets guards, or not Claude Code (Codex sends turn_id)
    ident = payload.get("prompt_id") if event == "user-prompt" else payload.get("tool_use_id")
    session = payload.get("session_id")
    if not ident or not session or not expected():
        return {}
    path = os.path.join(_home(), "alive", heartbeat_name(session, event, ident))
    end = time.monotonic() + wait
    while True:
        if os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass
            return {}
        if time.monotonic() >= end:
            return _refusal(hook_event)
        time.sleep(0.05)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    wait = float(os.environ.get("MAISECRETS_GUARD_WAIT", "5"))
    out = decide(payload if isinstance(payload, dict) else {}, wait)
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
