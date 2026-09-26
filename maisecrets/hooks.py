"""Hook handlers for Claude Code (and, with an adapter, Codex).

Every handler reads one JSON payload from stdin and prints one JSON object.
It never prints a value. It fails closed: an error inside a handler blocks
the action it guards, and says so.

Events:
  user-prompt  UserPromptSubmit  -> block + store + clipboard on a hit
  pre-tool     PreToolUse        -> rehydrate ⟦REF⟧ in Bash commands
  post-tool    PostToolUse       -> redact tool results before the model sees them
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
from typing import Any

from . import detect
from .placeholder import find_refs
from .vault import Vault, load_config

# a Windows path carries a drive letter and backslashes: @C:\Users\x\.env
AT_MENTION_RE = re.compile(r"(?<![\w@])@(?P<path>[\w./~\\:-]+)")


# ---------------------------------------------------------------- helpers --
def client_of(payload: dict) -> str:
    """Which agent sent this payload. Codex marks turn-scoped events with `turn_id` and
    every event with `model`; Claude Code sends `prompt_id`/`effort` and neither of those."""
    if "turn_id" in payload or ("model" in payload and "prompt_id" not in payload):
        return "codex"
    return "claude"


def _out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _clipboard(text: str) -> bool:
    try:
        sysname = platform.system()
        if sysname == "Darwin":
            cmd = ["pbcopy"]
        elif sysname == "Windows":
            cmd = ["clip"]
        else:
            cmd = ["xclip", "-selection", "clipboard"]
        subprocess.run(cmd, input=text.encode(), check=True, timeout=3)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _clipboard_read() -> str:
    try:
        sysname = platform.system()
        if sysname == "Darwin":
            cmd = ["pbpaste"]
        elif sysname == "Windows":
            cmd = ["powershell", "-command", "Get-Clipboard"]
        else:
            cmd = ["xclip", "-selection", "clipboard", "-o"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _replace(text: str, matches: list[detect.Match], vault: Vault, session: str | None) -> tuple[str, list]:
    """Replace every match with its reference, right to left so offsets hold."""
    entries = []
    out = text
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        e = vault.put(m.value, m.type, m.kind, session=session)
        entries.append(e)
        out = out[: m.start] + e.ref + out[m.end:]
    return out, list(reversed(entries))


def _walk_strings(node: Any, fn) -> Any:
    """Apply fn to every string inside a JSON-like structure, keeping the shape."""
    if isinstance(node, str):
        return fn(node)
    if isinstance(node, list):
        return [_walk_strings(x, fn) for x in node]
    if isinstance(node, dict):
        return {k: _walk_strings(v, fn) for k, v in node.items()}
    return node


def _scrub_transcript(path: str, values: list[str], refs: list[str]) -> bool:
    """Best effort: rewrite the transcript lines that carry the raw prompt.

    Claude Code writes the prompt as a queue-operation record before the
    UserPromptSubmit hook runs (measured 2026-09-26), so a blocked prompt is
    already on disk. Replacing it here is the only way to keep the value out
    of ~/.claude/projects.
    """
    try:
        if not path or not os.path.exists(path) or os.path.getsize(path) > 50 * 1024 * 1024:
            return False
        with open(path, encoding="utf-8") as f:
            data = f.read()
        changed = data
        for v, r in zip(values, refs):
            changed = changed.replace(json.dumps(v)[1:-1], json.dumps(r)[1:-1])
        if changed == data:
            return False
        tmp = path + ".maisecrets.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(changed)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


# --------------------------------------------------------- UserPromptSubmit --
def user_prompt(payload: dict) -> dict:
    cfg = load_config()
    prompt = payload.get("prompt", "")
    session = payload.get("session_id")

    # 1. @file mentions inline the file OUTSIDE the hook pipeline. Force a Read.
    if cfg.get("block_at_mentions", True):
        for m in AT_MENTION_RE.finditer(prompt):
            p = os.path.expanduser(m.group("path")).rstrip(".,;:)")
            if os.path.exists(p) or os.path.exists(os.path.join(payload.get("cwd", ""), p)):
                return {
                    "decision": "block",
                    "reason": (
                        f"maisecrets: @{m.group('path')} would inline the file without scanning. "
                        "Ask Claude to read it instead, so the Read result can be redacted."
                    ),
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
                }

    # 2. secrets and PII
    matches = detect.scan(prompt)
    if not matches:
        return {}
    vault = Vault(cfg)
    rewritten, entries = _replace(prompt, matches, vault, session)
    copied = _clipboard(rewritten)
    if cfg.get("scrub_transcript", True):
        _scrub_transcript(payload.get("transcript_path", ""), [m.value for m in matches], [e.ref for e in entries])
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.type] = counts.get(e.type, 0) + 1
    summary = ", ".join(f"{n} {t}" for t, n in counts.items())
    keys = ", ".join(e.key for e in entries)
    where = "in the clipboard: paste and send again" if copied else "below (clipboard unavailable)"
    reason = (
        f"maisecrets: {summary} detected and stored as {keys}. "
        f"The prompt did not reach the model. The rewritten prompt is {where}."
    )
    if not copied:
        reason += "\n\n" + rewritten
    if vault.backend.test_mode:
        reason += "\n(vault backend: jsonfile, TEST MODE)"
    if cfg.get("report_url"):
        reason += f" Wrong? Report it: {cfg['report_url']}"
    if client_of(payload) == "codex":
        return {"decision": "block", "reason": reason}
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    }


# --------------------------------------------------------------- PreToolUse --
def pre_tool(payload: dict) -> dict:
    cfg = load_config()
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    server = (payload.get("mcp_server") or {}).get("name", "")

    # Gateway tools resolve their own placeholders (deposit path, later).
    if server and server in cfg.get("gateway_servers", []):
        return {}

    if tool != "Bash":
        return {}
    command = tool_input.get("command", "")
    refs = find_refs(command)
    if not refs:
        return {}
    vault = Vault(cfg)
    missing: list[str] = []
    resolved = command
    for key, start, end in sorted(refs, key=lambda r: r[1], reverse=True):
        value, status = vault.get(key)
        if status != "ok":
            missing.append(f"{key} ({status})")
            continue
        resolved = resolved[:start] + value + resolved[end:]
    if missing:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "maisecrets: cannot run, placeholder not resolvable: " + ", ".join(missing),
            }
        }
    new_input = dict(tool_input)
    new_input["command"] = resolved
    if client_of(payload) == "codex":
        # Codex accepts updatedInput only together with "allow"; its own approval policy still applies.
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "updatedInput": new_input}}
    # Claude Code: no permissionDecision, the normal permission rules apply to the resolved command.
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": new_input}}


# -------------------------------------------------------------- PostToolUse --
def post_tool(payload: dict) -> dict:
    cfg = load_config()
    response = payload.get("tool_response")
    if response is None:
        return {}
    session = payload.get("session_id")
    vault: Vault | None = None
    hit = {"n": 0}
    values: list[str] = []
    entries: list = []

    def redact(s: str) -> str:
        nonlocal vault
        matches = detect.scan(s)
        if not matches:
            return s
        if vault is None:
            vault = Vault(cfg)
        out, ents = _replace(s, matches, vault, session)
        hit["n"] += len(matches)
        values.extend(m.value for m in matches)
        entries.extend(ents)
        return out

    new_response = _walk_strings(response, redact)
    if not hit["n"]:
        return {}
    if client_of(payload) == "codex":
        # Codex has no updatedToolOutput. A "block" replaces the model-visible result with the
        # reason text, so the reason IS the redacted output. Measured on codex-cli 0.155.1
        # (2026-09-26): `continue: false` + stopReason let the RAW output reach the model; "block"
        # kept the request clean (the code-mode script sees a rejected promise, which is acceptable).
        # Codex also writes the raw command output into its rollout file before this hook runs
        # (item_completed / CommandExecution), so that file is scrubbed too.
        text = new_response if isinstance(new_response, str) else json.dumps(new_response, ensure_ascii=False)
        if cfg.get("scrub_transcript", True):
            _scrub_transcript(payload.get("transcript_path", ""), values, [e.ref for e in entries])
        return {"decision": "block",
                "reason": f"[maisecrets redacted {hit['n']} value(s); placeholders are references]\n{text}"}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": new_response,
            "additionalContext": (
                f"maisecrets redacted {hit['n']} value(s) in this tool result; "
                "use the ⟦REF⟧ placeholders as-is."
            ),
        }
    }


HANDLERS = {"user-prompt": user_prompt, "pre-tool": pre_tool, "post-tool": post_tool}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in HANDLERS:
        sys.stderr.write("usage: hook.py user-prompt|pre-tool|post-tool\n")
        return 2
    event = argv[1]
    try:
        payload = json.load(sys.stdin)
    except ValueError as exc:
        sys.stderr.write(f"maisecrets: bad payload: {exc}\n")
        return 2  # fail closed
    try:
        _out(HANDLERS[event](payload))
        return 0
    except Exception as exc:  # noqa: BLE001 - a guard that fails open is no guard
        sys.stderr.write(f"maisecrets {event}: {type(exc).__name__}: {exc}\n")
        return 2
