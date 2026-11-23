"""The second net for a tool result (claude-mod/maisecrets-mod.mjs, `session.append` on the door `tool-result`).

In Claude Code a PostToolUse hook that fails does not withhold the output, and a failed command takes the
PostToolUseFailure path, whose answer cannot replace it. The mod sees each row before the client stores and sends it.

The mod decides from positive evidence only. With the mod running, it sets MAISECRETS_MOD_NET=1 for the hooks it starts,
and the tool-result hooks then put a fixed marker into their answer (mark_answers): RESULT_MASKED when the answer
replaces the output, else RESULT_CHECKED. The mod reads the marker in the classic answer and removes it, so it never
reaches the model. A result without the marker of maisecrets goes to mask_result (`hooks/dispatch.py mod-result`).
"""
from __future__ import annotations

import os
import re

from .placeholder import KEY_RE

RESULT_CHECKED = "[maisecrets: result checked]"
RESULT_MASKED = "[maisecrets: result masked]"
ENV = "MAISECRETS_MOD_NET"
_EVENTS = {"post-tool": "PostToolUse", "post-tool-failure": "PostToolUseFailure"}
_KEY = re.compile("⟦(" + KEY_RE + ")(?::[^⟧\n]{0,80})?⟧")
_AGENT = re.compile(r"[A-Za-z0-9_-]{1,64}")


def mark(obj: dict, event: str) -> dict:
    """The answer of a tool-result hook with the marker of maisecrets in its additionalContext. A Codex answer (a
    decision) and an event that is no tool-result event stay as they are. Holds no value."""
    name = _EVENTS.get(event)
    if not name or not isinstance(obj, dict) or "decision" in obj:
        return obj
    hso = dict(obj.get("hookSpecificOutput") or {})
    hso["hookEventName"] = name
    tag = RESULT_MASKED if ("updatedToolOutput" in hso or "updatedMCPToolOutput" in hso) else RESULT_CHECKED
    ctx = hso.get("additionalContext")
    hso["additionalContext"] = f"{ctx}\n\n{tag}" if isinstance(ctx, str) and ctx else tag
    return {**obj, "hookSpecificOutput": hso}


def mark_answers(hooks_module, event: str) -> None:
    """Every answer this hook process writes (the handler's, the watchdog's, a crash's) carries the marker: they all go
    out through hooks._out. Only when the mod asked for it (ENV): without the mod the text would reach the model."""
    if os.environ.get(ENV) != "1" or event not in _EVENTS:
        return
    write = hooks_module._out
    hooks_module._out = lambda obj: write(mark(obj, event))


def _keys(text: str) -> set:
    return {m.group(1) for m in _KEY.finditer(text)}


def mask_result(payload: dict) -> dict:
    """The texts of a result that no tool-result hook of maisecrets marked, masked as hooks.post_tool masks them, with
    the note on unchecked names that post_tool's hook adds. Answers {"texts": [...], "changed": bool, "note": str},
    the texts in the same order, or {"withheld": True} when the name setting withholds an unchecked result. Raises on
    any failure: the mod then withholds the result. Writes no row: hooks.log counts hook runs, and this is none."""
    texts = payload.get("texts")
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise ValueError("texts")
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    from . import detect, hooks, vault_refs
    from .home import regions_from_config
    from .placeholder import REFERENCES
    from .sources import PLUGIN_SOURCES
    from .tool_withhold import with_unchecked_names
    from .vault import load_config
    detect.use_regions(regions_from_config)
    detect.use_sources(PLUGIN_SOURCES)
    detect.use_references(REFERENCES)
    vault_refs.use_client("claude")
    # the shape of a Claude Code payload (prompt_id): the answer is Claude's updatedToolOutput. No file path, so a
    # value in a test file is masked here, where post_tool may keep it as a fixture
    tool = str(payload.get("tool_name") or "tool")[:80]
    hook_payload = {"hook_event_name": "PostToolUse", "prompt_id": "mod", "session_id": session,
                    "cwd": str(payload.get("cwd") or ""), "tool_name": tool, "tool_input": {},
                    "tool_response": list(texts)}
    out = hooks.post_tool(hook_payload)
    out = with_unchecked_names(hook_payload, out if isinstance(out, dict) else {}, False, load_config)
    hso = out.get("hookSpecificOutput") or {}
    new = hso.get("updatedToolOutput")
    note = hso.get("additionalContext") if isinstance(hso.get("additionalContext"), str) else ""
    if new is None:
        return {"texts": texts, "changed": False, "note": note}
    if isinstance(new, str):
        return {"withheld": True}         # with_unchecked_names withheld it: one text in place of the result
    if not isinstance(new, list) or len(new) != len(texts) or not all(isinstance(t, str) for t in new):
        raise ValueError("answer")
    _scrub_later(texts, new, session, payload.get("agent_id"))
    return {"texts": new, "changed": new != texts, "note": note}


def _scrub_later(texts: list, new: list, session: str | None, agent) -> None:
    """The client keeps the tool's own record of the result (toolUseResult) as the tool made it, and writes the row
    after this answer: a detached child masks the values of the new placeholders in the transcript of this session,
    found by its id, and for a subagent's result in that subagent's transcript (<session>/subagents/agent-<id>.jsonl).
    The values come from the store by the keys the masking put in. Never raises."""
    try:
        from .vault import Vault, load_config
        cfg = load_config()
        if not cfg.get("scrub_transcript", True):
            return
        keys = set().union(*(_keys(t) for t in new)) - set().union(*(_keys(t) for t in texts))
        vault = Vault(cfg)
        values = [v for v in (vault.backend.get(k) for k in sorted(keys)) if v]
        if not values:
            return
        from .hooks import _SESSION_ID_RE, _scrub_transcript_later
        _scrub_transcript_later("", values, [], session=session)
        if isinstance(agent, str) and _AGENT.fullmatch(agent) and session and _SESSION_ID_RE.fullmatch(session):
            from pathlib import Path
            base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
            name = agent if agent.startswith("agent-") else "agent-" + agent
            for path in base.glob(f"*/{session}/subagents/{name}.jsonl"):
                _scrub_transcript_later(str(path), values, [])
    except Exception:  # noqa: BLE001 - the answer stands; the scrub is the transcript's, not the model's
        pass
