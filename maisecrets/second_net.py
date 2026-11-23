"""The second net for a tool result (claude-mod/maisecrets-mod.mjs, `session.append` on the door `tool-result`).

In Claude Code a PostToolUse hook that fails does not withhold the output, and a failed command takes the
PostToolUseFailure path, whose answer cannot replace it. The mod sees each row before the client stores and sends it,
and asks here (`hooks/dispatch.py mod-result`) for a result that no PostToolUse hook replaced.
"""
from __future__ import annotations

import re

from . import detect
from .placeholder import KEY_RE

_KEY = re.compile("\u27e6(" + KEY_RE + ")(?::[^\u27e7\n]{0,80})?\u27e7")


def _keys(text: str) -> set:
    return {m.group(1) for m in _KEY.finditer(text)}


def mask_result(payload: dict) -> dict:
    """The texts of a result that the PostToolUse hook did not mask, masked as hooks.post_tool masks them. With `since`
    (epoch seconds) it first asks whether the PostToolUse hook of this session left a row in hooks.log since then: then
    that hook ran and found nothing, and the texts stay as they are ({"ran": True}). Else {"texts": [...], "changed":
    bool}, the texts in the same order. Raises on any failure: the mod then withholds the result. Writes no row:
    hooks.log counts hook runs, and this is none."""
    texts = payload.get("texts")
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise ValueError("texts")
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    if payload.get("since") is not None:
        from .home import HOME
        from .status_verdict import ran_since
        if ran_since(HOME / "hooks.log", session, "post-tool", payload.get("since")):
            return {"ran": True}
    from . import hooks, vault_refs
    from .home import regions_from_config
    from .placeholder import REFERENCES
    from .sources import PLUGIN_SOURCES
    detect.use_regions(regions_from_config)
    detect.use_sources(PLUGIN_SOURCES)
    detect.use_references(REFERENCES)
    vault_refs.use_client("claude")
    # the shape of a Claude Code payload (prompt_id): the answer is Claude's updatedToolOutput. No file path, so a
    # value in a test file is masked here, where post_tool may keep it as a fixture
    tool = str(payload.get("tool_name") or "tool")[:80]
    out = hooks.post_tool({"hook_event_name": "PostToolUse", "prompt_id": "mod", "session_id": session,
                           "cwd": str(payload.get("cwd") or ""), "tool_name": tool, "tool_input": {},
                           "tool_response": list(texts)})
    new = (out.get("hookSpecificOutput") or {}).get("updatedToolOutput") if isinstance(out, dict) else None
    if new is None:
        return {"texts": texts, "changed": False}
    if not isinstance(new, list) or len(new) != len(texts) or not all(isinstance(t, str) for t in new):
        raise ValueError("answer")
    _scrub_later(texts, new, session)
    return {"texts": new, "changed": new != texts}


def _scrub_later(texts: list, new: list, session: str | None) -> None:
    """The client keeps the tool's own record of the result (toolUseResult) as the tool made it, and writes the row
    after this answer: a detached child masks the values of the new placeholders in the transcript of this session,
    found by its id. The values come from the store by the keys the masking put in. Never raises."""
    try:
        from .vault import Vault, load_config
        cfg = load_config()
        if not cfg.get("scrub_transcript", True):
            return
        keys = set().union(*(_keys(t) for t in new)) - set().union(*(_keys(t) for t in texts))
        vault = Vault(cfg)
        values = [v for v in (vault.backend.get(k) for k in sorted(keys)) if v]
        if values:
            from .hooks import _scrub_transcript_later
            _scrub_transcript_later("", values, [], session=session)
    except Exception:  # noqa: BLE001 - the answer stands; the scrub is the transcript's, not the model's
        pass
