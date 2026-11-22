"""A claude.ai connector's tool call gets no stored value (THREAT-MODEL C14, #99): its call goes through Anthropic's
connector proxy, where TLS ends. The MCP path of the PreToolUse hook (hooks._pre_mcp) asks claude_ai_connector
before it resolves anything, and refuses with refusal()."""
from __future__ import annotations

import os

from . import cowork


# The sources of the hook's `mcp_server` that name a server of the client's own configuration (Claude Code 2.1.330:
# the source is the config scope; a claude.ai connector has the scope `claudeai`, or `dynamic` where it is not of a
# plugin, and its type is `claudeai-proxy`). #99
_CONFIG_SOURCES = frozenset({"user", "project", "local", "managed", "enterprise"})
CONNECTOR_PREFIX = "mcp__claude_ai_"


def claude_ai_connector(payload: dict, tool: str) -> bool:
    """True for a tool of a claude.ai connector: its call goes through Anthropic's connector proxy, where TLS ends.
    The source `claudeai` names one whatever its tool name. A scope of the client's own config names none. In Cowork
    every other source counts as one (a connector can arrive there as an `sdk` server with a tool name the host
    chooses), and in a remote session (CLAUDE_CODE_REMOTE) the source `dynamic` does. Else the tool name
    `mcp__claude_ai_…` decides (a payload without `mcp_server` too). Codex sends no `mcp_server`: its tools keep the
    resolve, and its own connectors (`codex_apps`) are not detected (docs/KNOWN-GAPS.md)."""
    server = payload.get("mcp_server") if isinstance(payload.get("mcp_server"), dict) else {}
    source = server.get("source")
    if source == "claudeai":
        return True
    if source in _CONFIG_SOURCES:
        return False
    if cowork.active():
        return True
    if source == "dynamic" and os.environ.get("CLAUDE_CODE_REMOTE"):
        return True
    from .hooks import client_of
    if "mcp_server" not in payload and client_of(payload) == "codex":
        return False
    return tool.startswith(CONNECTOR_PREFIX)


def refusal(tool: str, keys: list[str]) -> str:
    names = ", ".join("⟦" + k + "⟧" for k in dict.fromkeys(keys))
    return (f"maisecrets: {tool} is a claude.ai connector. Its call passes Anthropic's connector proxy, where "
            f"{names} would be in clear text, so maisecrets puts no stored value into it. The call did not run. "
            "Use a directly configured MCP server for this value. If this connector is your gateway, use the "
            "gateway's own references (⟦sref:…⟧) through it.")
