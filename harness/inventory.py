"""The tools a real client offered the model, read from the request bodies the fake upstream kept,
checked against tests/client_tools.json: a built-in tool that is not classified there fails the
harness, because the PreToolUse matcher and the store guard may not reach it. A tool list written by
hand missed ReadMcpResourceTool, which reads a file: URI and was outside the matcher (2026-09-28)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = json.loads((ROOT / "tests" / "client_tools.json").read_text(encoding="utf-8"))


def _names(node, out: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("tools", "additional_tools") and isinstance(value, list):
                for tool in value:
                    if isinstance(tool, dict):
                        name = tool.get("name") or tool.get("type")
                        if isinstance(name, str):
                            out.add(name)
            _names(value, out)
    elif isinstance(node, list):
        for item in node:
            _names(item, out)


def offered(bodies: list[Path]) -> set[str]:
    """The built-in tool names in the bodies; MCP tools (mcp__*) go by their prefix."""
    out: set[str] = set()
    for body in bodies:
        try:
            _names(json.loads(body.read_text(encoding="utf-8", errors="ignore")), out)
        except ValueError:
            continue
    return {n for n in out if not n.startswith("mcp__")}


def unclassified(client: str, bodies: list[Path]) -> list[str]:
    known = TOOLS[client]["tools"]
    return sorted(offered(bodies) - set(known))
