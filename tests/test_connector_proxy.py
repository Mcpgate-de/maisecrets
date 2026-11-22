"""A claude.ai connector's tool call gets no stored value (#99).

The call of a claude.ai connector does not go from the client to the server: it goes through Anthropic's connector
proxy, where TLS ends, so a value resolved into its arguments is in clear text there. The PreToolUse hook refuses such
a call before anything is resolved: no value, no audit line, no use counted. A directly configured MCP server keeps
the resolve. A server token (C27) and a gateway reference (C31) are no stored values; they pass unchanged.

Run: python3 -m unittest tests.test_connector_proxy -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

VALUE = "connector-proxy-value-7Qx2"
SREF = "⟦sref:secret:" + "a1B2c3D4e5F6g7H8i9J0k1L2" + "⟧"
SERVER_TOKEN = "⟦SECRET_17⟧"


def _reset() -> None:
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    for f in ("index.json", "vault.json", "audit.log"):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _state() -> dict:
    """What a resolve changes: the audit log and the uses and limiter counts in the index."""
    out = {}
    for f in ("audit.log", "index.json"):
        p = Path(HOME, f)
        out[f] = p.read_text(encoding="utf-8") if p.exists() else ""
    return out


class ConnectorProxyTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref

    def pre(self, tool: str, server: dict | None, client: dict = CLAUDE, tool_input: dict | None = None) -> dict:
        payload = {"tool_name": tool, "tool_input": tool_input or {"text": "the key is " + self.ref, "to": "C1"},
                   "session_id": "S1", "transcript_path": "", **client}
        if server is not None:
            payload["mcp_server"] = server
        return hooks.pre_tool(payload).get("hookSpecificOutput", {})

    def assert_refused(self, hso: dict, what: str) -> None:
        self.assertEqual(hso.get("permissionDecision"), "deny", what)
        self.assertNotIn("updatedInput", hso, what)
        reason = hso.get("permissionDecisionReason", "")
        self.assertNotIn(VALUE, reason, what)
        self.assertIn(self.ref, reason, what)
        self.assertIn("connector proxy", reason, what)
        self.assertIn("directly configured MCP server", reason, what)

    def assert_resolved(self, hso: dict, what: str) -> None:
        self.assertNotEqual(hso.get("permissionDecision"), "deny", f"{what}: {hso}")
        self.assertIn(VALUE, json.dumps(hso.get("updatedInput"), ensure_ascii=False), what)

    def test_a_claude_code_connector_call_gets_no_stored_value_and_nothing_is_counted(self):
        # Claude Code 2.1.330 sends mcp_server {name, source}; a claude.ai connector has the source "claudeai" and the
        # tool name of its display name "claude.ai Slack". The source names it also under another tool name.
        for tool, name in (("mcp__claude_ai_Slack__slack_send_message", "claude.ai Slack"),
                           ("mcp__org_Slack__slack_send_message", "Slack")):
            with self.subTest(tool=tool):
                _reset()
                self.ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
                before = _state()
                self.assert_refused(self.pre(tool, {"name": name, "source": "claudeai"}), tool)
                self.assertEqual(_state(), before, "a refused call resolves, audits and counts nothing")

    def test_a_cowork_connector_call_gets_no_stored_value(self):
        # Cowork runs Claude Code in a VM with the same tool-name prefix; its mcp_server source is not measured there,
        # so the name decides for every source that is no scope of the client's own config
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "remote_cowork"}):
            for server in ({"name": "claude.ai Gmail", "source": "claudeai"},
                           {"name": "claude.ai Gmail", "source": "dynamic"}, {"name": "claude.ai Gmail"}, None):
                with self.subTest(server=server):
                    _reset()
                    self.ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
                    before = _state()
                    self.assert_refused(self.pre("mcp__claude_ai_Gmail__create_draft", server), str(server))
                    self.assertEqual(_state(), before)

    def test_a_directly_configured_server_keeps_the_resolve(self):
        # a server of the person's own config, also one named like a connector, and any server in Codex
        for tool, server, client in (
                ("mcp__svc__lookup", {"name": "svc", "source": "user"}, CLAUDE),
                ("mcp__claude_ai_mine__lookup", {"name": "claude.ai mine", "source": "user"}, CLAUDE),
                ("mcp__claude_ai_mine__lookup", {"name": "claude.ai mine", "source": "project"}, CLAUDE),
                ("mcp__claude_ai_mine__lookup", {"name": "claude.ai mine", "source": "local"}, CLAUDE),
                ("mcp__claude_ai_mine__lookup", None, CODEX)):
            with self.subTest(tool=tool, server=server):
                _reset()
                self.ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref
                self.assert_resolved(self.pre(tool, server, client), tool)

    def test_a_server_token_and_a_gateway_reference_pass_a_connector_call_unchanged(self):
        # C27 and C31 never resolve into an MCP call: the token or reference goes to the server as text
        server = {"name": "claude.ai Team GW", "source": "claudeai"}
        for text in (SREF, SERVER_TOKEN):
            with self.subTest(text=text):
                hso = self.pre("mcp__claude_ai_Team_GW__jira_write_actions", server, tool_input={"body": text})
                self.assertEqual(hso, {}, "no decision and no rewrite")


if __name__ == "__main__":
    unittest.main()
