"""A claude.ai connector's tool call gets no stored value (#99).

The call of a claude.ai connector does not go from the client to the server: it goes through Anthropic's connector
proxy, where TLS ends, so a value resolved into its arguments is in clear text there. The PreToolUse hook refuses such
a call before anything is resolved: no value, no audit line, no use counted. A directly configured MCP server keeps
the resolve. In Cowork every source that is no scope of the own config counts as a connector, and in a remote session
the source dynamic does. A server token (C27) and a gateway reference (C31) are no stored values; they pass unchanged.

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

from maisecrets import connector_proxy, hooks  # noqa: E402
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


# the variables that change the decision: the entry point (Cowork), a remote session, and Codex's own variables
_DECIDING = ("CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_REMOTE")


def _env(**extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _DECIDING and not k.startswith("CODEX_")}
    return {**env, "CLAUDE_CODE_ENTRYPOINT": "cli", **extra}


class ConnectorProxyTests(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, _env(), clear=True)
        env.start()
        self.addCleanup(env.stop)
        _reset()
        self.ref = Vault().put(VALUE, "SECRET", "manual", session="S1").ref

    def fresh(self) -> None:
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
        # the gateway's references are a hint only for a connector that is the person's gateway
        self.assertIn("If this connector is your gateway, use the gateway's own references", reason, what)

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

    def test_a_claudeai_source_is_refused_also_when_the_payload_reads_like_codex(self):
        # Claude Code sends no prompt_id before the first user input of the process; with a `model` key or a CODEX_*
        # variable client_of() then says codex. The source claudeai is Claude Code's alone: Codex sends no mcp_server
        server = {"name": "claude.ai Slack", "source": "claudeai"}
        for client, env in (({}, {"CODEX_HOME": "/nonexistent/codex-home"}), ({"model": "m"}, {})):
            with self.subTest(client=client, env=env), mock.patch.dict(os.environ, env):
                self.fresh()
                before = _state()
                self.assert_refused(self.pre("mcp__claude_ai_Slack__slack_send_message", server, client), str(env))
                self.assertEqual(_state(), before)

    def test_a_payload_with_a_server_is_not_taken_for_codex(self):
        # Codex sends no mcp_server: a payload that has one is Claude Code's, also with a `model` key, no prompt_id
        # and a CODEX_* variable, so the tool name still decides there
        with mock.patch.dict(os.environ, {"CODEX_HOME": "/nonexistent/codex-home"}):
            server = {"name": "claude.ai mine", "source": "plugin"}
            hso = self.pre("mcp__claude_ai_mine__lookup", server, {"model": "m"})
            self.assert_refused(hso, "plugin source, model key, CODEX_HOME")

    def test_a_cowork_connector_call_gets_no_stored_value(self):
        # In Cowork (each of its entry points) and in the desktop app's local agent session (local-agent, for this
        # refusal only) a connector can arrive as an `sdk` server with a tool name the host chooses: every source that
        # is no scope of the client's own config counts as a connector
        servers = ({"name": "claude.ai Gmail", "source": "claudeai"}, {"name": "Gmail", "source": "sdk"},
                   {"name": "Gmail", "source": "dynamic"}, {"name": "Gmail", "source": "plugin"},
                   {"name": "Gmail", "source": "agent"}, {"name": "Gmail"}, None)
        for entry in ("remote_cowork", "remote_cowork_trigger", "local-agent"):
            for server in servers:
                with self.subTest(entry=entry, server=server), \
                        mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": entry}):
                    self.fresh()
                    before = _state()
                    self.assert_refused(self.pre("mcp__Gmail__create_draft", server), str(server))
                    self.assertEqual(_state(), before)

    def test_in_cowork_a_server_of_the_own_config_keeps_the_resolve(self):
        for entry in sorted(connector_proxy.FAIL_CLOSED_ENTRYPOINTS):
            for source in ("user", "project", "local", "managed", "enterprise"):
                with self.subTest(entry=entry, source=source), \
                        mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": entry}):
                    self.fresh()
                    self.assert_resolved(self.pre("mcp__svc__lookup", {"name": "svc", "source": source}), source)

    def test_a_remote_session_refuses_a_dynamic_server(self):
        # in a remote session (CLAUDE_CODE_REMOTE) a connector can have the source dynamic and no claude_ai_ prefix
        server = {"name": "Slack", "source": "dynamic"}
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_REMOTE": "true"}):
            self.assert_refused(self.pre("mcp__Slack__slack_send_message", server), "remote, dynamic")
            # only the source dynamic: an sdk or a plugin server without the prefix keeps the resolve there
            for source in ("sdk", "plugin"):
                with self.subTest(source=source):
                    self.fresh()
                    self.assert_resolved(self.pre("mcp__svc__lookup", {"name": "svc", "source": source}), source)
        self.fresh()
        self.assert_resolved(self.pre("mcp__Slack__slack_send_message", server), "local, dynamic")

    def test_a_server_named_like_a_connector_from_a_plugin_agent_or_dynamic_source_is_refused(self):
        # an over-refusal, accepted: the name is all that tells such a server from a connector there
        for source in ("plugin", "agent", "dynamic", "sdk"):
            with self.subTest(source=source):
                self.fresh()
                self.assert_refused(self.pre("mcp__claude_ai_mine__lookup", {"name": "claude.ai mine",
                                                                           "source": source}), source)

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

    def test_a_connector_call_with_only_a_server_token_or_a_gateway_reference_gets_no_decision(self):
        # find_refs reads no stored value in a server token (C27) or a gateway reference (C31), so the hook gives no
        # decision and no rewrite; what the server does with the text is not checked here
        server = {"name": "claude.ai Team GW", "source": "claudeai"}
        for text in (SREF, SERVER_TOKEN):
            with self.subTest(text=text):
                hso = self.pre("mcp__claude_ai_Team_GW__jira_write_actions", server, tool_input={"body": text})
                self.assertEqual(hso, {}, "no decision and no rewrite")


if __name__ == "__main__":
    unittest.main()
