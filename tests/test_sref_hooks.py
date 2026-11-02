"""Sensitive References through the hooks: a reference that an MCP result of the gateway showed in this session goes
into a Bash command as its value, from the resolver (sink process), and an echo of it comes back as the reference.
Against the fake gateway (harness/sref_server.py); synthetic values only."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks, sref_client as S  # noqa: E402
from maisecrets.vault import HOME, JsonFileBackend  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402
import test_sref_client as T  # noqa: E402

BASH = shutil.which("bash")
VALUE = "value-one@example.org"


@unittest.skipUnless(T.HAS_OPENSSL and BASH and os.name != "nt", "openssl and bash on POSIX")
class SrefBashTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        _hygiene.assert_children_ended()

    def setUp(self) -> None:
        _hygiene.watch_children(self)
        HOME.mkdir(parents=True, exist_ok=True)
        for name in ("sref", "vault-refs", "index.json", "vault.json", "audit.log"):
            p = HOME / name
            if p.is_dir():
                shutil.rmtree(p)
            elif p.exists():
                p.unlink()
        self.srv = T.SrefServer(cert=T._cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        (HOME / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": self.srv.cert}))
        self.profile = Path(tempfile.mkdtemp(prefix="sref-hooks-profile-"))
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.profile)})
        env.start()
        self.addCleanup(env.stop)
        (self.profile / ".claude.json").write_text(json.dumps(
            {"mcpServers": {"gw": {"type": "http", "url": self.srv.url + "/mcp"}}}))
        hooks._live_cache.clear()
        self.cfg = {"client_vault_cafile": self.srv.cert}
        self.found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.backend = JsonFileBackend()
        self.addCleanup(S.forget, self.backend, self.found["origin"])
        self.ref = self.srv.mint("email", VALUE)
        self.shown = self.ref[:-1] + ":va•••@example.org" + self.ref[-1]   # with the display part a gateway adds

    def login(self) -> None:
        helper = T.SrefClientTests("test_discovery_names_the_resolver_and_its_sinks")
        helper.srv = self.srv
        S.login(self.cfg, self.backend, self.found, helper.browser, wait=10)

    def result(self, session: str = "s1") -> None:
        """The MCP result of the gateway that shows the reference in this session."""
        hooks._post_tool_guarded({"tool_name": "mcp__gw__gitlab_read_actions", "session_id": session, **CLAUDE,
                                  "mcp_server": {"name": "gw", "source": "user"}, "tool_input": {"iid": 7},
                                  "tool_response": {"content": [{"type": "text", "text": "author: " + self.shown}]}})

    def bash(self, command: str, session: str = "s1") -> dict:
        hooks._live_cache.clear()
        return hooks.pre_tool({"tool_name": "Bash", "session_id": session, **CLAUDE,
                               "tool_input": {"command": command}})

    def test_the_value_reaches_the_command_and_the_gateway_learns_the_program(self):
        self.login()
        self.result()
        out = self.bash(f"printf 'got:%s' {self.shown}")
        command = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn(VALUE, command, "the command carries no value")
        run = subprocess.run([BASH, "-c", command], capture_output=True, text=True)
        self.assertEqual(run.stdout, "got:" + VALUE)
        self.assertEqual([(r["sink_type"], r["destination"], r["count"]) for r in self.srv.resolved],
                         [("process", "printf", 1)])

    def test_an_echo_of_the_value_comes_back_as_the_reference(self):
        self.login()
        self.result()
        self.bash(f"printf 'got:%s' {self.shown}")
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                        "tool_input": {"command": "cat out.txt"},
                                        "tool_response": {"stdout": f"got:{VALUE}\n", "stderr": ""}})
        upd = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)
        self.assertNotIn(VALUE, upd)
        self.assertIn(self.shown, upd)

    def test_another_session_gets_a_reason_and_the_gateway_is_not_asked(self):
        self.login()
        self.result("s1")
        out = self.bash(f"printf %s {self.shown}", session="s2")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("another session", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(self.srv.resolved, [])

    def test_without_a_login_the_command_does_not_run_and_names_the_login(self):
        self.result()
        out = self.bash(f"printf %s {self.shown}")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("/maisecrets:sref login", reason)
        self.assertNotIn(self.ref[6:-1].split(":")[-1], reason.replace(self.shown, ""), "no id beyond the reference")

    def test_the_audit_names_the_reference_without_its_id(self):
        self.login()
        self.result()
        self.bash(f"printf %s {self.shown}")
        audit = (HOME / "audit.log").read_text(encoding="utf-8") if (HOME / "audit.log").exists() else ""
        rid = self.ref.split(":")[2].rstrip(self.ref[-1])
        self.assertIn("sref:email:" + rid[:4], audit)
        self.assertNotIn(rid, audit)


if __name__ == "__main__":
    unittest.main()
