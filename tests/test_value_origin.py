"""The permission prompt names where a value came from that maisecrets masked by itself (#108).

A gateway answer carried an 8-digit hex `grade_token`; the label rule masked it, and the next call of the same
server sent it back. The prompt asked the person to "check the target and the value", for a value the person never
stored. Now the store keeps the tool and the key of a new entry from a tool result, and the prompt names them.

Run: python3 -m unittest tests.test_value_origin -v
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
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import hooks, value_origin  # noqa: E402
from maisecrets.placeholder import find_refs  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
TOKEN = "9f3e" + "21ab"                 # an 8-digit hex token, built here so the tree scan sees no secret shape
SERVER_READ = "mcp__gw__notes_read"
SERVER_WRITE = "mcp__gw__notes_write"
OWN = "Kx7Qp2" + "Zr9Lm4Wn"


class FoundTests(unittest.TestCase):
    def test_the_key_before_a_value_is_named(self):
        class M:
            def __init__(self, start):
                self.start = start
        for text, key in ((f'{{"grade_token": "{TOKEN}"}}', "grade_token"), (f"token={TOKEN}", "token"),
                          (f"api_key: '{TOKEN}'", "api_key"), (f"the value {TOKEN}", None)):
            with self.subTest(text=text):
                self.assertEqual(value_origin.found(text, [M(text.index(TOKEN))], "t"), [("t", key)])


class PromptTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)

    def result(self, text: str, tool: str = SERVER_READ) -> str:
        """The masked text of an MCP result, and its placeholder."""
        hooks._live_cache.clear()
        out = hooks.post_tool({"tool_name": tool, "session_id": "S1", **CLAUDE, "tool_input": {"id": "n1"},
                               "tool_response": [{"type": "text", "text": text}]})
        masked = json.dumps(out, ensure_ascii=False)
        self.assertNotIn(TOKEN, masked, "the token is masked in the result")
        refs = [k for k, _a, _b in find_refs(masked)]
        self.assertTrue(refs, masked[:300])
        return refs[0]

    def ask(self, tool: str, tool_input: dict) -> str:
        hooks._live_cache.clear()
        payload = {"tool_name": tool, "tool_input": tool_input, "session_id": "S1", "transcript_path": "", **CLAUDE}
        with mock.patch.object(hooks, "load_config", return_value={**hooks.load_config(), "rehydration": "confirm"}):
            hso = hooks.pre_tool(payload).get("hookSpecificOutput", {})
        self.assertEqual(hso.get("permissionDecision"), "ask", hso)
        reason = hso["permissionDecisionReason"]
        self.assertNotIn(TOKEN, reason, "a reason never names the value")
        return reason

    def test_the_store_keeps_the_tool_and_the_key(self):
        key = self.result(f'{{"note_id": "n1", "grade_token": "{TOKEN}"}}')
        meta = Vault().origin(key)
        self.assertEqual((meta.get("found_in"), meta.get("found_at")), (SERVER_READ, "grade_token"))

    def test_a_value_sent_back_to_the_same_server_names_its_origin(self):
        key = self.result(f'{{"note_id": "n1", "grade_token": "{TOKEN}"}}')
        reason = self.ask(SERVER_WRITE, {"action": "grade", "token": f"⟦{key}⟧"})
        self.assertIn(f"You did not store ⟦{key}⟧: maisecrets masked it by itself", reason)
        self.assertIn("(key grade_token in a result of notes_read on gw)", reason)
        self.assertIn("This call sends it back to the same server.", reason)
        self.assertNotIn("Check the target and the value", reason, "no request to check a value the person never had")

    def test_a_value_sent_to_another_server_asks_whether_that_place_may_get_it(self):
        key = self.result(f'{{"grade_token": "{TOKEN}"}}')
        reason = self.ask("mcp__other__post", {"token": f"⟦{key}⟧"})
        self.assertIn("This call sends it to another place than the one that sent it.", reason)
        self.assertNotIn("back to the same server", reason)

    def test_a_stored_value_keeps_the_old_text(self):
        ref = Vault().put(OWN, "SECRET", "manual", session="S1").ref
        reason = self.ask(SERVER_WRITE, {"token": ref})
        self.assertTrue(reason.endswith(" Check the target and the value before you allow it."), reason)
        self.assertNotIn("You did not store", reason)

    def test_a_value_the_person_gives_later_is_the_persons_own(self):
        # put: /maisecrets put and the CLI; put_many without tool: a value found in a prompt the person typed
        for give in (lambda v: v.put(TOKEN, "SECRET", "manual", session="S1"),
                     lambda v: v.put_many([(TOKEN, "SECRET", "manual")], session="S1")):
            with self.subTest(give=give):
                self.setUp()
                key = self.result(f'{{"grade_token": "{TOKEN}"}}')
                give(Vault())
                reason = self.ask(SERVER_WRITE, {"token": f"⟦{key}⟧"})
                self.assertNotIn("You did not store", reason)
                self.assertIn("Check the target and the value", reason)


if __name__ == "__main__":
    unittest.main()
