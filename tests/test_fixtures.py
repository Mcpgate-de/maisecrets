"""A value that a label rule finds in test code is a fixture: no block, no placeholder. Token shapes and personal
data stay hits there.

A unit test holds passwords as fixtures (`PASS§WD = 'testPass'`, `KEY_PASS§WORD = "somepass"`: the Python standard
library, measured 2026-09-29). A label rule cannot tell them from a real password, and a block of the prompt or a
placeholder in the Read of the test only stopped the work. The test code is known by its path or by a test marker
in the 40 lines before the value.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import detect, hooks  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
PW = "Qx7vR2mK9pLw"                                   # a password shape after a label
TOKEN = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"             # a token shape, built at run time
TEST = (f"import pytest\n\n\ndef test_login(client):\n    pass§word = '{PW}'\n"
        "    assert client.login('bob', pass§word)\n")


def scan(text: str, path: str = "") -> list[tuple[str, str]]:
    text = text.replace("§", "")
    return [(m.type, m.value) for m in detect.scan(text) if not detect.is_fixture(m, text, path)]


class InTestCodeTests(unittest.TestCase):
    def test_a_label_value_in_test_code_is_a_fixture(self):
        self.assertEqual(scan(TEST), [])
        for marker in ("def test_login():", "    async def test_login(self):", "class TestLogin:", "@pytest.fixture",
                       "import unittest", "describe('login', () => {", "  it('logs in', async () => {",
                       "func TestLogin(t *testing.T) {", "#[test]", "@Test", "    self.assertTrue(ok)",
                       "    expect(res.status).toBe(200)"):
            with self.subTest(marker=marker):
                self.assertEqual(scan(f"{marker}\n    pass§word = '{PW}'\n"), [])

    def test_a_test_path_makes_the_whole_file_test_code(self):
        for path in ("tests/test_login.py", "/repo/test/login.py", "src/__tests__/login.js", "pkg/login_test.go",
                     "web/login.spec.ts", "web/login.test.js", "conftest.py", "C:\\repo\\tests\\settings.py",
                     "spec/fixtures/users.yml", "testdata/creds.json"):
            with self.subTest(path=path):
                self.assertEqual(scan(f"pass§word = '{PW}'\n", path), [])

    def test_a_grep_line_names_its_test_file(self):
        grep = f"tests/test_login.py:12:    pass§word = '{PW}'\nsrc/settings.py:3:pass§word = '{PW}x'\n"
        self.assertEqual(scan(grep), [("SECRET", PW + "x")])

    def test_outside_test_code_the_value_stays_a_hit(self):
        for path in ("src/settings.py", "config/prod.yml", "latest/settings.py", "contest.py", "attestation.py",
                     "", "docs/testing.md"):
            with self.subTest(path=path):
                self.assertEqual(scan(f"pass§word = '{PW}'\n", path), [("SECRET", PW)])
        # a marker more than 40 lines before the value does not count
        far = "def test_login():\n" + "x = 1\n" * 41 + f"pass§word = '{PW}'\n"
        self.assertEqual(scan(far), [("SECRET", PW)])
        near = "def test_login():\n" + "x = 1\n" * 38 + f"pass§word = '{PW}'\n"
        self.assertEqual(scan(near), [])
        # a marker after the value does not count
        self.assertEqual(scan(f"pass§word = '{PW}'\n\ndef test_login():\n    pass\n"), [("SECRET", PW)])

    def test_a_token_shape_and_personal_data_stay_hits_in_test_code(self):
        text = f"def test_login():\n    tok = '{TOKEN}'\n    mail = 'anna.berg@acme.de'\n"
        self.assertEqual(scan(text, "tests/test_login.py"), [("SECRET", TOKEN), ("EMAIL", "anna.berg@acme.de")])


class HookTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)

    def read(self, path: str, content: str) -> dict:
        return hooks.post_tool({"tool_name": "Read", "session_id": "s1", **CLAUDE, "tool_input": {"file_path": path},
                                "tool_response": {"type": "text", "file": {"filePath": path, "content": content}}})

    def test_a_pasted_test_passes_the_prompt_hook(self):
        out = hooks.user_prompt({"prompt": "why does this fail?\n" + TEST.replace("§", ""), "session_id": "s1",
                                 **CLAUDE})
        self.assertNotEqual(out.get("decision"), "block", out)
        self.assertFalse(Path(_TMP, "index.json").exists() and json.loads(Path(_TMP, "index.json").read_text())
                         .get("entries"), "a fixture is not stored")

    def test_the_same_value_outside_a_test_still_blocks(self):
        out = hooks.user_prompt({"prompt": f"password = '{PW}'", "session_id": "s1", **CLAUDE})
        self.assertEqual(out.get("decision"), "block")

    def test_a_read_of_a_test_file_keeps_its_fixtures(self):
        content = f"pass§word = '{PW}'\n".replace("§", "")
        self.assertEqual(self.read("/repo/tests/test_login.py", content), {})
        out = self.read("/repo/src/settings.py", content)
        self.assertNotIn(PW, json.dumps(out))

    def test_a_token_in_a_test_file_is_still_redacted(self):
        out = self.read("/repo/tests/test_login.py", f"tok = '{TOKEN}'\n")
        self.assertNotIn(TOKEN, json.dumps(out))


if __name__ == "__main__":
    unittest.main()
