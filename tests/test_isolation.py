"""The isolation every other module relies on: no client environment, a temp dir of its own,
tripwires for the real tools, and a state check that sees a leak.

Inside a Codex session 28 tests failed and 5 errored, because the code takes a payload without
a client marker for Codex when any CODEX_ variable is set (Codex review of the suite, 2026-09-27).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
import _hygiene  # noqa: E402


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


class IsolationTests(unittest.TestCase):
    def test_no_client_variable_reaches_a_test_or_a_child(self):
        self.assertEqual(_isolate.client_variables(), [])
        code = ("import json, os, sys; sys.path.insert(0, sys.argv[1]); import _isolate; "
                "print(json.dumps(_isolate.client_variables(os.environ)))")
        r = subprocess.run([sys.executable, "-c", code, os.path.dirname(os.path.abspath(__file__))],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(json.loads(r.stdout), [], r.stderr)
        self.assertEqual(hooks.client_of({}), "claude", "a payload without a marker is Claude by default")
        with mock.patch.dict(os.environ, {"CODEX_SANDBOX": "seatbelt"}):
            self.assertIn("CODEX_SANDBOX", _isolate.client_variables())
            self.assertIn("client variables are set: CODEX_SANDBOX", "; ".join(_hygiene.state_problems()))

    def test_the_process_has_its_own_temp_dir_and_no_runtime_dir(self):
        self.assertEqual(tempfile.gettempdir(), _isolate.TMP)
        self.assertEqual(os.environ["TMPDIR"], _isolate.TMP)
        self.assertNotIn("XDG_RUNTIME_DIR", os.environ)
        self.assertTrue(hooks._run_dir().startswith(_isolate.TMP + os.sep))
        self.assertTrue(os.environ["CLAUDE_CONFIG_DIR"].startswith(_isolate.TMP + os.sep))

    @unittest.skipIf(os.name == "nt", "the tripwires are shell scripts")
    def test_a_real_tool_reached_by_a_test_is_seen(self):
        self.assertFalse(hooks._clipboard("fake-value-for-the-tripwire"), "the tripwire fails like a missing tool")
        problems = _hygiene.state_problems()
        tool = "pbcopy" if sys.platform == "darwin" else "xclip"
        self.assertTrue(any(f"a test ran a real tool: {tool}" in p for p in problems), problems)
        self.assertEqual(_hygiene.state_problems(), [], "reported once")

    def test_a_replaced_module_function_is_seen_until_it_is_restored(self):
        with mock.patch.object(hooks, "_clipboard", lambda t: True):
            self.assertTrue(any("hooks._clipboard" in p for p in _hygiene.state_problems()))
        with mock.patch.object(tempfile, "tempdir", "/elsewhere"):
            self.assertTrue(any("tempfile.tempdir" in p for p in _hygiene.state_problems()))
        self.assertEqual(_hygiene.state_problems(), [])


if __name__ == "__main__":
    unittest.main()
