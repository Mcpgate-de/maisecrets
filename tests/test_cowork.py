"""Cowork (the Claude desktop app's Cowork tab) marks its sessions with CLAUDE_CODE_ENTRYPOINT=remote_cowork and knows
a plugin's commands by their short name only (maisecrets/cowork.py). Measured live on 2026-11-21: before the fix, a
command typed in Cowork showed nothing, and the status output named `/maisecrets:status test`, which Cowork answers
with "unknown skill".

Synthetic values only.
Run: python3 -m unittest tests.test_cowork -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cowork, hooks, prompt_commands  # noqa: E402
import _hygiene  # noqa: E402

SESSION = "0b6f1c2e-0000-4000-8000-0000000000c7"
COWORK = {"CLAUDE_CODE_ENTRYPOINT": cowork.ENTRYPOINT}


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


def _dispatch(*argv: str, env: dict, stdin: str = "") -> subprocess.CompletedProcess:
    full = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_ENTRYPOINT"}
    full.update(env, PYTHONUTF8="1")
    return subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), *argv], input=stdin,
                          capture_output=True, text=True, env=full, cwd=str(ROOT), timeout=120)


class ShortTests(unittest.TestCase):
    def test_each_long_command_name_becomes_the_short_one(self):
        self.assertEqual(cowork.short("→  /maisecrets:status test, then /maisecrets:sref login gw"),
                         "→  /status test, then /sref login gw")

    def test_other_text_stays(self):
        for text in ("maisecrets: list", "/maisecrets", "/maisecrets:", "plugin maisecrets:2"):
            self.assertEqual(cowork.short(text), text)

    def test_active_reads_the_entry_point(self):
        with mock.patch.dict(os.environ, COWORK):
            self.assertTrue(cowork.active())
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "cli"}):
            self.assertFalse(cowork.active())


class ModCommandTests(unittest.TestCase):
    """Cowork draws no dropped-prompt line: a typed command goes on to the command file, which shows its output."""

    def _mod(self, prompt: str) -> dict | None:
        hooks._live_cache.clear()
        return prompt_commands.mod_command({"prompt": prompt, "session_id": SESSION, "cwd": "", "origin": "composer"})

    def test_a_typed_command_is_answered_by_the_mod_outside_cowork(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "cli"}):
            self.assertIsNotNone(self._mod("/maisecrets:list"))

    def test_in_cowork_the_mod_leaves_it_to_the_command_file(self):
        with mock.patch.dict(os.environ, COWORK):
            self.assertIsNone(self._mod("/maisecrets:list"))


class HookAnswerTests(unittest.TestCase):
    """Cowork does not show a dropped prompt: the answer of a command the hook answers goes to the model to show."""

    def setUp(self):
        import test_mod_commands as tm
        self.tm = tm
        tm._reset()
        self.addCleanup(tm._reset)
        env = mock.patch.dict(os.environ, COWORK)
        env.start()
        self.addCleanup(env.stop)
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **k: None)

    def test_a_term_add_becomes_a_request_to_show_its_answer_without_the_term(self):
        out = self.tm._mod(f"maisecrets: term add {self.tm.NAME}")
        self.assertNotIn("drop", out)
        self.assertIn("on your list now", out["text"])
        self.assertTrue(out["text"].startswith(cowork._SHOW))
        self.assertIn("/term shows them", out["text"])
        self.assertNotIn("/maisecrets:", out["text"])
        self.assertNotIn(self.tm.NAME, out["text"], "the model gets the answer, never the term")
        masked = self.tm._mod(f"write to {self.tm.NAME} today")
        self.assertNotIn(self.tm.NAME, masked.get("text", self.tm.NAME), "the term was added")

    def test_a_value_in_an_answer_reaches_the_model_masked(self):
        token = "ghp_" + "R7kQ2mZx9VbT4nLp8WcY3sHd6FjA1uEo5GiN"
        out = cowork.show_answer({"session_id": self.tm.SESSION, "cwd": "", "origin": "composer"},
                                 f"maisecrets: done with {token}")
        self.assertNotIn(token, out["text"])
        self.assertIn("done with", out["text"])

    def test_the_request_reads_as_no_command_to_the_prompt_hook(self):
        out = self.tm._mod(f"maisecrets: term add {self.tm.NAME}")
        self.assertIsNone(prompt_commands.mod_command({"prompt": out["text"], "session_id": self.tm.SESSION,
                                                       "cwd": "", "origin": "composer"}))
        hooks._live_cache.clear()
        out = hooks.user_prompt({"prompt": out["text"], "session_id": self.tm.SESSION, "cwd": "",
                                 "prompt_id": "t", "transcript_path": ""})
        self.assertNotEqual(out.get("decision"), "block", out)


class OutputTests(unittest.TestCase):
    def test_the_status_output_names_the_short_commands_in_cowork(self):
        r = _dispatch("status", env=COWORK)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/status all", r.stdout)
        self.assertNotIn("/maisecrets:", r.stdout + r.stderr)

    def test_the_status_output_keeps_the_long_names_elsewhere(self):
        r = _dispatch("status", env={})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/maisecrets:status all", r.stdout)

    def test_a_tool_hook_keeps_the_tool_output_as_it_is(self):
        # a file that names a command (a README, a command file) reaches the model unchanged, so an edit of it matches
        token = "ghp_" + "R7kQ2mZx9VbT4nLp8WcY3sHd6FjA1uEo5GiN"     # a token shape the hook masks, so it answers
        text = f"run /maisecrets:status test to check it\ntoken={token}"
        payload = {"session_id": SESSION, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                   "tool_input": {"command": "cat README.md"}, "tool_response": {"stdout": text, "stderr": ""},
                   "cwd": str(ROOT)}
        r = _dispatch("post-tool", env=COWORK, stdin=json.dumps(payload))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(token, r.stdout)
        self.assertIn("/maisecrets:status test", r.stdout)


if __name__ == "__main__":
    unittest.main()
