"""A word that a label rule took in a tool result blocks no later prompt; a random value and a word the person gives
in a prompt are still hunted everywhere, and every hunted value is still masked in a later tool result.

`password: Wartungsfenster` in a tool result stored the German word, and the store then hunted it: every later tool
result of every session showed a placeholder for the word, and a typed prompt about the maintenance window was
blocked, for a day (field report on 0.6.16, 2026-10-14). Each call below runs the real entry point (hooks/dispatch.py)
in a new process, as the client does.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CFG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
WORD = "Wartungs" + "fenster"          # German: maintenance window
FOREIGN = "Lieblings" + "farbe"       # German: favourite colour, an answer field only the tool channel takes
RANDOM = "xqzv" + "bnmq"               # random small letters (Codex review, 2026-09-29): a secret wherever it shows up
RANDOM_TOOL = "pozk" + "emva"          # random small letters only the tool channel takes; 8 letters, because a later
#                                        text of another session hunts a value of 8 characters and more (0.6.16 too)


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


class WordValuesNotHuntedTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        self.home = Path(tempfile.mkdtemp(prefix="word-hunt-", dir=_isolate.HOME))
        Path(self.home, "config.json").write_text(CFG)
        self.bin = Path(self.home, "bin")   # a blocked prompt copies its rewrite: a stand-in clipboard
        self.bin.mkdir()
        for name in ("pbcopy", "xclip", "clip"):
            Path(self.bin, name).write_text("#!/bin/sh\ncat > /dev/null\n")
            Path(self.bin, name).chmod(0o700)

    def hook(self, event: str, payload: dict) -> dict:
        env = {**os.environ, "MAISECRETS_HOME": str(self.home), "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def bash(self, stdout: str, session: str) -> str:
        out = self.hook("post-tool", {"tool_name": "Bash", "session_id": session, **CLAUDE,
                                      "tool_input": {"command": "x"},
                                      "tool_response": {"stdout": stdout, "stderr": "", "interrupted": False,
                                                        "isImage": False}})
        # no answer means the result goes to the model as it was: return that text, so assertNotIn can fail
        return json.dumps(out, ensure_ascii=False) if out else stdout

    def blocked(self, prompt: str, session: str) -> bool:
        return self.hook("user-prompt", {"prompt": prompt, "session_id": session, **CLAUDE}).get("decision") == "block"

    def test_a_word_after_a_password_label_in_a_tool_result_blocks_no_later_prompt(self):
        self.assertNotIn(WORD, self.bash(f"password: {WORD}\n", "s1"), "the result that held the label is redacted")
        self.assertFalse(self.blocked(f"Das {WORD} ist morgen ab 22 Uhr.", "s2"), "a prompt with the word is text")
        self.assertNotIn(WORD, self.bash(f"{WORD}: Montag 22 Uhr\n", "s3"), "a later tool result still masks it")

    def test_a_word_the_person_then_gives_after_a_label_is_hunted_in_prompts_again(self):
        self.bash(f"password: {WORD}\n", "s1")
        self.assertTrue(self.blocked(f"password: {WORD}", "s2"), "the label rule takes it in the prompt")
        self.assertTrue(self.blocked(f"Das {WORD} ist morgen.", "s3"), "from now on it is the person's password")

    def test_the_first_start_quiets_a_word_an_older_version_stored_and_keeps_a_random_value(self):
        self.assertTrue(self.blocked(f"password: {WORD}", "s1"))
        self.assertTrue(self.blocked(f"DB_PASSWORD={RANDOM}", "s1"))
        index = Path(self.home, "index.json")
        idx = json.loads(index.read_text())
        for meta in idx["entries"].values():
            meta.pop("quiet", None)                          # as 0.6.16 wrote them
        idx.pop("quiet_pass", None)
        index.write_text(json.dumps(idx))
        self.assertTrue(self.blocked(f"Das {WORD} ist morgen.", "s2"), "before the start: hunted as in 0.6.16")
        start = self.hook("session-start", {"session_id": "s3", **CLAUDE})
        self.assertIn("1 stored word(s) no longer block a prompt", start.get("systemMessage", ""))
        self.assertFalse(self.blocked(f"Das {WORD} ist morgen.", "s4"))
        self.assertTrue(self.blocked(f"the value is {RANDOM}", "s4"), "a random value is still hunted in prompts")
        self.assertNotIn("no longer block", self.hook("session-start", {"session_id": "s5", **CLAUDE})
                         .get("systemMessage", ""), "the pass runs once per store")

    def test_a_tool_result_after_a_failed_command_takes_the_tool_rule_too(self):
        out = self.hook("post-tool-failure", {"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                              "tool_input": {"command": "x"},
                                              "error": f'error: password = Some("{RANDOM_TOOL}"), rejected'})
        self.assertIn("systemMessage", out, out)
        self.assertTrue(self.blocked(f"the value is {RANDOM_TOOL}", "s2"), "stored from the failed output, hunted")

    def test_a_random_value_that_reads_like_a_word_is_still_masked_in_a_later_tool_result(self):
        value = "ppsm" + "ohsyeeub"     # random small letters of common letter pairs (Codex review, 2026-10-14)
        self.assertNotIn(value, self.bash(f"DB_PASSWORD={value}\n", "s1"))
        self.assertNotIn(value, self.bash(f"echo {value}\n", "s2"), "hunted in every later tool result")

    def test_a_word_only_the_tool_channel_takes_is_not_hunted_either(self):
        self.assertNotIn(FOREIGN, self.bash(f'password = Some("{FOREIGN}"),\n', "s1"))
        self.assertFalse(self.blocked(f"rename the field {FOREIGN} in the form", "s2"))

    def test_a_random_value_after_a_label_is_still_hunted_in_a_later_prompt(self):
        self.assertNotIn(RANDOM, self.bash(f"DB_PASSWORD={RANDOM}\n", "s1"))
        self.assertTrue(self.blocked(f"the value is {RANDOM}", "s2"), "a random value is a secret wherever it shows up")

    def test_a_random_value_only_the_tool_channel_takes_is_still_hunted(self):
        self.assertNotIn(RANDOM_TOOL, self.bash(f'password = Some("{RANDOM_TOOL}"),\n', "s1"))
        self.assertTrue(self.blocked(f"the value is {RANDOM_TOOL}", "s2"))


if __name__ == "__main__":
    unittest.main()
