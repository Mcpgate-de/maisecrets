"""A tool result takes a password of letters after a password label; a typed prompt does not (measurement branch)."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect, hooks  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

LETTERS = 'password = Some("qwmzpl"),'


class ToolChannelTests(unittest.TestCase):
    def kinds(self, text: str, channel: str = "prompt") -> list:
        return [m.kind for m in detect.scan(text, channel=channel)]

    def test_letters_after_a_password_label_are_a_hit_in_a_tool_result_only(self):
        self.assertEqual(self.kinds(LETTERS), [])
        self.assertEqual(self.kinds(LETTERS, "tool"), ["label-pw-literal"])

    def test_the_channel_of_one_scan_does_not_reach_the_next_scan_of_the_same_text(self):
        self.assertEqual(self.kinds(LETTERS, "tool"), ["label-pw-literal"])
        self.assertEqual(self.kinds(LETTERS), [], "the per-text cache must not serve the tool result to a prompt")
        self.assertEqual(self.kinds(LETTERS, "tool"), ["label-pw-literal"])

    def test_measures_durations_and_words_of_other_scripts_stay_text_in_a_tool_result(self):
        for v in ("95.5%", "12:30", "250W", "P90D", "Пароль"):
            with self.subTest(v=v):
                self.assertEqual(self.kinds(f'password = Some("{v}"),', "tool"), [])

    def test_a_word_only_the_tool_channel_takes_is_stored_weak_and_a_random_value_is_not(self):
        from maisecrets.vault import is_weak
        self.assertTrue(is_weak("label-pw-literal", "senha_atual", tool=True), "hunting it would block a prompt")
        self.assertTrue(is_weak("ds-keyword-colon", "Wartungs" + "fenster", tool=True), "a word in a tool result")
        self.assertFalse(is_weak("ds-keyword-colon", "Wartungs" + "fenster"), "a word the person typed stays hunted")
        self.assertFalse(is_weak("label-pw-literal", "qwmzpl", tool=True), "random letters are a secret everywhere")
        self.assertFalse(is_weak("label-pw-literal", "kwfrzmplt"), "the prompt rule takes it too: it stays hunted")
        self.assertFalse(is_weak("ds-keyword-colon", "qwmzpl"), "another rule found it: it stays hunted")

    def test_a_typed_prompt_with_letters_after_a_password_label_is_not_blocked(self):
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        hooks._live_cache.clear()
        out = hooks.user_prompt({"prompt": f"why does {LETTERS} not compile?", "session_id": "s7", **CLAUDE})
        self.assertNotEqual(out.get("decision"), "block", "a typed prompt keeps the prompt rule of 0.6.16")

    def test_post_tool_masks_the_value_in_a_read_result(self):
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)
        out = hooks.post_tool({"tool_name": "Read", "session_id": "s1", **CLAUDE,
                               "tool_input": {"file_path": "/repo/src/db.rs"},
                               "tool_response": {"type": "text", "file": {"filePath": "/repo/src/db.rs",
                                                                          "content": LETTERS + "\n"}}})
        self.assertNotIn("qwmzpl", json.dumps(out), "the Read result must not carry the value")
        self.assertIn("⟦SECRET_", json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
