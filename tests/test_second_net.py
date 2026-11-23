"""The second net of the mod in Python (maisecrets/second_net.py): the marker of the tool-result hooks, and
mask_result's note on names that the name service did not check.

Run: python3 -m unittest tests.test_second_net -v
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import second_net  # noqa: E402


class MarkTests(unittest.TestCase):
    def test_the_marker_names_what_the_answer_did_and_leaves_codex_and_other_events_alone(self):
        self.assertEqual(second_net.mark({}, "post-tool")["hookSpecificOutput"],
                         {"hookEventName": "PostToolUse", "additionalContext": second_net.RESULT_CHECKED})
        masked = second_net.mark({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": "x",
                                                         "additionalContext": "note"}}, "post-tool")
        self.assertEqual(masked["hookSpecificOutput"]["additionalContext"], "note\n\n" + second_net.RESULT_MASKED)
        self.assertEqual(second_net.mark({"decision": "block", "reason": "r"}, "post-tool"),
                         {"decision": "block", "reason": "r"}, "a Codex answer stays as it is")
        self.assertEqual(second_net.mark({}, "pre-tool"), {}, "only the tool-result events")

    def test_only_the_mod_switches_the_marker_on(self):
        class Hooks:
            seen: list = []

            @staticmethod
            def _out(obj):
                Hooks.seen.append(obj)
        with mock.patch.dict(os.environ, {second_net.ENV: ""}):
            second_net.mark_answers(Hooks, "post-tool")
            Hooks._out({})
        with mock.patch.dict(os.environ, {second_net.ENV: "1"}):
            second_net.mark_answers(Hooks, "post-tool")
            Hooks._out({})
        self.assertEqual(Hooks.seen[0], {})
        self.assertEqual(Hooks.seen[1]["hookSpecificOutput"]["additionalContext"], second_net.RESULT_CHECKED)


class MaskResultTests(unittest.TestCase):
    def test_the_note_on_unchecked_names_goes_with_the_result(self):
        def add_note(payload, result, codex, load_config):
            return {**result, "hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                     "additionalContext": "names: not checked"}}
        with mock.patch("maisecrets.tool_withhold.with_unchecked_names", add_note):
            out = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": ["nothing here"]})
        self.assertEqual(out, {"texts": ["nothing here"], "changed": False, "note": "names: not checked"})

    def test_a_result_the_name_setting_withholds_is_withheld(self):
        def withhold(payload, result, codex, load_config):
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": "[withheld]"}}
        with mock.patch("maisecrets.tool_withhold.with_unchecked_names", withhold):
            out = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": ["a", "b"]})
        self.assertEqual(out, {"withheld": True})


if __name__ == "__main__":
    unittest.main()
