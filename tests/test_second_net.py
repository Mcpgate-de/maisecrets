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


KEY = bytes(range(32))          # a synthetic key of the marker; the real one lies in the home (net_key)
CALL = "toolu_01Synthetic"      # a tool_use_id of the form Claude Code gives


def setUpModule():
    # no band of a result that another test module checked in this process (#105, B11)
    from maisecrets import remote_layer
    remote_layer.NER_DOWN["band"] = None


def mac(kind, digest="", rest="", call=CALL, key=KEY):
    """The MAC as the mod computes it (claude-mod/maisecrets-mod.mjs markMac), written out here on its own."""
    import hashlib
    import hmac
    return hmac.new(key, "\n".join((kind, call, digest, rest)).encode(), hashlib.sha256).hexdigest()[:32]


class MarkTests(unittest.TestCase):
    def test_the_marker_carries_the_mac_of_the_call_and_for_masked_the_hash_of_the_output(self):
        self.assertEqual(second_net.mark({}, "post-tool", KEY, CALL)["hookSpecificOutput"],
                         {"hookEventName": "PostToolUse",
                          "additionalContext": f"[maisecrets: result checked {mac('checked')}]"})
        out = {"stdout": "a", "stderr": ""}
        h = second_net.output_hash(out)
        masked = second_net.mark({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": out,
                                                         "additionalContext": "note"}}, "post-tool", KEY, CALL)
        self.assertEqual(masked["hookSpecificOutput"]["additionalContext"],
                         f"note\n\n[maisecrets: result masked {mac('masked', h)} {h}]")
        self.assertEqual(second_net.mark({"decision": "block", "reason": "r"}, "post-tool", KEY, CALL),
                         {"decision": "block", "reason": "r"}, "a Codex answer stays as it is")
        self.assertEqual(second_net.mark({}, "pre-tool", KEY, CALL), {}, "only the tool-result events")

    def test_the_mac_binds_the_key_the_call_the_kind_and_the_hash(self):
        # a marker of another call, another key or another kind is another MAC: the mod counts it as none
        line = second_net.mark({}, "post-tool", KEY, CALL)["hookSpecificOutput"]["additionalContext"]
        for other in (second_net.mark({}, "post-tool", KEY, "toolu_01Other"),
                      second_net.mark({}, "post-tool", bytes(32), CALL)):
            self.assertNotEqual(other["hookSpecificOutput"]["additionalContext"], line)
        # the fixed vector of tests/mod.test.ts (PY_VECTOR): the mod's WebCrypto HMAC gives the same
        self.assertEqual(second_net.mac(KEY, "checked", CALL, "", ""), "43b2b70e03ea8ac3e769b2f0310bc432")
        self.assertNotEqual(mac("checked"), mac("masked"))
        self.assertNotEqual(mac("masked", "0" * 16), mac("masked", "1" * 16))
        self.assertNotIn(KEY.hex(), line)
        self.assertNotIn(KEY.hex()[:32], line)

    def test_a_call_without_a_well_formed_id_gets_no_marker(self):
        for call in (None, "", 7, "toolu_1\nchecked", "x" * 129, "toolu 1"):
            with self.subTest(call=call):
                self.assertEqual(second_net.mark({}, "post-tool", KEY, call), {})

    def test_the_marker_of_a_result_with_a_rest_carries_the_share_and_the_mode_only(self):
        # #105, B11: the mod's band reads them; a failed call never carries a rest of an earlier result
        from maisecrets import remote_layer
        with mock.patch.dict(remote_layer.NER_DOWN, {"band": (70, "rules")}):
            self.assertEqual(second_net.mark({}, "post-tool", KEY, CALL)["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {mac('checked', '', '70 rules')} rest 70 rules]")
            out = {"stdout": "a"}
            h = second_net.output_hash(out)
            masked = second_net.mark({"hookSpecificOutput": {"updatedToolOutput": out}}, "post-tool", KEY, CALL)
            self.assertEqual(masked["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result masked {mac('masked', h, '70 rules')} {h} rest 70 rules]")
            self.assertEqual(second_net.mark({}, "post-tool-failure", KEY, CALL)["hookSpecificOutput"]
                             ["additionalContext"], f"[maisecrets: result checked {mac('checked')}]")
        with mock.patch.dict(remote_layer.NER_DOWN, {"band": None}):
            self.assertEqual(second_net.mark({}, "post-tool", KEY, CALL)["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {mac('checked')}]")

    def test_the_hash_takes_the_strings_and_keys_in_a_fixed_order(self):
        # the mod computes the same (tests/mod.test.ts hashOf): keys sorted, each before its value, NUL between
        import hashlib
        want = hashlib.sha256("a\0x\0b\0y".encode()).hexdigest()[:16]
        self.assertEqual(second_net.output_hash({"b": "y", "a": ["x", 1, None]}), want)
        self.assertNotEqual(second_net.output_hash("x"), second_net.output_hash("y"))


class KeyTests(unittest.TestCase):
    """net_key: 32 random bytes in the maisecrets home, mode 600, made at the first use, never in a log."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.home = Path(tempfile.mkdtemp(prefix="ms-net-key-"))
        patcher = mock.patch("maisecrets.home.HOME", self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        import shutil
        self.addCleanup(shutil.rmtree, self.home, True)
        self.path = self.home / second_net.KEY_NAME

    def test_the_first_use_makes_the_key_with_mode_600_and_later_uses_read_the_same(self):
        key = second_net.net_key()
        self.assertEqual(len(key), 32)
        self.assertTrue(self.path.is_file())
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(second_net.net_key(), key)
        self.assertEqual([p.name for p in self.home.iterdir()], [second_net.KEY_NAME], "no temp file stays")

    def test_two_homes_get_two_keys(self):
        first = second_net.net_key()
        self.path.unlink()
        self.assertNotEqual(second_net.net_key(), first, "a new key is random, not derived")

    @unittest.skipUnless(os.name == "posix", "file modes")
    def test_a_key_file_that_others_may_read_gets_mode_600_again(self):
        second_net.net_key()
        os.chmod(self.path, 0o644)
        second_net.net_key()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_a_damaged_key_file_is_made_anew(self):
        self.home.mkdir(exist_ok=True)
        self.path.write_text("not a key\n", encoding="ascii")
        key = second_net.net_key()
        self.assertEqual(len(key), 32)
        self.assertEqual(self.path.read_text(encoding="ascii").strip(), key.hex())

    @unittest.skipUnless(os.name == "posix", "symbolic links")
    def test_a_link_in_place_of_the_key_file_is_not_followed(self):
        self.home.mkdir(exist_ok=True)
        target = self.home / "elsewhere"
        target.write_text("ab" * 32 + "\n", encoding="ascii")
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            second_net.net_key()

    def test_the_key_goes_into_no_answer_of_a_hook_and_no_log(self):
        # the hooks write the MAC only; mod-result gives the key on stdout to the mod alone
        key = second_net.net_key()
        with mock.patch.dict(os.environ, {second_net.ENV: second_net.ON}):
            h = MarkAnswersTests.hooks(None)
            second_net.mark_answers(h, "post-tool")
            h.post_tool({"tool_response": "x", "tool_use_id": CALL})
        text = repr(h.seen)
        self.assertIn("[maisecrets: result checked", text)
        self.assertNotIn(key.hex(), text)
        self.assertNotIn(key.hex()[:32], text)
        for p in self.home.iterdir():
            if p.name != second_net.KEY_NAME:
                self.assertNotIn(key.hex(), p.read_text(encoding="utf-8", errors="replace"), p.name)


class MarkAnswersTests(unittest.TestCase):
    def hooks(self):
        class Hooks:
            seen: list = []

            @staticmethod
            def _out(obj):
                Hooks.seen.append(obj)

            @staticmethod
            def post_tool(payload):
                Hooks._out({})
                return {}
        return Hooks

    def test_only_the_mod_switches_the_marker_on_with_its_literal_value(self):
        for value in ("", "1", "ON", "zz" * 16, "0123456789abcdef" * 2):
            with self.subTest(value=value), mock.patch.dict(os.environ, {second_net.ENV: value}), \
                    mock.patch.object(second_net, "net_key", return_value=KEY):
                h = self.hooks()
                second_net.mark_answers(h, "post-tool")
                h.post_tool({"tool_response": "x", "tool_use_id": CALL})
                self.assertEqual(h.seen, [{}])

    def test_a_payload_with_no_result_or_no_id_gets_no_marker(self):
        with mock.patch.dict(os.environ, {second_net.ENV: second_net.ON}), \
                mock.patch.object(second_net, "net_key", return_value=KEY):
            empty = self.hooks()
            second_net.mark_answers(empty, "post-tool")
            empty.post_tool({"session_id": "S1", "tool_use_id": CALL})
            self.assertEqual(empty.seen, [{}], "no tool_response: nothing was scanned")
            no_id = self.hooks()
            second_net.mark_answers(no_id, "post-tool")
            no_id.post_tool({"tool_response": "x"})
            self.assertEqual(no_id.seen, [{}], "no tool_use_id: no call to bind the MAC to")
            full = self.hooks()
            second_net.mark_answers(full, "post-tool")
            full.post_tool({"tool_response": "x", "tool_use_id": CALL})
            self.assertEqual(full.seen[0]["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {mac('checked')}]")

    def test_no_key_means_no_marker(self):
        with mock.patch.dict(os.environ, {second_net.ENV: second_net.ON}), \
                mock.patch.object(second_net, "net_key", side_effect=OSError("no home")):
            h = self.hooks()
            second_net.mark_answers(h, "post-tool")
            h.post_tool({"tool_response": "x", "tool_use_id": CALL})
            self.assertEqual(h.seen, [{}])


class MaskResultTests(unittest.TestCase):
    def test_the_note_on_unchecked_names_goes_with_the_result(self):
        def add_note(payload, result, codex, load_config):
            return {**result, "hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                     "additionalContext": "names: not checked"}}
        from maisecrets import remote_layer
        # a band of an earlier result in this process is not this result's (#105, B11)
        with mock.patch("maisecrets.tool_withhold.with_unchecked_names", add_note), \
                mock.patch.dict(remote_layer.NER_DOWN, {"band": (49, "rules")}):
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
