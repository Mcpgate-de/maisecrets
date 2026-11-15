"""The self-test (maisecrets/selftest.py): /maisecrets:status test proves the tool-result path and the prompt path in
the real client. The PreToolUse hook registers the value, the PostToolUse hook masks it and records the tool path, the
prompt hook answers "passed" only for the pending value, and the value never lands in the vault.

Run: python3 -m unittest tests.test_selftest -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, hooks, selftest  # noqa: E402

HOME = Path(os.environ["MAISECRETS_HOME"])
SESSION = "selftest-session-1"
COMMAND = 'bash "/x/maisecrets/hooks/run.sh" status test'
CLAUDE = {"prompt_id": "p1", "session_id": SESSION, "transcript_path": "", "cwd": "/tmp"}
CODEX = {"turn_id": "t1", "model": "m", "session_id": SESSION, "transcript_path": "", "cwd": "/tmp"}


class _Clean(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        for name in ("selftest.json", "vault.json", "index.json", "events.log", "incidents.json"):
            (HOME / name).unlink(missing_ok=True)
        hooks._live_cache.clear()

    def arm(self, base=CLAUDE) -> str:
        hooks.pre_tool({**base, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": COMMAND}, "tool_use_id": "u1"})
        return selftest.load()["pending"]["value"]

    def command_output(self) -> str:
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": SESSION}):
            self.assertEqual(cli.cmd_status(["test"]), 0)
        return buf.getvalue()

    def post(self, output, base=CLAUDE) -> dict:
        return hooks._post_tool_guarded({**base, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                                         "tool_input": {"command": COMMAND}, "tool_use_id": "u1",
                                         "tool_response": output})


class RegisterTests(_Clean):
    def test_the_tool_call_hook_registers_a_fresh_value_that_names_itself(self):
        value = self.arm()
        self.assertRegex(value, r"\Ams-selftest-[a-z0-9]{12}\Z")
        self.assertNotEqual(value, self.arm())

    def test_another_command_registers_nothing(self):
        hooks.pre_tool({**CLAUDE, "tool_name": "Bash", "tool_input": {"command": "echo status test"},
                        "tool_use_id": "u2"})
        self.assertNotIn("pending", selftest.load())

    def test_the_command_prints_the_value_only_after_its_hook_registered_it(self):
        out = self.command_output()
        self.assertIn("FAIL", out)
        self.assertNotIn("ms-selftest-", out.replace("starts with ms-selftest-", ""))
        value = self.arm()
        self.assertIn(value, self.command_output())

    def test_a_registration_of_another_session_prints_no_value(self):
        value = self.arm({**CLAUDE, "session_id": "other-session"})
        out = self.command_output()
        self.assertNotIn(value, out)
        self.assertIn("FAIL", out)

    def test_codex_started_from_claude_code_finds_its_own_thread(self):
        # Codex passes on the Claude Code session variable of the shell that started it (harness, codex-cli 0.169.0)
        value = self.arm(CODEX)
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "outer-claude-session",
                                                                "CODEX_THREAD_ID": SESSION}):
            cli.cmd_status(["test"])
        self.assertIn(value, buf.getvalue())

    def test_a_registration_older_than_a_minute_prints_no_value(self):
        value = self.arm()
        state = selftest.load()
        state["pending"]["at"] -= selftest.ARMED + 5
        (HOME / "selftest.json").write_text(json.dumps(state))
        self.assertNotIn(value, self.command_output())


class ToolPathTests(_Clean):
    def test_the_tool_result_hook_masks_the_value_and_records_the_tool_path(self):
        value = self.arm()
        out = self.post({"stdout": self.command_output(), "stderr": "", "interrupted": False})
        model_sees = json.dumps(out["hookSpecificOutput"], ensure_ascii=False)
        self.assertNotIn(value, model_sees)
        self.assertIn(selftest.PLACEHOLDER, model_sees)
        self.assertIn(value, out["systemMessage"])                  # the person sees it
        self.assertTrue(selftest.load()["result"]["tool"])

    def test_codex_gets_a_block_whose_reason_holds_the_placeholder_only(self):
        value = self.arm(CODEX)
        out = self.post(f"the value: {value}\n", CODEX)
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(value, out["reason"])
        self.assertIn(selftest.PLACEHOLDER, out["reason"])
        self.assertTrue(selftest.load()["result"]["tool"])

    def test_a_value_that_is_not_pending_is_masked_but_records_nothing(self):
        self.arm()
        other = "ms-selftest-" + "a1b2c3d4e5f6"
        out = self.post({"stdout": f"x {other} y"})
        self.assertNotIn(other, json.dumps(out["hookSpecificOutput"]))
        self.assertFalse(selftest.load()["result"]["tool"])

    def test_the_value_and_the_rest_of_the_output_are_never_stored(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        for name in ("vault.json", "index.json", "events.log", "incidents.json"):
            p = HOME / name
            self.assertFalse(p.exists() and value in p.read_text(), name)
        self.assertNotIn(value, cli_list_output())


class PromptPathTests(_Clean):
    def prompt(self, text: str, base=CLAUDE) -> dict:
        return hooks.user_prompt({**base, "hook_event_name": "UserPromptSubmit", "prompt": text})

    def test_the_pending_value_is_blocked_and_answered_passed(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        out = self.prompt(value)
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(out["reason"], "Self-test passed: the prompt hook ran, and the model did not get the value.")
        self.assertTrue(selftest.load()["result"]["prompt"])

    def test_codex_gets_the_block_answer(self):
        value = self.arm(CODEX)
        self.post(value, CODEX)
        out = self.prompt(value, CODEX)
        self.assertEqual(out, {"decision": "block", "reason": "Self-test passed: the prompt hook ran, and the model "
                                                                "did not get the value."})

    def test_without_the_tool_path_the_answer_does_not_say_passed_for_both(self):
        value = self.arm()
        out = self.prompt(value)
        self.assertEqual(out["decision"], "block")
        self.assertNotIn("Self-test passed:", out["reason"])

    def test_an_unknown_value_gets_no_passed(self):
        self.arm()
        out = self.prompt("ms-selftest-" + "zzzzzzzzzzzz")
        self.assertNotIn("Self-test", json.dumps(out))
        self.assertFalse(selftest.load()["result"]["prompt"])

    def test_an_expired_value_gets_no_passed(self):
        value = self.arm()
        state = selftest.load()
        state["pending"]["expires"] = time.time() - 1
        (HOME / "selftest.json").write_text(json.dumps(state))
        out = self.prompt(value)
        self.assertNotIn("Self-test", json.dumps(out))

    def test_without_a_registration_a_value_gets_no_passed(self):
        out = self.prompt("ms-selftest-" + "abcdefabcdef")
        self.assertNotIn("Self-test", json.dumps(out))

    def test_a_secret_next_to_an_unknown_test_value_is_still_blocked(self):
        token = "glpat-" + "SelftestXyz1234567890ab"
        out = self.prompt(f"ms-selftest-{'b' * 12} {token}")
        self.assertEqual(out.get("decision"), "block")
        self.assertNotIn("Self-test", out["reason"])

    def test_the_mod_leaves_the_pending_value_to_the_hook(self):
        value = self.arm()
        self.assertEqual(hooks.rewrite_prompt({**CLAUDE, "prompt": value, "origin": "composer"}), {})

    def test_the_value_never_lands_in_the_vault(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        self.prompt(value)
        self.prompt(f"please look at {value}")
        for name in ("vault.json", "index.json", "events.log", "incidents.json"):
            p = HOME / name
            self.assertFalse(p.exists() and value in p.read_text(), name)
        self.assertNotIn(value, cli_list_output())

    def test_the_typed_form_asks_the_agent_to_run_the_command(self):
        out = self.prompt("maisecrets: status test", CODEX)
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("status test", ctx)
        self.assertNotIn("decision", out)


class VerdictTests(_Clean):
    def test_not_run(self):
        self.assertEqual(selftest.verdict()[0], "warn")

    def test_both_paths(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        hooks.user_prompt({**CLAUDE, "prompt": value})
        state, text = selftest.verdict()
        self.assertEqual(state, "ok")
        self.assertIn("passed", text)

    def test_tool_path_only_while_pending(self):
        self.arm()
        self.post({"stdout": self.command_output()})
        self.assertEqual(selftest.verdict()[0], "warn")

    def test_pending_and_never_masked_fails(self):
        self.arm()
        self.assertEqual(selftest.verdict()[0], "FAIL")


def cli_list_output() -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            cli.main(["list"])
        except SystemExit:
            pass
    return buf.getvalue()


if __name__ == "__main__":
    unittest.main()
