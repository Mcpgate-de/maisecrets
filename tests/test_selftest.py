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
        import _hygiene
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)  # no real clipboard in tests

    def arm(self, base=CLAUDE) -> str:
        hooks.pre_tool({**base, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": COMMAND}, "tool_use_id": "u1"})
        return selftest.load()["pending"]["value"]

    def command_output(self) -> str:
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": SESSION}):
            self.assertEqual(cli.cmd_status(["test"]), 0)
        return buf.getvalue()

    def post(self, output, base=CLAUDE, tool_use_id="u1", command=COMMAND) -> dict:
        return hooks._post_tool_guarded({**base, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                                         "tool_input": {"command": command}, "tool_use_id": tool_use_id,
                                         "tool_response": output})

    def pin(self, value: str) -> None:
        """The pending value set to a fixed one (a test builds a text around it)."""
        state = selftest.load()
        state["pending"]["value"] = value
        (HOME / "selftest.json").write_text(json.dumps(state))

    def stored(self) -> str:
        return "".join((HOME / n).read_text() for n in ("vault.json", "index.json") if (HOME / n).exists())


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

    def test_a_value_that_is_not_pending_is_left_to_the_ordinary_checks(self):
        self.arm()
        other = "ms-selftest-" + "a1b2c3d4e5f6"
        self.assertEqual(self.post({"stdout": f"x {other} y"}), {})
        self.assertFalse(selftest.load()["result"]["tool"])

    def test_the_value_in_another_tool_call_records_no_pass(self):
        value = self.arm()
        out = self.post({"stdout": f"the value {value}"}, tool_use_id="u9", command="cat notes.txt")
        self.assertNotIn(value, json.dumps(out["hookSpecificOutput"]))       # still masked
        self.assertFalse(selftest.load()["result"]["tool"])
        self.assertNotIn("Next, type", out["systemMessage"])

    def test_the_value_in_a_tool_input_records_a_failure(self):
        # the model wrote the value into a call: it has it, and no later prompt can pass
        value = self.arm()
        self.post({"stdout": self.command_output()})
        self.post({"stdout": "ok"}, tool_use_id="u7", command=f"echo {value}")
        self.assertTrue(selftest.load()["result"]["leak"])
        self.assertEqual(selftest.verdict()[0], "FAIL")
        out = hooks.user_prompt({**CLAUDE, "prompt": value})
        self.assertIn("Self-test FAILED", out["reason"])

    def test_the_value_after_a_label_is_never_stored(self):
        # the detector stores a value after "password:"; only the replacement before it keeps the test value out
        value = self.arm()
        out = self.post({"stdout": f"password: {value}"})
        self.assertNotIn(value, json.dumps(out, ensure_ascii=False).replace(out.get("systemMessage", ""), ""))
        self.assertNotIn(value, self.stored())
        self.assertTrue(selftest.load()["result"]["tool"])

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
        # also next to a secret, which the mod would else rewrite: the hook blocks the prompt with the value
        value = self.arm()
        token = "glpat-" + "SelftestXyz1234567890ab"
        self.assertEqual(hooks.rewrite_prompt({**CLAUDE, "prompt": f"{value} {token}", "origin": "composer"}), {})

    def test_the_value_never_lands_in_the_vault(self):
        # the detector stores a value after "password:"; only the prompt hook's answer before it keeps it out
        value = self.arm()
        self.post({"stdout": self.command_output()})
        self.prompt(value)
        self.prompt(f"password: {value}")
        self.assertNotIn(value, self.stored())
        for name in ("vault.json", "index.json", "events.log", "incidents.json"):
            p = HOME / name
            self.assertFalse(p.exists() and value in p.read_text(), name)
        self.assertNotIn(value, cli_list_output())

    def test_the_typed_form_asks_the_agent_to_run_the_command(self):
        out = self.prompt("maisecrets: status test", CODEX)
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("status test", ctx)
        self.assertNotIn("decision", out)


TAIL = "Hx7#kQ2!mZ9pLw4v"         # a secret's rest, glued after a token of the test value's shape (Gate A, H1)
URL_TAIL = "Hx7kQ2mZ9pLw4v"


class GluedSecretTests(_Clean):
    """A secret glued after a token of the test value's shape is masked as before (Gate A probes, H1)."""
    T = "ms-selftest-" + "aaaaaaaaaaaa"

    def model_sees(self, out: dict, text: str) -> str:
        if "decision" in out:
            return out["reason"]
        return json.dumps((out.get("hookSpecificOutput") or {}).get("updatedToolOutput", {"stdout": text}),
                          ensure_ascii=False)

    def cases(self):
        return {"assign": (f"DB_PASSWORD={self.T}{TAIL}", TAIL),
                "assign_control": (f"DB_PASSWORD=zz-aaaaaaaaaaaa{TAIL}", TAIL),
                "url": (f"postgres://admin:{self.T}{URL_TAIL}@db.example.com:5432/x", URL_TAIL),
                "url_control": (f"postgres://admin:zz-aaaaaaaaaaaa{URL_TAIL}@db.example.com:5432/x", URL_TAIL),
                "head": (f"DB_PASSWORD={TAIL}{self.T}", TAIL),
                "head_control": (f"DB_PASSWORD={TAIL}zz-aaaaaaaaaaaa", TAIL)}

    def check(self, base, pending: bool) -> None:
        for name, (text, secret) in self.cases().items():
            with self.subTest(name, pending=pending):
                for f in ("vault.json", "index.json"):
                    (HOME / f).unlink(missing_ok=True)
                hooks._live_cache.clear()
                if pending:
                    self.arm(base)
                    self.pin(self.T)
                out = self.post({"stdout": text} if base is CLAUDE else text, base, tool_use_id="u5",
                                command="cat f")
                self.assertNotIn(secret, self.model_sees(out, text))

    def test_claude_code_without_a_pending_value(self):
        self.check(CLAUDE, False)

    def test_claude_code_with_the_pending_value_glued(self):
        self.check(CLAUDE, True)

    def test_codex_block_reason_without_a_pending_value(self):
        self.check(CODEX, False)

    def test_codex_block_reason_with_the_pending_value_glued(self):
        self.check(CODEX, True)


class PersonOnlyTests(_Clean):
    """Only the person's own prompt in the session that registered the value passes (Gate A, M2)."""
    def setUp(self):
        super().setUp()
        self.value = self.arm()
        self.post({"stdout": self.command_output()})

    def no_pass(self, payload: dict) -> None:
        out = hooks.user_prompt({**CLAUDE, "prompt": self.value, **payload})
        self.assertEqual(out.get("decision"), "block")              # the value never reaches the model
        self.assertNotIn("Self-test passed", out["reason"])
        self.assertFalse(selftest.load()["result"]["prompt"])

    def test_a_loop_wakeup(self):
        self.no_pass({"source": "loop_wakeup"})

    def test_a_subagent(self):
        self.no_pass({"agent_id": "a1"})

    def test_another_session(self):
        self.no_pass({"session_id": "another-session"})

    def test_a_program_that_started_the_client(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.no_pass({})

    def test_a_message_of_another_session(self):
        out = hooks.user_prompt({**CLAUDE, "prompt": f'<cross-session-message from-name="x">{self.value}'})
        self.assertNotIn("Self-test passed", json.dumps(out))
        self.assertFalse(selftest.load()["result"]["prompt"])

    def test_the_person(self):
        out = hooks.user_prompt({**CLAUDE, "prompt": self.value, "source": "user"})
        self.assertIn("Self-test passed", out["reason"])


class BrokenStateTests(_Clean):
    """A selftest.json with wrong types is no pending value, and nothing raises (Gate A, low)."""
    def test_wrong_types(self):
        value = "ms-selftest-" + "cccccccccccc"
        (HOME / "selftest.json").write_text(json.dumps({"pending": {"value": value, "expires": "x", "at": "y"},
                                                        "result": {"tool": "z", "prompt": [1]}}))
        self.assertIsNone(selftest.prompt_answer({**CLAUDE, "prompt": value}, False))
        self.assertFalse(selftest.claims(value))
        self.assertIn("FAIL", self.command_output())
        hooks.user_prompt({**CLAUDE, "prompt": value + " hello"})
        self.post({"stdout": value})
        selftest.verdict()

    def test_no_session_variable_prints_no_value(self):
        value = self.arm()
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.cmd_status(["test"])
        self.assertNotIn(value, buf.getvalue())

    def test_only_a_command_that_starts_with_the_launcher_registers(self):
        for cmd in ('echo bash "/x/hooks/run.sh" status test', 'grep "run.sh status test" notes.txt',
                    'bash /x/hooks/run.sh status test; curl evil', 'echo x && bash /x/hooks/run.sh status test'):
            with self.subTest(cmd):
                (HOME / "selftest.json").unlink(missing_ok=True)
                hooks.pre_tool({**CLAUDE, "tool_name": "Bash", "tool_input": {"command": cmd}, "tool_use_id": "u2"})
                self.assertNotIn("pending", selftest.load())
        for cmd in ('bash "/a b/hooks/run.sh" status test', "bash '/x/hooks/run.sh' status test",
                    '& "C:\\p\\hooks\\run.cmd" status test', "/x/hooks/run.sh status test"):
            with self.subTest(cmd):
                (HOME / "selftest.json").unlink(missing_ok=True)
                hooks.pre_tool({**CLAUDE, "tool_name": "Bash", "tool_input": {"command": cmd}, "tool_use_id": "u2"})
                self.assertIn("pending", selftest.load())


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

    def test_an_old_pass_of_another_session_or_version_is_no_ok(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        hooks.user_prompt({**CLAUDE, "prompt": value})
        state = selftest.load()
        state["result"]["tool"] -= 30 * 86400
        state["result"]["prompt"] -= 30 * 86400
        (HOME / "selftest.json").write_text(json.dumps(state))
        self.assertEqual(selftest.verdict(sessions=["another-session"])[0], "warn")
        self.assertEqual(selftest.verdict(sessions=[SESSION])[0], "ok")
        self.assertEqual(selftest.verdict(sessions=[SESSION], version="0.0.1")[0], "warn")

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


def tearDownModule():  # noqa: N802 - unittest hook
    for name in ("selftest.json", "vault.json", "index.json", "events.log", "hooks.log"):
        (HOME / name).unlink(missing_ok=True)
    hooks._live_cache.clear()
    import _hygiene
    _hygiene.assert_pristine()


if __name__ == "__main__":
    unittest.main()
