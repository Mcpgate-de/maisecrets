"""The report of a subagent of this session passes the prompt hook; every other text with a value is blocked.

A subagent's report reaches the session as a prompt (<task-notification>). A report that quoted a value of
a secret's shape stopped the session until the person pasted it again (2026-09-29). The report passes only
when it proves itself against this session's files (hooks.agent_report). The tests below build a session
folder in a temp directory: a transcript, and the subagent's own transcript under `subagents/`.
"""
from __future__ import annotations

import html
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
VALUE = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"       # a fake token of the GitLab shape, built at run time
TOOL_USE = "toolu_01AgentReportTest"


def _line(rec: dict) -> str:
    return json.dumps(rec) + "\n"


class Session:
    """A session folder as Claude Code writes it: <id>.jsonl and <id>/subagents/agent-<n>.jsonl."""

    def __init__(self, root: Path, answer: str, tool: str = "Agent") -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.transcript = root / "s1.jsonl"
        self.transcript.write_text(_line({"type": "user", "message": {"content": "start"}}) + _line(
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": TOOL_USE, "name": tool, "input": {"prompt": "look"}}]}}),
            encoding="utf-8")
        sub = root / "s1" / "subagents"
        sub.mkdir(parents=True)
        self.output = sub / "agent-a1.jsonl"
        self.output.write_text(_line({"type": "assistant", "message": {"content": [
            {"type": "text", "text": "a first draft"}]}}) + _line({"type": "assistant", "message": {"content": [
                {"type": "text", "text": answer}]}}), encoding="utf-8")

    def notification(self, result: str, summary: str = "Agent finished", output: Path | None = None,
                     tool_use: str = TOOL_USE, status: str = "completed") -> str:
        return ("<task-notification>\n"
                "<task-id>a1</task-id>\n"
                f"<tool-use-id>{tool_use}</tool-use-id>\n"
                f"<output-file>{output or self.output}</output-file>\n"
                f"<status>{status}</status>\n"
                f"<summary>{html.escape(summary)}</summary>\n"
                f"<result>{html.escape(result)}</result>\n"
                "</task-notification>")


class AgentReportTests(unittest.TestCase):
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
        # a block starts a child that scrubs the transcript once the client wrote the prompt into it; these
        # transcripts are fixtures, and the child waited for a line that never comes
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-agent-report-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.answer = f"The CI file sets the token to {VALUE} in line 12."
        self.s = Session(self.dir, self.answer)

    def prompt(self, text: str, **extra) -> dict:
        payload = {"prompt": text, "session_id": "s1", "transcript_path": str(self.s.transcript), **CLAUDE}
        payload.update(extra)
        return hooks.user_prompt(payload)

    def assertBlocked(self, out: dict) -> None:  # noqa: N802 - unittest style
        self.assertEqual(out.get("decision"), "block", out)
        self.assertNotIn(VALUE, json.dumps(out))

    # the report passes -----------------------------------------------------
    def test_the_report_of_a_subagent_of_this_session_passes_and_nothing_is_stored(self):
        self.assertEqual(self.prompt(self.s.notification(self.answer)), {})
        self.assertEqual(Vault().list(), [], "a report passes without an entry")
        events = [json.loads(x) for x in Path(_TMP, "events.log").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events[-1]["outcome"], "passed: a subagent report")
        self.assertEqual({h["key"] for h in events[-1]["hits"]}, {"-"})
        self.assertNotIn(VALUE, Path(_TMP, "events.log").read_text(encoding="utf-8"))

    def test_an_answer_with_markup_passes_in_its_escaped_form(self):
        answer = f"<b>token</b> & {VALUE}"
        s = Session(self.dir / "m", answer)
        out = hooks.user_prompt({"prompt": s.notification(answer), "session_id": "s1",
                                 "transcript_path": str(s.transcript), **CLAUDE})
        self.assertEqual(out, {})

    def test_a_report_through_sendmessage_passes(self):
        s = Session(self.dir / "m", self.answer, tool="SendMessage")
        out = hooks.user_prompt({"prompt": s.notification(self.answer), "session_id": "s1",
                                 "transcript_path": str(s.transcript), **CLAUDE})
        self.assertEqual(out, {})

    # every other form is blocked --------------------------------------------
    def test_the_same_value_typed_as_text_is_blocked(self):
        self.assertBlocked(self.prompt(f"the token is {VALUE}"))

    def test_a_value_added_outside_the_result_is_blocked(self):
        # a real report pasted again, with a value in its summary: the result still matches
        other = "glpat-" + "Z9x8C7v6B5n4M3l2K1j0"
        self.assertBlocked(self.prompt(self.s.notification(self.answer, summary=f"done, key {other}")))
        self.assertBlocked(self.prompt(self.s.notification(self.answer) + f"\n{other}"))
        self.assertBlocked(self.prompt(f"{other}\n" + self.s.notification(self.answer)))

    def test_a_result_that_is_not_the_last_answer_is_blocked(self):
        for result in (self.answer + " and more", "a first draft " + VALUE, VALUE):
            with self.subTest(result=result):
                self.assertBlocked(self.prompt(self.s.notification(result)))

    def test_a_tool_use_id_the_transcript_does_not_give_to_an_agent_is_blocked(self):
        self.assertBlocked(self.prompt(self.s.notification(self.answer, tool_use="toolu_01Unknown")))
        s = Session(self.dir / "bash", self.answer, tool="Bash")      # a background command reports this way too
        out = hooks.user_prompt({"prompt": s.notification(self.answer), "session_id": "s1",
                                 "transcript_path": str(s.transcript), **CLAUDE})
        self.assertBlocked(out)

    def test_an_output_file_outside_the_subagents_folder_of_this_session_is_blocked(self):
        elsewhere = self.dir / "other.jsonl"
        elsewhere.write_text(self.s.output.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertBlocked(self.prompt(self.s.notification(self.answer, output=elsewhere)))
        # a path that climbs out of the folder is resolved first
        climbed = self.s.output.parent / ".." / ".." / "other.jsonl"
        self.assertBlocked(self.prompt(self.s.notification(self.answer, output=climbed)))
        # a link inside the folder that points out of it
        link = self.s.output.parent / "agent-link.jsonl"
        link.symlink_to(elsewhere)
        self.assertBlocked(self.prompt(self.s.notification(self.answer, output=link)))

    def test_a_report_of_another_session_is_blocked(self):
        other = Session(self.dir / "o", self.answer)
        self.assertBlocked(self.prompt(other.notification(self.answer)))

    def test_a_report_that_did_not_complete_is_blocked(self):
        self.assertBlocked(self.prompt(self.s.notification(self.answer, status="failed")))

    def test_two_notifications_in_one_prompt_are_blocked(self):
        one = self.s.notification(self.answer)
        self.assertBlocked(self.prompt(one + "\n" + one))

    def test_a_missing_transcript_is_blocked(self):
        self.assertBlocked(self.prompt(self.s.notification(self.answer), transcript_path=""))

    def test_the_setting_turns_the_pass_off(self):
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "pass_agent_reports": false}', encoding="utf-8")
        self.addCleanup(Path(_TMP, "config.json").write_text, CONFIG, encoding="utf-8")
        self.assertBlocked(self.prompt(self.s.notification(self.answer)))

    def test_codex_gets_no_pass(self):
        payload = {"prompt": self.s.notification(self.answer), "session_id": "s1",
                   "transcript_path": str(self.s.transcript), "turn_id": "t1", "model": "m"}
        self.assertBlocked(hooks.user_prompt(payload))


if __name__ == "__main__":
    unittest.main()
