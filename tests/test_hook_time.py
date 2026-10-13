"""The hook answers inside its time limit (0.6.15).

A regex search holds the GIL, so the thread watchdog could not answer while one backtracked; the client then ended
the hook at its timeout and let the output through. The watchdog now also arms a SIGALRM timer in the main thread.

Run: python3 -m unittest tests.test_hook_time -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402

# the scan of the hook replaced by a regex that backtracks for longer than any test runs, and holds the GIL meanwhile
SLOW_SCAN = (
    "import re, sys; sys.path.insert(0, sys.argv[1]); from maisecrets import detect, hooks\n"
    "def slow(*a, **k):\n"
    "    re.compile(r'(a|aa)+$').search('a' * 64 + '!')\n"
    "    return []\n"
    "detect.scan = slow\n"
    "sys.exit(hooks.main(['hook', sys.argv[2]]))\n")

BASH_OUTPUT = {"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t1",
               "tool_input": {"command": "cat notes.txt"},
               "tool_response": {"stdout": "some output", "stderr": "", "interrupted": False, "isImage": False}}


class TestWatchdogKnobTests(unittest.TestCase):
    """The test knob for the watchdog time cannot move the fail-closed answer past the client's timeout."""

    def seconds(self, knob, owned=None) -> float:
        home = tempfile.mkdtemp(prefix="maisecrets-knob-")
        self.addCleanup(shutil.rmtree, home, True)
        env = {"MAISECRETS_HOME": home, "MAISECRETS_TEST_HOME_OWNED": owned if owned is not None else home,
               "MAISECRETS_TEST_WATCHDOG": knob}
        with mock.patch.dict(os.environ, env):
            return hooks._test_watchdog_seconds(7.0)

    def test_a_short_time_in_the_test_home_counts(self):
        self.assertEqual(self.seconds("1.5"), 1.5)

    def test_a_long_or_odd_time_is_ignored(self):
        for knob in ("30", "6.5", "0", "-1", "nan", "inf", "soon"):
            with self.subTest(knob=knob):
                self.assertEqual(self.seconds(knob), 7.0)

    def test_a_marker_that_names_another_home_is_ignored(self):
        self.assertEqual(self.seconds("1.5", owned=tempfile.gettempdir()), 7.0)
        self.assertEqual(self.seconds("1.5", owned=""), 7.0)


@unittest.skipIf(os.name == "nt", "Windows has no SIGALRM: the thread watchdog stays alone there")
class SlowRegexWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="maisecrets-hook-time-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        (self.home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def run_hook(self, event: str, payload: dict, watchdog: str = "1.5"):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        env.update({"MAISECRETS_HOME": str(self.home), "MAISECRETS_TEST_HOME_OWNED": str(self.home),
                    "MAISECRETS_TEST_WATCHDOG": watchdog, "PYTHONDONTWRITEBYTECODE": "1"})
        started = time.monotonic()
        try:
            r = subprocess.run([sys.executable, "-c", SLOW_SCAN, str(ROOT), event], input=json.dumps(payload),
                               capture_output=True, text=True, env=env, timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("no answer within 10 s: the slow regex held the hook, and the client lets the output through")
        return r, time.monotonic() - started

    def test_a_slow_regex_in_a_tool_output_gets_the_fail_closed_answer_in_time(self):
        r, took = self.run_hook("post-tool", BASH_OUTPUT)
        self.assertEqual(r.returncode, 0, r.stderr)
        answer = json.loads(r.stdout)                # exactly one JSON object, or this raises
        withheld = answer["hookSpecificOutput"]["updatedToolOutput"]
        self.assertIn("took longer than 2s", withheld)          # the 1.5 s of the test, rounded by the message
        self.assertIn("its output is withheld", withheld)
        self.assertNotIn("some output", withheld)
        self.assertLess(took, 1.5 + 2.5, "the alarm answered inside the regex, before the client's timeout")

    def test_a_slow_regex_in_a_prompt_blocks_it_in_time(self):
        r, took = self.run_hook("user-prompt", {"session_id": "s1", "hook_event_name": "UserPromptSubmit",
                                                "prompt": "aaaa"})
        answer = json.loads(r.stdout)
        self.assertEqual(answer["decision"], "block")
        self.assertIn("took longer", answer["reason"])
        self.assertLess(took, 1.5 + 2.5)


@unittest.skipIf(os.name == "nt", "Windows has no SIGALRM")
class AlarmDisarmTests(unittest.TestCase):
    def test_a_hook_that_answers_leaves_no_alarm_and_the_old_handler_behind(self):
        import io
        import signal
        from unittest import mock

        from maisecrets import hooks
        before = signal.getsignal(signal.SIGALRM)
        payload = {"session_id": "s1", "hook_event_name": "UserPromptSubmit", "prompt": "hello"}
        with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(hooks.main(["hook", "user-prompt"]), 0)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), before)


if __name__ == "__main__":
    unittest.main()
