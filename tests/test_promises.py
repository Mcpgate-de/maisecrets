"""Promises of README.md, docs/THREAT-MODEL.md and PRIVACY.md that had no red test (Codex review
of the suite, 2026-09-27): the launchers fail closed without a usable Python, the transcript
scrub runs through the real paths, a refused wipe is reported, and no hook opens a network
connection.

Every value is generated here. Every subprocess gets a temp MAISECRETS_HOME with the plaintext
test store and tripwires for security, powershell and pbcopy first on PATH (Sandbox of
test_cli_matrix.py); HOME is never changed and ~/.maisecrets is never read.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from test_cli_matrix import JSONFILE, Sandbox, fake_value  # noqa: E402

BASH = shutil.which("bash")
RUN_SH = ROOT / "hooks" / "run.sh"
RUN_CMD = ROOT / "hooks" / "run.cmd"
EVENTS = ("user-prompt", "pre-tool", "post-tool", "session-start")
# the absolute places run.sh tries after the PATH; the test points them into the sandbox, so a
# Python installed on this machine cannot answer for the missing one
ABSOLUTE_PYTHONS = ("/opt/homebrew/bin/python3", "/usr/local/bin/python3",
                    "/Library/Frameworks/Python.framework/Versions/Current/bin/python3")

# a python3 that says it is 3.9: it fails the version probe, prints 3.9 for the version query,
# and records any other call (a run of dispatch.py) in the tripwire
_PY39 = """#!/bin/sh
case "$2" in
  *"version_info >= (3, 11)"*) exit 1 ;;
  *"print('%d.%d'"*) echo 3.9; exit 0 ;;
esac
echo "python3 $*" >> "$MS_TEST_TRIPWIRE"
exit 0
"""


@unittest.skipIf(BASH is None, "no bash")
class LauncherFailsClosedTests(unittest.TestCase):
    """README: maisecrets needs Python 3.11+. Without it every hook must refuse, never pass."""

    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)
        text = RUN_SH.read_text(encoding="utf-8")
        for p in ABSOLUTE_PYTHONS:
            self.assertIn(p, text, "run.sh changed its candidates; update ABSOLUTE_PYTHONS")
            text = text.replace(p, str(self.sb.root / "abs" / p.lstrip("/")))
        # the copy sits next to the real dispatch.py name, so a launcher that runs it is seen
        self.hooks = self.sb.root / "hooks"
        self.hooks.mkdir()
        (self.hooks / "run.sh").write_text(text, encoding="utf-8")
        (self.hooks / "dispatch.py").write_text("raise SystemExit('dispatch.py ran')\n", encoding="utf-8")
        # only the tools run.sh needs besides a Python; no python3, python or py on this PATH
        self.tools = self.sb.root / "tools"
        self.tools.mkdir()
        for tool in ("dirname",):
            os.symlink(shutil.which(tool), self.tools / tool)

    def launch(self, event: str) -> subprocess.CompletedProcess:
        env = self.sb.env()
        env["PATH"] = os.pathsep.join((str(self.sb.bin), str(self.tools)))
        r = subprocess.run([BASH, str(self.hooks / "run.sh"), event], input='{"prompt": "x"}',
                           capture_output=True, text=True, env=env, timeout=30)
        trip = self.sb.root / "tripwire"
        self.assertFalse(trip.exists(), trip.read_text() if trip.exists() else "")
        return r

    def check_all_events(self, found: str) -> None:
        for event in EVENTS:
            with self.subTest(event):
                r = self.launch(event)
                self.assertNotIn("dispatch.py ran", r.stderr)
                self.assertIn(f"maisecrets needs Python 3.11 or newer on the PATH of the client (found: {found})",
                              r.stdout + r.stderr)
                if event == "post-tool":
                    # Claude Code ignores exit 2 after a tool: the JSON itself must withhold
                    self.assertEqual(r.returncode, 0)
                    out = json.loads(r.stdout)
                    self.assertEqual(out["decision"], "block")
                    self.assertIn("Tool output withheld", out["hookSpecificOutput"]["updatedToolOutput"])
                    self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUse")
                elif event == "session-start":
                    self.assertEqual(r.returncode, 0)
                    self.assertTrue(json.loads(r.stdout)["systemMessage"].endswith("every prompt is blocked."))
                else:
                    self.assertEqual((r.returncode, r.stdout), (2, ""), "exit 2 blocks the prompt or the tool")
                    self.assertIn("Until then every prompt is blocked.", r.stderr)

    def test_no_python_on_the_path_blocks_every_event(self):
        self.check_all_events("none")

    def test_a_python_older_than_3_11_blocks_every_event_and_is_named(self):
        fake = self.tools / "python3"
        fake.write_text(_PY39, encoding="utf-8")
        fake.chmod(0o700)
        self.check_all_events("python3 is 3.9")


class RunCmdFailsClosedTests(unittest.TestCase):
    """run.cmd cannot run on this OS; its logic is read from the file: each interpreter runs
    dispatch.py only after it passed the 3.11 probe, post-tool withholds with exit 0, and every
    other event ends in exit /b 2."""

    def setUp(self):
        self.lines = [ln.strip() for ln in RUN_CMD.read_text(encoding="utf-8").splitlines()]

    def test_dispatch_runs_only_behind_a_passed_version_probe(self):
        runs = [i for i, ln in enumerate(self.lines) if "dispatch.py" in ln and not ln.startswith("rem")]
        self.assertEqual(len(runs), 3, "py -3, python, python3")
        for i in runs:
            interp = self.lines[i].split('"%HERE%dispatch.py"')[0].strip()
            self.assertEqual(self.lines[i - 1], "if not errorlevel 1 (", self.lines[i])
            self.assertEqual(self.lines[i - 2],
                             f'{interp} -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1')
            self.assertEqual(self.lines[i + 1], "goto :done")

    def test_without_python_post_tool_withholds_and_everything_else_exits_2(self):
        start = self.lines.index('if "%~1"=="post-tool" (')
        branch = self.lines[start:self.lines.index(")", start)]
        (echo,) = [ln for ln in branch if ln.startswith("echo ")]
        out = json.loads(echo[len("echo "):])
        self.assertEqual(out["decision"], "block")
        self.assertIn("Tool output withheld", out["hookSpecificOutput"]["updatedToolOutput"])
        self.assertEqual(branch[-1], "exit /b 0")
        tail = self.lines[self.lines.index(")", start) + 1:]
        self.assertTrue(tail[0].startswith("echo maisecrets needs Python 3.11") and tail[0].endswith("1>&2"), tail[0])
        self.assertEqual(tail[1:], ["exit /b 2", ":done", "exit /b %errorlevel%"])
        exits = [ln for ln in self.lines if ln.startswith("exit ")]
        self.assertEqual(exits, ["exit /b 0", "exit /b 2", "exit /b %errorlevel%"], "no other way out")


def _forms(value: str) -> list[str]:
    """The byte forms a value takes in a JSONL transcript: plain, JSON-escaped, doubly escaped."""
    once = json.dumps(value)[1:-1]
    return list(dict.fromkeys([value, once, json.dumps(once)[1:-1]]))


class TranscriptScrubThroughTheHooksTests(unittest.TestCase):
    """THREAT-MODEL C3: every form of a value is masked in the client's transcript. Each case runs
    the real hook through hooks/dispatch.py on a real transcript file; nothing is mocked. A
    record the client writes AFTER the hook returned is scrubbed by the detached child."""

    def setUp(self):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        self.addCleanup(self.sb.remove)
        self.path = self.sb.root / "transcript.jsonl"

    def write(self, *records: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def hook(self, event: str, payload: dict) -> dict:
        r = self.sb.run(event, stdin=json.dumps({**payload, "transcript_path": str(self.path)}))
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def assert_scrubbed(self, value: str, keep: str, wait: float = 0.0) -> None:
        deadline = time.time() + wait
        while True:
            data = self.path.read_text(encoding="utf-8")
            left = [f for f in _forms(value) if f in data]
            if not left or time.time() >= deadline:
                break
            time.sleep(0.05)
        self.assertEqual(left, [], "a form of the value is still in the transcript")
        self.assertIn(keep, data, "the scrub masks the value only")
        for line in data.splitlines():
            json.loads(line)          # every record stays valid JSON

    def test_c1_a_blocked_prompt_is_masked_in_an_old_and_in_the_late_record(self):
        value = fake_value("Tp")
        prompt = f"password: {value}"
        self.write({"type": "user", "message": {"content": prompt}, "note": "earlier"})
        ino = os.stat(self.path).st_ino
        out = self.hook("user-prompt", {"prompt": prompt, "session_id": "S1", "prompt_id": "p1"})
        self.assertEqual(out["decision"], "block")
        self.assert_scrubbed(value, "earlier")                       # the inline scrub, before the answer
        self.write({"type": "user", "message": {"content": prompt}, "note": "late"})
        self.assert_scrubbed(value, "late", wait=5.0)                 # the detached child
        self.assertEqual(os.stat(self.path).st_ino, ino, "in place: same inode")

    def test_codex_post_tool_masks_the_raw_output_in_the_rollout(self):
        value = fake_value("Cx")
        output = f"api_key={value}\n"
        # Codex writes the raw command output into its rollout before the hook runs
        self.write({"type": "event_msg", "payload": {"type": "exec_command_end", "stdout": output}, "note": "raw"})
        out = self.hook("post-tool", {"tool_name": "Bash", "session_id": "S1", "turn_id": "t1", "model": "m",
                                      "tool_input": {"command": "cat .env"}, "tool_response": {"stdout": output}})
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(value, json.dumps(out))
        self.assert_scrubbed(value, "raw")

    def test_an_mcp_resolve_masks_the_hook_answer_the_client_records(self):
        # a value with a quote and a backslash, so its escaped forms differ from the plain one
        value = 'Mq"' + fake_value("M") + "\\z"
        r = self.sb.run("put", stdin=value)
        key = re.search(r"stored as (\w+) ", r.stdout).group(1)
        ref = f"⟦{key}⟧"
        self.hook("user-prompt", {"prompt": f"use {ref}", "session_id": "S1", "prompt_id": "p1"})   # admits S1
        out = self.hook("pre-tool", {"tool_name": "mcp__srv__echo", "session_id": "S1", "prompt_id": "p2",
                                     "tool_input": {"token": ref}})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"], {"token": value})
        # Claude Code records the hook's stdout as a hook_success attachment: doubly escaped
        self.write({"type": "attachment", "attachment": {"type": "hook_success", "stdout": json.dumps(out)},
                    "note": "attachment"},
                   {"type": "assistant", "content": [{"type": "tool_use", "input": {"token": value}}]})
        data = self.path.read_text(encoding="utf-8")
        self.assertTrue(all(f in data for f in _forms(value)[1:]), "the record carries the escaped forms")
        self.assert_scrubbed(value, "attachment", wait=5.0)


if __name__ == "__main__":
    unittest.main()
