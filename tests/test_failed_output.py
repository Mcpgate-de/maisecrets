"""A failed tool call (Claude Code PostToolUseFailure): the client shows its output to the model as it is, and the
answer cannot replace it (anthropics/claude-code#97278). maisecrets stores each value, so a repeat is redacted,
cleans the transcript, and tells the model and the person (THREAT-MODEL, "What is knowingly not defended")."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

# assembled, so the repository's own scan does not take the fixture for a secret
TOKEN = "glpat-" + "FailedOutputXyz12345678"


def setUpModule():  # noqa: N802 - unittest hook
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')


def tearDownModule():  # noqa: N802 - unittest hook
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    for f in ("index.json", "vault.json", "audit.log", "hooks.log"):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    _hygiene.assert_pristine()


def _failure(error: str, client: dict = CLAUDE, transcript: str = "") -> dict:
    return hooks.post_tool_failure({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                    "tool_input": {"command": "cat .env >&2; exit 3"}, "error": error,
                                    "session_id": "S1", "transcript_path": transcript, **client})


class FailedOutputTests(unittest.TestCase):
    def test_a_value_in_a_failed_output_is_stored_named_and_cleaned_from_the_transcript(self):
        with tempfile.TemporaryDirectory() as d:
            transcript = Path(d, "t.jsonl")
            record = {"type": "user", "message": {"content": [{"type": "tool_result", "is_error": True,
                                                                "content": f"Exit code 3\nTOKEN={TOKEN}"}]}}
            transcript.write_text(json.dumps(record) + "\n")
            out = _failure(f"Exit code 3\nTOKEN={TOKEN}", transcript=str(transcript))
            self.assertNotIn(TOKEN, transcript.read_text(), "the transcript on disk is cleaned")
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        self.assertIn("Do not repeat, copy or use these values", ctx)
        self.assertIn("⟦SECRET_c", ctx, "the model learns the placeholder to use instead")
        self.assertIn("the AI saw them", out["systemMessage"], "the person is told what happened")
        self.assertNotIn(TOKEN, json.dumps(out), "no answer carries the value")
        # the value is stored: a later, successful output that repeats it is redacted to the same placeholder
        later = hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                 "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                                 "tool_response": {"stdout": f"the old value was {TOKEN} here", "stderr": ""}})
        redacted = later["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertNotIn(TOKEN, redacted)
        ref = ctx.split("stored as ")[1].split(".")[0]
        self.assertIn(ref, redacted, "the repeat gets the placeholder the model was told")

    def test_the_message_says_when_the_transcript_is_not_cleaned(self):
        with mock.patch.object(hooks, "load_config", return_value={**load_config(), "scrub_transcript": False}):
            out = _failure(f"Exit code 3\nTOKEN={TOKEN}")
        self.assertIn("cleaning the transcript is off", out["systemMessage"])
        out = _failure(f"Exit code 3\nTOKEN={TOKEN}", transcript="/nonexistent/t.jsonl")
        self.assertIn("was not found", out["systemMessage"])
        with tempfile.TemporaryDirectory() as d:
            t = Path(d, "t.jsonl")
            t.write_text("{}\n")
            with mock.patch.object(hooks, "_scrub_transcript", return_value=False), \
                    mock.patch.object(hooks, "_scrub_transcript_later", return_value=None):
                out = _failure(f"Exit code 3\nTOKEN={TOKEN}", transcript=str(t))
        self.assertIn("could not clean the transcript", out["systemMessage"], "no claim of a cleaning that failed")

    def test_values_above_the_cap_are_named_as_not_stored(self):
        many = "\n".join(f"TOKEN{i}=glpat-" + f"CapProbe{i:02d}Xyz123456789" for i in range(5))
        with mock.patch.object(hooks, "load_config",
                               return_value={**load_config(), "max_new_entries_per_result": 2}):
            out = _failure(f"Exit code 3\n{many}")
        self.assertIn("3 more were not stored", out["systemMessage"])

    def test_the_real_entry_answers_and_the_run_log_records_it(self):
        import subprocess
        payload = {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "session_id": "S2",
                   "tool_use_id": "t1", "error": f"Exit code 3\nTOKEN={TOKEN}", **CLAUDE}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "post-tool-failure"],
                           input=json.dumps(payload), capture_output=True, text=True, timeout=30,
                           env=dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        self.assertNotIn(TOKEN, r.stdout)
        log = Path(HOME, "hooks.log").read_text()
        self.assertIn("post-tool-failure", log)
        self.assertNotIn(TOKEN, log)

    def test_no_hit_codex_and_a_missing_error_give_nothing(self):
        self.assertEqual(_failure("Exit code 1\nno such file"), {})
        self.assertEqual(_failure(f"Exit code 3\nTOKEN={TOKEN}", CODEX), {}, "Codex has no such event")
        self.assertEqual(hooks.post_tool_failure({"tool_name": "Bash", "session_id": "S1", **CLAUDE}), {})
        self.assertEqual(hooks.post_tool_failure({"tool_name": "Bash", "error": ["x"], "session_id": "S1",
                                                  **CLAUDE}), {})
        self.assertEqual(_failure(""), {})

    def test_a_failing_hook_names_the_reason_and_withholds_nothing(self):
        out = hooks._fail_closed("post-tool-failure", {**CLAUDE}, "failed (OSError).")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        self.assertNotIn("updatedToolOutput", out["hookSpecificOutput"])


if __name__ == "__main__":
    unittest.main()
