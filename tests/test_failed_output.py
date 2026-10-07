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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

# assembled, so the repository's own scan does not take the fixture for a secret
TOKEN = "glpat-" + "FailedOutputXyz12345678"


def setUpModule():  # noqa: N802 - unittest hook
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')


def tearDownModule():  # noqa: N802 - unittest hook
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    for f in ("index.json", "vault.json", "audit.log"):
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
        live = [e for e in Vault(load_config()).list() if not e.purged]
        self.assertTrue(live, "the value is stored, so a later output that repeats it is redacted")

    def test_no_hit_codex_and_a_missing_error_give_nothing(self):
        self.assertEqual(_failure("Exit code 1\nno such file"), {})
        self.assertEqual(_failure(f"Exit code 3\nTOKEN={TOKEN}", CODEX), {}, "Codex has no such event")
        self.assertEqual(hooks.post_tool_failure({"tool_name": "Bash", "session_id": "S1", **CLAUDE}), {})

    def test_a_failing_hook_names_the_reason_and_withholds_nothing(self):
        out = hooks._fail_closed("post-tool-failure", {**CLAUDE}, "failed (OSError).")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUseFailure")
        self.assertNotIn("updatedToolOutput", out["hookSpecificOutput"])


if __name__ == "__main__":
    unittest.main()
