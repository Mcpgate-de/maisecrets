"""A prompt hook that cannot finish blocks, and the prompt as typed still leaves the transcript
(Mcpgate-de/maisecrets#3).

The hook ran through the real entry point (hooks/dispatch.py) in a child process, with a vault home
whose index is damaged. Before this, the block stood and the value stayed in the transcript on disk:
the hook failed at Vault(cfg), before it started the scrub."""
from __future__ import annotations

import json
import os
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
import _hygiene  # noqa: E402

GLPAT = "glpat-" + "F1b2C3d4E5f6G7h8I9j0"
CFG = '{"backend": "jsonfile", "allow_plaintext_store": true}'


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


class FailedPromptScrubTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        self.dir = tempfile.mkdtemp(prefix="failed-prompt-", dir=_isolate.HOME)
        self.home = Path(self.dir, "home")
        self.home.mkdir()
        Path(self.home, "config.json").write_text(CFG)
        Path(self.home, "index.json").write_text("{damaged")
        self.transcript = Path(self.dir, "session.jsonl")

    def tearDown(self):
        import shutil
        deadline = time.time() + 20
        while time.time() < deadline:          # the scrub child of the hook may still hold the file
            try:
                shutil.rmtree(self.dir)
                return
            except OSError:
                time.sleep(0.2)

    def hook(self, prompt: str, home: Path | None = None) -> dict:
        env = {**os.environ, "MAISECRETS_HOME": str(home or self.home)}
        payload = {"prompt": prompt, "session_id": "s1", "prompt_id": "p", "transcript_path": str(self.transcript)}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "user-prompt"],
                           input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(GLPAT, r.stdout + r.stderr)
        return json.loads(r.stdout)

    def wait_masked(self) -> str:
        deadline = time.time() + 20
        while GLPAT in self.transcript.read_text(encoding="utf-8") and time.time() < deadline:
            time.sleep(0.2)
        return self.transcript.read_text(encoding="utf-8")

    def test_a_damaged_index_blocks_and_the_record_written_before_is_masked(self):
        self.transcript.write_text(json.dumps({"type": "user", "content": f"check {GLPAT}"}) + "\n")
        out = self.hook(f"check {GLPAT}")
        self.assertEqual(out["decision"], "block")
        text = self.wait_masked()
        self.assertNotIn(GLPAT, text)
        json.loads(text)

    def test_a_record_the_client_writes_after_the_hook_is_masked_too(self):
        # Claude Code writes the prompt's record after the hook answered (measured on 2.1.283)
        self.transcript.write_text("")
        out = self.hook(f"check {GLPAT}")
        self.assertEqual(out["decision"], "block")
        time.sleep(1.5)        # the child's first scrub has run on the empty file: only the delayed one is left
        with open(self.transcript, "a", encoding="utf-8") as f:
            f.write(json.dumps({"type": "queue-operation", "content": f"check {GLPAT}"}) + "\n")
        self.assertNotIn(GLPAT, self.wait_masked())

    def test_every_failing_branch_of_the_entry_point_starts_the_scrub(self):
        # in-process, with the handler made to fail: no store is touched
        import io
        from contextlib import redirect_stdout
        from maisecrets.vault import ConfigError
        payload = {"prompt": f"check {GLPAT}", "session_id": "s1", "prompt_id": "p", "transcript_path": "/t.jsonl"}
        for exc in (ConfigError("bad key"), RuntimeError("damaged index")):
            with self.subTest(type(exc).__name__):
                calls = []

                def fail(_payload, exc=exc):
                    raise exc
                with mock.patch.dict(hooks.HANDLERS, {"user-prompt": fail}), \
                        mock.patch.object(hooks, "_scrub_failed_prompt", lambda e, p: calls.append((e, p))), \
                        mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
                        redirect_stdout(io.StringIO()) as out:
                    hooks.main(["hook", "user-prompt"])
                self.assertEqual(json.loads(out.getvalue())["decision"], "block")
                self.assertEqual(calls, [("user-prompt", payload)])

    def test_the_watchdog_answers_ends_the_hook_and_the_value_is_masked(self):
        # codex review, 2026-10-06: a scrub inside the watchdog could hold the process past the client's timeout
        Path(self.home, "index.json").unlink()
        self.transcript.write_text(json.dumps({"type": "user", "content": f"check {GLPAT}"}) + "\n")
        env = {**os.environ, "MAISECRETS_HOME": str(self.home), "MAISECRETS_TEST_FAULT": "user-prompt-slow"}
        payload = {"prompt": f"check {GLPAT}", "session_id": "s1", "prompt_id": "p",
                   "transcript_path": str(self.transcript)}
        started = time.time()
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "user-prompt"],
                           input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)
        took = time.time() - started
        self.assertEqual(json.loads(r.stdout)["decision"], "block")
        self.assertIn("took longer", r.stdout)
        self.assertLess(took, hooks.WATCHDOG_SECONDS["user-prompt"] + 2, "the hook ends right after the watchdog")
        self.assertNotIn(GLPAT, self.wait_masked())

    def test_a_prompt_without_a_hit_starts_no_scrub(self):
        with mock.patch.object(hooks, "_scrub_transcript_later") as later, \
                mock.patch.object(hooks, "_scrub_transcript") as now:
            hooks._scrub_failed_prompt_now("say hi", "/t.jsonl")
        later.assert_not_called()
        now.assert_not_called()

    def test_the_child_starts_once_per_hook_and_not_for_other_events_or_bad_payloads(self):
        started = []
        with mock.patch.object(hooks, "_FAILED_SCRUB_STARTED", []), \
                mock.patch.object(hooks.subprocess, "Popen", side_effect=lambda *a, **k: started.append(a) or
                                  mock.MagicMock()):
            hooks._scrub_failed_prompt("pre-tool", {"prompt": f"check {GLPAT}", "transcript_path": "/t.jsonl"})
            for payload in ({}, {"prompt": 7, "transcript_path": "/t"}, {"prompt": "x", "transcript_path": None}):
                hooks._scrub_failed_prompt("user-prompt", payload)
            self.assertEqual(started, [])
            for _ in range(2):                  # the watchdog and the exception branch of one hook
                hooks._scrub_failed_prompt("user-prompt", {"prompt": f"check {GLPAT}", "transcript_path": "/t"})
        self.assertEqual(len(started), 1)
        self.assertNotIn(GLPAT, json.dumps(started, default=str), "the prompt goes on stdin, not as an argument")

    def test_the_scrub_never_raises(self):
        with mock.patch.object(hooks.detect, "scan", side_effect=RuntimeError("boom")):
            hooks._scrub_failed_prompt_now("x", "/t.jsonl")
        with mock.patch.object(hooks, "_FAILED_SCRUB_STARTED", []), \
                mock.patch.object(hooks.subprocess, "Popen", side_effect=OSError("no fork")):
            hooks._scrub_failed_prompt("user-prompt", {"prompt": "x", "transcript_path": "/t.jsonl"})

if __name__ == "__main__":
    unittest.main()
