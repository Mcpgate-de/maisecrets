"""A slash command that runs as another user than the one maisecrets protects.

Codex on Windows runs a command as a sandbox user that may read the person's profile but not write it: status
ended in a Python traceback on "PermissionError: [WinError 5]" for the store folder (measured 2026-09-30).
"""
from __future__ import annotations

import contextlib
import json
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
from maisecrets import cli  # noqa: E402


class PermissionErrorTests(unittest.TestCase):
    def test_a_store_folder_it_may_not_write_gives_a_message_not_a_traceback(self):
        folder = os.path.join("C:\\Users", "someone", ".maisecrets")

        def denied(_argv):
            raise PermissionError(13, "Zugriff verweigert", folder)

        err = io.StringIO()
        with mock.patch.dict(cli.COMMANDS, {"status": denied}), contextlib.redirect_stderr(err):
            rc = cli.main(["status"])
        self.assertEqual(rc, 1)
        self.assertIn(f"no write access to {folder}", err.getvalue())
        self.assertIn("outside the sandbox", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()


class HookPermissionErrorTests(unittest.TestCase):
    """The same sandbox user ran the hooks: each blocked with "a locked store or a slow disk" (2026-10-01)."""

    def run_hook(self, event: str, payload: dict) -> dict:
        import json
        from maisecrets import hooks
        folder = os.path.join("C:\\Users", "someone", ".maisecrets")

        def denied(_payload):
            raise PermissionError(13, "Zugriff verweigert", os.path.join(folder, ".lock"))

        out = io.StringIO()
        handler = "post_tool" if event == "post-tool" else event.replace("-", "_")
        with mock.patch.object(hooks, handler, denied), \
                mock.patch.dict(hooks.HANDLERS, {e: (denied if e == event and e != "post-tool"
                                                     else hooks.HANDLERS[e]) for e in hooks.HANDLERS}), \
                mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stdout(out):
            rc = hooks.main(["dispatch.py", event])
        self.assertEqual(rc, 0)
        return json.loads(out.getvalue())

    def test_every_event_blocks_and_names_the_write_access(self):
        base = {"session_id": "S", "prompt_id": "p", "tool_use_id": "t", "tool_name": "Bash",
                "tool_input": {"command": "ls"}, "tool_response": "x", "prompt": "hi"}
        for event in ("user-prompt", "pre-tool", "post-tool"):
            with self.subTest(event):
                text = json.dumps(self.run_hook(event, dict(base)))
                self.assertIn("no write access to", text)
                self.assertIn("another user", text)
                self.assertIn("hold it open", text)
                self.assertNotIn("slow disk", text)
                self.assertTrue('"block"' in text or '"deny"' in text or "withheld" in text, text)

    def test_the_run_log_names_the_code_and_the_file(self):
        from maisecrets import vault
        self.run_hook("user-prompt", {"session_id": "S", "prompt_id": "p", "prompt": "hi"})
        log = (vault.HOME / "hooks.log").read_text(encoding="utf-8").splitlines()[-1]
        self.assertIn("failed PermissionError (13, .lock)", log)
        self.assertNotIn("someone", log, "the last part of the path only")
