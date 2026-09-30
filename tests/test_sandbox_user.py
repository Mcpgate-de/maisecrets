"""A slash command that runs as another user than the one maisecrets protects.

Codex on Windows runs a command as a sandbox user that may read the person's profile but not write it: status
ended in a Python traceback on "PermissionError: [WinError 5]" for the store folder (measured 2026-09-30).
"""
from __future__ import annotations

import contextlib
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
