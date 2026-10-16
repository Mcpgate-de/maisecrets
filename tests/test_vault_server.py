"""The fake vault server of the harness (harness/vault_server.py) stays quiet when a client closes early.

A test of a timeout or a size limit closes before it reads the answer. socketserver printed a traceback for each
(BrokenPipeError, or an SSLError on the TLS socket), and the noise hid the real failure in a CI log (2026-10-16).

Run: python3 -m unittest tests.test_vault_server -v
"""
from __future__ import annotations

import contextlib
import io
import os
import ssl
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from vault_server import _QuietServer  # noqa: E402


class QuietServerTests(unittest.TestCase):
    def report(self, exc: BaseException) -> str:
        server = _QuietServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        self.addCleanup(server.server_close)
        out = io.StringIO()
        try:
            raise exc
        except BaseException:  # noqa: BLE001 - handle_error reads the exception being handled
            with contextlib.redirect_stderr(out):
                server.handle_error(None, ("127.0.0.1", 1))
        return out.getvalue()

    def test_a_client_that_closed_early_prints_nothing(self):
        for exc in (BrokenPipeError(32, "Broken pipe"), ConnectionResetError(54, "reset"),
                    ssl.SSLError(5, "[SYS] unknown error")):
            with self.subTest(type(exc).__name__):
                self.assertEqual(self.report(exc), "")

    def test_any_other_error_is_still_printed(self):
        self.assertIn("ValueError: a fault of the fake server", self.report(ValueError("a fault of the fake server")))


if __name__ == "__main__":
    unittest.main()
