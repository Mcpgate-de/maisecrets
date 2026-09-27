"""The real clipboard of the platform: a placeholder and a non-ASCII value go in and come back.

It runs only with MAISECRETS_NATIVE_CLIPBOARD_TEST=1 (the macOS and Windows CI runners), because
it overwrites the clipboard of the person who runs it. On Windows, clip.exe read UTF-8 bytes in
the console code page, and each bracket of ⟦KEY⟧ became three characters (found 2026-09-27).
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402


@unittest.skipUnless(os.environ.get("MAISECRETS_NATIVE_CLIPBOARD_TEST") == "1",
                     "overwrites the clipboard of this user; set MAISECRETS_NATIVE_CLIPBOARD_TEST=1")
class NativeClipboardTests(unittest.TestCase):
    def setUp(self):
        # the real pbcopy and pbpaste, not the tripwires tests/_isolate.py puts first on PATH
        path = os.pathsep.join(d for d in os.environ["PATH"].split(os.pathsep) if d != _isolate.TRIPWIRE_BIN)
        patcher = mock.patch.dict(os.environ, {"PATH": path})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_placeholder_and_non_ascii_text_survive_the_round_trip(self):
        for text in ("password: ⟦SECRET_c1⟧", "Übergabe ⟦EMAIL_c2⟧ für Jürgen", "plain ascii"):
            with self.subTest(text):
                self.assertTrue(hooks._clipboard(text))
                self.assertEqual(hooks._clipboard_read().rstrip("\r\n"), text)


if __name__ == "__main__":
    unittest.main()
