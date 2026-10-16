"""What a hook process pays before its first scan. Each hook call is a new process, so the import of maisecrets.hooks
is paid on every event. A module-level regex is compiled at its first use (detect._LazyRx): the import compiled 165
regexes before (24.5 ms in the profile of 2026-10-16, scripts/profile_hook.py) and most texts need few of them.

Run: python3 -m unittest tests.test_hook_start -v
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

# a new process counts the compilations of the import; the compiler of re is wrapped before anything is loaded
_COUNT = r"""
import sys
sys.path.insert(0, sys.argv[1])
try:
    from re import _compiler as sre
except ImportError:
    import sre_compile as sre
orig, seen = sre.compile, []

def counting(*a, **k):
    seen.append(1)
    return orig(*a, **k)

sre.compile = counting
import maisecrets.hooks  # noqa: F401
print(len(seen))
"""


class ImportCompilesLittleTests(unittest.TestCase):
    def test_the_import_of_the_hooks_compiles_at_most_30_regexes(self):
        r = subprocess.run([sys.executable, "-c", _COUNT, str(ROOT)], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLessEqual(int(r.stdout), 30, "a module-level re.compile in detect.py or hooks.py: use _LazyRx")

    def test_every_module_level_regex_of_detect_and_hooks_is_lazy(self):
        from maisecrets import hooks
        for mod in (detect, hooks):
            eager = [k for k, v in vars(mod).items() if isinstance(v, re.Pattern)]
            self.assertEqual(eager, [], mod.__name__)


class LazyRxTests(unittest.TestCase):
    def test_it_acts_as_the_pattern_and_compiles_once(self):
        from unittest import mock
        calls = []
        real = re.compile

        def counting(*a):
            calls.append(a)
            return real(*a)
        with mock.patch.object(re, "compile", counting):
            self.check_pattern()
        self.assertEqual(len(calls), 1, "one compilation")

    def check_pattern(self):
        rx = detect._LazyRx(r"(?P<w>[a-z]+)(\d)", re.I)
        self.assertEqual(rx.pattern, r"(?P<w>[a-z]+)(\d)")
        self.assertNotIn("_rx", vars(rx), "the source is read without a compilation")
        self.assertEqual(rx.search("-- Ab1 --").span(), (3, 6))
        compiled = vars(rx)["_rx"]
        self.assertEqual(rx.flags, compiled.flags)
        self.assertEqual((rx.groups, rx.groupindex), (2, {"w": 1}))
        self.assertEqual([m.group() for m in rx.finditer("a1 b2")], ["a1", "b2"])
        self.assertEqual(rx.sub("x", "a1 b2"), "x x")
        self.assertEqual(rx.match("c3").group("w"), "c")
        self.assertIsNone(rx.fullmatch("c3d"))
        self.assertEqual(rx.findall("a1"), [("a", "1")])
        self.assertEqual(rx.split("a1 b2"), ["", "a", "1", " ", "b", "2", ""])
        self.assertIs(vars(rx)["_rx"], compiled)


if __name__ == "__main__":
    unittest.main()
