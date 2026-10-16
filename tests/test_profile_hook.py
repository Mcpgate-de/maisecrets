"""scripts/profile_hook.py: the payloads keep the sizes of the hook time table, the clock counts exclusive time, and
the class of a rule comes from the registry.

Run: python3 -m unittest tests.test_profile_hook -v
"""
from __future__ import annotations

import importlib.util
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("profile_hook", ROOT / "scripts" / "profile_hook.py")
ph = importlib.util.module_from_spec(_spec)
sys.modules["profile_hook"] = ph
_spec.loader.exec_module(ph)


def _burn(seconds: float) -> None:
    end = time.process_time() + seconds
    while time.process_time() < end:
        pass


class ProfileHookTests(unittest.TestCase):
    def test_the_payloads_have_the_sizes_of_the_hook_time_table(self):
        p = ph.payloads()
        self.assertEqual(len(p["prompt 1 KB"][3]), 957)            # 160 words of the 0.6.24 script, under 1 KB
        self.assertEqual(len(p["Bash 20 KB"][3]), 20000)
        self.assertEqual(len(p["Read 70 KB"][3]), 62311)           # "70 KB" in the table: 1,200 functions, 62 KB
        self.assertEqual(p, ph.payloads())                         # a fixed seed: the same texts in every run
        self.assertEqual({v[0] for v in p.values()}, {"user-prompt", "post-tool"})

    def test_the_clock_counts_a_label_without_the_labels_inside_it(self):
        clock = ph._Clock()
        clock.enter("outer")
        _burn(0.03)
        clock.enter("inner")
        _burn(0.05)
        clock.leave()
        clock.leave()
        self.assertGreaterEqual(clock.excl["inner"], 0.045)
        self.assertLess(clock.excl["outer"], 0.045)                # the inner 50 ms are not the outer's
        self.assertGreaterEqual(clock.excl["outer"], 0.025)

    def test_a_timed_generator_yields_every_item(self):
        clock = ph._Clock()
        self.assertEqual(list(ph._wrap_gen(clock, "g", iter([1, 2, 3]))), [1, 2, 3])
        self.assertIn("g", clock.excl)
        self.assertEqual(clock.stack, [])

    def test_a_rule_takes_its_class_from_the_registry(self):
        from maisecrets import detect
        classes = {ph._class_of(detect, r) for r in detect.rules()}
        self.assertTrue(any(c.startswith("token:") for c in classes))
        self.assertTrue(any(c.startswith("pii:") for c in classes))
        self.assertFalse(any(c.startswith("type:") for c in classes))   # only a tree before the registry


if __name__ == "__main__":
    unittest.main()
