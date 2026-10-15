"""scripts/measure_rule_classes.py: a class switched off loses what only it catches, and the base is the real scan.

Run: python3 -m unittest tests.test_measure_rule_classes -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

ROOT = Path(__file__).resolve().parent.parent


class MeasureRuleClassesTests(unittest.TestCase):
    def test_the_label_rules_alone_catch_labelled_values_and_the_corpus_of_normal_work_stays_clean(self):
        out = Path(tempfile.mkdtemp(prefix="maisecrets-classes-test-"))
        self.addCleanup(shutil.rmtree, out, True)
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_rule_classes.py"), "--channels", "prompt",
                            "--workers", "2", "--out", str(out / "r.json")], capture_output=True, text=True,
                           timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads((out / "r.json").read_text(encoding="utf-8"))
        prompt = res["channels"]["prompt"]
        self.assertEqual(prompt["base"]["fp_corpus:false_hits"], 0)          # tests/test_fp_corpus.py holds this too
        self.assertEqual(prompt["base"]["fp_corpus:positives_masked"], prompt["base"]["fp_corpus:positives"])
        keyword = prompt["classes"]["label:keyword"]
        self.assertGreater(keyword["fp_corpus:recall_lost"], 0)               # a labelled value only a label rule finds
        vendored = "token" + ":" + "betterleaks"                               # split for the tree scan
        self.assertGreater(res["rules_per_class"][vendored], 100)
        self.assertNotIn("§", r.stdout)                                       # counts and names, no snippet


if __name__ == "__main__":
    unittest.main()
