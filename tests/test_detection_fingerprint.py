"""scripts/detection_fingerprint.py: two runs on the same code give the same bytes, and a changed hit changes them.

The script is the identity check of a refactor of the rules (docs/TESTING.md). It is only useful when it is
deterministic and when it sees a change, so both are tested here on a small synthetic sample.

Run: python3 -m unittest tests.test_detection_fingerprint -v
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
SCRIPT = ROOT / "scripts" / "detection_fingerprint.py"
GLPAT = "glpat-" + "Zq8Rk2Lm5Np7Tv9Xb3Cd"
LABEL, VALUE = "pass" + "word", "Kq7-mZ2p" + "Lw9x"     # split, so the tree scan does not take the line for a leak
SAMPLE = [
    ["probe", "a token", f"use {GLPAT} now"],
    ["probe", "a label", LABEL + " = " + VALUE],
    ["probe", "a label in a test", "def test_login():\n    " + LABEL + " = '" + VALUE + "'\n"],
    ["probe", "an address", "write to someone@example.com"],
    ["probe", "prose", "the build runs every night"],
]


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-fingerprint-test-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def run_script(self, sample: list, name: str) -> bytes:
        samples = self.dir / (name + ".json")
        samples.write_text(json.dumps(sample), encoding="utf-8")
        out = self.dir / (name + ".jsonl")
        r = subprocess.run([sys.executable, str(SCRIPT), "--samples", str(samples), "--out", str(out),
                            "--regions", "de", "--workers", "1"], capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode, 0, r.stderr)
        return out.read_bytes()

    def test_two_runs_give_the_same_bytes_and_a_changed_hit_changes_them(self):
        a = self.run_script(SAMPLE, "a")
        self.assertEqual(a, self.run_script(SAMPLE, "b"))
        lines = [json.loads(x) for x in a.decode().splitlines()]
        head, rows = lines[0], {(r[2], r[3]): r[4] for r in lines[1:]}
        self.assertEqual(head["inputs"], len(SAMPLE))
        self.assertGreater(head["rules"]["de"]["rules"], 100)
        self.assertEqual(len(rows), 2 * len(SAMPLE))                 # each input in both channels
        self.assertEqual(rows[("a token", "prompt")], [["gitlab-pat", "SECRET", 4, 4 + len(GLPAT), 0, 0, 0]])
        self.assertEqual(rows[("prose", "tool")], [])
        fixture = [h for h in rows[("a label in a test", "tool")] if h[1] == "SECRET"]
        self.assertTrue(fixture and fixture[0][4] == 1, fixture)     # a label hit in test code is a fixture
        self.assertNotIn(GLPAT.encode(), a)                           # ids and offsets only, never a value
        changed = [x if x[1] != "a token" else ["probe", "a token", f"use  {GLPAT} now"] for x in SAMPLE]
        self.assertNotEqual(a, self.run_script(changed, "c"))         # one offset moved: the bytes differ

    def test_two_inputs_with_the_same_name_are_refused(self):
        samples = self.dir / "dup.json"
        samples.write_text(json.dumps([SAMPLE[0], SAMPLE[0]]), encoding="utf-8")
        r = subprocess.run([sys.executable, str(SCRIPT), "--samples", str(samples), "--out", str(self.dir / "d"),
                            "--regions", "de", "--workers", "1"], capture_output=True, text=True, timeout=180)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("same corpus and id", r.stderr)


if __name__ == "__main__":
    unittest.main()
