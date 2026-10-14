"""scripts/measure_creddata.py on a tiny CredData-shaped tree: it counts each labelled row once, leaves out the
excluded repository, sorts a missed row into its class, and never prints or writes a value (docs/BENCHMARKS.md).

Run: python3 -m unittest tests.test_measure_creddata -v
The values are built at run time, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

RNG = random.Random(29)


def rnd(n: int) -> str:
    return "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


class MeasureCredDataTests(unittest.TestCase):
    def setUp(self):
        self.cd = Path(tempfile.mkdtemp(prefix="creddata-"))
        token = "ghp_" + rnd(36)                                     # a token shape: caught
        uuid = "-".join(rnd(n).lower().translate(str.maketrans("ghijklmnopqrstuvwxyz", "0123456789abcdef0123"))
                        for n in (8, 4, 4, 4, 12))                     # an identifier: missed by design
        word = "hello" + "_world"                                    # a non-secret after a weak label: left alone
        vector = "ghp_" + rnd(36)                                    # in the excluded repository
        labelled = rnd(10)                                           # missed: a label that names no secret
        bare = rnd(12)                                               # missed: no label at all
        letters = "sun" + "shine"                                    # missed: a password of letters only
        self.values = [token, uuid, word, vector, labelled, bare, letters]
        rows = [("r1", "aaaa0001", f"token = '{token}'", token, "T", "Token"),
                ("r1", "aaaa0002", f"request_id: {uuid}", uuid, "T", "UUID"),
                ("r1", "aaaa0003", f"name = {word}", word, "F", "Password"),
                ("vec1", "aaaa0004", f"key = {vector}", vector, "T", "Key"),
                ("r1", "aaaa0005", f"description = {labelled}", labelled, "T", "Key"),
                ("r1", "aaaa0006", f"    {bare}", bare, "T", "Key"),
                ("r1", "aaaa0007", f"name = {letters}", letters, "T", "Password")]
        (self.cd / "meta").mkdir()
        with open(self.cd / "meta" / "r1.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Id", "FileID", "Domain", "RepoName", "FilePath", "LineStart", "LineEnd", "GroundTruth",
                        "ValueStart", "ValueEnd", "CryptographyKey", "PredefinedPattern", "Category"])
            for i, (repo, fid, line, value, gt, cat) in enumerate(rows, 1):
                path = Path("data", repo, "src", fid + ".txt")
                (self.cd / path).parent.mkdir(parents=True, exist_ok=True)
                (self.cd / path).write_text("first line\n" + line + "\n", encoding="utf-8")
                a = line.index(value)
                w.writerow([i, fid, "GitHub", repo, path.as_posix(), 2, 2, gt, a, a + len(value), "", "", cat])
        self.out = self.cd / "result.json"

    def run_script(self, *args: str) -> str:
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_creddata.py"), str(self.cd),
                            "--workers", "1", "--out", str(self.out), *args],
                           capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout + r.stderr

    def test_counts_each_row_and_leaves_the_excluded_repository_out(self):
        self.run_script("--exclude-repo", "vec1")
        result = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(result["settings"]["rows"], 6)
        s = result["summary"]
        self.assertEqual((s["tp"], s["fn"], s["fp"], s["tn"]), (1, 4, 0, 1), s)
        self.assertNotIn("halves", result, "no split without --split half")

    def test_each_missed_row_lands_in_its_class(self):
        self.run_script("--exclude-repo", "vec1")
        self.assertEqual(json.loads(self.out.read_text(encoding="utf-8"))["misses"], {
            "identifier (UUID, bucket name, id)": {"missed_T": 1, "same_class_F": 0},
            "labelled value, not a word": {"missed_T": 1, "same_class_F": 0},
            "value without a label": {"missed_T": 1, "same_class_F": 0},
            "password of letters only": {"missed_T": 1, "same_class_F": 1}})

    def test_every_row_counts_without_an_exclusion(self):
        self.run_script("--exclude-repo", "")
        s = json.loads(self.out.read_text(encoding="utf-8"))["summary"]
        self.assertEqual((s["tp"], s["fn"], s["fp"], s["tn"]), (2, 4, 0, 1), s)

    def test_the_split_puts_each_repository_in_one_half(self):
        self.run_script("--exclude-repo", "", "--split", "half")
        result = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(set(result["halves"]), {"D", "V"})
        rows_of = {h: sum(result["halves"][h][k] for k in ("tp", "fn", "fp", "tn")) for h in "DV"}
        expected = {"D": 0, "V": 0}
        for repo, n in (("r1", 6), ("vec1", 1)):     # the rule of docs/BENCHMARKS.md, written out once more here
            expected["D" if int(hashlib.sha256(repo.encode()).hexdigest()[:8], 16) % 2 == 0 else "V"] += n
        self.assertEqual(rows_of, expected)

    def test_a_baseline_run_reports_no_difference_against_itself(self):
        self.run_script("--exclude-repo", "", "--baseline", str(ROOT))
        delta = json.loads(self.out.read_text(encoding="utf-8"))["delta"]
        self.assertEqual(sum(sum(d.values()) for d in delta.values()), 0, delta)

    def test_a_baseline_that_finds_nothing_shows_each_caught_row_as_a_gain(self):
        empty = Path(tempfile.mkdtemp(prefix="empty-detector-"))   # a release stand-in that masks nothing
        (empty / "maisecrets").mkdir()
        (empty / "maisecrets" / "__init__.py").write_text("", encoding="utf-8")
        (empty / "maisecrets" / "detect.py").write_text("def rules():\n    return []\n\n\ndef scan(text):\n"
                                                        "    return []\n", encoding="utf-8")
        self.run_script("--exclude-repo", "", "--baseline", str(empty))
        result = json.loads(self.out.read_text(encoding="utf-8"))
        gains = sum(d["gain_T"] for d in result["delta"].values())
        self.assertEqual(gains, result["summary"]["tp"], result["delta"])
        self.assertEqual(result["baseline"]["tp"], 0)

    def test_no_value_reaches_the_output_or_the_file(self):
        printed = self.run_script("--exclude-repo", "", "--channel", "tool", "--split", "half")
        written = self.out.read_text(encoding="utf-8")
        self.assertTrue(printed.strip())
        for value in self.values:
            self.assertNotIn(value, printed)
            self.assertNotIn(value, written)


if __name__ == "__main__":
    unittest.main()
