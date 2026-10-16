"""scripts/measure_holdouts.py: the D/C split stays the split of the posted numbers, the classes sort by shape, and a
scan of a small synthetic bench counts leaks and false alarms without printing a value.

Run: python3 -m unittest tests.test_measure_holdouts -v
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("measure_holdouts", ROOT / "scripts" / "measure_holdouts.py")
mh = importlib.util.module_from_spec(_spec)
sys.modules["measure_holdouts"] = mh
_spec.loader.exec_module(mh)


class SplitTests(unittest.TestCase):
    def test_the_split_is_the_split_of_the_posted_numbers(self):
        # sha256("<set>/<id>"), first 8 hex digits, even is D. A change here changes every table of BENCHMARKS.md.
        got = [mh.half(f"holdout_v{n}", i) for n in (2, 7) for i in ("a1", "a2", "a3", "b7", 12, 13)]
        self.assertEqual(got, ["C", "C", "D", "C", "D", "D", "D", "D", "D", "C", "D", "D"])
        run = "".join(mh.half("holdout_v5", i) for i in range(200))
        self.assertEqual(run.count("D"), 101)
        self.assertEqual(hashlib.sha256(run.encode()).hexdigest()[:16], "86547e7042d145a5")

    def test_an_integer_id_and_its_string_fall_into_the_same_half(self):
        for i in range(50):
            self.assertEqual(mh.half("holdout_v3", i), mh.half("holdout_v3", str(i)))


class ClassTests(unittest.TestCase):
    def test_each_shape_falls_into_its_class(self):
        cases = {
            "Ada Lovelace": "names", "my-test-user": "user names", "Hauptstraße 5": "addresses",
            "1990-04-01": "birth dates", "someone@example.com": "e-mail addresses",
            "+1 (202) 555-0100": "phone numbers", "4111 1111 1111 1111": "ID numbers",
            "Abc123/def456+ghi789=": "tokens and passwords", "10.0.0.1": "other",
        }
        for value, cls in cases.items():
            self.assertEqual(mh.value_class(value), cls, value)
        self.assertEqual(set(mh.CLASS_OF_SHAPE.values()), set(mh.CLASSES))


class RunTests(unittest.TestCase):
    def test_a_scan_counts_leaks_and_false_alarms_and_prints_no_value(self):
        bench = Path(tempfile.mkdtemp(prefix="maisecrets-holdouts-test-"))
        self.addCleanup(shutil.rmtree, bench, True)
        name = "Talia Brennwald"
        rows = {"holdout_v2": [{"id": "a", "text": f"Name: {name}", "planted": [name]},
                               {"id": "b", "text": "word Zebrafinch stays", "planted": ["Zebrafinch"]},
                               {"id": "c", "text": "nothing personal here", "planted": []}]}
        for s in mh.SETS:
            with open(bench / f"{s}.jsonl", "w", encoding="utf-8") as fh:
                for r in rows.get(s, []):
                    fh.write(json.dumps(r) + "\n")
        res = mh.scan_tree(str(ROOT), bench, ["us"], "en_US")
        self.assertEqual(sorted(map(tuple, res["values"])), [("holdout_v2", "a", 0, False),
                                                             ("holdout_v2", "b", 0, True)])
        self.assertEqual(res["negatives"], [["holdout_v2", "c", False]])
        t = mh.tables(mh.load(bench), {"maisecrets": res})
        self.assertEqual(t["class_values"]["names"], 2)            # a single capitalised word is a name too
        self.assertEqual(sum(t["classes"]["maisecrets"].values()), 1)
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mh.report("us", t, ("maisecrets",), {"maisecrets": "this"})
        self.assertNotIn(name, buf.getvalue())
        self.assertNotIn("Zebrafinch", buf.getvalue())
        self.assertIn("| v2 to v7 |", buf.getvalue())

    def test_a_changed_file_is_refused(self):
        bench = Path(tempfile.mkdtemp(prefix="maisecrets-holdouts-test-"))
        self.addCleanup(shutil.rmtree, bench, True)
        for s in mh.SETS:
            (bench / f"{s}.jsonl").write_text("", encoding="utf-8")
        with self.assertRaises(mh.DataError):
            mh.verify(bench)


if __name__ == "__main__":
    unittest.main()
