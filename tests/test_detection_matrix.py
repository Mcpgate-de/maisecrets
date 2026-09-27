"""The generated detection matrix is a gate: every combination gives exactly its value and the
e-mail address after it, nothing else, and no counter-example gives any hit. See tests/detection_matrix.py."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from maisecrets import detect  # noqa: E402
import detection_matrix as dm  # noqa: E402


class DetectionMatrixTests(unittest.TestCase):
    def test_every_combination_gives_exactly_its_secret_and_its_mail_in_order(self):
        # the complete result, not "the expected hit is among them": an extra SECRET, a split or
        # widened value, a hit of another type, or a lost mail all fail (Codex review, 2026-09-27)
        cases = dm.cases()
        self.assertGreaterEqual(len(cases), 2000, "a population test must fail on a thin population")
        wrong = []
        for c in cases:
            got = [(m.type, m.value) for m in detect.scan(c.text)]
            want = [("SECRET", c.secret)] + ([("EMAIL", c.mail)] if c.mail else [])
            if got != want:
                wrong.append((c.combo, c.text, got))
        self.assertEqual(wrong[:5], [], f"{len(wrong)} of {len(cases)} combinations fail")

    def test_no_counter_example_gives_any_hit(self):
        for text, why in dm.NEGATIVES:
            with self.subTest(why=why):
                self.assertEqual([(m.type, m.kind, m.value) for m in detect.scan(text)], [], text)


if __name__ == "__main__":
    unittest.main()
