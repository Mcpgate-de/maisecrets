"""The generated detection matrix is a gate: every combination finds its exact value, keeps the
e-mail address after it apart, and no counter-example is a hit. See tests/detection_matrix.py."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from maisecrets import detect  # noqa: E402
import detection_matrix as dm  # noqa: E402


class DetectionMatrixTests(unittest.TestCase):
    def test_every_combination_finds_its_exact_value_and_the_mail_after_it(self):
        cases = dm.cases()
        self.assertGreaterEqual(len(cases), 2000, "a population test must fail on a thin population")
        wrong = []
        for c in cases:
            got = detect.scan(c.text)
            if not any(m.type == "SECRET" and m.value == c.secret for m in got):
                wrong.append(("secret", c.combo, c.text))
            elif c.mail and not any(m.type == "EMAIL" and m.value == c.mail for m in got):
                wrong.append(("mail", c.combo, c.text))
        self.assertEqual(wrong[:5], [], f"{len(wrong)} of {len(cases)} combinations fail")

    def test_no_counter_example_is_a_secret(self):
        for text, why in dm.NEGATIVES:
            with self.subTest(why=why):
                self.assertEqual([m.kind for m in detect.scan(text) if m.type == "SECRET"], [], text)


if __name__ == "__main__":
    unittest.main()
