"""The corpus of normal work (tests/fp_corpus.py): every NO_HIT snippet stays silent, every HIT keeps its values.

The snippets come from the review of 2026-09-29 (679 snippets of code, config, docs, logs and prose in English and
German) and from a run over a real repository. A change that makes the detector stricter shows up here as a new
false alarm in normal work; a change that makes it laxer shows up as a lost true positive.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402
import fp_corpus  # noqa: E402


def found(text: str) -> list[tuple[str, str]]:
    return [(m.type, m.value) for m in detect.scan(text.replace("§", ""))]


class CorpusTests(unittest.TestCase):
    def test_normal_work_is_no_hit(self):
        wrong = [(name, found(text)) for name, text in fp_corpus.NO_HIT if found(text)]
        self.assertEqual(wrong, [], f"{len(wrong)} of {len(fp_corpus.NO_HIT)} snippets of normal work are hits")

    def test_the_true_positives_next_to_them_stay_hits(self):
        for name, text, expected in fp_corpus.HIT:
            with self.subTest(name=name):
                self.assertEqual(found(text), [(t, v.replace("§", "")) for t, v in expected])

    def test_the_corpus_is_large_enough_to_mean_something(self):
        self.assertGreaterEqual(len(fp_corpus.NO_HIT), 590)
        self.assertGreaterEqual(len(fp_corpus.HIT), 20)


if __name__ == "__main__":
    unittest.main()
