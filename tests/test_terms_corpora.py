"""The corpora of normal work stay silent with a realistic term list (maisecrets/terms.py, C26).

A person's list holds full names, surnames with their genitive, case numbers and customer names, as
`/maisecrets:term add` writes them. None of them may hit a snippet of normal work (tests/fp_corpus.py,
tests/fp_corpus_pii.py, tests/fp_corpus_forms.py), in either channel. A probe text shows that the list is loaded, so
the test cannot pass on an empty matcher. Invented names only; Jan Kowalski is the stand-in name of the epic (#19).
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

from maisecrets import detect, terms  # noqa: E402
import fp_corpus  # noqa: E402
import fp_corpus_forms  # noqa: E402
import fp_corpus_pii  # noqa: E402

REALISTIC = """\
PERSON_1  Jan Kowalski | Kowalski | Kowalskis
PERSON_2  Anna Nowak | Nowak | Nowaks
PERSON_3  Łucja Wiśniewska | Wiśniewska
PERSON_4  Thomas Schulze | Schulze | Schulzes
PERSON_5  Maria Hoffmann | Hoffmann | Hoffmanns
PERSON_6  Anna Koch | Koch | Kochs
PERSON_7  Emma Johansson | Johansson | Johanssons
PERSON_8  Priya Raman | Raman
PERSON_9  Lukas Brandt | Brandt | Brandts
PERSON_10  Sophie Meyer | Meyer | Meyers
CASE_1  AZ 4 O 123/24
CASE_2  KD-2024-08154
CUSTOMER_1  Brandt Logistik GmbH | Brandt Logistik
CUSTOMER_2  Meyer & Söhne KG
CUSTOMER_3  Nordwind Software
"""


class RealisticListTests(unittest.TestCase):
    def setUp(self):
        Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
        terms.PERSONAL.write_text(REALISTIC, encoding="utf-8")
        os.chmod(terms.PERSONAL, 0o600)
        detect.reset_rules()

    def tearDown(self):
        for path in (terms.PERSONAL, terms.CACHE_FILE):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        detect.reset_rules()

    def test_the_list_is_loaded(self):
        text = "Herr Kowalski, Anna Koch, KD-2024-08154 und Brandt Logistik GmbH"
        self.assertEqual(sum(m.kind.startswith("term:") for m in detect.scan(text)), 4)

    def test_no_snippet_of_normal_work_hits_a_term(self):
        corpora = (("fp_corpus", fp_corpus.NO_HIT), ("fp_corpus_pii", fp_corpus_pii.PII_NO_HIT),
                   ("fp_corpus_forms", fp_corpus_forms.FORMS_NO_HIT))
        wrong = []
        for corpus, items in corpora:
            for item in items:
                text = item[1].replace("§", "")
                for channel in ("prompt", "tool"):
                    if any(m.kind.startswith("term:") for m in detect.scan(text, channel=channel)):
                        wrong.append((corpus, item[0], channel))
        self.assertEqual(wrong, [])
        self.assertGreaterEqual(sum(len(items) for _c, items in corpora), 1600)


if __name__ == "__main__":
    unittest.main()
