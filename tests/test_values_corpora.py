"""The corpora of normal work stay silent with a realistic import (maisecrets/values.py, C26, #19 part 3).

A NER output of invented names, e-mail addresses, customer names and case numbers is imported. None of the values may
hit a snippet of normal work (tests/fp_corpus.py, tests/fp_corpus_pii.py, tests/fp_corpus_forms.py), in either
channel. A probe shows that the import is loaded, so the test cannot pass on an empty matcher. Invented values only.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, values  # noqa: E402
import fp_corpus  # noqa: E402
import fp_corpus_forms  # noqa: E402
import fp_corpus_pii  # noqa: E402

FIRST = ["Zbigniew", "Wendelin", "Quirina", "Hjalmar", "Ottilie", "Bartolomej", "Ysolde", "Kasimira", "Leodegar",
         "Fenja", "Ignaz", "Malwine", "Teodor", "Severin", "Jaromir", "Odalys", "Kunibert", "Notburga"]
SYL = ["kra", "wen", "dol", "pfei", "zan", "mur", "tesk", "olt", "brau", "sen", "quar", "lin", "fes", "torp", "wiel",
       "grun", "hovs", "zek", "ramm", "trov", "nisk", "pell"]
END = ["ski", "mann", "er", "ow", "eck", "inger", "berg", "hoff", "itz", "rich"]


def ner_output(n: int = 400) -> list:
    rnd = random.Random(19)
    out, seen = [], set()
    while len(out) < n:
        first, last = rnd.choice(FIRST), (rnd.choice(SYL) + rnd.choice(SYL) + rnd.choice(END)).capitalize()
        k = rnd.random()
        if k < 0.55:
            row = {"value": f"{first} {last}", "type": "NAME"}
        elif k < 0.8:
            row = {"value": f"{first.lower()}.{last.lower()}" + "@" + f"{rnd.choice(SYL)}-gmbh.de", "type": "EMAIL"}
        elif k < 0.9:
            row = {"value": last, "type": "NAME"}
        elif k < 0.96:
            row = {"value": f"{last} {rnd.choice(['Logistik', 'Software', 'Handel'])} GmbH", "type": "NAME"}
        else:
            row = {"value": f"AZ {rnd.randint(1, 9)} O {rnd.randint(100, 999)}/{rnd.randint(20, 26)}"}
        if row["value"].lower() not in seen:
            seen.add(row["value"].lower())
            out.append(row)
    return out


class RealisticImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = ner_output()
        cls.src = Path(tempfile.mkdtemp(prefix="ms-values-corpora-"))
        p = cls.src / "ner.jsonl"
        p.write_text("".join(json.dumps(r) + "\n" for r in cls.rows), encoding="utf-8")
        os.chmod(p, 0o600)
        values.import_file(p)
        detect.reset_rules()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.src, ignore_errors=True)
        shutil.rmtree(values.IMPORTS, ignore_errors=True)
        for f in (values.CACHE_FILE, values.STATE_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        detect.reset_rules()

    def test_the_import_is_loaded(self):
        names = [r["value"] for r in self.rows if r.get("type") == "NAME"][:20]
        hits = [m for v in names for m in detect.scan(f"see {v} here") if m.kind.startswith("import:")]
        self.assertEqual(len(hits), len(names))

    def test_no_snippet_of_normal_work_hits_an_imported_value(self):
        corpora = (("fp_corpus", fp_corpus.NO_HIT), ("fp_corpus_pii", fp_corpus_pii.PII_NO_HIT),
                   ("fp_corpus_forms", fp_corpus_forms.FORMS_NO_HIT))
        wrong = []
        for corpus, items in corpora:
            for item in items:
                text = item[1].replace("§", "")
                for channel in ("prompt", "tool"):
                    if any(m.kind.startswith("import:") for m in detect.scan(text, channel=channel)):
                        wrong.append((corpus, item[0], channel))
        self.assertEqual(wrong, [])
        self.assertGreaterEqual(sum(len(items) for _c, items in corpora), 1600)


if __name__ == "__main__":
    unittest.main()
