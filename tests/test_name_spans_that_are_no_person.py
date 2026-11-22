"""A name span of the name service that has no shape of a person is dropped: a span with a digit or an initial and
acronyms (#93), an observability product (#93), a greeting phrase (#95). The rule is `remote.is_no_person`, which a
caller that applies the spans itself (the gateway) asks too, and the remote path applies it to every NAME span.
Real names of the same texts stay names. The names here are invented.

Run: python3 -m unittest tests.test_name_spans_that_are_no_person -v
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

from maisecrets.detection import remote as rm  # noqa: E402
from test_remote_detector import Service  # noqa: E402


class SpanRuleTests(unittest.TestCase):
    def test_a_digit_an_initial_with_acronyms_or_an_observability_product_is_no_person(self):
        for span in ("G. PII", "D8", "(D8)", "A1 B2", "Loki", "B. MCP", "C. API", " A. API ", "X. API SQL",
                     "Prometheus", "Mimir", "Kibana", "Windmill", "Metabase", "Grafana Loki", "PR42"):
            with self.subTest(span=span):
                self.assertTrue(rm.is_no_person(span))
                self.assertTrue(rm.is_no_person_in(f"see {span} here", 4, 4 + len(span)))

    def test_a_name_of_the_same_shapes_stays_a_name(self):
        # an initial and a surname, an all-caps name, a short name, an initial and a long caps word
        for span in ("Mara Feldkamp", "Jonte Brakel", "JONAS WEBER", "Li", "G. Feldkamp", "G. FELDKAMP", "G. VOSKA",
                     "G. PIIX Y", "G PII", "Jaeger"):
            with self.subTest(span=span):
                self.assertFalse(rm.is_no_person(span))

    def test_a_short_caps_surname_after_an_initial_or_a_name_with_a_digit_stays_a_name(self):
        # Gate B: a form or a label writes an initial and a surname of 2 to 4 capitals; a name runs into a user name's
        # digit or a footnote mark, and the remote path widens the span over it. Tempo and Jaeger are surnames
        for span in ("J. LEE", "T. KOCH", "M. KIM LEE", "A. API LEE", "Feldkamp2", "Feldkamp¹",
                     "Mara Feldkamp2", "Team7", "Ola7", "Li2", "Wu1", "B. NER", "Tempo", "Jaeger"):
            with self.subTest(span=span):
                self.assertFalse(rm.is_no_person(span))

    def test_a_greeting_phrase_is_no_person(self):
        for span in ("Hallo Ihr Lieben", "Ihr Lieben", "Hallo zusammen", "Liebe alle", "Hallo Ihr Lieben,",
                     "hallo Leute", "Hi Team"):
            with self.subTest(span=span):
                self.assertTrue(rm.is_greeting_phrase(span))
                self.assertTrue(rm.is_no_person(span))

    def test_a_greeting_with_a_name_or_an_address_word_alone_stays(self):
        for span in ("Hallo Anke", "Liebe Frau Feldkamp", "Ihr", "Sie", "Du", "Ihr Feldkamp", "Du Bois",
                     "alle zusammen"):
            with self.subTest(span=span):
                self.assertFalse(rm.is_greeting_phrase(span))
                self.assertFalse(rm.is_no_person(span))


class RemotePathTests(unittest.TestCase):
    """The eight texts of #93: the service marks every span below as a person; only the names stay."""

    def _kept(self, text: str, words: tuple) -> list:
        def answer(t):
            out = []
            for word in words:
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.95, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        return [text[s:e] for s, e, _t, _sc in spans]

    def test_the_texts_without_a_person_stay_clear(self):
        for text, word in (("| G. PII outbound | CHOICE_REQUIRED |", "G. PII"),
                           ("We chose option (D8) for the release.", "D8"),
                           ("The logs are in Loki for six days.", "Loki"),
                           ("See B. MCP and C. API in the table.", "B. MCP"),
                           ("Hallo Ihr Lieben, wie geht es euch?", "Hallo Ihr Lieben")):
            with self.subTest(text=text):
                self.assertEqual(self._kept(text, (word,)), [])

    def test_the_names_stay_names(self):
        for text, word in (("Thanks, Mara Feldkamp", "Mara Feldkamp"),
                           ("Kontakt: Jonte Brakel", "Jonte Brakel"),
                           ("PAYEE: JONAS WEBER\nIBAN: SEE ABOVE", "JONAS WEBER"),
                           ("Hi Li, the build is green.", "Li"),
                           ("Hallo Anke, wie geht es dir?", "Hallo Anke"),
                           ("Paket fuer Herrn Feldkamp¹ ist da.", "Feldkamp¹"),
                           ("Gruss, Mara Feldkamp2 aus Hamburg", "Mara Feldkamp2")):
            with self.subTest(text=text):
                self.assertEqual(self._kept(text, (word,)), [word])


if __name__ == "__main__":
    unittest.main()
