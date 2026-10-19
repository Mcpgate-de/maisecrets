"""Benchmark V1 (docs/BENCHMARK-V1.md): the case format, the marks of the bank and the span metric."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import cases, score  # noqa: E402


def case(text, spans, **kw):
    return {"id": "t", "text": text, "channel": "tool", "context": "prose", "spans": spans, "split": "dev",
            "source": {"name": "test"}, **kw}


class MarkTests(unittest.TestCase):
    def test_the_marks_give_the_offsets_and_leave_the_text(self):
        text, spans = cases.unmark("key: «ab§cd» and «x»")
        self.assertEqual(text, "key: abcd and x")
        self.assertEqual([text[s:e] for s, e in spans], ["abcd", "x"])

    def test_a_broken_mark_is_an_error(self):
        for raw in ("«a", "a»", "««a»»"):
            with self.subTest(raw=raw), self.assertRaises(cases.CaseError):
                cases.unmark(raw)

    def test_a_bank_case_needs_one_class_per_mark(self):
        with self.assertRaises(cases.CaseError):
            cases.bank_case(case("«a» «b»", [{"class": "pii.email"}]), "x")
        with self.assertRaises(cases.CaseError):
            cases.bank_case(case("«a»", [{"class": "pii.unknown"}]), "x")
        c = cases.bank_case(case("mail «a@b»", [{"class": "pii.email"}]), "x")
        self.assertEqual(c["spans"][0]["start"], 5)

    def test_the_split_of_a_record_is_fixed_and_about_60_20_20(self):
        self.assertEqual(cases.split_of("nemotron", "us:1"), cases.split_of("nemotron", "us:1"))
        counts = {s: 0 for s in cases.SPLITS}
        for i in range(10000):
            counts[cases.split_of("src", str(i))] += 1
        self.assertTrue(5700 < counts["dev"] < 6300 and 1700 < counts["val"] < 2300, counts)

    def test_the_bank_files_load(self):
        bank = ROOT / "bench" / "bank"
        loaded = cases.load_bank(bank)
        self.assertGreater(len(loaded), 0)
        for c in loaded:
            self.assertNotIn(cases.SPLIT_MARK, c["text"])
            self.assertNotIn(cases.OPEN, c["text"])
            self.assertNotIn(cases.CLOSE, c["text"])

    def test_two_cases_with_one_id_are_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            line = json.dumps(case("«a@b»", [{"class": "pii.email"}]))
            Path(d, "a.jsonl").write_text(line + "\n" + line + "\n", encoding="utf-8")
            with self.assertRaises(cases.CaseError):
                cases.load_bank(Path(d))


class SpanMetricTests(unittest.TestCase):
    URL = "https://x.example/" + "a" * 186     # 204 characters, as the Teams webhook of 0.6.38

    def test_a_webhook_masked_17_of_204_is_partial_not_found(self):
        c = case(f"hook: {self.URL}", [{"class": "secret.webhook", "start": 6, "end": 210}])
        sc = score.score_case(c, [(6 + 50, 6 + 67, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "partial")
        self.assertEqual(sc["spans"][0]["covered"], 17)
        sc = score.score_case(c, [(6, 210, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "full")

    def test_two_findings_that_together_cover_the_span_are_full(self):
        c = case("v=abcdefgh", [{"class": "secret.generic", "start": 2, "end": 10}])
        sc = score.score_case(c, [(2, 6, "secret"), (6, 10, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "full")

    def test_an_alt_range_counts_as_full(self):
        c = case('k="abcdef"', [{"class": "secret.generic", "start": 2, "end": 10, "alt": [[3, 9]]}])
        sc = score.score_case(c, [(3, 9, "secret")], ("secret.",))
        self.assertEqual(sc["spans"][0]["outcome"], "full")

    def test_a_span_outside_the_scope_is_neither_missed_nor_a_false_positive(self):
        c = case("a@example.com key", [{"class": "pii.email", "start": 0, "end": 13}])
        sc = score.score_case(c, [(0, 13, "secret")], ("secret.",))
        self.assertEqual((sc["spans"], sc["fp"]), ([], 0))

    def test_a_finding_on_no_span_is_a_false_positive(self):
        c = case("plain words here", [])
        sc = score.score_case(c, [(0, 5, "secret")], ("secret.",))
        self.assertEqual((sc["fp"], sc["negative"]), (1, True))

    def test_masking_the_label_is_not_too_wide_but_the_next_line_is(self):
        text = "pass" + "word: hunter2xyz\nnext line of ordinary text here"
        c = case(text, [{"class": "secret.password", "start": 10, "end": 20}])
        self.assertEqual(score.score_case(c, [(0, 20, "secret")], ("secret.",))["too_wide"], 0)
        self.assertEqual(score.score_case(c, [(10, len(text), "secret")], ("secret.",))["too_wide"], 1)

    def test_the_family_of_the_finding_is_reported_not_scored(self):
        c = case("a@example.com", [{"class": "pii.email", "start": 0, "end": 13}])
        sc = score.score_case(c, [(0, 13, "secret")], ("pii.",))
        self.assertEqual((sc["spans"][0]["outcome"], sc["spans"][0]["family_right"]), ("full", False))

    def test_aggregate_counts_strict_and_lenient_recall_and_fp_density(self):
        res = []
        for i in range(40):
            c = case("x" * 20, [{"class": "secret.token", "start": 0, "end": 20}])
            f = [(0, 20, "secret")] if i < 30 else [(0, 5, "secret")] if i < 35 else []
            res.append((c, score.score_case(c, f, ("secret.",))))
        neg = case("y" * 10, [])
        res.append((neg, score.score_case(neg, [(0, 3, "secret")], ("secret.",))))
        m = score.aggregate(res)
        self.assertEqual((m["secret.token"]["full"], m["secret.token"]["partial"], m["secret.token"]["missed"]),
                         (30, 5, 5))
        self.assertEqual(m["secret.token"]["recall_strict"], 0.75)
        self.assertEqual(m["secret.token"]["recall_lenient"], 0.875)
        self.assertEqual(m["all"]["fp"], 1)
        self.assertEqual(m["all"]["precision"], round(35 / 36, 4))
        self.assertEqual(m["all"]["fp_per_1000_negative"], 1000.0)

    def test_a_class_with_few_spans_gives_no_rate(self):
        c = case("x" * 5, [{"class": "pii.iban", "start": 0, "end": 5}])
        m = score.aggregate([(c, score.score_case(c, [(0, 5, "pii")], ("pii.",)))])
        self.assertTrue(m["pii.iban"]["too_few"])
        self.assertNotIn("recall_strict", m["pii.iban"])


if __name__ == "__main__":
    unittest.main()
