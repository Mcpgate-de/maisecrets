"""A whole census entry after the word token is no secret (#96, #101).

A log line that counts records per family, such as `{'token': 'bound=1234 unbound=567 plain=0 other=0 ready=no'}`,
put the label `token` before the value `bound=1234`. generic-api-key takes `=` into its value, so the count read as an
API key; the keyword rules took the same span. Only a whole census entry is a count: the quoted value holds
`bound=<n> unbound=<n> plain=<n> other=<n> ready=yes|no` and nothing else, in this order. 0.9.22 skipped any lower-case
word=digits with another word=digits after it, so `session: sid=<digits> expires=3600` gave no finding (#101). A
random value, a count list that is no whole census entry and a census-like tail without quotes stay a hit.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402
from maisecrets.detection import Active, Detector, Host, NO_REFERENCES, NO_SOURCES  # noqa: E402
from maisecrets.detection import core  # noqa: E402

TOKEN = "to" + "ken"
BOUND = "bo" + "und="
RANDOM = "Zq8" + "Lr2Wv5Tn9Kc4Hx7Bm3Pd6Fs1Jy0Ag5"
DIGITS = "8301" + "7462" + "5519"          # a made-up numeric session id
TAIL = " unbound=5 plain=0 other=0 ready=no"


def family(name: str, bound: int, unbound: int, ready: str) -> str:
    return "'%s': '%s%d unbound=%d plain=0 other=0 ready=%s'" % (name, BOUND, bound, unbound, ready)


def census(bound: int) -> str:
    return "[CENSUS] {" + ", ".join([family("mcp_" + TOKEN, 12, 0, "yes"), family(TOKEN, bound, 567, "no"),
                                      family("session", 40, 0, "yes"), family("service", 3, 0, "yes")]) + "}"


def secret_hits(text: str, channel: str) -> list:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel) if m.type == "SECRET"]


class CensusCountTests(unittest.TestCase):
    NO_VALUE = [census(n) for n in (7, 21, 1234, 12345, 998877, 123456789012)] + [
        '{"' + TOKEN + '": "' + BOUND + '4321 unbound=8 plain=0 other=0 ready=no"}',
        '{\\"' + TOKEN + '\\": \\"' + BOUND + '4321 unbound=8 plain=0 other=0 ready=yes\\"}',   # JSON in a string
        "{'mcp_" + TOKEN + "_index': '" + BOUND + "48291" + TAIL + "'}",
    ]
    VALUE = [
        (TOKEN + "=" + RANDOM, RANDOM),
        (TOKEN + ": " + RANDOM, RANDOM),
        ("'" + TOKEN + "': '" + RANDOM + "'", RANDOM),
        ("'" + TOKEN + "': '" + BOUND + RANDOM + " unbound=0'", BOUND + RANDOM),   # a word=<random> value
        (TOKEN + "=48291375 expires=3600", "48291375"),                            # a digit-only token
        (TOKEN + ": " + BOUND + "4321 " + RANDOM, BOUND + "4321"),                 # no count after it
    ]
    # #101: a word=<digits> value with another word=<digits> after it, but no whole census entry
    NO_CENSUS = [
        "GET /api session: sid=" + DIGITS + " expires=3600",
        "refresh " + TOKEN + "=" + BOUND + DIGITS + " ttl=3600",                    # two numeric fields
        TOKEN + ": otp=" + DIGITS + " attempt=1",
        "'" + TOKEN + "': '" + BOUND + DIGITS + TAIL + " extra=1'",                 # a census with an extra field
        "'" + TOKEN + "': '" + BOUND + DIGITS + " unbound=5 plain=0 other=0'",      # a census without ready=
        "'" + TOKEN + "': '" + BOUND + DIGITS + " unbound=5 other=0 plain=0 ready=no'",   # keys in another order
        "'" + TOKEN + "': '" + BOUND + DIGITS + " unbound=5 plain=0 other=0 ready=maybe'",
        "'" + TOKEN + "': 'sid=" + DIGITS + TAIL + "'",                             # another first key
        "password: " + BOUND + DIGITS + TAIL,                                       # no quotes around it
        "password: " + BOUND + DIGITS + TAIL + " user=7",
        "'" + TOKEN + "': '" + BOUND + DIGITS + TAIL + '"',                         # the quotes do not match
    ]

    def test_a_census_count_after_the_word_token_is_no_secret(self):
        for text in self.NO_VALUE:
            for channel in ("prompt", "tool"):
                with self.subTest(text=text, channel=channel):
                    self.assertEqual(secret_hits(text, channel), [])

    def test_the_library_detector_finds_no_secret_in_the_census(self):
        d = Detector(regions=Active(regions=("generic", "de"), languages=("en", "de"), source="test"),
                     sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))
        for n in (1234, 998877):
            with self.subTest(bound=n):
                self.assertEqual([m.kind for m in d.findings(census(n), channel="tool") if m.type == "SECRET"], [])

    def test_a_labelled_value_stays_a_hit(self):
        for text, value in self.VALUE:
            for channel in ("prompt", "tool"):
                with self.subTest(text=text, channel=channel):
                    self.assertTrue(any(value in v for _, v in secret_hits(text, channel)), text)

    def test_a_count_list_that_is_no_whole_census_entry_stays_a_hit(self):
        for text in self.NO_CENSUS:
            for channel in ("prompt", "tool"):
                with self.subTest(text=text, channel=channel):
                    self.assertTrue(any(DIGITS in v for _, v in secret_hits(text, channel)), text)


class CensusEntryShapeTests(unittest.TestCase):
    """The check itself, for spans that no rule gives today: the value ends inside the entry and its quotes close."""
    ENTRY = BOUND + "998877" + TAIL

    def check(self, before: str, entry: str, after: str, end_in_entry: int) -> bool:
        text = before + entry + after
        return core._census_count(text, len(before), len(before) + end_in_entry)

    def test_a_whole_entry_in_matching_quotes_is_a_count(self):
        for before, after in (("{'" + TOKEN + "': '", "'}"), ('{"' + TOKEN + '": "', '"}'),
                              ('{\\"' + TOKEN + '\\": \\"', '\\"}'), ("{\\'" + TOKEN + "\\': \\'", "\\'}")):
            with self.subTest(before=before):
                self.assertTrue(self.check(before, self.ENTRY, after, len(BOUND) + 6))
                self.assertTrue(self.check(before, self.ENTRY, after, len(self.ENTRY)))

    def test_a_span_past_the_entry_is_a_value(self):
        self.assertFalse(self.check("'", self.ENTRY, "'", len(self.ENTRY) + 1))

    def test_the_closing_quote_must_match_the_opening_one(self):
        self.assertFalse(self.check('\\"', self.ENTRY, '"', len(BOUND) + 6))
        self.assertFalse(self.check("'", self.ENTRY, '"', len(BOUND) + 6))
        self.assertFalse(self.check("", self.ENTRY, "'", len(BOUND) + 6))

    def test_only_ascii_digits_are_a_count(self):
        entry = BOUND + "٩٨٧" + TAIL
        self.assertFalse(self.check("'", entry, "'", len(BOUND) + 3))


if __name__ == "__main__":
    unittest.main()
