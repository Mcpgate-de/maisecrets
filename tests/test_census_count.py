"""A census count after the word token is no secret (#96).

A log line that counts records per family, such as `{'token': 'bound=1234 unbound=567 ready=no'}`, put the label
`token` before the value `bound=1234`. generic-api-key takes `=` into its value, so the count read as an API key; the
keyword rules took `bound=7 unbound=0` after `'token': '` and `bound=7` after `token:` or `token=`. A lower-case
word=digits, with another word=digits as the next field on the line, is a count. A random value after the label stays
a hit (its span may hold more of the line), also a digit-only one and a word=<random> one.
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

TOKEN = "to" + "ken"
RANDOM = "Zq8" + "Lr2Wv5Tn9Kc4Hx7Bm3Pd6Fs1Jy0Ag5"


def family(name: str, bound: int, unbound: int, ready: str) -> str:
    return "'%s': 'bound=%d unbound=%d plain=0 other=0 ready=%s'" % (name, bound, unbound, ready)


def census(bound: int) -> str:
    return "[CENSUS] {" + ", ".join([family("mcp_" + TOKEN, 12, 0, "yes"), family(TOKEN, bound, 567, "no"),
                                      family("session", 40, 0, "yes"), family("service", 3, 0, "yes")]) + "}"


def secret_hits(text: str, channel: str) -> list:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel) if m.type == "SECRET"]


class CensusCountTests(unittest.TestCase):
    NO_VALUE = [census(n) for n in (7, 21, 1234, 12345, 998877, 123456789012)] + [
        '{"' + TOKEN + '": "bound=4321 unbound=8 plain=0 other=0 ready=no"}',
        "'" + TOKEN + "': 'bound=7 unbound=0'",                       # the whole quoted string after the label
        TOKEN + ": bound=4321 unbound=0 ready=yes",
        TOKEN + ":bound=7 unbound=0",
        TOKEN + "=bound=7 unbound=12 ready=yes",
        "families: session bound=21 unbound=0; " + TOKEN + " bound=4321 unbound=2",
    ]
    VALUE = [
        (TOKEN + "=" + RANDOM, RANDOM),
        (TOKEN + ": " + RANDOM, RANDOM),
        ("'" + TOKEN + "': '" + RANDOM + "'", RANDOM),
        ("'" + TOKEN + "': 'bound=" + RANDOM + " unbound=0'", "bound=" + RANDOM),   # a word=<random> value
        (TOKEN + "=48291375 expires=3600", "48291375"),                              # a digit-only token
        (TOKEN + ": bound=4321 " + RANDOM, "bound=4321"),                            # no count after it
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


if __name__ == "__main__":
    unittest.main()
