"""Personal data after a label or in a fixed form (maisecrets/personal.py), and three token forms with a shorter tail
(0.6.21). Each rule is checked on a hit, on the ordinary developer text next to it, and on its channel and region.

Run: python3 -m unittest tests.test_personal_data -v
Every value is synthetic. A token is built at run time from parts, so the tree scan stays clean.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, personal, regions  # noqa: E402
import fp_corpus_pii  # noqa: E402

J = "".join
ALL_REGIONS = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au")


def scan(text: str, channel: str = "tool", region: tuple = ALL_REGIONS):
    saved = detect._RULES
    active = regions.Active(regions=("generic", *region), languages=("en",), source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return detect.scan(text, channel=channel)
    finally:
        detect._RULES = saved


def masked(text: str, value: str, channel: str = "tool", region: tuple = ALL_REGIONS) -> bool:
    out = text
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        out = out[:m.start] + "\u2022" + out[m.end:]
    return value not in out


def values(text: str, channel: str = "tool", region: tuple = ALL_REGIONS) -> list:
    return [(m.kind, m.value) for m in scan(text, channel, region) if m.kind in personal.RULE_IDS]


class BirthDateTests(unittest.TestCase):
    def test_a_date_after_a_birth_label(self):
        for text, v in (("DOB: 1987-04-12", "1987-04-12"), ("Geburtsdatum: 03.11.1979", "03.11.1979"),
                        ("née le 4 mars 1985", "4 mars 1985"), ("fecha de nacimiento: 12/05/1990", "12/05/1990")):
            with self.subTest(text=text):
                self.assertEqual(values(text), [("birth-date-after-label", v)])

    def test_other_dates_and_the_word_born_stay_text(self):
        for text in ("created: 2024-03-11", "released: 12.03.2024", "born 23 June 1912 in London",
                     "DOB 01/01/1970 is the placeholder for unknown records"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])



class IdNumberTests(unittest.TestCase):
    def test_an_id_number_after_an_id_label(self):
        for text, v in (("MRN: 00482913", "00482913"), ("passport no: K4829173", "K4829173"),
                        ("DL: D4812736", "D4812736"), ("tax id: 912-48-3017", "912-48-3017")):
            with self.subTest(text=text):
                # a passport or a tax id of a region rule is masked by that rule, which comes first
                self.assertTrue(masked(text, v))

    def test_a_specimen_a_snowflake_and_a_count_stay_text(self):
        for text in ("Specimen passport X0000000 (ICAO 9303 example)", "member id: 123456789012345678",
                     "account number of retries: 3", "x = sin(12345)", "<dl>12345</dl>",
                     "HPE ProLiant DL360 Gen10 Plus", "WHERE member_id = 20231115 LIMIT 10"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class UrlUserTests(unittest.TestCase):
    def test_the_user_of_a_url(self):
        self.assertEqual(values("postgres://lbrueckner:pw4@db.internal:5432/app"),
                         [("user-in-url", "lbrueckner")])

    def test_service_accounts_templates_and_key_ids_stay_text(self):
        for text in ("postgres://postgres:postgres@localhost/db", J(["https://__to", "ken__:x@upload.pypi.org/legacy/"]),
                     "ftp://anonymous:anonymous@ftp.example.org/pub/", "redis://${REDIS_USER}:${REDIS_PASS}@cache:6379",
                     "https://app4k29x1m8:x@api.example.net/", "amqp://rabbitmq:x@mq:5672/",
                     "https://gitlab-ci-token:x@gitlab.example.net/g/p.git", "postgres://app_user:x@db/app"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])


class PhoneTests(unittest.TestCase):
    def test_a_number_with_one_digit_groups_in_both_channels(self):
        text = "call me on +1 4 1 5 223 3344"
        for ch in ("tool", "prompt"):
            with self.subTest(channel=ch):
                self.assertEqual(values(text, ch), [("phone-one-digit-groups", "+1 4 1 5 223 3344")])

    def test_a_us_number_needs_its_label_its_region_and_no_555(self):
        self.assertEqual(values("Tel: (312) 846-2291", region=("us",)), [("phone-us-national", "(312) 846-2291")])
        self.assertEqual(values("Tel: (312) 846-2291", region=("de",)), [])
        self.assertEqual(values("f(312) 846-2291", region=("us",)), [])
        self.assertEqual(values("phone: (312) 555-0100", region=("us",)), [])
        self.assertEqual(values("call (100) 250-1000", region=("us",)), [])   # no area code starts with 0 or 1

    def test_version_and_offset_runs_stay_text(self):
        for text in ("UTC +05 30", "a + 1 2 3", "score +1 0 0 0 0 0 0 0"):
            with self.subTest(text=text):
                self.assertEqual(values(text), [])



if __name__ == "__main__":
    unittest.main()
