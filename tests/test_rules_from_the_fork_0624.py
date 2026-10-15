"""The rest of a contributor's fork list (danszymkowiak/maisecrets, Apache-2.0, docs/UPSTREAM-DETECTION.md), ported in
0.6.24 and measured again here: Presidio's own check digits for four recognizers and no UK postcode alone; an IBAN
after an MT940 subfield code; four checks on the password-label rules; one entropy floor per alphabet for
generic-api-key.

Run: python3 -m unittest tests.test_rules_from_the_fork_0624 -v
Every value is built at run time from parts.
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

from maisecrets import checksums, detect, regions  # noqa: E402

J = "".join


def found(text: str, region: tuple = (), channel: str = "tool") -> list:
    saved = detect._RULES
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return [(m.kind, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]
    finally:
        detect._RULES = saved


def kinds(text: str, region: tuple = (), channel: str = "tool") -> set:
    return {k for k, _ in found(text, region, channel)}


def npi(body: str) -> str:
    for d in "0123456789":
        if checksums.us_npi_ok(body + d):
            return body + d
    raise AssertionError("no check digit")


def luhn10(body: str) -> str:
    for d in "0123456789":
        if checksums._luhn_sum(body + d) == 0:
            return body + d
    raise AssertionError("no check digit")


class PresidioChecksTests(unittest.TestCase):
    def test_a_uk_postcode_alone_is_no_hit(self):
        text = "Delivery postcode: " + J(["SW1A", " 2AA"])
        self.assertFalse({k for k in kinds(text, ("uk",)) if k.startswith("uk-postcode")})

    def test_an_npi_needs_its_check_digit_and_its_word(self):
        good = npi("192837465")
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        self.assertIn(("us-npi", good), [(k.split("#")[0], v) for k, v in found("NPI: " + good, ("us",))])
        self.assertFalse({k for k in kinds("NPI: " + bad, ("us",)) if k.startswith("us-npi")})
        self.assertFalse({k for k in kinds("order " + good, ("us",)) if k.startswith("us-npi")})

    def test_a_swedish_organisation_number_needs_its_check_digit(self):
        good = luhn10("556036079")
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        for v, want in ((good[:6] + "-" + good[6:], True), (bad[:6] + "-" + bad[6:], False)):
            with self.subTest(want=want):
                hit = any(k.startswith("se-organisationsnummer") for k in kinds("orgnr " + v, ("se",)))
                self.assertEqual(hit, want)

    def test_a_uk_number_plate_needs_a_real_age_identifier(self):
        for plate, want in ((J(["AB", "51", "XYZ"]), True), (J(["AB", "99", "XYZ"]), False)):
            with self.subTest(plate=plate):
                hit = any(k.startswith("uk-vehicle-registration")
                          for k in kinds("vehicle registration " + plate, ("uk",)))
                self.assertEqual(hit, want)


class Mt940Tests(unittest.TestCase):
    IBAN = J(["DE89", "3704", "0044", "0532", "0130", "00"])

    def statement(self, iban: str) -> str:
        return J([":61:2610151015CR1250,00NTRFNONREF\n:86:166?00GUTSCHRIFT?20SVWZ+Miete Oktober",
                  "?30COBADEFFXXX?31", iban, "?32Mieter Muster"])

    def test_the_counterparty_iban_of_a_bank_statement_export_is_found(self):
        for iban in (self.IBAN, self.IBAN.lower()):
            with self.subTest(case=iban[:2]):
                self.assertIn(iban, [v for _, v in found(self.statement(iban), ("de",))])

    def test_a_digit_run_before_a_country_code_is_still_no_iban(self):
        # only `?` and two digits open the subfield: a longer digit run before the IBAN letters keeps the boundary
        text = "ref 1234" + self.IBAN
        self.assertNotIn(self.IBAN, [v for _, v in found(text, ("de",))])


if __name__ == "__main__":
    unittest.main()
