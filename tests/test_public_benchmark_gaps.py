"""Three gaps that a public benchmark found (Mcpgate-de/maisecrets#17, 2026-10-11): documented test values that were
false alarms, an email address with its @ percent-encoded, and SSNs that Presidio itself rejects.

Run: python3 -m unittest tests.test_public_benchmark_gaps -v
Every value is built at run time from parts, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import os
import random
import re
import string
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, pii_display, regions  # noqa: E402

J = "".join
RNG = random.Random(17)


def found(text: str, region: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    saved = detect._RULES
    active = regions.Active(regions=("generic", *region), languages=("en",), source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return [(m.type, m.value) for m in detect.scan(text)]
    finally:
        detect._RULES = saved


def luhn_complete(prefix: str, length: int) -> str:
    """A card number with a valid check digit that no vendor publishes for tests."""
    body = prefix + J(RNG.choice(string.digits) for _ in range(length - len(prefix) - 1))
    for d in string.digits:
        if detect._luhn_ok(body + d):
            return body + d
    raise AssertionError("no check digit")


class PublicTestValueTests(unittest.TestCase):
    def test_the_rule_file_holds_digests_and_never_a_value(self):
        lines = [ln.split("#", 1)[0].strip()
                 for ln in (ROOT / "maisecrets" / "rules" / "public_test_values.txt").read_text().splitlines()]
        digests = [ln for ln in lines if ln]
        self.assertGreaterEqual(len(digests), 30)
        for d in digests:
            self.assertRegex(d, r"^[0-9a-f]{16}$")

    def test_a_documented_test_card_is_no_hit_and_a_card_beside_it_is(self):
        stripe_visa = " ".join(["4242"] * 4)
        mastercard = J(["5" * 12, "4" * 4])
        other = luhn_complete("4", 16)
        self.assertEqual(found(f"Stripe test cards (docs): Visa {stripe_visa} | MC {mastercard}"), [])
        self.assertEqual(found(f"card: {other}"), [("CARD", other)])

    def test_the_stripe_reference_key_is_no_hit_and_a_key_of_its_shape_is(self):
        reference = J(["sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc"])
        other = J(["sk", "_test_", *(RNG.choice(string.ascii_letters + string.digits) for _ in range(24))])
        self.assertEqual(found(f"The Stripe API reference shows {reference}"), [])
        self.assertEqual(found(f"STRIPE_KEY={other}"), [("SECRET", other)])

    def test_the_jwt_io_example_is_no_hit(self):
        token = J(["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".",
                   "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", ".",
                   "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])
        self.assertEqual(found(f"Example JWT from jwt.io docs: {token}"), [])

    def test_an_aws_documentation_account_is_no_bank_number(self):
        account = J(["1111", "2222", "3333"])
        self.assertEqual(found(f"Example from the IAM docs (account {account})", ("us",)), [])

    def test_a_twilio_test_number_is_no_phone_and_a_number_beside_it_is(self):
        magic = J(["+1", "500", "555", "0006"])
        other = J(["+1", "415", "555", "0177"])
        self.assertEqual(found(f"From: {magic}"), [])
        self.assertEqual(found(f"From: {other}"), [("PHONE", other)])


class PercentEncodedEmailTests(unittest.TestCase):
    def test_an_address_with_its_at_percent_encoded_is_an_email(self):
        address = J(["jane.doe", "%40", "firma-xyz", ".de"])
        self.assertEqual(found(f"GET /login?email={address}&next=/ HTTP/1.1"), [("EMAIL", address)])
        self.assertEqual(found(f"bounce: {address} -- retry"), [("EMAIL", address)])

    def test_after_another_percent_escape_the_address_starts_at_its_name(self):
        address = J(["jane", "%40", "firma-xyz", ".de"])
        self.assertEqual(found(J(["href=mailto%3A", address])), [("EMAIL", address)])

    def test_a_reserved_domain_stays_no_hit_encoded_too(self):
        self.assertEqual(found(J(["?email=jane", "%40", "example", ".com"])), [])

    def test_the_display_masks_an_encoded_address_like_a_plain_one(self):
        shown = pii_display.display(J(["jane.doe", "%40", "firma-xyz", ".de"]), "email")
        self.assertIn(pii_display.BULLET, shown)
        self.assertNotIn("jane.doe", shown)
        self.assertNotIn("firma-xyz", shown)


class SsnValidatorTests(unittest.TestCase):
    def test_numbers_presidio_rejects_are_no_ssn(self):
        for v in ("000-00-0000", J(["078", "-05-", "1120"]), J(["123", "-45-", "6789"]), "666-12-3456",
                  "123-00-4567", "123-45-0000", "111-11-1111"):
            with self.subTest(shape=re.sub(r"\d", "9", v)):
                self.assertFalse(detect.VALIDATORS["us_ssn"](v))
                self.assertEqual(found(f"SSN {v}", ("us",)), [])

    def test_a_plausible_number_stays_a_hit(self):
        v = J(["536", "-22-", "8147"])
        self.assertTrue(detect.VALIDATORS["us_ssn"](v))
        self.assertEqual(found(f"SSN {v}", ("us",)), [("US_SSN", v)])


if __name__ == "__main__":
    unittest.main()
