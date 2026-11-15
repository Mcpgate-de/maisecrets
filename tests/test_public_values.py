"""Values with the shape of personal data that name no person (detection/public_values.py, ideas from Cloakroom 1.4.0):
a bank number that is a run or one repeated digit, a North American toll-free number, a birth date of no living
person. Invented values."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402
from maisecrets.detection import public_values  # noqa: E402


def types(text: str) -> list:
    act = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=act).activate():
        return [m.type for m in detect.scan(text, channel="tool")]


class PublicValueTests(unittest.TestCase):
    def test_a_run_or_a_repeated_digit_is_no_bank_number(self):
        for text in ("account number: 12345678", "account number: 98765432", "account number: 0000000000"):
            with self.subTest(text=text):
                self.assertNotIn("US_BANK_NUMBER", types(text))
        self.assertIn("US_BANK_NUMBER", types("account number: 48172930"))

    def test_a_toll_free_number_is_no_persons_phone(self):
        for text in ("phone: 1-800-555-7788", "Call us: (888) 412-7790", "phone: +1 866 412 7790"):
            with self.subTest(text=text):
                self.assertNotIn("PHONE", types(text))
        for text in ("phone: (415) 820-4471", "Tel.: 0800 123 4567"):
            with self.subTest(text=text):
                self.assertIn("PHONE", types(text), "a geographic number, and a German 0800 number by its region")

    def test_a_birth_date_of_no_living_person_is_no_birth_date(self):
        self.assertNotIn("BIRTH_DATE", types("born on 14 March 1879"))
        self.assertNotIn("BIRTH_DATE", types("date of birth: 03/14/2087"))
        self.assertIn("BIRTH_DATE", types("born on 14 March 1987"))

    def test_the_bounds_of_the_checks(self):
        nv = public_values.no_person_value
        self.assertTrue(nv("1915", "BIRTH_DATE", year=2026))
        self.assertFalse(nv("1916", "BIRTH_DATE", year=2026), "110 years: still possible")
        self.assertFalse(nv("12345", "US_BANK_NUMBER"), "too short to be a placeholder run")
        self.assertFalse(nv("12345678", "PHONE"), "a run is no toll-free number")
        self.assertFalse(nv("+44 800 412 7790", "PHONE"), "toll-free is a North American rule")


if __name__ == "__main__":
    unittest.main()
