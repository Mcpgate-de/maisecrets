"""#49 step 1: after a strong address label (street, home, residential, mailing, billing, postal, property address), the
street before its number, as Eastern and Central Europe write it. `Address:` alone keeps its stricter value check, and
a value whose words are all words of the word list names a thing. Invented street names."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402


def masked(text: str) -> str:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        found = detect.scan(text, channel="tool")
    for m in sorted(found, key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class StreetNumberLastTests(unittest.TestCase):
    def test_each_form_after_each_strong_label(self):
        for text, value in (("- **Street Address:** Lindenweg Kalinova, 17\n- **City:** x", "Lindenweg Kalinova, 17"),
                            ("Street Address: Kalinova Ulica 17\nPostcode: 4000", "Kalinova Ulica 17"),
                            ("Street Address: ul. Kalinova 17\n", "ul. Kalinova 17"),
                            ("Property Address: Kalinova-Ostrov Ulica 9\n", "Kalinova-Ostrov Ulica 9"),
                            ("Home address: Rivne Prospekt, 42\n", "Rivne Prospekt, 42"),
                            ("Billing Address: Kalinova Ulica 17/3\n", "Kalinova Ulica 17/3")):
            with self.subTest(text=text):
                self.assertNotIn(value, masked(text))

    def test_a_plain_label_and_a_thing_stay_text(self):
        for text in ("Address: Kalinova Ulica 17\n", "Street Address: Version 17\n", "Street Address: Port 8080\n",
                     "Billing address: Plan Basic 2\n", "Property Address: See Section 4\n",
                     "Billing address: Same As Shipping 1\n", "Postal address: Room 101\n", "IP address: Server 12\n",
                     "email address: Contact 5\n", "Street Address: https://x.example/a 17\n"):
            with self.subTest(text=text):
                self.assertEqual(text, masked(text))


if __name__ == "__main__":
    unittest.main()
