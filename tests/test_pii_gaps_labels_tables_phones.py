"""Personal data after a label in six more forms (the gap analysis of the dev split, Nemotron-PII, Gretel, Mendeley).

Each class is one change: a two-column Markdown row read as label and value (T1), a birth date after a comma or a bold
label (B1), a user id label with an account name (U2), the US national phone form after a call cue (P1), the user name
in an apposition (U1), and a street line after "located at", "situated at", "property at" (A2). Each positive is an
invented value; each negative is the developer text or business text of the same shape.

Run: python3 -m unittest tests.test_pii_gaps_labels_tables_phones -v
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

from maisecrets import detect, regions  # noqa: E402

ALL = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au", "nl", "se")

# invented values, split so that no literal in this file has a value's whole shape
BIRTH = "1984-03-" + "12"
PHONE = "(312) " + "846-2291"
PHONE_555 = "(312) " + "555-0147"
USER = "synthetic.person" + "42"
STREET = "4821 " + "Synthetic Ridge Drive"


def scan(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", *ALL), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool") -> str:
    for m in sorted(scan(text, channel), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool") -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel), text)

    def assertText(self, text: str, channel: str = "tool") -> None:
        self.assertEqual(text, masked(text, channel))


class MarkdownKeyValueRowTests(Base):
    """T1: | Date of Birth | value | in a table without a header row is the label and its value."""

    def test_a_headerless_key_value_table_is_masked(self):
        self.assertMasked("| Patient | record 7 |\n| Date of Birth | " + BIRTH + " |\n| Ward | 3 |\n", BIRTH)
        self.assertMasked("| **Date of Birth** | " + BIRTH + " |\n", BIRTH)

    def test_a_docs_table_stays_text(self):
        self.assertText("| Option | Meaning |\n|---|---|\n| --timeout | seconds to wait |\n"
                        "| Date of birth | a date |\n")
        self.assertText("| Field | Type |\n| Date of Birth | date |\n| Phone | string |\n")

    def test_a_lone_first_name_stays_text(self):
        self.assertText("| First name | Dana |\n| Plan | basic |\n")


if __name__ == "__main__":
    unittest.main()
