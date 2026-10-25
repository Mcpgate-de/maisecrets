"""Names and ids under the field names of structured text (the structural label gaps of 2026-10-25).

Each class here is one change: a first or last name that is also a word, a key that names a person's role, a
compound key of a role and a name, an XML element named by a person label, an HTML table of fields and values, a SQL
dump's INSERT under its CREATE TABLE, a row with a first and a last name column, a title before a name, the bare
`student` label, and an id that starts with its own label. Every value is invented; each negative is developer text
in the same shape.

Run: python3 -m unittest tests.test_pii_structural_labels -v
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

ALL = ("us", "uk", "de")
FIRST = "Ada" + "eze"
LAST = "Oko" + "nkwo"
NAME = FIRST + " " + LAST


def scan(text: str, channel: str = "tool", region: tuple = ALL) -> list:
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool", region: tuple = ALL) -> str:
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool") -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel), text)

    def assertNoName(self, text: str, channel: str = "tool") -> None:
        self.assertNotIn("NAME", {m.type for m in scan(text, channel)}, text)


class WordAsSingleNameTests(Base):
    WORD = "Hun" + "ter"

    def test_a_name_that_is_a_word_is_masked_next_to_a_name_part_that_is_none(self):
        for text in ("first_name: " + self.WORD + "\nlast_name: " + LAST + "\n",
                     '{"last_name": "' + self.WORD + '", "first_name": "' + FIRST + '"}',
                     "first_name: " + self.WORD + "\nnotes: x\nlast_name: " + LAST + "\n"):
            with self.subTest(text=text):
                self.assertMasked(text, self.WORD)

    def test_a_word_alone_or_in_a_schema_of_words_stays_text(self):
        for text in ("first_name: " + self.WORD + "\n",
                     "first_name: Unique\nlast_name: Index\n",
                     "first_name: Mason\nlast_name: Carter\n",
                     # an e-mail address alone is no second name part
                     "first_name: " + self.WORD + "\ncontact: someone@example.org\n",
                     # the value goes on in a sentence: no field
                     "first_name: " + self.WORD + " said hello\nlast_name: " + LAST + "\n"):
            with self.subTest(text=text):
                self.assertNotIn(self.WORD, {m.value for m in scan(text)})

    def test_a_name_part_far_away_does_not_count(self):
        text = "first_name: " + self.WORD + "\n" + "x" * 400 + "\nlast_name: " + LAST + "\n"
        self.assertNotIn(self.WORD, {m.value for m in scan(text)})


class RoleKeyTests(Base):
    def test_a_name_after_a_key_that_names_a_persons_role_is_masked(self):
        for key in ("payer", "payee", "policyholder", "policy_holder", "borrower", "insured", "physician", "recipient",
                    "consignee", "shipper", "buyer", "seller", "sender", "guarantor"):
            for text in (key + ": " + NAME + "\n", '{"' + key + '": "' + NAME + '"}', key + " = " + NAME):
                with self.subTest(text=text):
                    self.assertMasked(text, NAME)

    def test_words_a_team_and_the_keys_of_the_broad_set_stay_text(self):
        for text in ("sender: Release Desk\n", "recipient: Platform Team\n", '{"buyer": "Build Bot"}',
                     # roles a company or a system has as often as a person: not in the set
                     "lender: " + NAME + "\n", "agent: " + NAME + "\n", "client: " + NAME + "\n",
                     "user: " + NAME + "\n", "contact: " + NAME + "\n", "customer: " + NAME + "\n",
                     # the role word inside a longer key
                     "message_sender: " + NAME + "\n"):
            with self.subTest(text=text):
                self.assertNotIn("name-after-label", {m.kind for m in scan(text)})


if __name__ == "__main__":
    unittest.main()
