"""Personal data after its label in more forms (the gap analysis of 2026-10-16 on Nemotron-PII and Gretel).

Each class here is one change: a label in Markdown bold, a phone number after a phone word, an ID number after a
health, tax or national label, one name word after a first or last name label, a street line after an address label,
the person columns of a Markdown table, and the passport and driving licence labels of the EU languages. Each
positive is an invented value in the shape of the datasets; each negative is developer text in the same shape.

Run: python3 -m unittest tests.test_personal_after_its_label -v
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

from maisecrets import detect, normalise, regions  # noqa: E402

ALL = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au", "nl", "se")


def scan(text: str, channel: str = "tool", region: tuple = ALL) -> list:
    saved = detect._RULES
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return detect.scan(text, channel=channel)
    finally:
        detect._RULES = saved


def masked(text: str, channel: str = "tool", region: tuple = ALL) -> str:
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool", region: tuple = ALL) -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel, region), text)

    def assertText(self, text: str, channel: str = "tool", region: tuple = ALL) -> None:
        self.assertEqual(text, masked(text, channel, region))


# ------------------------------------------------------------------------------------------------- Markdown bold --
BIRTH = "1984-03-" + "12"
NAME = "Dana " + "Okafor"
PASSWORD = "Qz8k" + "Lm2pR7xw"


class BoldLabelTests(Base):
    def test_a_value_after_a_bold_label_is_masked_like_after_the_plain_label(self):
        for text, value in (
                ("**Date of birth:** " + BIRTH, BIRTH),
                ("**Date of birth**: " + BIRTH, BIRTH),
                ("- **Full name:** " + NAME + "\n- **Role:** reviewer", NAME),
                ("__Date of birth:__ " + BIRTH, BIRTH),
                ("**Password:** " + PASSWORD, PASSWORD),
                ("| **Password:** " + PASSWORD + " |", PASSWORD)):
            with self.subTest(text=text):
                self.assertMasked(text, value)

    def test_the_offsets_of_the_value_stay_those_of_the_original(self):
        text = "**Date of birth:** " + BIRTH + " and more"
        hits = [m for m in scan(text) if m.type == "BIRTH_DATE"]
        self.assertEqual([(text[m.start:m.end]) for m in hits], [BIRTH])
        # a hit never takes the stars of the next bold label with it
        text = "**Full name:** " + NAME + " **Role:** reviewer"
        self.assertEqual([text[m.start:m.end] for m in scan(text) if m.type == "NAME"], [NAME])

    def test_the_emphasis_stage_drops_only_the_stars_around_a_label(self):
        self.assertEqual(normalise.normalise("**Date of birth:** x").text, "Date of birth: x")
        self.assertEqual(normalise.normalise("**Date of birth**: x").text, "Date of birth: x")
        self.assertEqual(normalise.normalise("__Name:__ x").text, "Name: x")
        for text in ("a **bold** word", "__version__ = 1", "__all__: list = []", "f(**kwargs)", "**Note**",
                     "x ** 2: y", "__init__ : x"):
            with self.subTest(text=text):
                self.assertIs(normalise.normalise(text).text, text)

    def test_a_typed_prompt_keeps_its_decisions(self):
        self.assertText("**Date of birth:** " + BIRTH, "prompt")

    def test_a_bold_label_without_a_value_stays_text(self):
        for text in ("**Note:** see below", "**Password:** must be 12 characters", "**First name:** String, required",
                     "**Date of birth**: required, format YYYY-MM-DD", "**Version:** 1.2.3"):
            with self.subTest(text=text):
                self.assertText(text)

    def test_a_long_line_of_bold_labels_stays_linear(self):
        import time
        line = ("**Note:** x " * 20000) + ("**" * 40000)
        t0 = time.process_time()
        scan(line)
        self.assertLess(time.process_time() - t0, 20)


if __name__ == "__main__":
    unittest.main()
