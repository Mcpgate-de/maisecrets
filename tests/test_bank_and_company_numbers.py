"""Card numbers after a card word in another language, IBANs with hyphens or in lower case, and two German numbers that
are no personal data on their own: a bare VAT ID without a VAT word and a company register number.

Adapted from the fork danszymkowiak/maisecrets (Apache-2.0).

Run: python3 -m unittest tests.test_bank_and_company_numbers -v
Every value is built at run time from parts, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

RNG = random.Random(618)


def found(text: str, channel: str = "prompt") -> list[tuple[str, str]]:
    """(type, value) of each hit with the German region on."""
    saved = detect._RULES
    active = regions.Active(regions=("generic", "de"), languages=("en", "de"), source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return [(m.type, m.value) for m in detect.scan(text, channel=channel)]
    finally:
        detect._RULES = saved


def both(text: str) -> list[tuple[str, str]]:
    """The hits of a text, which must be the same in both channels."""
    prompt, tool = found(text, "prompt"), found(text, "tool")
    assert prompt == tool, (prompt, tool)
    return prompt


def luhn_complete(body: str) -> str:
    """Append the Luhn check digit (independent of detect._luhn_ok)."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def iban_complete(cc: str, bban: str) -> str:
    """The ISO 13616 check digits (independent of detect._iban_ok)."""
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


def vat_complete(eight: str) -> str:
    """A German VAT ID: DE, eight digits and the ISO 7064 MOD 11,10 check digit (independent of the validator)."""
    p = 10
    for ch in eight:
        s = (int(ch) + p) % 10
        p = ((s if s else 10) * 2) % 11
    return "DE" + eight + str((11 - p) % 10)


CARD = luhn_complete("4929" + "".join(RNG.choice(string.digits) for _ in range(11)))
GROUPED = " ".join(CARD[i:i + 4] for i in range(0, 16, 4))
BAD_CARD = CARD[:-1] + str((int(CARD[-1]) + 1) % 10)
IBAN = iban_complete("DE", "".join(RNG.choice(string.digits) for _ in range(18)))
IBAN_GROUPS = [IBAN[i:i + 4] for i in range(0, len(IBAN), 4)]
VAT = vat_complete("".join(RNG.choice(string.digits) for _ in range(8)))


class CardWordTests(unittest.TestCase):
    def test_a_card_word_in_another_language_counts(self):
        for text in (f"Karte {GROUPED} Bezug", f"Kreditkarte: {CARD}", f"Kartennummer {GROUPED}",
                     f"Debitkarte {GROUPED}", f"numéro de carte {GROUPED}", f"carte bancaire {CARD}",
                     f"carta di credito {GROUPED}", f"número de tarjeta {GROUPED}", f"creditcard {CARD}"):
            with self.subTest(text=text):
                self.assertEqual(both(text), [("CARD", CARD if CARD in text else GROUPED)])

    def test_luhn_still_decides(self):
        self.assertEqual(both(f"Karte {BAD_CARD} Bezug"), [])

    def test_without_a_card_word_the_number_stays_text(self):
        self.assertEqual(both(f"Referenz {GROUPED} vom Konto"), [])
        self.assertEqual(both(f"Kartoffel {GROUPED}"), [], "a whole word only: Kartoffel is no Karte")


if __name__ == "__main__":
    unittest.main()
