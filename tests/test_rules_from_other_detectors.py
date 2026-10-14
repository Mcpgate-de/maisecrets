"""Rules that a survey of other detectors (Presidio, python-stdnum, detect-secrets, trufflehog, a fork of this project)
showed missing or wrong in 0.6.18: the German document number, the printed forms of the Steuer-ID and the
Rentenversicherungsnummer, the Steuer-ID's repeat rule, crypto wallet secrets, Swiss and Austrian numbers, the ported
check digits of five Presidio recognizers, and token prefixes.

Run: python3 -m unittest tests.test_rules_from_other_detectors -v
Every value is generated at run time from a seeded generator, so no literal sits in the tree. Each rule has a valid
value that is a hit and a twin with a wrong check character that is not.
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

from maisecrets import checksums, detect, regions  # noqa: E402

J = "".join
D = string.digits
U = string.ascii_uppercase


_RULES_OF: dict = {}


def found(text: str, region: tuple = ("de",), channel: str = "prompt") -> list:
    """(kind, type, value) of each hit with the given regions. The rules of each regions setting are loaded once."""
    saved = detect._RULES
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    try:
        with mock.patch.object(detect, "active_regions", return_value=active):
            if region not in _RULES_OF:
                detect._RULES = None
                _RULES_OF[region] = detect.rules()
            detect._RULES = _RULES_OF[region]
            return [(m.kind, m.type, m.value) for m in detect.scan(text, channel=channel)]
    finally:
        detect._RULES = saved


def types_of(text: str, value: str, region: tuple = ("de",), channel: str = "prompt") -> list:
    """The types of the hits that cover the whole value."""
    a = text.index(value)
    return [t for k, t, v in found(text, region, channel) if v == value or (value in v and text.find(v) <= a)]


def rd(r: random.Random, n: int, alphabet: str = D) -> str:
    return J(r.choice(alphabet) for _ in range(n))


def complete(body: str, ok, alphabet: str = D) -> str:
    """body and the one check character from alphabet that ok accepts (the first one)."""
    for c in alphabet:
        if ok(body + c):
            return body + c
    raise AssertionError("no check character")


def twin(value: str, ok, pos: int = -1, alphabet: str = D) -> str:
    """The value with the character at pos changed so that ok rejects it."""
    p = pos % len(value)
    for c in alphabet:
        w = value[:p] + c + value[p + 1:]
        if w != value and not ok(w):
            return w
    raise AssertionError("no twin")


# --------------------------------------------------------------- Germany --
DOC = "CFGHJKLMNPRTVWXYZ"


def doc_number(r: random.Random) -> str:
    """A 9-character German document number: a letter first, at least one digit, the 9th a letter or a digit."""
    while True:
        v = r.choice(DOC) + rd(r, 8, DOC + D)
        if any(c.isdigit() for c in v) and v[-1].isalpha():
            return v


class GermanDocumentNumberTests(unittest.TestCase):
    def test_the_icao_check_digit_matches_the_published_specimens(self):
        # ICAO Doc 9303 Part 3 4.9; the BMI specimen passport of 2021 prints CZ6311T47 and the MRZ check digit 2
        self.assertEqual(checksums.icao_check_digit(J(["CZ63", "11T47"])), 2)
        self.assertEqual(checksums.icao_check_digit(J(["L898", "902C3"])[:-1]), 3)

    def test_a_number_whose_ninth_character_is_a_letter_is_found_after_its_label(self):
        r = random.Random(1)
        for _ in range(40):
            v = doc_number(r)
            for text in (f"Personalausweisnummer: {v}", f"Meine Ausweisnummer ist {v}, bitte eintragen."):
                with self.subTest(text=text):
                    self.assertEqual(types_of(text, v), ["DE_ID_CARD"])
            self.assertEqual(types_of(f"Reisepassnummer {v}", v), ["DE_PASSPORT"])

    def test_the_specimen_numbers_are_found_with_and_without_the_check_digit(self):
        for v in (J(["L01X", "00T47"]), J(["L01X", "00T471"]), J(["LZ63", "11T47"]), J(["T220", "00129"])):
            with self.subTest(v=v):
                self.assertEqual(types_of(f"Personalausweis: {v}", v), ["DE_ID_CARD"])
        self.assertEqual(types_of("Reisepass " + J(["CZ63", "11T472"]), J(["CZ63", "11T472"])), ["DE_PASSPORT"])

    def test_a_wrong_check_digit_a_vowel_or_no_label_is_no_hit(self):
        r = random.Random(2)
        for _ in range(40):
            v = doc_number(r)
            full = v + str(checksums.icao_check_digit(v))
            bad = full[:-1] + str((int(full[-1]) + 1) % 10)
            with self.subTest(v=v):
                self.assertEqual(types_of(f"Ausweisnummer: {full}", full), ["DE_ID_CARD"])
                self.assertEqual(found(f"Ausweisnummer: {bad}"), [])
                self.assertEqual(found(v), [])
                self.assertEqual(found(f"Ausweisnummer: {v[:4]}A{v[5:]}"), [])   # A is no character of the number
                self.assertEqual(found(f"Ausweisnummer: 1{v[1:]}"), [])          # the first is a letter

    def test_the_official_word_dokumentennummer_is_a_label(self):
        v = doc_number(random.Random(21))
        self.assertEqual(types_of(f"Dokumentennummer: {v}", v), ["DE_ID_CARD"])   # Gate B of 0.6.19: Presidio's word

    def test_pass_alone_is_no_passport_label(self):
        v = doc_number(random.Random(3))
        self.assertEqual(found(f"pass {v} to the builder"), [])


def tax_id(r: random.Random) -> str:
    while True:
        body = rd(r, 1, D[1:]) + rd(r, 9)
        try:
            return complete(body, detect._de_tax_id_ok)
        except AssertionError:
            continue


class SteuerIdTests(unittest.TestCase):
    def test_exactly_one_digit_twice_or_three_times_and_never_three_in_a_row(self):
        ok = detect._de_tax_id_ok
        # ITZBund, KONZEPT IdNr 2.3, section 1, and the example of both sources: 9 at places 3, 5 and 6
        self.assertTrue(ok(J(["6592", "9970", "489"])))
        bodies = {"two digits twice": "1123345678", "one digit three times in a row": "1112345678",
                  "one digit four times": "1121314156", "no digit twice": "1234567890"}
        for why, body in bodies.items():
            with self.subTest(why=why):
                self.assertFalse(any(ok(body + c) for c in D))
        self.assertTrue(any(ok("1213456780" + c) for c in D))     # one digit twice
        self.assertTrue(any(ok("1121345678" + c) for c in D))     # three times, two of them adjacent

    def test_a_random_number_passes_rarely(self):
        r = random.Random(4)
        n = 20000
        passed = sum(detect._de_tax_id_ok(rd(r, 1, D[1:]) + rd(r, 10)) for _ in range(n))
        self.assertLess(passed / n, 0.01)

    def test_the_printed_form_with_spaces_is_found_after_its_label(self):
        r = random.Random(5)
        for _ in range(40):
            v = tax_id(r)
            spaced = f"{v[:2]} {v[2:5]} {v[5:8]} {v[8:]}"
            bad = twin(spaced, lambda s: detect._de_tax_id_ok(s.replace(" ", "")))
            with self.subTest(v=spaced):
                self.assertEqual(types_of(f"Steuer-ID: {spaced}", spaced), ["DE_TAX_ID"])
                self.assertEqual(found(f"Steuer-ID: {bad}"), [])
                self.assertEqual(found(spaced), [])
                self.assertEqual(found(f"Steuer-ID: {spaced} 12"), [])      # a longer run of groups


def rv_number(r: random.Random) -> str:
    while True:
        body = rd(r, 2) + f"{r.randint(1, 28):02d}{r.randint(1, 12):02d}{r.randint(0, 99):02d}" + r.choice(U) + rd(r, 2)
        try:
            return complete(body, detect._de_social_security_ok)
        except AssertionError:
            continue


class RentenversicherungsnummerTests(unittest.TestCase):
    def test_the_printed_form_with_spaces_is_found(self):
        r = random.Random(6)
        for _ in range(40):
            v = rv_number(r)
            spaced = f"{v[:2]} {v[2:8]} {v[8]} {v[9:]}"
            bad = twin(spaced, detect._de_social_security_ok)
            with self.subTest(v=spaced):
                self.assertEqual(types_of(f"Rentenversicherungsnummer {spaced}", spaced), ["DE_SOCIAL_SECURITY"])
                self.assertEqual(types_of(spaced, spaced), ["DE_SOCIAL_SECURITY"])
                nbsp = spaced.replace(" ", "\u00a0")                        # Gate A of 0.6.19
                self.assertEqual(types_of(nbsp, nbsp), ["DE_SOCIAL_SECURITY"])
                self.assertEqual(found(bad), [])




if __name__ == "__main__":
    unittest.main()
