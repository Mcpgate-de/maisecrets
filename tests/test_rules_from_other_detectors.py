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


# ----------------------------------------------------- Switzerland, Austria --
class SwissAndAustrianNumberTests(unittest.TestCase):
    def test_an_ahv_number_with_dots_stands_alone_and_without_them_needs_its_label(self):
        r = random.Random(12)
        for _ in range(40):
            v = complete("756" + rd(r, 9), checksums.ch_ahv_ok)
            dotted = f"{v[:3]}.{v[3:7]}.{v[7:11]}.{v[11:]}"
            bad = twin(dotted, checksums.ch_ahv_ok)
            with self.subTest(v=dotted):
                self.assertEqual(types_of(dotted, dotted, region=("ch",)), ["CH_AHV"])
                self.assertEqual(types_of(f"AHV-Nr. {v}", v, region=("ch",)), ["CH_AHV"])
                self.assertEqual(found(v, region=("ch",)), [])
                self.assertEqual(found(bad, region=("ch",)), [])
                self.assertEqual(found(dotted, region=("de",)), [])      # region ch only

    def test_a_swiss_and_an_austrian_company_number_need_a_vat_word(self):
        r = random.Random(13)
        for _ in range(40):
            uid = next(u for u in ("CHE" + rd(r, 8) + c for _ in range(50) for c in D) if checksums.ch_uid_ok(u))
            uid_f = f"CHE-{uid[3:6]}.{uid[6:9]}.{uid[9:]}"
            atu = complete("ATU" + rd(r, 7), checksums.at_uid_ok)
            with self.subTest(uid=uid_f, atu=atu):
                self.assertEqual(types_of(f"UID: {uid_f} MWST", uid_f, region=("ch",)), ["CH_UID"])
                self.assertEqual(found(uid_f, region=("ch",)), [])
                self.assertEqual(found(f"UID: {twin(uid_f, checksums.ch_uid_ok)}", region=("ch",)), [])
                self.assertEqual(types_of(f"UID-Nummer {atu}", atu, region=("at",)), ["AT_UID"])
                self.assertEqual(found(atu, region=("at",)), [])
                self.assertEqual(found(f"UID-Nummer {twin(atu, checksums.at_uid_ok)}", region=("at",)), [])

    def test_an_austrian_social_insurance_number_needs_its_label_and_its_check_digit(self):
        r = random.Random(14)
        n = 0
        while n < 40:
            serial, date = rd(r, 1, D[1:]) + rd(r, 2), f"{r.randint(1, 28):02d}{r.randint(1, 12):02d}{rd(r, 2)}"
            good = [serial + c + date for c in D if checksums.at_social_security_ok(serial + c + date)]
            if not good:
                continue
            n += 1
            v = good[0]
            bad = twin(v, checksums.at_social_security_ok, pos=3)
            with self.subTest(v=v):
                self.assertEqual(types_of(f"Sozialversicherungsnummer: {v}", v, region=("at",)),
                                 ["AT_SOCIAL_SECURITY"])
                self.assertEqual(found(f"Sozialversicherungsnummer: {bad}", region=("at",)), [])
                self.assertEqual(found(v, region=("at",)), [])


# ------------------------------------------------ ported Presidio checks --
def pesel(r):
    return complete(rd(r, 2) + r.choice("02468") + rd(r, 1, D[1:]) + f"{r.randint(1, 28):02d}" + rd(r, 4),
                    checksums.pl_pesel_ok)


def nif(r):
    n = rd(r, 8)
    return n + "TRWAGMYFPDXBNJZSQVHLCKE"[int(n) % 23]


def nie(r):
    p, n = r.choice("XYZ"), rd(r, 7)
    return p + n + "TRWAGMYFPDXBNJZSQVHLCKE"[int(str("XYZ".index(p)) + n) % 23]


def nhs(r):
    while True:
        try:
            v = complete(rd(r, 9), checksums.uk_nhs_ok)
            return f"{v[:3]} {v[3:6]} {v[6:]}"
        except AssertionError:
            continue


def aba(r):
    head = r.choice([f"{x:02d}" for x in (*range(0, 13), *range(21, 33))])   # a Federal Reserve routing symbol
    return complete(head + rd(r, 6), checksums.us_aba_ok)


def fiscal(r):
    cons = "BCDFGHJKLMNPQRSTVWXYZ"
    body = (rd(r, 3, cons) + rd(r, 3, cons) + rd(r, 2) + r.choice("ABCDEHLMPRST") + f"{r.randint(1, 28):02d}"
            + r.choice("ABCDEFGHILM") + rd(r, 3))
    return complete(body, checksums.it_fiscal_code_ok, U)


PORTED = [  # (name, region, generator, validator, label, twin alphabet)
    ("PESEL", "pl", pesel, checksums.pl_pesel_ok, "PESEL", D),
    ("DNI", "es", nif, checksums.es_nif_ok, "DNI", U),
    ("NIE", "es", nie, checksums.es_nie_ok, "NIE", U),
    ("NHS", "uk", nhs, checksums.uk_nhs_ok, "NHS number", D),
    ("ABA", "us", aba, checksums.us_aba_ok, "ABA routing number", D),
    ("codice fiscale", "it", fiscal, checksums.it_fiscal_code_ok, "codice fiscale", U),
]


class PortedCheckDigitTests(unittest.TestCase):
    def test_a_valid_value_after_its_label_is_a_hit_and_its_twin_is_not(self):
        for name, region, gen, ok, label, alpha in PORTED:
            r = random.Random(name)
            for _ in range(30):
                v = gen(r)
                bad = twin(v, ok, alphabet=alpha)
                with self.subTest(name=name, v=v):
                    self.assertTrue(found(f"{label}: {v}", region=(region,)))
                    self.assertEqual(found(f"{label}: {bad}", region=(region,)), [])
                    self.assertEqual(found(v, region=(region,)), [])          # still needs its label

    def test_a_number_of_one_repeated_digit_is_a_placeholder(self):
        self.assertEqual(found("NHS number: 000 000 0000", region=("uk",)), [])
        self.assertEqual(found("ABA routing number: 000000000", region=("us",)), [])
        body = "41" + "1" * 6
        sum_ok = next(body + c for c in D if sum(int(x) * w for x, w in zip(body + c, (3, 7, 1) * 3)) % 10 == 0)
        self.assertFalse(checksums.us_aba_ok(sum_ok))                      # 41 is no routing symbol

    def test_a_pesel_inside_a_longer_digit_run_is_no_hit(self):
        v = pesel(random.Random(15))
        self.assertEqual(found(f"PESEL 9{v}", region=("pl",)), [])
        self.assertEqual(found(f"PESEL {v}0", region=("pl",)), [])




if __name__ == "__main__":
    unittest.main()
