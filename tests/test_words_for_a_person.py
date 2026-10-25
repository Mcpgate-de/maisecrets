"""The words a person reads for what maisecrets found: one noun per class of the type vocabulary (notices.TYPE_WORDS,
CLASS_WORDS), and the form of a personal-data rule that finds a value only by the words around it.

Run: python3 -m unittest tests.test_words_for_a_person -v
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

from maisecrets import detect, notices  # noqa: E402
from maisecrets.detection.vocabulary import TYPES  # noqa: E402


class NounTests(unittest.TestCase):
    def test_every_class_of_the_vocabulary_has_one_noun(self):
        classes = {v["class"] for v in TYPES.values()}
        self.assertEqual(classes, set(notices.CLASS_WORDS))
        for type_ in TYPES:
            with self.subTest(type_):
                self.assertNotIn("value of the type", notices.type_word(type_))

    def test_the_article_follows_the_sound(self):
        self.assertEqual(notices.type_word("SECRET"), "a secret")
        self.assertEqual(notices.type_word("EMAIL"), "an e-mail address")
        self.assertEqual(notices.type_word("IBAN"), "an IBAN")
        self.assertEqual(notices.type_word("IP"), "an IP address")
        self.assertEqual(notices.type_word("US_SSN"), "an official ID number")
        self.assertEqual(notices.type_word("MY_OWN_TYPE"), "a value of the type MY_OWN_TYPE")

    def test_a_postal_code_and_a_licence_plate_are_no_official_id(self):
        # pii.national_id holds a postal code and licence plates: the class noun would call them an ID of a person
        self.assertEqual(notices.type_word("DE_PLZ"), "a postal code")
        for plate in ("DE_KFZ", "UK_VEHICLE_REGISTRATION", "TR_LICENSE_PLATE", "IN_VEHICLE_REGISTRATION",
                      "NG_VEHICLE_REGISTRATION"):
            self.assertEqual(notices.type_word(plate), "a licence plate", plate)
        self.assertEqual(notices.type_word("DE_VAT_ID"), "a VAT number")


class PersonalFormTests(unittest.TestCase):
    def test_a_personal_rule_that_needs_the_words_around_it_is_a_label_rule(self):
        # name-after-label, phone-after-phone-word, the vCard rules: each finds a value only by the words around it,
        # so its spec must not say shape (a shape is found alone)
        personal = [s for s in detect.pass_specs() if s.source == "personal"]
        self.assertTrue(personal)
        for s in personal:
            with self.subTest(s.id):
                self.assertEqual(s.form, "label" if s.needs else "shape")
        ids = {s.id: s.form for s in personal}
        for rid in ("name-after-label", "phone-after-phone-word", "name-vcard-n", "address-in-form"):
            self.assertEqual(ids[rid], "label", rid)
        self.assertEqual(ids["phone-one-digit-groups"], "shape")

    def test_the_rule_list_keeps_the_form_of_its_ids(self):
        # the form of a rule of the rule list decides the fixture check: it must not move with the words for a person
        for spec, rule in detect.rule_specs():
            self.assertEqual(spec.form, rule.form, spec.key)


if __name__ == "__main__":
    unittest.main()
