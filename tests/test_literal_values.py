"""A label and a literal value that no older rule took: a password that is no word after a password label.

Run: python3 -m unittest tests.test_literal_values -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean. The developer text these rules must not flag (references, templates, masks, words, vault and Kubernetes
references) is in tests/fp_corpus.py NO_HIT.
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RNG = random.Random(616)
ALNUM = string.ascii_letters + string.digits


def password(n: int = 10, symbols: str = "") -> str:
    """A password with a capital, a small letter and a digit that is no word, also after undoing leet."""
    while True:
        v = "".join(RNG.choice(ALNUM + symbols) for _ in range(n))
        if (any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v)
                and detect._wordlike(detect._deleet(v)) < 0.3):
            return v


def kinds(text: str) -> list:
    return [(m.kind, m.value) for m in detect.scan(text)]


class PasswordLiteralTests(unittest.TestCase):
    def test_a_password_after_a_password_label_is_a_hit(self):
        """Forms the keyword rules missed: an XML element, SQL, PowerShell, a value of 4 to 7 characters, a call
        with the label as its name."""
        p4, p6, p10 = password(4), password(6), password(10, "!#%")
        cases = [
            f"<password>{p10}</password>",
            f"<db:Password>{p10}</db:Password>",
            f"ALTER USER app IDENTIFIED BY '{p10}';",
            f"CREATE USER app WITH LOGIN IDENTIFIED WITH mysql_native_password BY '{p10}';",
            f"$sec = ConvertTo-SecureString '{p10}' -AsPlainText -Force",
            f'mysql_pwd = "{p4}"',
            f"PASSWORD: '{p6}'",
            f'conn.Password("{p10}")',
            f"db.passwd={p4}",
            f'"userPassword": "{p6}"',
        ]
        for text in cases:
            with self.subTest(text=text.replace(p10, "<p10>").replace(p6, "<p6>").replace(p4, "<p4>")):
                got = kinds(text)
                self.assertTrue(any(k == "label-pw-literal" for k, _ in got), got and [k for k, _ in got])
                self.assertTrue(any(v in (p4, p6, p10) for _, v in got))

    def test_a_word_or_a_reference_after_a_password_label_is_no_hit(self):
        """No value or one that says what it is: a word, a word in leet, a fixture, a mask, a template, a reference."""
        for value in ("hunter", "Sunshine", "P4ssw0rd", "testpass", "changeme", "********", "abcdef", "123456789",
                      "secret123", "mypassword", "${DB_PASSWORD}", "{{ db_password }}", "%(password)s",
                      "settings.DB_PASSWORD", "<your-password>", "xxxxxxxx", "dragonfly"):
            for form in ('db_password = "{}"', "<password>{}</password>", "PASSWORD={}", "?pwd={}&x=1"):
                text = form.format(value)
                with self.subTest(text=text):
                    self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_a_label_that_names_something_else_is_no_hit(self):
        v = password(10)
        for label in ("password_hint", "passwordPolicy", "password_regex", "new_password_title", "password_field",
                      "password_hash", "bypass", "compass", "two_pass", "PASSWORD_MIN_LENGTH", "skip_pw"):
            text = f'{label} = "{v}"'
            with self.subTest(label=label):
                self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_the_word_list_is_read_only_after_a_password_label(self):
        detect._WORDS.clear()
        detect.scan("def handler(event):\n    return {'status': 200, 'body': event['id']}\n" * 50)
        self.assertEqual(detect._WORDS, [], "text without a password label read the word list")
        detect.scan(f'password = "{password(10)}"')
        self.assertEqual(len(detect._WORDS), 1)

    def test_the_word_list_is_the_one_its_license_names(self):
        rules = ROOT / "maisecrets" / "rules"
        words = (rules / "words_en.txt").read_text(encoding="utf-8").split("\n")[:-1]
        self.assertEqual(words, sorted(set(words)))
        self.assertTrue(all(w.isascii() and w.isalpha() and w.islower() and 4 <= len(w) <= 8 for w in words))
        self.assertTrue(15000 <= len(words) <= 25000, len(words))
        lic = (rules / "LICENSE-scowl").read_text(encoding="utf-8")
        version = (rules / "SCOWL_VERSION").read_text(encoding="utf-8").strip()
        self.assertIn("Copyright 2000-2026 by Kevin Atkinson", lic)
        self.assertIn(version, lic)
        self.assertIn("words_en.txt", (ROOT / "NOTICE").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
