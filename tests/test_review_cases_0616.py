"""The cases of the four codex review rounds of 0.6.16 (and the Opus verification) as tests: each one a leak, a partial
mask, a false alarm or a slow input that a review found. A new rule must keep all of them.

Run: python3 -m unittest tests.test_review_cases_0616 -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean.
"""
from __future__ import annotations

import os
import random
import string
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RNG = random.Random(4616)
NEW = ("label-pw-literal", "label-secret-literal", "label-weak-key", "label-otp-seed")


def password(n: int = 10) -> str:
    while True:
        v = "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(n))
        if (any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v)
                and detect._wordlike(detect._deleet(v)) < 0.3):
            return v


def kinds(text: str) -> list:
    return [(m.kind, m.value) for m in detect.scan(text)]


def new_hits(text: str) -> list:
    return [k for k, _ in kinds(text) if k in NEW]


FORMS = ('password = "{}"', '{{"password": "{}"}}', "<password>{}</password>", '$password = "{}"')


class Round2Tests(unittest.TestCase):
    """codex Gate A on 363f235."""

    def test_a_keyword_label_with_a_tail_of_201_and_more_characters_takes_its_value(self):
        v = password(12) + "#7"
        for n in (199, 200, 201, 2000):
            with self.subTest(n=n):
                self.assertIn(v, [m.value for m in detect.scan("password" + "x" * n + " = " + v)])

    def test_sql_doubled_and_escaped_quotes_mask_the_whole_value(self):
        p = password(10)
        for inner in (p[:4] + "''" + p[4:], p[:4] + "\\'" + p[4:]):
            with self.subTest(inner=inner.replace(p[:4], "<a>")):
                self.assertIn(inner, [v for _, v in kinds(f"ALTER USER app IDENTIFIED BY '{inner}';")])

    def test_a_foreign_identifier_and_a_comparison_stay_text(self):
        for text in ('password = "senhaAtual"', 'if pw == "' + password(10) + '":'):
            with self.subTest(text=text[:22]):
                self.assertEqual(new_hits(text), [])

    def test_a_paserk_key_ends_before_a_period(self):
        import base64
        key = "k4.local." + base64.urlsafe_b64encode(bytes(RNG.randrange(256) for _ in range(32))).decode().rstrip("=")
        self.assertIn(("paserk-secret-key", key), kinds(f"The key is {key}."))


class Round3Tests(unittest.TestCase):
    """codex verification of 37e0dad."""

    def test_a_doubled_delimiter_first_is_part_of_the_value(self):
        p = password(10)
        for text in (f"ALTER USER app IDENTIFIED BY '''{p}';", f"$s = ConvertTo-SecureString '''{p}' -AsPlainText",
                     f"pw: '''{p}'''"):
            with self.subTest(form=text[:12]):
                self.assertTrue(any(v.endswith(p) or p in v for _, v in kinds(text)))
                self.assertNotIn(p, text.replace(next(v for _, v in kinds(text) if p in v), ""))

    def test_snake_case_names_stay_text(self):
        for value in ("senha_atual", "nueva-contrasena", "clave.nueva", "mot_de_passe_oublie"):
            for form in FORMS:
                text = form.format(value)
                with self.subTest(text=text):
                    self.assertEqual(new_hits(text), [])


class Round4Tests(unittest.TestCase):
    """codex final round on ebd1f51."""

    def test_a_password_with_a_regex_fragment_is_masked_whole(self):
        for frag in ("\\d", ".*", "[ab]+", "{2}"):
            v = "xK9!" + frag + "Qz7w"
            for text in (f"<password>{v}</password>", f"ALTER USER app IDENTIFIED BY '{v}';"):
                with self.subTest(frag=frag, form=text[:10]):
                    self.assertIn(v, [x for _, x in kinds(text)])

    def test_a_whole_pattern_after_a_secret_label_stays_text(self):
        for text in ("token: '[A-Za-z0-9_-]{20,}'", "secret: '[a-f0-9]{64}'", "api_key: '^" + chr(92) + "d{6}$'",
                     'api_key: "' + chr(92) * 2 + 'b[A-Z0-9]{20}' + chr(92) * 2 + 'b"'):
            with self.subTest(text=text):
                self.assertEqual(new_hits(text), [])

    def test_a_value_ending_in_a_backtick_is_masked_outside_powershell(self):
        v = "xKqTz" + "9" + "`"
        for text in (f'{{"password": "{v}", "login": "demo"}}', f'password = "{v}" # used by test',
                     f'pw = "{v}"; next = "demo"'):
            with self.subTest(text=text[:16]):
                self.assertIn(v, [x for _, x in kinds(text)])

    def test_a_random_mixed_case_value_in_another_script_is_a_password(self):
        for letters in ("пАрОлЬкД", "κΑλΟσΔεΚ"):
            for text in (f"<password>{letters}</password>", f"ALTER USER app IDENTIFIED BY '{letters}';",
                         f"$s = ConvertTo-SecureString '{letters}' -AsPlainText"):
                with self.subTest(form=text[:10]):
                    self.assertIn(letters, [x for _, x in kinds(text)])

    def test_consonant_heavy_identifiers_and_foreign_words_stay_text(self):
        for value in ("ctxPtr", "grpcSrv", "Svensk", "Pflicht"):
            for form in FORMS:
                text = form.format(value)
                with self.subTest(text=text):
                    self.assertEqual(new_hits(text), [])

    def test_paths_and_references_after_a_password_label_stay_text(self):
        for value in ("/x/y/z", "../x/y/z", "/mnt/pvc/db", "/run/secrets/db", "./secrets/pw.txt", "~/.pgpass",
                      "C:" + chr(92) + "keys" + chr(92) + "db.pw", "file:///etc/app/pw", "vault:secret/data/db#pw",
                      "env:DB_PASSWORD"):
            for form in FORMS:
                text = form.format(value)
                with self.subTest(text=text):
                    self.assertEqual(new_hits(text), [])


class SpeedTests(unittest.TestCase):
    def test_one_long_word_and_long_runs_stay_fast(self):
        rec = "password: ${DB_PASSWORD}\nmot de passe : voir le coffre\n"
        started = time.process_time()
        detect.scan(rec * 2000 + "x" * 300)
        detect.scan("password=" + "".join(RNG.choice("bcdfghjkmnpqrstvwxz") for _ in range(320000)))
        self.assertLess(time.process_time() - started, 3.0)


if __name__ == "__main__":
    unittest.main()
