"""Passwords with no shape where no `=` or `:` stands between label and value. A public benchmark (Cloakroom
holdout v7, 2026-10-12) leaked ten such passwords: .netrc, CLI flags, `mysql -p`, Redis AUTH and prose.

Run: python3 -m unittest tests.test_shapeless_passwords -v
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

J = "".join
RNG = random.Random(1012)


def found(text: str) -> list[tuple[str, str]]:
    saved = detect._RULES
    active = regions.Active(regions=("generic",), languages=("en",), source="test")
    try:
        detect._RULES = None
        with mock.patch.object(detect, "active_regions", return_value=active):
            return [(m.type, m.value) for m in detect.scan(text)]
    finally:
        detect._RULES = saved


def password(n: int = 12, symbols: str = "#%*!-") -> str:
    """A password of the benchmark's shape: capitals, small letters, digits and a symbol, in random order. No `&` or
    `;` by default: unquoted in a shell they end the command, so no unquoted value holds them."""
    parts = [RNG.choice(string.ascii_uppercase), RNG.choice(string.ascii_lowercase), RNG.choice(string.digits),
             RNG.choice(symbols)]
    parts += [RNG.choice(string.ascii_letters + string.digits) for _ in range(n - len(parts))]
    RNG.shuffle(parts)
    return J(parts)


PW_FLAG = J(["--pass", "word"])
PW = J(["pass", "word"])


class CliFlagTests(unittest.TestCase):
    def test_a_password_after_a_flag_and_a_space_is_a_hit(self):
        pw = password()
        for text in (f"$ pg_dump --host db1 --username app {PW_FLAG} '{pw}' prod > dump.sql",
                     f'nats server info --user admin {PW_FLAG} "{pw}" --help',
                     f"ogg --user ggadmin {PW_FLAG} {pw} \\",
                     f"tool --db-{PW} {pw}",
                     f"$cred = Connect-Thing -User bob -{PW.capitalize()} {pw}"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_options_placeholders_and_words_after_the_flag_are_no_hit(self):
        for text in (f'echo "$CI_REGISTRY_{PW.upper()}" | docker login -u ci {PW_FLAG}-stdin',
                     f"tool {PW_FLAG}-file ./secret.txt", f"tool {PW_FLAG} {PW.upper()}",
                     f"tool {PW_FLAG} <{PW}>", f"[-user <domain-user>] [-{PW} <domain-{PW}>]",
                     f"use the {PW_FLAG} argument to set it", f'tool {PW_FLAG} "$DB_{PW.upper()}"',
                     f"tool {PW_FLAG} ${{DB_{PW.upper()}}}", f"dpl heroku --username user {PW_FLAG} pass",
                     f"tool {PW_FLAG} <admin-pw>, then the host", f"git send-email --no-{PW} --force-tls \\"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])

    def test_an_elided_value_in_docs_is_no_hit(self):
        # a keyword filter of scan(): the label rules without `=` or `:` get them too (KEYWORD_RULES)
        self.assertEqual(found(f"tool {PW_FLAG} {password(8)[:8]}... (shortened)"), [])

    def test_a_flag_password_in_test_code_is_a_fixture(self):
        # a label rule (LABEL_RULES): in test code it is a fixture, as `password = "<value>"` is
        pw = password()
        text = f'def test_login(self):\n    cmd = "tool {PW_FLAG} {pw} --verbose"\n'
        hits = [m for m in detect.scan(text) if m.value == pw]
        self.assertEqual(len(hits), 1)
        self.assertTrue(detect.is_fixture(hits[0], text, "tests/test_login.py"))


class MysqlTests(unittest.TestCase):
    def test_a_password_glued_to_dash_p_is_a_hit(self):
        pw = password()
        for text in (f"$ mysql -h 10.2.0.14 -u report -p'{pw}' analytics",
                     f"mysqldump -uroot -p{pw} shop > shop.sql", f'mariadb -u app -p"{pw}" -e "select 1"'):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_a_prompt_a_port_and_a_variable_are_no_hit(self):
        for text in ("mysql -u root -p app", "mysql -h db -P3306 -u root -p", "mysql -u root -proot app",
                     f'mysql -u root -p"$MYSQL_{PW.upper()}" app', "grep -pattern x mysql.log"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class RedisTests(unittest.TestCase):
    def test_auth_at_the_prompt_and_redis_cli_dash_a_are_hits(self):
        pw = password(11)
        for text in (f"127.0.0.1:6379> AUTH {pw}\nOK\n127.0.0.1:6379> KEYS session:*\n",
                     f"AUTH default {pw}", f"redis-cli -h cache.internal -a {pw} ping"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_auth_words_and_prose_are_no_hit(self):
        for text in ("AUTH LOGIN", "the auth token expired, AUTH failed", "250-AUTH PLAIN LOGIN",
                     "step:\nauth 2fa-required",
                     "127.0.0.1:6379> AUTH $REDIS_" + PW.upper()):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class NetrcTests(unittest.TestCase):
    def test_a_netrc_password_on_several_lines_and_on_one_is_a_hit(self):
        pw = password(10)
        for text in (f"machine git.example-corp.net\n  login deploy\n  {PW} {pw}\n",
                     f"machine api.example-corp.net login ci {PW} {pw}",
                     f"default login anonymous {PW} {pw}"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_prose_with_machine_or_default_is_no_hit(self):
        for text in (f"the default {PW} is printed on the label", f"machine learning {PW} reset flow",
                     f"==== Disabling default {PW} expiration",
                     f"machine host login user {PW} $NETRC_{PW.upper()}"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class ProseTests(unittest.TestCase):
    def test_a_password_in_a_sentence_is_a_hit(self):
        pw = password(11, symbols="%#&*")
        for text in (f"the staging db is down again, my {PW} is {pw} if you want to try logging in yourself",
                     f'the {PW} was "{pw}".', f"{PW.capitalize()} is: {pw}", f"my {PW} is {pw}. Thanks"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_words_of_a_sentence_are_no_hit(self):
        for text in (f"the {PW} is incorrect.", f"the {PW} is base64-encoded before it is stored",
                     f"the {PW} is hunter2 and the user is max", f"the {PW} is shown as plain text",
                     f"the {PW} is required", f"the {PW} is ${{DB_{PW.upper()}}}", f"the {PW} is 12345678",
                     f'"description": "The {PW} is invalid."', f"<p>The {PW} is ignored.</p>",
                     f'"doc": "the user for whom the {PW} is valid.\\n@param userName"', f"the {PW} is set.*/",
                     f"the {PW} is Read-Only", f'"doc": "the {PW} is v2\\n@param"'):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


if __name__ == "__main__":
    unittest.main()
