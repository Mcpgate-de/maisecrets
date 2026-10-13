"""A label and a literal value that no older rule took (a password that is no word after a password label, a key
after a secret label), and four token formats with a public prefix (NTLMSSP, NATS nkey seed, PASERK, PASETO).

Run: python3 -m unittest tests.test_literal_values -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean. The developer text these rules must not flag (references, templates, masks, words, vault and Kubernetes
references) is in tests/fp_corpus.py NO_HIT.
"""
from __future__ import annotations

import base64
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


def key(n: int = 16) -> str:
    """A key: letters of both cases and digits, no word, high entropy."""
    while True:
        v = password(n)
        if detect._norm_entropy(v) >= 0.9 and detect._wordlike(detect._deleet(v)) < 0.15:
            return v


class SecretLiteralTests(unittest.TestCase):
    """A key after a label that names a secret (label-secret-literal) or may name one (label-weak-key), in forms the
    keyword rules did not read: an XML element, a call, a session, cookie, HMAC or PSK label."""

    def test_a_key_after_a_secret_label_is_a_hit(self):
        k12, k16 = key(12), key(16)
        for rule, text, value in (("label-secret-literal", f"<clientSecret>{k12}</clientSecret>", k12),
                                  ("label-secret-literal", f"<AccessToken>{k16}</AccessToken>", k16),
                                  ("label-weak-key", f'hmac = "{k16}"', k16),
                                  ("label-weak-key", f'session = "{k16}"', k16),
                                  ("label-weak-key", f'cookie: "{k16}"', k16),
                                  ("label-weak-key", f'"psk": "{k16}"', k16),
                                  ("label-weak-key", f'appKey("{k16}")', k16),
                                  ("label-weak-key", f"<key>{k16}</key>", k16)):
            with self.subTest(rule=rule, form=text.split(value)[0]):
                self.assertIn((rule, value), kinds(text))

    def test_a_word_a_public_part_or_a_nonce_stays_text(self):
        k16 = key(16)
        hex32 = "".join(RNG.choice("0123456789abcdef") for _ in range(32))
        texts = [f'public_key = "{k16}"', f'cache_key = "{k16}"', f'primary_key = "{k16}"', f'nonce = "{hex32}"',
                 f'key = "{hex32}"', 'session = "user-session-cookie"', '<clientSecret>${CLIENT_SECRET}</clientSecret>',
                 '<AccessToken>{{ access_token }}</AccessToken>', 'hmac = "HMAC-SHA256-SIGNATURE"', f"session: {k16}",
                 'x-amz-signature: "' + k16 + '"']
        for text in texts:
            with self.subTest(text=text.split(" ")[0]):
                self.assertEqual([k for k, _ in kinds(text) if k in ("label-secret-literal", "label-weak-key")], [])


def b64(raw: bytes, url: bool = False) -> str:
    return (base64.urlsafe_b64encode(raw).decode().rstrip("=") if url else base64.b64encode(raw).decode())


def rnd(n: int) -> bytes:
    return bytes(RNG.randrange(256) for _ in range(n))


B32 = string.ascii_uppercase + "234567"


class TokenFormatTests(unittest.TestCase):
    """Four token formats with a public prefix: an NTLMSSP message, a NATS nkey seed, a PASERK secret key, a PASETO
    token."""

    def cases(self):
        ntlm = b64(b"NTLMSSP\x00\x03\x00\x00\x00" + rnd(60))
        seed = "SU" + "".join(RNG.choice(B32) for _ in range(56))
        paserk = "k4.local." + b64(rnd(32), url=True)
        paseto = "v4.local." + b64(rnd(64), url=True)
        return [("ntlmssp-message", f"Authorization: NTLM {ntlm}", ntlm),
                ("ntlmssp-message", f"WWW-Authenticate: Negotiate {ntlm}", ntlm),
                ("nats-nkey-seed", f"seed: {seed}", seed),
                ("nats-nkey-seed", f"nkeys.FromSeed([]byte(\"{seed}\"))", seed),
                ("paserk-secret-key", f"PASERK={paserk}", paserk),
                ("paserk-secret-key", f"k = '{paserk}'", paserk),
                ("paseto-token", f"headers = {{\"X-Session\": \"{paseto}\"}}", paseto),
                ("paseto-token", f"token = {paseto}", paseto)]

    def test_each_format_is_a_hit_by_its_rule(self):
        for rule, text, value in self.cases():
            with self.subTest(rule=rule, form=text.split(value)[0]):
                self.assertIn((rule, value), kinds(text))

    def test_public_parts_and_short_lookalikes_stay_text(self):
        pub = "U" + "".join(RNG.choice(B32) for _ in range(55))
        for text in (f"nkey public: {pub}",                                   # a public nkey: U, N, A …
                     "k4.public." + b64(rnd(32), url=True),                     # a PASERK public key
                     "k4.lid." + b64(rnd(33), url=True),                        # a PASERK key id
                     "v4.local.short",                                          # no token
                     "TlRMTVNTUA",                                              # the prefix alone, in prose
                     "the field SUPERCALIFRAGILISTICEXPIALIDOCIOUS is long"):
            with self.subTest(text=text[:12]):
                self.assertEqual([k for k, _ in kinds(text) if k in ("ntlmssp-message", "nats-nkey-seed",
                                                                      "paserk-secret-key", "paseto-token")], [])


if __name__ == "__main__":
    unittest.main()
