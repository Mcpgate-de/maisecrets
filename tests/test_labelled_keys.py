"""Keys that a label names but no label rule took: each key in a list after a label that names secrets.

Run: python3 -m unittest tests.test_labelled_keys -v
Every value is built at run time from a hash or a seeded random source, so no literal sits in the tree and the tree
scan stays clean. The false alarms these rules must not raise in developer text (tokenizer output, lockfiles, ids,
paths, crypto test vectors) are in tests/fp_corpus.py NO_HIT.
"""
from __future__ import annotations

import base64
import hashlib
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

RNG = random.Random(16)
ALNUM = string.ascii_letters + string.digits


def hexkey(seed: str, n: int = 32) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


def b64key(seed: str, n: int = 32) -> str:
    """A key as most services hand it out: base64url of random bytes, with a capital, a small letter and a digit."""
    while True:
        k = base64.urlsafe_b64encode(hashlib.sha512(seed.encode()).digest()).decode().rstrip("=")[:n]
        if any(c.isupper() for c in k) and any(c.islower() for c in k) and any(c.isdigit() for c in k):
            return k
        seed += "+"


def hits(text: str, kind: str) -> list[str]:
    return [m.value for m in detect.scan(text) if m.kind == kind]


def values(text: str) -> list[str]:
    return [m.value for m in detect.scan(text)]


class SecretListTests(unittest.TestCase):
    def test_each_key_in_a_list_after_a_secret_label_is_a_hit(self):
        a, b = hexkey("list-a", 32), b64key("list-b")
        for text in (f'{{"api_keys": ["{a}", "{b}"], "color": null}}',
                     f"passwords = ['{a}', '{b}']",
                     f'\tSecrets:   []string{{"{a}", "{b}"}},',
                     f'"refresh_tokens": [\n    "{a}",\n    "{b}"\n]',
                     f'const password = ["{a}", "{b}"];',
                     f'clientSecrets: ["{a}", "{b}"]'):
            with self.subTest(text=text[:20]):
                self.assertEqual(hits(text, "label-secret-list"), [a, b])

    def test_a_long_list_is_masked_to_its_end(self):
        keys = [hexkey(f"long-{i}", 32) for i in range(200)]
        text = '"api_keys": [' + ", ".join(f'"{k}"' for k in keys) + "]"
        self.assertEqual(hits(text, "label-secret-list"), keys)

    def test_a_list_after_a_label_that_names_no_secret_is_no_hit(self):
        k = hexkey("not-secret", 32)
        for label in ("tokens", "token", "Tokens", "code_tokens", "cache_tokens", "revokedTokens", "payment_tokens",
                      "vault_secrets", "keys", "access_keys", "token_hashes"):
            with self.subTest(label=label):
                self.assertEqual(values(f'"{label}": ["{k}", "{b64key(label)}"]'), [])

    def test_values_that_are_no_key_stay_text(self):
        bcrypt = "$2b$12$" + "".join(RNG.choice(ALNUM) for _ in range(53))
        for item in ("DB_PASSWORD", "ProdDbPassword2024Rotated", "TokenizerPiece2024X", "convertToUTF8String",
                     "projects/my-proj/secrets/db-pass/versions/3", "secret/data/app/" + b64key("vault", 12),
                     ":".join(["arn", "aws", "secretsmanager", "eu-central-1", "123456789012", "sec" + "ret",
                               b64key("arn", 12)]), bcrypt,
                     "0x" + hexkey("eth", 40), "pm_" + b64key("stripe", 24), "sess_" + b64key("clerk", 24),
                     "sha256:" + hexkey("dg", 64),
                     "sha384-" + base64.b64encode(hashlib.sha384(b"sri").digest()).decode(),
                     "${API_KEY_1}", "a" * 20 + "1", "0" * 16, str(int(hexkey("numeric-id"), 16))[:18]):
            with self.subTest(item=item[:24]):   # other rules may take a part (an ARN, a typed id) as before
                self.assertEqual(hits(f'"secrets": ["{item}"]', "label-secret-list"), [])

    def test_the_list_ends_at_its_bracket(self):
        a, other = hexkey("end-a", 32), hexkey("end-b", 32)
        self.assertEqual(hits(f'"api_keys": ["{a}"], "ids": ["{other}"]', "label-secret-list"), [a])
        self.assertEqual(hits(f'"api_keys": ["{a}"]\n"{other}",\n', "label-secret-list"), [a])
        self.assertEqual(hits(f'"api_keys": [{{"id": "{other}"}}]', "label-secret-list"), [])

    def test_a_tuple_is_no_list_of_secrets(self):
        # the Elasticsearch client takes api_key=("<id>", "<key>"); the id is public
        self.assertEqual(values(f'es = Elasticsearch(hosts, api_key=("{b64key("es-id", 20)}", os.environ["K"]))'), [])

    def test_a_key_after_a_word_in_the_list_is_still_a_hit(self):
        a = hexkey("after-word", 32)
        self.assertEqual(hits(f'"passwords": ["Bearer", "{a}"]', "label-secret-list"), [a])


if __name__ == "__main__":
    unittest.main()
