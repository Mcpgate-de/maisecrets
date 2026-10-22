"""Secrets in config and code forms that Benchmark V3 found in the clear (aparte, llmredactor, CredSweeper dev,
2026-10): a key or a salt of PHP's define(), and the other forms this file adds a class for.

Run: python3 -m unittest tests.test_config_forms -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean.
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

RNG = random.Random(2210)
ALNUM = string.ascii_letters + string.digits
# the signs of a WordPress salt (wp-config.php, api.wordpress.org/secret-key): no quote and no backslash
SALT_SIGNS = ALNUM + "!@#$%^&*()-_[]{}<>~`+=,.;:/?|"


def salt(n: int = 64) -> str:
    while True:
        v = "".join(RNG.choice(SALT_SIGNS) for _ in range(n))
        if any(c in "()|`" for c in v) and any(c.isdigit() for c in v):
            return v


def key(n: int = 32) -> str:
    while True:
        v = "".join(RNG.choice(ALNUM) for _ in range(n))
        if any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v):
            return v


def hits(text: str, channel: str = "prompt") -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel)]


def values(text: str, channel: str = "prompt") -> list[str]:
    return [v for _, v in hits(text, channel)]


class PhpDefineTests(unittest.TestCase):
    def test_a_wordpress_salt_in_define_is_a_hit(self):
        names = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "NONCE_SALT")
        salts = [salt() for _ in names]
        text = "<?php\n" + "".join(f"define( '{n}', '{s}' );\n" for n, s in zip(names, salts))
        for channel in ("prompt", "tool"):
            got = values(text, channel)
            for s in salts:
                self.assertIn(s, got, channel)

    def test_a_key_in_double_quotes_is_a_hit(self):
        s = salt(48)
        self.assertIn(("label-php-define-key", s), hits(f'define("STRIPE_SECRET", "{s}");'))

    def test_a_placeholder_a_constant_or_a_short_value_is_no_hit(self):
        for value in ("put your unique phrase here", "MY_OTHER_KEY_CONSTANT_NAME", "something_here_for_you",
                      "short" + "Val1", "x" * 64):
            text = f"define( 'AUTH_KEY', '{value}' );"
            self.assertEqual([], values(text), value)

    def test_a_name_that_names_no_key_is_no_hit(self):
        self.assertEqual([], [k for k, _ in hits(f"define( 'WP_HOME', '{salt()}' );")
                              if k == "label-php-define-key"])


if __name__ == "__main__":
    unittest.main()
