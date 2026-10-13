"""The scan time stays linear for rules that look past a prefix: the AWS secret after its key id, and the two curl
rules of betterleaks. Each one scanned the rest of the line again from each prefix, so a line with many of them took
O(n^2) and ran past the hook's time limit, which lets the output through (0.6.15).

Run: python3 -m unittest tests.test_scan_bounds -v
Every token is generated at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import os
import random
import re
import string
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect  # noqa: E402

AN = string.ascii_letters + string.digits
_R = random.Random(615)
AWS = "aws-secret-after-access-key"
CURL = ("curl-auth-header", "curl-auth-user")


def secret_span(m, ngroups: int) -> tuple:
    """The span of the first group that matched: the credential scan() takes when secret_group is 0."""
    g = next((i for i in range(1, ngroups + 1) if m.group(i)), 0)
    return m.start(g), m.end(g)


def rnd(n: int, alphabet: str = AN) -> str:
    return "".join(_R.choice(alphabet) for _ in range(n))


def akid() -> str:
    return "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")


def aws_secret() -> str:
    return rnd(40, AN + "/+")


def took(text: str, ids) -> float:
    t = time.perf_counter()
    detect.scan(text, enabled=set(ids))
    return time.perf_counter() - t


class AwsSecretAfterKeyIdTests(unittest.TestCase):
    def values(self, text: str) -> list[str]:
        return [m.value for m in detect.scan(text) if m.kind == AWS]

    def test_the_console_form_on_two_lines_is_found(self):
        kid, sk = akid(), aws_secret()
        for text in (f"Access key ID: {kid}\nSecret access key: {sk}\n",
                     f"Access key\n{kid}\nSecret access key\n{sk}\n",
                     f'"AccessKeyId": "{kid}",\n        "Status": "Active",\n        "SecretAccessKey": "{sk}",\n'):
            with self.subTest(text[:12]):
                self.assertEqual(self.values(text), [sk])

    def test_a_credentials_csv_row_is_found(self):
        kid, sk = akid(), aws_secret()
        text = ("User name,Password,Access key ID,Secret access key,Console login link\n"
                f"deploy-bot,{rnd(16)},{kid},{sk},https://123456789012.signin.aws.amazon.com/console\n")
        self.assertEqual(self.values(text), [sk])

    def test_a_secret_more_than_400_characters_after_the_id_on_its_line_is_not_taken(self):
        # the bound that keeps the scan linear; a paste "within a few lines" is far inside it
        kid, sk = akid(), aws_secret()
        self.assertEqual(self.values(f"{kid} {'x ' * 150} {sk}"), [sk])
        self.assertEqual(self.values(f"{kid} {'x ' * 220} {sk}"), [])

    def test_a_line_of_64k_of_key_ids_scans_in_under_a_second(self):
        # released code: 32K took 2.3 s, 256K took 97 s in the hook (client timeout 20 s, then the output passes)
        text = " ".join(akid() for _ in range(64000 // 21))
        self.assertLess(took(text, [AWS]), 1.0)


class CurlRuleTests(unittest.TestCase):
    def commands(self) -> list[str]:
        tok, b64, up = rnd(32), rnd(24, AN + "+/"), "deploy" + ":" + rnd(14)
        return [
            f"curl -H 'Authorization: Bearer {tok}' https://api.example.com/v1",
            f'curl https://api.example.com/v1 -H "Authorization: Basic {b64}"',
            f"curl -s \\\n  -X POST \\\n  --header 'X-Api-Key: {tok}' \\\n  https://api.example.com/x",
            f"curl -s https://api.example.com/x\\\n\n  -H 'Authorization: Token {tok}'",
            f"curl -u {up} https://example.com/a",
            f"curl --user '{up}' https://example.com/a",
            f'curl -s \\\n  --user="{up}" \\\n  https://example.com/a',
            f"curl -s\n1\n2\n3\n4\n5\n -u {up} https://example.com/a",        # 6 breaks: too far for the rule
            f"curl -s\n\n\n\n\n\n -u {up} https://example.com/a",              # blank lines: 3 breaks
            f"echo curl\n -H 'Authorization: Bearer {tok}'",
            f"curl https://example.com/a\n1\n2\n3\n4\n5\n6\n7\ncurl -u {up} https://example.com/b",  # near one
            f"wget --header 'Authorization: Bearer {tok}'",                         # no curl: no hit
        ]

    def test_the_curl_rules_take_the_linear_path(self):
        for rule in detect.rules():
            if rule.id in CURL:
                self.assertIsNotNone(detect._curl_parts(rule), f"{rule.id}: a sync changed the head of its regex")

    def test_the_linear_path_finds_what_the_regex_finds(self):
        rules = {r.id: r for r in detect.rules() if r.id in CURL}
        self.assertEqual(set(rules), set(CURL))
        for text in self.commands():
            for rid, rule in rules.items():
                with self.subTest(rule=rid, text=text[:30]):
                    rx = re.compile(rule.regex.pattern)
                    want = [(m.start(), secret_span(m, rx.groups), m.groups()) for m in rx.finditer(text)]
                    got = [(m.start(), secret_span(m, rx.groups), tuple(m.group(i) for i in range(1, rx.groups + 1)))
                           for m in detect._matches(rule, text)]
                    self.assertEqual(got, want)

    def test_a_second_credential_right_after_the_first_is_found(self):
        # the trailing space of the first -u was part of its match, and finditer went on after it (Gate B of 0.6.15)
        a, b = "admin" + ":" + rnd(14), "bob" + ":" + rnd(14)
        text = f"curl -u {a} --user {b} https://example.com/a"
        self.assertEqual([m.value for m in detect.scan(text) if m.kind == "curl-auth-user"], [a, b])

    def test_fuzz_the_linear_path_finds_every_credential_the_regex_finds(self):
        # every secret span the betterleaks regex finds is found by the linear path (it may find more: each -u)
        r = random.Random(1)
        tok = rnd(30)
        pieces = ["curl", "CURL", f" -H 'X-API-Key: {tok}'", f' -H "Authorization: Basic {tok}"', f" -u admin:{tok}",
                  " --user bob" + ":" + tok + " \\\n", "\n", "\n\n", "\r\n", " -X POST", " https://x", " echo",
                  " -d @f",
                  " && ", "curl -s", " -H 'Accept: */*'", "\r"]
        rules = [x for x in detect.rules() if x.id in CURL]
        misses = []
        for _ in range(3000):
            text = "".join(r.choice(pieces) for _ in range(r.randint(2, 14)))
            for rule in rules:
                rx = re.compile(rule.regex.pattern)
                want = {secret_span(m, rx.groups) for m in rx.finditer(text)}
                got = {secret_span(m, rx.groups) for m in detect._curl_matches(detect._curl_parts(rule), text)}
                if not want <= got:
                    misses.append((rule.id, len(text)))
        self.assertEqual(misses[:5], [])

    def test_a_line_of_many_curl_words_scans_in_under_a_second(self):
        # released code: 32K characters of "curl " took 16.6 s for the two curl rules and the AWS rule
        for tok in ("curl ", "curl -u ", "curl -H 'Authorization: Bearer "):
            with self.subTest(tok):
                self.assertLess(took((tok * 7000)[:32000], CURL), 1.0)


class LabelRuleTests(unittest.TestCase):
    def test_a_long_line_of_a_command_word_scans_in_under_a_second(self):
        # `mysql … -p` and `redis-cli … -a` looked for the option over the rest of the line from each command word:
        # 32K characters took 0.35 s, 256K about 22 s (Gate A of 0.6.15); bounded to 400 characters as the AWS rule
        for tok in ("mysql -u root ", "redis-cli -h cache "):
            with self.subTest(tok):
                self.assertLess(took((tok * 8000)[:96000], ("label-mysql-p", "label-redis-cli-a")), 1.0)

    def test_the_option_400_characters_after_the_command_is_still_found(self):
        pw = rnd(10) + "#7"
        text = "mysql " + "--host db " * 39 + f"-p{pw} shop"
        self.assertEqual([m.value for m in detect.scan(text) if m.kind == "label-mysql-p"], [pw])


class KeywordLabelTailTests(unittest.TestCase):
    """The detect-secrets keyword rules read `<keyword>\\w*` as the label. On `password=` and a long run of letters with
    no space, each keyword inside the run (pwd, key) took the rest of the run: 320 KB took 10 s (0.6.15). The tail is
    bounded at 200 word characters (detect._DS_LABEL_TAIL_BOUNDED)."""

    def rules(self):
        return [r for r in detect.rules() if r.id.startswith("ds-keyword")]

    def test_a_long_run_of_letters_after_a_label_scans_in_under_a_second(self):
        run = "".join(_R.choice("bcdfghjkmnpqrstvwxz") for _ in range(320000))
        self.assertLess(took("password=" + run, [r.id for r in self.rules()]), 1.0)

    def test_every_keyword_rule_is_bounded(self):
        rules = self.rules()
        self.assertEqual(len(rules), 7)
        for r in rules:
            with self.subTest(r.id):
                self.assertIn(")" + detect._DS_LABEL_TAIL_BOUNDED, r.regex.pattern)

    def test_fuzz_the_bounded_rules_find_what_the_vendored_ones_find(self):
        """Inside the bound (label tails of up to 150 word characters) both forms give the same matches."""
        parts = ["password", "pwd", "api_key", "secret", "db_pass", "Passwd", "token", "_", "x", "Ab9", "value",
                 "=", "==", "!=", ":", " : ", "=>", " ", "  ", "'", '"', "`", ";", ",", "]", "\t", "\n", "-", "#7"]
        rng = random.Random(1616)
        texts = []
        for _ in range(3000):
            t = "".join(rng.choice(parts) for _ in range(rng.randint(2, 14)))
            if rng.random() < 0.3:
                t = t.replace("_", "_" + "w" * rng.randint(1, 140), 1)
            texts.append(t)
        found = 0
        for r in self.rules():
            old = re.compile(r.regex.pattern.replace(")" + detect._DS_LABEL_TAIL_BOUNDED, ")\\w*", 1),
                             r.regex._get().flags)
            new = r.regex._get()
            self.assertNotEqual(old.pattern, new.pattern)
            for t in texts:
                spans = [[m.span(i) for i in range(new.groups + 1)] for m in new.finditer(t)]
                want = [[m.span(i) for i in range(old.groups + 1)] for m in old.finditer(t)]
                self.assertEqual(spans, want, f"{r.id}: {t!r}")
                found += len(spans)
        self.assertGreater(found, 400, "the fuzz inputs must hold labels and values, or the comparison proves nothing")


if __name__ == "__main__":
    unittest.main()
