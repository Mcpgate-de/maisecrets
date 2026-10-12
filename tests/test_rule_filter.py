"""The betterleaks rules and their filters (maisecrets/rule_filter.py, Mcpgate-de/maisecrets#18).

betterleaks replaced the gitleaks ruleset: gitleaks takes security patches only since v8.30.1, and its maintainers
develop betterleaks. Its rules drop a finding when an Expr filter is true; rule_filter reads the subset the vendored
rules use and refuses the rest, so a rule never runs without its filter.

Run: python3 -m unittest tests.test_rule_filter -v
Every token is built at run time from a seeded alphabet, so no literal sits in the tree.
"""
from __future__ import annotations

import json
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

from maisecrets import detect, rule_filter  # noqa: E402

RNG = random.Random(18)
VENDORED = json.loads((ROOT / "maisecrets" / "rules" / "betterleaks.json").read_text(encoding="utf-8"))


def tok(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def env(value: str, line: str = "") -> dict:
    return {"secret": value, "match": value, "line": line, "path": ""}


def kinds(text: str) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text)]


class FilterReaderTests(unittest.TestCase):
    def test_every_vendored_filter_compiles_except_the_four_programs(self):
        refused = []
        for r in VENDORED["rules"]:
            if r.get("filter"):
                try:
                    rule_filter.compile_filter(r["filter"])
                except rule_filter.Unsupported:
                    refused.append(r["id"])
        self.assertEqual(sorted(refused), ["generic-api-key", "generic-credential-uri", "generic-password",
                                           "generic-username"])
        rule_filter.compile_filter(VENDORED["filter"])

    def test_the_operators_and_functions_read_like_expr(self):
        f = rule_filter.compile_filter('entropy(finding["secret"]) < 3.0 || '
                                       'matchesAny(finding["secret"], [`^x+$`, `(?i)^TEST`]) && '
                                       '!containsAny(finding["line"], ["keep"])')
        self.assertTrue(f(env("aaaa", "")))                      # entropy 0 < 3.0
        self.assertTrue(f(env("testQ7w8E9r0T1y2", "")))          # (?i)^TEST, no "keep" on the line
        self.assertFalse(f(env("testQ7w8E9r0T1y2", "keep it")))  # && binds tighter than ||
        self.assertFalse(f(env(tok(24), "")))
        self.assertTrue(f(env("aaaa", "keep it")))   # A || (B && C): A alone is enough; (A || B) && C would be False

    def test_token_ratio_is_zero_as_betterleaks_answers_without_a_tokenizer(self):
        f = rule_filter.compile_filter('filter.entropy(finding["secret"]) < 3.0 || '
                                       'filter.tokenRatio(finding["secret"]) >= 2.5')
        self.assertFalse(f(env("the quick brown fox jumps over")))
        self.assertTrue(f(env("abababab")))

    def test_a_program_or_an_unknown_name_is_refused_not_run_without_it(self):
        for src in ('let x = finding["secret"]; x == "a"', 'filter.setConfidence("low")',
                    'unknownFn(finding["secret"])',
                    'finding["fragment_raw"] == ""', 'entropy(finding["secret"]) <',
                    'isExampleValue || entropy(finding["secret"]) < 3.0'):   # a let variable of a program
            with self.subTest(src):
                with self.assertRaises(rule_filter.Unsupported):
                    rule_filter.compile_filter(src)

    def test_entropy_counts_bytes_like_betterleaks(self):
        self.assertEqual(rule_filter.entropy(""), 0.0)
        self.assertEqual(rule_filter.entropy("aaaa"), 0.0)
        self.assertAlmostEqual(rule_filter.entropy("abcd"), 2.0)
        self.assertAlmostEqual(rule_filter.entropy("\u00e4\u00e4"), 1.0)   # two bytes each: c3 a4 c3 a4, not one rune

    def test_an_inline_case_flag_applies_from_its_place_as_in_re2(self):
        rx = rule_filter.to_python_regex("^/Users/(?i)[a-z0-9]+/x$")
        self.assertTrue(rx.search("/Users/AbC/x"))
        self.assertFalse(rx.search("/users/abc/x"))
        drop = rule_filter.compile_filter(VENDORED["filter"])            # the global filter holds ^/Users/(?i)…
        self.assertTrue(drop(env("/Users/" + tok(12, string.ascii_lowercase) + "/project")))
        self.assertFalse(drop(env("/users/" + tok(12, string.ascii_lowercase) + "/project")))
        with self.assertRaises(rule_filter.Unsupported):
            rule_filter.compile_filter('matchesAny(finding["secret"], [`a(?i)b|c`])')



class BetterleaksRuleTests(unittest.TestCase):
    def test_skip_report_components_and_unreadable_programs_are_not_loaded(self):
        ids = {r.id for r in detect._load_betterleaks()}
        skipped = {r["id"] for r in VENDORED["rules"] if r.get("skipReport")}
        self.assertTrue(skipped and not skipped & ids)
        self.assertFalse({"generic-password", "generic-username", "generic-credential-uri"} & ids)
        self.assertEqual(len([r for r in detect.rules() if r.id == "generic-api-key"]), 1,
                         "generic-api-key comes once, in its gitleaks form")

    def test_a_shape_gitleaks_did_not_know_is_found(self):
        value = "ddp_" + tok(36)                   # a Deno account token: no gitleaks v8.30.1 rule
        self.assertIn(("deno-account-token", value), kinds(f"DENO_DEPLOY={value}\n"))

    def test_the_shapes_betterleaks_lost_stay_found_through_the_kept_gitleaks_rules(self):
        lower = string.ascii_lowercase + string.digits
        for text, value in (("etsy: {v}", tok(24, lower)), ("artifactory: {v}", tok(73, lower)),
                            ("jfrog = {v}", tok(64, lower)), ("deploy with {v} now", "fo1_" + tok(43))):
            with self.subTest(text):
                self.assertIn(value, [v for _, v in kinds(text.format(v=value))])

    def test_each_kept_gitleaks_rule_finds_what_betterleaks_alone_misses(self):
        """The population of rules/gitleaks_compat.json: each rule but generic-api-key stays only while betterleaks
        misses a realistic token of its shape. A later betterleaks that closes a gap turns this red: drop the rule."""
        low, hexd = string.ascii_lowercase + string.digits, "0123456789abcdef"
        samples = {
            "alibaba-access-key-id": "LTAI" + tok(20, low + string.ascii_uppercase),
            "etsy-access-token": "etsy: " + tok(24, low),
            "jfrog-api-key": "artifactory: " + tok(73, low),
            "jfrog-identity-token": "jfrog = " + tok(64, low),
            "flyio-access-token.gitleaks8": "fo1_" + tok(43, string.ascii_letters + string.digits + "_-"),
            "atlassian-api-token.gitleaks8": "confluence: " + tok(20, low) + tok(4, hexd),
            "vault-service-token.gitleaks8": "s." + tok(24, low),
            "twilio-api-key.gitleaks8": "SK" + tok(32, hexd),
            "codecov-access-token.gitleaks8": "codecov: " + tok(32, low),
        }
        kept = [r for r in detect._load_gitleaks_compat() if r.id != "generic-api-key"]
        self.assertEqual(sorted(r.id for r in kept), sorted(samples), "the premise: one sample per kept rule")
        full = detect.rules()
        alone = [r for r in full if r.id not in samples]
        saved = detect._RULES
        try:
            for rid, text in samples.items():
                with self.subTest(rid):
                    detect._RULES = alone
                    self.assertEqual([m.kind for m in detect.scan(text + "\n")], [], "betterleaks finds it alone")
                    detect._RULES = full
                    self.assertIn(rid, [m.kind for m in detect.scan(text + "\n")])
        finally:
            detect._RULES = saved

    def test_the_rule_filter_drops_a_low_entropy_value(self):
        value = "ddp_" + "ab" * 18                 # entropy 1.x: the rule's filter drops it
        self.assertNotIn("deno-account-token", [k for k, _ in kinds(f"x {value} y")])

    def test_the_global_filter_drops_a_template(self):
        rule = next(r for r in detect._load_betterleaks() if r.id == "deno-account-token")
        path = "/usr/" + tok(30)                  # high entropy: the rule's own filter keeps it, the global one not
        self.assertTrue(rule.drop(env(path)))
        self.assertFalse(rule.drop(env("ddp_" + tok(36))))


if __name__ == "__main__":
    unittest.main()
