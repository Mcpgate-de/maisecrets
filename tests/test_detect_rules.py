"""The detector (detect.py): rule loaders, validators, placeholders, context words, the scanner's
overlap and extension rules, the label on the next line, the keyword window, and two corpora.

Run: python3 -m unittest tests.test_detect_rules -v
Every token is generated at run time from a seeded alphabet, so no literal sits in the tree and
the repository's own secret scan stays clean.
"""
from __future__ import annotations

import base64
import hashlib
import os
import random
import string
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
if "maisecrets.vault" not in sys.modules:
    # never the real store and never the keychain: the jsonfile backend in a temp home
    _TMP = tempfile.mkdtemp(prefix="maisecrets-test-")
    os.environ["MAISECRETS_HOME"] = _TMP
    Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect, hooks  # noqa: E402

AN = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
_R = random.Random(11)


def rnd(n: int, alphabet: str = AN, r: random.Random = _R) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def kinds(text: str, **kw) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text, **kw)]


def luhn_complete(body: str) -> str:
    """Append the Luhn check digit (independent of detect._luhn_ok)."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:            # these are doubled once the check digit is appended
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def iban_complete(cc: str, bban: str) -> str:
    """Compute the ISO 13616 check digits (independent of detect._iban_ok)."""
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


def tax_id_check(first10: str) -> str:
    """ISO 7064 MOD 11,10 check digit (independent of detect._de_tax_id_ok)."""
    p = 10
    for ch in first10:
        s = (int(ch) + p) % 10
        p = ((s if s else 10) * 2) % 11
    return str((11 - p) % 10)


# ------------------------------------------------------------------ loaders --
class RuleLoaderTests(unittest.TestCase):
    def test_gitleaks_rules_are_secret_rules_with_their_allowlists(self):
        rules = detect._load_gitleaks()
        self.assertGreater(len(rules), 150)
        self.assertEqual({r.type for r in rules}, {"SECRET"})
        self.assertEqual(len({r.id for r in rules}), len(rules))
        by_id = {r.id: r for r in rules}
        generic = by_id["generic-api-key"]
        self.assertEqual(generic.entropy, 3.5)
        self.assertIn("token", generic.keywords)
        self.assertTrue(all(k == k.lower() for r in rules for k in r.keywords))
        self.assertTrue(all(s == s.lower() for s in generic.stopwords))
        self.assertIn("line", {t for _, t in generic.allow_regexes})
        # RE2 flags and anchors are rewritten for Python: every regex compiles
        for r in rules:
            with self.subTest(rule=r.id):
                r.regex.search("")

    def test_re2_flags_move_to_the_front_and_z_becomes_Z(self):
        self.assertEqual(detect._re2_to_python(r"abc(?i)def\z"), r"(?i)abcdef\Z")
        self.assertEqual(detect._re2_to_python(r"plain"), "plain")

    def test_presidio_regions_are_opt_in(self):
        generic = {r.id.split("#")[0] for r in detect._load_presidio(("generic",))}
        with_de = {r.id.split("#")[0] for r in detect._load_presidio(("generic", "de"))}
        with_us = {r.id.split("#")[0] for r in detect._load_presidio(("generic", "us"))}
        self.assertIn("iban", generic)
        self.assertFalse(any(i.startswith("de-") for i in generic))
        self.assertIn("de-tax-id", with_de)
        self.assertIn("aba-routing", with_us)
        self.assertNotIn("aba-routing", with_de)
        self.assertFalse(generic & detect.PRESIDIO_SKIP)

    def test_presidio_region_is_derived_from_the_recognizer_id(self):
        for rec, region in [("de-tax-id", "de"), ("us-ssn", "us"), ("nhs", "uk"), ("aba-routing", "us"),
                            ("iban", "generic"), ("credit-card", "generic"), ("abc-x", "generic")]:
            with self.subTest(rec=rec):
                self.assertEqual(detect.presidio_region(rec), region)

    def test_presidio_rules_carry_type_validator_and_weakness(self):
        rules = {r.id: r for r in detect._load_presidio(("generic", "de"))}
        self.assertEqual((rules["iban"].type, rules["iban"].validator, rules["iban"].require_context),
                         ("IBAN", "iban", False))
        self.assertEqual(rules["credit-card"].type, "CARD")
        self.assertTrue(rules["de-tax-id"].require_context)            # a plain digit run
        self.assertTrue(rules["de-fuehrerschein"].score < 1.0)
        self.assertIn("de-id-card#0", rules)                           # several patterns: numbered ids
        self.assertIn("de-id-card#1", rules)
        self.assertTrue(all(r.whole_match for r in rules.values()))
        self.assertTrue(all(c == c.lower() for r in rules.values() for c in r.context))

    def test_detect_secrets_rules_know_the_german_labels(self):
        rules = detect._load_detect_secrets()
        self.assertTrue(all(r.validator == "ds_value" and r.type == "SECRET" for r in rules))
        basic = [r for r in rules if r.id == "ds-basic-auth"][0]
        self.assertEqual(basic.keywords, ())
        colon = [r for r in rules if r.id == "ds-keyword-colon"][0]
        self.assertIn("kennw", colon.keywords)
        for kw in detect.GERMAN_KEYWORDS:
            self.assertIn(kw, colon.regex.pattern)

    def test_prefix_rules_skip_comments_and_blank_lines(self):
        rules = detect._load_prefixes()
        ids = [r.id for r in rules]
        self.assertIn("gitlab-runner-token", ids)
        self.assertFalse(any(i.startswith("#") for i in ids))
        text = (detect.RULES_DIR / "prefixes.txt").read_text(encoding="utf-8")
        live = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(len(rules), len(live))

    def test_rule_order_is_own_secrets_then_detect_secrets_gitleaks_presidio_then_own_pii(self):
        ids = [r.id for r in detect.rules()]
        pos = {i: n for n, i in enumerate(ids)}
        self.assertLess(pos["url-query-secret"], pos["ds-keyword-colon"])
        self.assertLess(pos["ds-keyword-colon"], pos["generic-api-key"])
        self.assertLess(pos["generic-api-key"], pos["iban"])
        self.assertLess(pos["iban"], pos["email"])
        self.assertEqual(ids[-2:], ["email", "phone"])
        self.assertIs(detect.rules(), detect.rules())

    def test_a_broken_config_falls_back_to_the_default_regions(self):
        with mock.patch("maisecrets.vault.load_config", side_effect=RuntimeError("broken")):
            self.assertEqual(detect._pii_regions(), detect.DEFAULT_PII_REGIONS)
        with mock.patch("maisecrets.vault.load_config", return_value={"pii_regions": ["generic", "us"]}):
            self.assertEqual(detect._pii_regions(), ("generic", "us"))
        with mock.patch("maisecrets.vault.load_config", return_value={"pii_regions": []}):
            self.assertEqual(detect._pii_regions(), detect.DEFAULT_PII_REGIONS)

    def test_shannon_entropy(self):
        self.assertEqual(detect.shannon_entropy(""), 0.0)
        self.assertEqual(detect.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(detect.shannon_entropy("abab"), 1.0)
        self.assertAlmostEqual(detect.shannon_entropy("abcd"), 2.0)


# --------------------------------------------------------------- validators --
class ValidatorTests(unittest.TestCase):
    def test_luhn_accepts_every_completed_number_and_refuses_a_changed_check_digit(self):
        r = random.Random(1)
        for _ in range(300):
            body = rnd(r.randint(11, 18), string.digits, r)
            good = luhn_complete(body)
            bad = good[:-1] + str((int(good[-1]) + r.randint(1, 9)) % 10)
            with self.subTest(good=good):
                self.assertTrue(detect._luhn_ok(good))
                self.assertFalse(detect._luhn_ok(bad))
        self.assertTrue(detect.VALIDATORS["luhn"](" ".join(["4111"] + ["1111"] * 3)))

    def test_iban_checksum_length_and_case(self):
        r = random.Random(2)
        for _ in range(200):
            bban = rnd(r.randint(11, 30), string.digits + string.ascii_uppercase, r)
            good = iban_complete(r.choice(["DE", "GB", "FR", "NL"]), bban)
            with self.subTest(good=good):
                self.assertTrue(detect._iban_ok(good))
                self.assertTrue(detect._iban_ok(good.lower()))
                spaced = " ".join(good[i:i + 4] for i in range(0, len(good), 4))
                self.assertTrue(detect._iban_ok(spaced))
                self.assertFalse(detect._iban_ok(good[:2] + f"{(int(good[2:4]) + 1) % 100:02d}" + good[4:]))
        self.assertTrue(detect._iban_ok(" ".join(["DE89", "3704", "0044", "0532", "0130", "00"])))
        self.assertFalse(detect._iban_ok(iban_complete("DE", "1234567890")))     # 14 characters
        self.assertFalse(detect._iban_ok(iban_complete("DE", "1" * 31)))         # 35 characters

    def test_public_ip(self):
        for ip, ok in [("8.8.8.8", True), ("172.15.0.1", True), ("172.32.0.1", True), ("193.168.1.1", True),
                       ("10.1.2.3", False), ("127.0.0.1", False), ("0.0.0.0", False), ("192.168.0.1", False),
                       ("172.16.0.1", False), ("172.31.255.255", False), ("169.254.1.1", False),
                       ("256.1.1.1", False), ("1.2.3.4/24", False), ("1.2.3", False),
                       ("2a00:1450:4001::200e", True), ("2001:db8::1", True), ("::1", False), ("::", False),
                       ("fe80::1", False), ("fc00::1", False), ("fd12:3456::1", False), ("0:0:0:0::0", False),
                       ("2a00:1450", False), ("zz::zz:zz", False)]:
            with self.subTest(ip=ip):
                self.assertEqual(detect._public_ip(ip), ok)

    def test_german_tax_id(self):
        self.assertTrue(detect._de_tax_id_ok("86095742719"))
        for bad in ("86095742710", "06095742719", "8609574271", "8609574271x", "11112345671"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._de_tax_id_ok(bad))
        # the frequency rule: no digit more than three times in the first ten
        self.assertFalse(any(detect._de_tax_id_ok("1111234567" + str(c)) for c in range(10)))
        # a leading zero is refused although the check digit is right
        lead0 = "0609574271"
        self.assertFalse(detect._de_tax_id_ok(lead0 + tax_id_check(lead0)))
        self.assertTrue(detect._de_tax_id_ok("8609574271" + tax_id_check("8609574271")))

    def test_german_social_security_number(self):
        for good in ("65170839J003", "65 170839 J 003", "65170839j003"):
            self.assertTrue(detect._de_social_security_ok(good), good)
        for bad in ("65170839J004", "65170839J00", "651708393003", "65321339J003", "65170039J003",
                    "65171339J003"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._de_social_security_ok(bad))
        # day + 50 (a second number for the same date) is a valid day; day 32 and month 13 are not,
        # whatever the check digit
        self.assertTrue(any(detect._de_social_security_ok(f"65510839J00{c}") for c in range(10)))
        self.assertTrue(any(detect._de_social_security_ok(f"65810839J00{c}") for c in range(10)))
        for invalid in ("653208", "651713", "658208", "651700"):
            with self.subTest(invalid=invalid):
                self.assertFalse(any(detect._de_social_security_ok(f"{invalid}39J00{c}") for c in range(10)))

    def test_icao_check_digit_and_the_legacy_id_card(self):
        self.assertTrue(detect._icao_check("L898902C3"))          # ICAO Doc 9303 specimen number
        self.assertTrue(detect._icao_check("l898902c3"))
        for bad in ("L898902C4", "L898902C", "L898902CX", "L8989-2C3"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._icao_check(bad))
        self.assertTrue(detect._de_id_card_ok("T22000129"))       # before 2010: no check digit
        self.assertTrue(detect._de_id_card_ok("L898902C3"))
        self.assertFalse(detect._de_id_card_ok("T2200012"))
        self.assertTrue(detect.VALIDATORS["de_passport"]("L898902C3"))
        # a passport number never holds A, B, D, E, I, O, Q, S or U, even with a valid check digit
        for letter in "ABDEIOQSU":
            body = "L8989" + letter + "2C"
            full = next(body + str(c) for c in range(10) if detect._icao_check(body + str(c)))
            with self.subTest(letter=letter):
                self.assertFalse(detect.VALIDATORS["de_passport"](full))

    def test_german_health_insurance_number(self):
        self.assertTrue(detect._de_health_insurance_ok("A123456780"))
        self.assertTrue(detect._de_health_insurance_ok("a123456780"))
        for bad in ("A123456781", "1123456780", "A12345678", "AB23456780"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._de_health_insurance_ok(bad))

    def test_german_lanr_bsnr_and_vat_id(self):
        # LANR 123456|6|01: 1*4+2*9+3*4+4*9+5*4+6*9 = 144, check (10 - 4) % 10 = 6
        self.assertTrue(detect._de_lanr_ok("123456601"))
        for bad in ("123456701", "12345660", "12345660x"):
            self.assertFalse(detect._de_lanr_ok(bad), bad)
        bsnr = detect.VALIDATORS["de_bsnr"]
        self.assertTrue(bsnr("123456789"))
        self.assertFalse(bsnr("000000000"))
        self.assertFalse(bsnr("12345678"))
        for good in ("DE123456789", "de 123.456.789", "DE-123-456-789"):
            self.assertTrue(detect._de_vat_id_ok(good), good)
        for bad in ("AT123456789", "DE12345678", "DE1234567890", "DE12345678X"):
            self.assertFalse(detect._de_vat_id_ok(bad), bad)

    def test_ds_value_filters(self):
        ok = ["Xk9mQ2vL8zz", "hunter2 x9y8z7", "Tr0ub4dor&3", "a" * 7 + "B9"]
        rejected = {
            "short": "Xk9mQ2v", "long": "Xk9" * 90, "jinja": "{{ vault_password }}", "shell": "${DB_PASSWORD}",
            "angle": "<your password>", "percent": "%DB_PASSWORD%", "dollar": "$DB_PASSWORD",
            "call": "get_secret(name)", "index": "settings[key]", "paren": "value)1234567", "backtick": "`abc1234567`",
            "pipe": "abc | 1234567", "no alnum": "!@#$%^&*-+", "sentence": "my key 12",
            "two words": "bad payload", "identifier": "NAME_OF_SECRET", "word": "placeholder", "word 8": "ChangeMe",
            "repeated": "aaaaaaaaaa", "sequential letters": "abcdefghij", "sequential digits": "123456789",
            "own placeholder": "⟦secret_c1⟧xx", "legacy placeholder": "<SECRET_c12>",
        }
        for v in ok:
            self.assertTrue(detect._ds_value_ok(v), v)
        for why, v in rejected.items():
            with self.subTest(why=why):
                self.assertFalse(detect._ds_value_ok(v))

    def test_not_placeholder_and_person_email(self):
        np = detect.VALIDATORS["not_placeholder"]
        self.assertTrue(np("Zq8vT3xK9mP2"))
        self.assertFalse(np("PLACEHOLDER"))
        self.assertFalse(np("<token>"))
        pe = detect.VALIDATORS["person_email"]
        self.assertTrue(pe("anna@acme.de"))
        for system in ("git@github.com", "noreply@acme.de", "Root@host.de", "mailer-daemon@x.org"):
            self.assertFalse(pe(system), system)

    def test_a_validator_that_cannot_parse_its_value_rejects_the_hit(self):
        def boom(_v):
            raise ValueError("unparseable")
        with mock.patch.dict(detect.VALIDATORS, {"iban": boom}):
            self.assertEqual(kinds("IBAN " + " ".join(["DE89", "3704", "0044", "0532", "0130", "00"])), [])


# ------------------------------------------------------------- placeholders --
class PlaceholderValueTests(unittest.TestCase):
    def test_every_placeholder_value_is_recognised_in_quotes_too(self):
        for v in detect.PLACEHOLDER_VALUES:
            for form in (v, v.upper(), f'"{v}"', f"'{v}'", f"`{v}` "):
                self.assertTrue(detect.looks_like_placeholder(form), form)

    def test_placeholder_parts_and_template_names(self):
        for v in ("your_token_1234", "my-dummy-key-99", "EXAMPLEKEY123", "abcfake123456", "PORTKEY_API_KEY",
                  "<redacted-by-ops>", "xxxxxxxx1234"):
            self.assertTrue(detect.looks_like_placeholder(v), v)
        for v in ("Zq8vT3xK9mP2", "ABC_123_DEF", "Xk9mQ2vL8zz", "PORTKEY"):
            self.assertFalse(detect.looks_like_placeholder(v), v)

    def test_a_secret_shaped_placeholder_is_never_a_hit(self):
        aws_doc = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        for text in (f"id {aws_doc}", "password = changeme", "password = YOUR_DB_PASSWORD",
                     'api_key = "your_api_key_here_123"', "token: dummy-" + rnd(20)):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_a_span_that_holds_our_placeholder_is_never_a_hit(self):
        for text in ("password = ⟦SECRET_c1⟧", "curl -u app:⟦SECRET_c1⟧ https://example.org",
                     "password = <SECRET_c2>", "https://user:<SECRET_c3>@example.org/x",
                     "Authorization: Bearer ⟦SECRET_c4⟧", "api_key: ⟦SECRET_c5:ab•••⟧", "secret: ⟦SECRET_c6⟧"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_a_legacy_placeholder_inside_a_longer_value_is_not_a_hit(self):
        self.assertEqual(kinds("password = pre<SECRET_c7>post9"), [])


# ------------------------------------------------------------ context words --
class ContextWordTests(unittest.TestCase):
    def test_a_context_word_counts_only_as_a_whole_word(self):
        self.assertEqual(kinds("Ort: 10115"), [("de-plz", "10115")])
        self.assertEqual(kinds("PLZ 10115"), [("de-plz", "10115")])
        self.assertEqual(kinds("Report 10115"), [])
        self.assertEqual(kinds("Sportort 10115"), [])
        self.assertEqual(kinds("Ortsname 10115"), [])
        self.assertFalse(detect._has_context_word("anything", ()))

    def test_a_digit_run_needs_its_context_word_near_the_value(self):
        tax = "86095742719"
        self.assertEqual(kinds(f"Steuer-ID: {tax}"), [("de-tax-id", tax)])
        self.assertEqual(kinds(f"{tax} ist meine Steuer-ID"), [("de-tax-id", tax)])
        self.assertEqual(kinds(tax), [])
        # the word is in the text, but more than 80 characters before the value
        self.assertEqual(kinds("Steuer-ID bitte. " + "x " * 60 + tax), [])

    def test_a_weak_card_shape_needs_a_context_word_near_it(self):
        card = " ".join(["4111"] + ["1111"] * 3)
        self.assertEqual(kinds(f"card {card}"), [("credit-card", card)])
        self.assertEqual(kinds(card), [])
        self.assertEqual(kinds("card " + "x " * 60 + card), [])
        self.assertEqual(kinds("visa " + card[:-1] + "2"), [])       # context, but not a Luhn number

    def test_german_identifiers_with_their_context(self):
        for text, kind, value in [("Rentenversicherungsnummer 65170839J003", "de-social-security#0", "65170839J003"),
                                  ("Personalausweis L898902C3", "de-id-card#0", "L898902C3"),
                                  ("Reisepass L898902C3", "de-passport", "L898902C3"),
                                  ("Krankenversichertennummer A123456780", "de-health-insurance", "A123456780"),
                                  ("LANR 123456601", "de-lanr", "123456601"),
                                  ("USt-IdNr DE123456789", "de-vat-id#0", "DE123456789")]:
            with self.subTest(kind=kind):
                self.assertEqual(kinds(text), [(kind, value)])
        self.assertEqual(kinds("kvnr A123456781"), [])                 # wrong check digit


# ------------------------------------------------------------ scanner rules --
class ScanRuleTests(unittest.TestCase):
    GLPAT = "glpat-" + rnd(20)

    def test_enabled_limits_the_rules(self):
        text = f"token {self.GLPAT} mail anna.berg@acme.de"
        self.assertEqual({k for k, _ in kinds(text)}, {"gitlab-pat", "email"})
        self.assertEqual(kinds(text, enabled={"gitlab-pat"}), [("gitlab-pat", self.GLPAT)])
        self.assertEqual(kinds(text, enabled={"email"}), [("email", "anna.berg@acme.de")])
        self.assertEqual(kinds(text, enabled=set()), [])
        self.assertEqual(detect.scan(""), [])

    def test_the_first_rule_to_claim_a_span_wins(self):
        ghp = "ghp_" + rnd(36)
        # detect-secrets runs before gitleaks: the keyword rule claims the span of the github token
        self.assertEqual(kinds(f"password = {ghp}"), [("ds-keyword-equal-signs", ghp)])
        self.assertEqual(kinds(f"password = {ghp}", enabled={"github-pat"}), [("github-pat", ghp)])

    def test_results_are_leftmost_first_and_never_overlap(self):
        r = random.Random(4)
        pieces = [lambda: "glpat-" + rnd(20, AN, r), lambda: "ghp_" + rnd(36, AN, r),
                  lambda: f"password = {rnd(14, AN, r)}", lambda: "anna.berg@acme.de", lambda: "8.8.4.4",
                  lambda: "IBAN " + iban_complete("DE", rnd(18, string.digits, r)), lambda: "+49 170 1234567",
                  lambda: "Bearer " + rnd(24, AN, r), lambda: "https://x.org/?token=" + rnd(16, AN, r),
                  lambda: "plain words", lambda: "\n"]
        for _ in range(40):
            text = " ".join(r.choice(pieces)() for _ in range(12))
            ms = detect.scan(text)
            with self.subTest(text=text[:80]):
                self.assertEqual([m.start for m in ms], sorted(m.start for m in ms))
                for a, b in zip(ms, ms[1:]):
                    self.assertLessEqual(a.end, b.start)
                for m in ms:
                    self.assertEqual(text[m.start:m.end], m.value)
                self.assertGreaterEqual(len(ms), 1)

    def test_a_fixed_length_shape_runs_to_the_end_of_the_token_up_to_128_more(self):
        self.assertEqual(kinds(f"x {self.GLPAT}-tail_9 y"), [("gitlab-pat", self.GLPAT + "-tail_9")])
        self.assertEqual(kinds(f"x {self.GLPAT}.rest"), [("gitlab-pat", self.GLPAT)])
        long = self.GLPAT + "Q" * 200
        self.assertEqual([len(v) for _, v in kinds(f"x {long} y")], [len(self.GLPAT) + 128])

    def test_a_label_takes_the_next_non_empty_line(self):
        v = "Zq8vT3xK9mP2"
        for text in ("passwort:\n" + v, "passwort:\n\n\n" + v, "password =\n" + v, "Secret:\r\n" + v):
            with self.subTest(text=text):
                self.assertIn(v, [val for _, val in kinds(text)])
        self.assertEqual(kinds("passwort:\n\n\n"), [])                  # a label at the end of the text

    def test_a_hit_from_the_label_pair_starts_in_the_next_line(self):
        # the pair would read "abc:\n<value>" as one value; only a hit that starts after the label counts
        for text in ("password: abc:\nXk9mQ2vL8zz", "secret: xy1:\n\nZq8vT3xK9mP2"):
            with self.subTest(text=text):
                self.assertFalse([v for _, v in kinds(text) if "\n" in v])

    def test_code_that_ends_in_a_colon_does_not_take_the_next_line(self):
        v = "Xk9mQ2vL8zz1"
        for code in ('if kind != "SECRET":\n    ' + v, "class Secret:\n    " + v, "def secret():\n    " + v,
                     "if value is not secret:\n    " + v, "if n >= min_secret:\n    " + v,
                     "while pwd <= secret:\n    " + v, 'elif mode == "secret":\n    ' + v):
            with self.subTest(code=code[:24]):
                self.assertEqual(kinds(code), [])
        for text in ("for the db, password:\n" + v, "if needed, passwort:\n" + v, "while you wait, secret:\n" + v,
                     "is it the password:\n" + v, "class notes, secret:\n" + v):
            with self.subTest(text=text[:24]):
                self.assertEqual(kinds(text), [("ds-keyword-colon", v)])

    def test_german_labels(self):
        v = "Zq8vT3xK9mP2"
        for label in ("passwort", "Passwort", "KENNWORT", "geheimnis", "Schlüssel", "schluessel", "Zugangsdaten",
                      "db_passwort"):
            for sep in (": ", " = ", ":\n"):
                with self.subTest(label=label, sep=sep):
                    self.assertIn(v, [val for _, val in kinds(label + sep + v)])
        # the product's own name holds "secret" and is never a detect-secrets label
        self.assertEqual([k for k, _ in kinds("maisecrets: " + v) if k.startswith("ds-")], [])
        self.assertEqual(kinds("/maisecrets:shortcut"), [])


# ------------------------------------------------------------ keyword window --
class KeywordWindowTests(unittest.TestCase):
    """_windowed must find exactly what the regex finds over the whole text."""

    rule = next(r for r in detect.rules() if r.id == "generic-api-key")
    kw = detect._WINDOWED["generic-api-key"]
    WORDS = ["the", "api", "key", "token", "password", "secret", "auth", "access", "credential", "value", "=", ":",
             "=>", ",", "'", '"', "\n", "\r\n", "\n\n", "\r\n\r\n", "   ", "\t", "x" * 45, "a.b-c_d" * 8, "keyboard",
             "monkey", "api_version", "==", ";"]

    def _text(self, r: random.Random, target: int) -> str:
        out, n = [], 0
        while n < target:
            if r.random() < 0.15:
                # a keyword, up to 3 whitespace, a separator, up to 5 whitespace, a value
                ws = [" ", "\t", "\n", "\r\n", "'"]
                sep = "".join(r.choice(ws) for _ in range(r.randint(0, 3))) + r.choice(["=", ":", "=>", ","])
                sep += "".join(r.choice(ws) for _ in range(r.randint(0, 5)))
                t = r.choice(["password", "token", "api_key", "secret"]) + sep + rnd(r.randint(10, 40), AN, r)
            elif r.random() < 0.2:
                t = rnd(r.randint(8, 40), "abcdefXYZ0123456789+/=-_.", r)
            else:
                t = r.choice(self.WORDS)
            out.append(t + r.choice([" ", "", "\n", "-"]))
            n += len(out[-1])
        return "".join(out)[:target]

    def _spans(self, it):
        return [(m.start(), m.end(), m.start(1), m.end(1)) for m in it]

    def test_the_window_finds_what_the_whole_text_regex_finds(self):
        r = random.Random(9)
        for i in range(120):
            text = self._text(r, r.choice([300, 4095, 4096, 4097, 4600]))
            with self.subTest(i=i):
                self.assertEqual(self._spans(detect._windowed(self.rule, self.kw, text)),
                                 self._spans(self.rule.regex.finditer(text)))

    @unittest.expectedFailure   # bug: the keyword window ends one line early, fixed in a later commit
    def test_a_value_up_to_eight_line_breaks_after_its_keyword(self):
        value = "Zq8vT3xK9mP2wL7nB5"
        filler = "filler text. " * 400
        for before in range(4):
            for after in range(6):
                sep = "\n" * before + ":" + "\n" * after
                text = filler + "password" + sep + value + "\n" + "y" * 50
                with self.subTest(before=before, after=after):
                    self.assertEqual(self._spans(detect._windowed(self.rule, self.kw, text)),
                                     self._spans(self.rule.regex.finditer(text)))

    def test_scan_gives_the_same_hits_with_and_without_the_window(self):
        r = random.Random(10)
        for i in range(25):
            text = self._text(r, r.choice([4097, 5000]))
            windowed = kinds(text, enabled={"generic-api-key"})
            with mock.patch.dict(detect._WINDOWED, clear=True):
                whole = kinds(text, enabled={"generic-api-key"})
            with self.subTest(i=i):
                self.assertEqual(windowed, whole)


# --------------------------------------------------------- label value ends --
class LabelValueTests(unittest.TestCase):
    """What a detect-secrets keyword rule takes as the value after `password:` / `api_key=`."""

    MAIL = "anna.berg@acme.de"

    @unittest.expectedFailure   # bug: the value runs to the line end, fixed in a later commit
    def test_an_unquoted_value_ends_at_the_first_whitespace(self):
        pw = "wwdwewrwrwrwrwwr"
        for text, expected in [
            (f"password:{pw} and {self.MAIL}", [("SECRET", pw), ("EMAIL", self.MAIL)]),
            (f"password:{pw} {self.MAIL}", [("SECRET", pw), ("EMAIL", self.MAIL)]),
            ("passwort: Sommer2026! bitte", [("SECRET", "Sommer2026!")]),
            ("api_key=abc123XYZdef extra words", [("SECRET", "abc123XYZdef")]),
            ("password = Xk9mQ2vL8zz, user = bob", [("SECRET", "Xk9mQ2vL8zz")]),
            ("passwort:\nSommer2026! bitte schnell", [("SECRET", "Sommer2026!")]),
        ]:
            with self.subTest(text=text):
                self.assertEqual([(m.type, m.value) for m in detect.scan(text)], expected)

    @unittest.expectedFailure   # bug: the value runs to the line end, fixed in a later commit
    def test_a_quoted_value_keeps_its_spaces(self):
        self.assertEqual(kinds('password: "correct horse9"'), [("ds-keyword-colon", "correct horse9")])
        self.assertEqual(kinds("password = 'correct horse9'"), [("ds-keyword-equal-signs", "correct horse9")])
        # the unquoted form ends at the space ("correct" alone is then too short for a value)
        self.assertFalse([v for _, v in kinds("password: correct horse9") if " " in v])
        # a quoted phrase is judged whole, never cut at its first space
        cut = [v for _, v in kinds('password: "correct horse battery"') if v in ("correct", "correct horse")]
        self.assertFalse(cut)

    def test_prose_after_a_label_is_still_not_a_value(self):
        for text in ("secret: very important", "api_key: Add API key", '"api_key_label": "Add API key"',
                     "the token expired yesterday"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    @unittest.expectedFailure   # bug: two distinct characters are filler, fixed in a later commit
    def test_two_distinct_characters_are_a_value(self):
        for text, value in [("password:asasasasasasaasasasa", "asasasasasasaasasasa"),
                            ("passwort: abababab12", "abababab12")]:
            with self.subTest(text=text):
                self.assertEqual([m.value for m in detect.scan(text)], [value])

    def test_one_repeated_character_is_filler(self):
        for text in ("password: ********", "password: xxxxxxxx", "secret: ........", "password: aaaaaaaaaa",
                     "passwort: ZZZZZZZZZZZZ"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])


class GitleaksAllowlistTests(unittest.TestCase):
    """gitleaks' regexTarget "match" means the whole match; the default target is the secret."""

    V = "Zq8vT3xK9mP2wL7n"

    @unittest.expectedFailure   # bug: a match allowlist sees only the secret, fixed in a later commit
    def test_a_match_allowlist_sees_the_label(self):
        for label in ("keyboard = ", "public_key: ", "api_version = ", "csrf_token: ", "key_alias: ", "access_id: ",
                      "author = "):
            with self.subTest(label=label):
                self.assertEqual(kinds(label + self.V), [])

    def test_the_same_value_after_a_credential_label_is_still_a_hit(self):
        for label in ("api_token = ", "access_token: ", "auth_key = "):
            with self.subTest(label=label):
                self.assertEqual([v for _, v in kinds(label + self.V)], [self.V])

    def test_a_secret_allowlist_still_sees_only_the_secret(self):
        self.assertEqual(kinds("api_key = abcdefghijKLMNOPq"), [])       # letters only: `^[a-zA-Z_.-]+$`


# ----------------------------------------------------------------- corpora --
def _provider_tokens() -> dict[str, str]:
    r = random.Random(3)
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
    return {
        "github-pat": "ghp_" + rnd(36, AN, r),
        "github-fine-grained-pat": "github_pat_" + rnd(82, AN + "_", r),
        "gitlab-pat": "glpat-" + rnd(20, AN, r),
        "slack-bot-token": "xoxb-" + rnd(11, string.digits, r) + "-" + rnd(12, string.digits, r) + "-" + rnd(24, AN, r),
        "stripe-access-token": "sk_" + "live_" + rnd(24, AN, r),
        "anthropic-api-key": "sk-ant-" + "api03-" + rnd(93, AN + "_-", r) + "AA",
        "gcp-api-key": "AI" + "za" + rnd(35, AN + "_-", r),
        "npm-access-token": "npm_" + rnd(36, string.ascii_lowercase + string.digits, r),
        "sendgrid-api-token": "SG." + rnd(22, AN, r) + "." + rnd(43, AN, r),
        "digitalocean-pat": "dop_" + "v1_" + rnd(64, HEX, r),
        "shopify-access-token": "shpat_" + rnd(32, HEX, r),
        "pypi-upload-token": "pypi-" + "AgEIcHlwaS5vcmc" + rnd(60, AN + "_-", r),
        "openai-api-key": "sk-" + "proj-" + rnd(58, AN + "_-", r) + "T3Blbk" + "FJ" + rnd(58, AN + "_-", r),
        "huggingface-access-token": "hf_" + rnd(34, string.ascii_letters, r),
        "gitlab-runner-token": "glrt-" + rnd(26, AN, r),
        "gitlab-deploy-token-any": "gldt-" + rnd(24, AN, r),
        "webhook-signing-secret": "whsec_" + rnd(32, AN, r),
        "cloudflare-user-api-token": "cfut_" + rnd(40, AN, r),
        "private-key": begin + "\n" + rnd(64, AN + "+/", r) + "\n" + rnd(64, AN + "+/", r) + "\n" + end,
        "aws-access-token": "AKIA" + rnd(16, string.ascii_uppercase + "234567", r),
    }


class TruePositiveCorpusTests(unittest.TestCase):
    def test_every_provider_shape_is_found_with_its_exact_value(self):
        for kind, token in _provider_tokens().items():
            for text in (f"here: {token} done", f"{token}\n", f'"{token}"'):
                with self.subTest(kind=kind, text=text[:20]):
                    self.assertEqual(kinds(text), [(kind, token)])

    def test_positional_credentials(self):
        v = "Zq8vT3xK9mP2"
        akid = "AKIA" + rnd(16, string.ascii_uppercase + "234567")
        aws_secret = rnd(40, AN + "/+")
        for text, expected in [
            (f"curl https://deploy:{v}@example.org/x", [("ds-basic-auth", v)]),
            (f"GET https://example.org/cb?api_key={v}&x=1", [("url-query-secret", v)]),
            (f"Authorization: Bearer {v}{v}", [("auth-scheme", v + v)]),
            (f"password = {v}", [("ds-keyword-equal-signs", v)]),
            (f'"api_key": "{v}"', [("ds-keyword-colon", v)]),
            (f"id {akid}\nsecret {aws_secret}\n",
             [("aws-access-token", akid), ("aws-secret-after-access-key", aws_secret)]),
        ]:
            with self.subTest(text=text[:30]):
                got = kinds(text)
                self.assertEqual(sorted(got), sorted(expected))

    def test_pii_shapes(self):
        card = luhn_complete("41111111111111" + "1")
        iban = iban_complete("DE", "370400440532013000")
        for text, expected in [("mail anna.berg@acme.de now", [("email", "anna.berg@acme.de")]),
                               ("call +49 170 1234567", [("phone", "+49 170 1234567")]),
                               (f"card {card}", [("credit-card", card)]), (f"IBAN {iban}", [("iban", iban)]),
                               ("from 8.8.4.4", [("ip#2", "8.8.4.4")])]:
            with self.subTest(text=text):
                self.assertEqual(kinds(text), expected)


class FalsePositiveCorpusTests(unittest.TestCase):
    CODE = [
        "def check_password(password: str) -> bool:\n    return len(password) >= 12\n",
        "if kind != \"SECRET\":\n    continue\n",
        "password = getpass.getpass()\n",
        "secret = load_secret(name)\n",
        "token = request.headers.get(\"Authorization\")\n",
        "password: ${DB_PASSWORD}\n",
        "password: {{ vault_db_password }}\n",
        "password = \"<your password here>\"\n",
        "PASSWORD_MIN_LENGTH = 12\n",
        "class PasswordResetForm(forms.Form):\n    pass\n",
        "    if not password:\n        raise ValueError(\"password required\")\n",
        "self.password = password\n",
        "def login(user, password=None):\n",
        "token = token.strip()\n",
        "secret_key = os.getenv(\"SECRET_KEY\")\n",
        "password: str = Field(default=None)\n",
        "\"password\": \"\",\n",
        "export PASSWORD=$PASSWORD\n",
        "password = args.password or prompt_password()\n",
        "api_key = request.args.get('api_key')\n",
        "api_key = kwargs['api_key']\n",
        "secret = secrets.token_hex(32)\n",
        "if api_key is None:\n    return\n",
        "assert token == other_token\n",
        "| password | the account password |\n",
        "password_hash = bcrypt.hashpw(password, salt)\n",
        "PASSWORD = env.str(\"PASSWORD\")\n",
        "api_key = API_KEY\n",
        "api_key = abcdefghijKLMNOPq\n",
        "password=\"$DB_PASS\"\n",
    ]
    # dotted references and identifiers that end in `:`, `;` or `[` (found by this corpus, 2026-09-27)
    REFERENCES = [
        "if password == confirm_password:\n    save(user)\n",
        "while password != expected_password:\n    retry()\n",
        "password = os.environ[\"DB_PASSWORD\"]\n",
        "api_key = settings.API_KEY\n",
        "password = self._password\n",
        "const apiKey = process.env.API_KEY;\n",
        "db_password = config.database.password\n",
        "passwort = eingabe.passwort\n",
    ]
    PROSE = [
        "The API key goes into the settings page; the password is never stored.",
        "Das Passwort wird nie gespeichert, der Schlüssel liegt im Tresor.",
        "Run `/maisecrets:report` | then send",
        "The /maisecrets:shortcut command installs /ms.",
        "localhost 127.0.0.1 and 10.0.0.1 and 192.168.1.10 and fe80::1",
        "Order 1234 5678 costs 12.50 EUR, room 101 at 3pm",
        "Version lodash@4.17.21 and actions/checkout@v4.1.1 and python@3.14",
        "Mail git@github.com or noreply@example.org",
    ]

    def _generated(self) -> list[str]:
        r = random.Random(6)
        out = []
        for i in range(20):
            out.append("commit " + hashlib.sha1(str(i).encode()).hexdigest() + " fixes the parser")
            out.append("git show " + hashlib.sha1(str(i).encode()).hexdigest()[:12])
            out.append("sha256: " + hashlib.sha256(str(i).encode()).hexdigest())
            out.append("request id " + str(uuid.UUID(int=r.getrandbits(128))))
            words = " ".join(r.choice(["the", "report", "is", "ready", "and", "plain", "text"]) for _ in range(12))
            out.append("data: " + base64.b64encode(words.encode()).decode())
            out.append(f"see https://docs.example.org/guide/{r.randint(1, 99)}?lang=de&page={r.randint(1, 9)}#setup")
        return out

    def _notices(self) -> list[str]:
        entries = [SimpleNamespace(type="SECRET", ref="⟦SECRET_c1⟧"),
                   SimpleNamespace(type="EMAIL", ref="⟦EMAIL_c1:ma•••@•••.de⟧"),
                   SimpleNamespace(type="PHONE", ref="⟦PHONE_c2:+49••••••67⟧")]
        vault = SimpleNamespace(backend=SimpleNamespace())
        out = []
        for copied in (True, False):
            for codex in (True, False):
                for cfg in ({}, {"report_url": "https://example.org/report", "renew_on_use": False,
                                 "ttl_seconds": {"default": 3600, "EMAIL": 600}}):
                    out.append("\n".join(hooks.block_notice(entries, "use ⟦SECRET_c1⟧ and ⟦EMAIL_c1:ma•••@•••.de⟧",
                                                            copied, codex, cfg, vault)))
        return out

    def _check(self, texts):
        for text in texts:
            with self.subTest(text=text[:60]):
                self.assertEqual(kinds(text), [])

    def test_code_with_credential_names_is_not_a_hit(self):
        self._check(self.CODE)

    @unittest.expectedFailure   # bug: a dotted reference is taken for a value, fixed in a later commit
    def test_references_to_a_credential_are_not_a_hit(self):
        self._check(self.REFERENCES)

    def test_prose_and_non_personal_addresses_are_not_a_hit(self):
        self._check(self.PROSE)

    def test_hashes_uuids_base64_and_urls_are_not_a_hit(self):
        self._check(self._generated())

    def test_the_plugins_own_notices_are_not_a_hit(self):
        notices = self._notices()
        self.assertTrue(all("maisecrets stopped this prompt" in n for n in notices))
        self._check(notices)


if __name__ == "__main__":
    unittest.main()
