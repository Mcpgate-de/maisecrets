"""The other direction: no relaxation of 0.5.15 lets a real, detectable value through that 0.5.14 stopped.

The second adversarial review of 2026-09-29 ran every relaxation of this release against real-looking values
and found where each went too far. Each case here was a hit before the relaxations, then no hit, and is a hit
again; its false-positive neighbour stays silent.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import detect, hooks  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
GLPAT = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"
JWT = ".".join(base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=") for p in (
    {"alg": "HS256", "typ": "JWT"}, {"sub": "4711", "name": "Max Muster", "iat": 1790000000}))
JWT += ".Sfl" + "KxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
UUID = str(uuid.UUID(int=0x6f1e2d3c4b5a4c6d8e7f9a0b1c2d3e4f))


def found(text: str, path: str = "") -> list[tuple[str, str]]:
    text = text.replace("§", "")
    return [(m.type, m.value) for m in detect.scan(text) if not detect.is_fixture(m, text, path)]


def secrets(text: str, path: str = "") -> list[str]:
    return [v for t, v in found(text, path) if t == "SECRET"]


class LeakDirectionTests(unittest.TestCase):
    def test_a_token_shape_after_a_label_stays_a_hit_in_test_code(self):
        for text in (f"tok§en = '{JWT}'\n", f"TOK§EN = '{GLPAT}'\n", f"Authorization: Bearer {JWT}\n"):
            with self.subTest(text=text[:20]):
                self.assertTrue(secrets(text, "tests/test_auth.py"), "a real token in a test is a leak")
        # the fixture next to it stays a fixture
        self.assertEqual(secrets("pass§word = 'Qx7vR2mK9pLw'\n", "tests/test_auth.py"), [])

    def test_a_base64_value_with_one_pad_is_no_label(self):
        b64 = base64.b64encode(bytes(range(7, 39))).decode()          # 44 characters, one pad, no + or /
        self.assertTrue(b64.endswith("=") and not b64.endswith("=="))
        for label in ("PASS§WORT=", "Kenn§wort: ", "PW§D=", "pa§ss="):
            with self.subTest(label=label):
                self.assertEqual(secrets(label + b64), [b64])
        self.assertEqual(secrets("PW§D=" + "Q7w8E9r0T1y2U3i4O5p6Ab="), ["Q7w8E9r0T1y2U3i4O5p6Ab="])
        self.assertEqual(found("DB_PASS§WORD=\nAPI_K§EY=\nSECRET_K§EY=\n"), [])       # the next label stays none

    def test_a_fixture_word_inside_a_real_password_does_not_make_it_a_fixture(self):
        for v in ("Contest-Winter2026!", "Passatwagen#88", "Passion2026!", "Geheimnis2026!", "Secretary1!",
                  "Latest!Deploy1", "Latest2026", "Kompass1!"):
            with self.subTest(v=v):
                self.assertEqual(secrets(f"SMTP_PASS§WORD={v}"), [v])
        for v in ("testpass", "secret123", "Passw0rd!", "wrongpassword", "SuperSecret1", "Str0ngPassw0rd!",
                  "topsecret", "mypassword", "rootpass"):
            with self.subTest(fixture=v):
                self.assertEqual(secrets(f"pass§word = \"{v}\""), [])
        # known: a password made of fixture words only is taken for a fixture (P@55w0rt2026!)
        self.assertEqual(secrets("pass§word: P@55w0rt2026!"), [])

    def test_a_uuid_is_a_secret_under_a_label_that_names_one(self):
        for label in ("POSTMARK_SERVER_TOK§EN=", "SCW_SECRET_K§EY=", "api_k§ey: ", "pass§word: ", "client_secr§et: ",
                      "KEYCLOAK_CLIENT_SECR§ET=", "webhook_secr§et: "):
            with self.subTest(label=label):
                self.assertEqual(secrets(label + UUID), [UUID])
        for label in ("k§ey: ", "secret_i§d: ", "request_i§d: "):
            with self.subTest(identifier=label):
                self.assertEqual(secrets(label + UUID), [])

    def test_real_values_in_files_of_real_values_stay_hits_under_tests(self):
        pw = "Qx7vR2mK" + "9pLw!"
        for path in ("tests/.env", "tests/integration/.env", "tests/.env.test", "tests/cassettes/api.yaml",
                     "specs/openapi.yaml", "fixtures/initial_data.json"):
            with self.subTest(path=path):
                self.assertEqual(secrets(f"DB_PASS§WORD={pw}\n", path), [pw])

    def test_assert_alone_or_another_file_of_a_diff_is_no_test_code(self):
        pw = "Qx7vR2mK" + "9pLw!"
        prod = "assert os.environ.get('ENV')\n" + "x = 1\n" * 20 + f"SMTP_PASS§WORD = \"{pw}\"\n"
        self.assertEqual(secrets(prod), [pw])
        diff = ("diff --git a/tests/test_a.py b/tests/test_a.py\n+++ b/tests/test_a.py\n     def test_a():\n"
                "         pass\ndiff --git a/src/config.py b/src/config.py\n+++ b/src/config.py\n"
                f"+SMTP_PASS§WORD = \"{pw}\"\n")
        self.assertEqual(secrets(diff), [pw])
        self.assertEqual(secrets(f"def test_a():\n    assert x\n    pass§word = \"{pw}\"\n"), [])

    def test_a_phone_number_after_key_equals_or_in_a_csv_column_is_a_phone(self):
        for text in ("CONTACT_PHONE=+4915112345678", "Alice Muster,+4915112345678,x",
                     "https://api.host/send?to=+4915112345678"):
            with self.subTest(text=text):
                self.assertIn(("PHONE", "+4915112345678"), found(text))
        self.assertEqual(found("a = +4294967296  # 1 << 32"), [])
        self.assertEqual(found("f(+12345678)"), [])

    def test_a_person_at_local_or_internal_is_a_person(self):
        for mail in ("hans.mueller@firma.local", "hans_mueller@corp.internal"):
            with self.subTest(mail=mail):
                self.assertEqual(found(f"mail {mail}"), [("EMAIL", mail)])
        self.assertEqual(found("mail alerts@nas.local"), [])

    def test_the_label_of_the_value_decides_not_the_line(self):
        self.assertEqual(secrets("smtp.host=mail.contoso.de smtp.pass§word=contoso"), ["contoso"])
        self.assertEqual(found("ALTER USER postgres WITH PASS§WORD 'postgres';"), [])
        self.assertEqual(secrets("user: max, pass§word: 48392011"), ["48392011"])
        self.assertEqual(found("TTL_REFRESH_TOK§EN = 15552000"), [])
        self.assertEqual(secrets("pass§word_field: Qx7vR2mK" + "9pLw!"), ["Qx7vR2mK9pLw!"])


class HiddenFalseAlarmTests(unittest.TestCase):
    """The false alarms that the loose fixture word hid; the ai-gateway repository held each (2026-09-29)."""

    def test_each_is_no_hit_on_its_own(self):
        for text, path in (
                ("  command: redis-server --requirepass ${REDIS_PASS§WORD:?REDIS_PASS§WORD must be set}\n", ""),
                ("  access_tok§en_fields: &gitlab_tok§en_fields\n", ""),
                ("- Delete old tok§en: `rm ~/.config/claude-code/mcp_tok§ens/phase6-gateway.json`\n", ""),
                ('"body": "  client_secr§et: process.env.NOTION_CLIENT_SECR§ET,\\n"\n', ""),
                ("        tok§en_data: TokenData\n", ""),
                ('    "⟦SECR§ET_c4:max.mu@•••.de⟧",\n', ""),
                ("      - ADMIN_TOK§EN=e2e-admin-tok§en\n      - REDIS_PASS§WORD=e2e-redis-pass§word\n",
                 "docker-compose.e2e-auth.yml")):
            with self.subTest(text=text[:40]):
                self.assertEqual(found(text, path), [])
        # the neighbours stay hits
        pw = "Qx7vR2mK" + "9pLw!"
        self.assertEqual(secrets(f"REDIS_PASS§WORD={pw}\n", "docker-compose.yml"), [pw])
        self.assertEqual(secrets("tok§en_data: Qx7vR2mK9pLwT4"), ["Qx7vR2mK9pLwT4"])


class CodexReviewTests(unittest.TestCase):
    """The findings of the Codex review of 2026-09-29 (gpt-5.6-sol, on 31fdfd1): each input was a hit on d805b1e
    and passed on 31fdfd1."""

    def test_a_letter_only_base64_value_on_the_label_line_is_a_value(self):
        self.assertEqual(secrets("PASS§WORD=SkTcFTZCBKg="), ["SkTcFTZCBKg="])
        self.assertEqual(found("DB_PASS§WORD=\nAPI_K§EY=\n"), [], "the label on the next line stays none")

    def test_a_mailbox_at_local_or_internal_without_a_dot_is_a_person(self):
        self.assertEqual(found("mail jdoe@corp.internal"), [("EMAIL", "jdoe@corp.internal")])
        self.assertEqual(found("mail noreply@corp.internal"), [])

    def test_four_one_digit_octets_are_an_address_unless_a_section_is_named(self):
        self.assertEqual(found("from 5.6.7.8"), [("IP", "5.6.7.8")])
        for text in ("RFC 6749 4.1.2.1 says", "OIDC Core 3.1.2.1 says", "see section 7.1.2.3"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])
        self.assertEqual(detect.scan("see \u00a7 5.1.2.4"), [])     # found() removes the section sign

    def test_a_comma_ends_a_phone_number(self):
        self.assertIn(("PHONE", "+4915112345678"), found("row,+4915112345678,123"))

    def test_a_capitalised_test_folder_and_a_tests_file_are_test_code(self):
        for path in ("/repo/Tests/AuthTests.cs", "src/Auth/LoginTest.java", "Tests/Login.swift"):
            with self.subTest(path=path):
                self.assertEqual(secrets("pass§word = Qx7vR2mK9pLw\n", path), [])
        for path in ("src/latest.py", "src/Contest.cs"):
            with self.subTest(prod=path):
                self.assertEqual(secrets("pass§word = Qx7vR2mK9pLw\n", path), ["Qx7vR2mK9pLw"])


class CodexSecondReviewTests(unittest.TestCase):
    """The findings of the second Codex review (gpt-5.6-sol, on 05052fe)."""

    def test_a_base64_value_on_the_next_line_is_a_value(self):
        for label in ("PASS§WORD=\n", "PASS§WORD:\n"):
            with self.subTest(label=label):
                self.assertEqual(secrets(label + "SkTcFTZCBKg="), ["SkTcFTZCBKg="])
        self.assertEqual(found("Zugangsdaten:\nBenutzer: max\n"), [])

    def test_a_spaced_phone_assignment_is_a_phone(self):
        self.assertIn(("PHONE", "+4915112345678"), found("CONTACT_PHONE = +4915112345678"))
        self.assertIn(("PHONE", "+4915112345678"), found("mobile = +4915112345678"))
        self.assertEqual(found("a = +4294967296"), [])
        self.assertEqual(found("TELEMETRY_OFFSET = +4294967296"), [], "tel inside a word is no telephone")

    def test_an_upper_case_env_file_under_tests_is_no_test_code(self):
        self.assertEqual(secrets("PASS§WORD=Qx7vR2mK9pLw!\n", "/repo/Tests/.ENV"), ["Qx7vR2mK9pLw!"])
        self.assertEqual(secrets("PASS§WORD=Qx7vR2mK9pLw!\n", "/repo/Tests/Cassettes/login.yaml"), ["Qx7vR2mK9pLw!"])

    def test_a_random_value_that_starts_with_its_label_is_a_value(self):
        self.assertEqual(secrets("TOK§EN=tokenQx7vR2mK9pLw"), ["tokenQx7vR2mK9pLw"])
        self.assertEqual(found("tok§en = tokenizer"), [])

    def test_a_template_inside_a_password_does_not_hide_it(self):
        self.assertEqual(secrets("PASS§WORD=Qx7v{user}R2mK9pLw"), ["Qx7v{user}R2mK9pLw"])
        self.assertEqual(found("    - MCP tok§ens: `mcp_{user}`"), [])

    def test_a_windows_grep_line_names_its_test_file(self):
        self.assertEqual(secrets("C:\\repo\\Tests\\AuthTests.cs:12:pass§word = Qx7vR2mK9pLw\n"), [])
        self.assertEqual(secrets("C:\\repo\\src\\Auth.cs:12:pass§word = Qx7vR2mK9pLw\n"), ["Qx7vR2mK9pLw"])

    def test_a_megabyte_of_opening_tags_is_refused_at_once(self):
        import time
        started = time.monotonic()
        text = ("<task-notification>\n" * 60000)[:1_000_000]
        self.assertFalse(hooks.agent_report({"transcript_path": "/tmp/x.jsonl", **CLAUDE}, text))
        self.assertLess(time.monotonic() - started, 1.0)


class FinalReviewTests(unittest.TestCase):
    """The findings of the final Fable review (on 0147e81, 2026-09-30)."""

    def test_a_long_line_of_labels_is_scanned_in_time(self):
        import time
        pw = "pass" + "word"
        cases = {
            "minified bundle": "var a=1;" * 8000 + "".join(f"x{i}({{{pw}:e.{pw},token:t.token}});" for i in range(300)),
            "one-line API response": "{" + ",".join(f'"a{i}":"yy","token":"t{i}"' for i in range(1500)) + "}",
            "a long word run": "a" * 100_000 + f" {pw}=Qx7vR2mK9pLw",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                started = time.monotonic()
                ms = detect.scan(text)
                [detect.is_fixture(m, text, "") for m in ms]
                self.assertLess(time.monotonic() - started, 3.0, "far below the 7 s watchdog")
        self.assertEqual(secrets(cases["a long word run"]), ["Qx7vR2mK9pLw"])
        started = time.monotonic()
        detect._FORMAT_ONLY_RE.fullmatch("%" * 200 + "Z")
        self.assertLess(time.monotonic() - started, 0.05)

    def test_a_camel_case_key_on_the_next_line_is_a_label(self):
        self.assertEqual(found("pass§word:\n    driverClassName: org.h2.Driver\n"), [])
        self.assertEqual(found("pass§word:\n  secretKeyRef:\n    name: db\n"), [])
        self.assertEqual(secrets("PASS§WORD=\nsKTcFTZCBKg="), ["sKTcFTZCBKg="])

    def test_phone_labels_as_words_of_a_label(self):
        for text in ("phoneNumber = +4915112345678", "Telefonnummer = +4915112345678", "Handynummer = +4915112345678",
                     "Mobiltelefon = +4915112345678", "MSISDN = +4915112345678", "phone(+4915112345678)",
                     "phone: [+4915112345678]"):
            with self.subTest(text=text):
                self.assertIn(("PHONE", "+4915112345678"), found(text))
        for text in ("TELEMETRY_OFFSET = +4294967296", "f(+12345678)", "x = [+4294967296]"):
            with self.subTest(number=text):
                self.assertEqual(found(text), [])

    def test_recorded_traffic_and_every_env_file_hold_real_values(self):
        bearer = "Bearer " + "8f3kd9sLq2pX7mN4vB6cZ1aW5eR9tY0u"
        for path in ("tests/recordings/login.yaml", "tests/__recordings__/login.json", "spec/vcr/login.yml",
                     "tests/login.har"):
            with self.subTest(path=path):
                self.assertTrue(secrets(f"authorization: {bearer}\n", path))
        for path in ("tests/secrets.env.local", "tests/integration/staging.env.enc"):
            with self.subTest(path=path):
                self.assertEqual(secrets("DB_PASS§WORD=Qx7vR2mK9pLw!\n", path), ["Qx7vR2mK9pLw!"])

    def test_a_production_method_named_test_is_no_test_code(self):
        pw = "Qx7vR2mK" + "9pLw!"
        for text in (f"class Db:\n    def test_connection(self):\n        return self.ping()\n\nPASS§WORD = \"{pw}\"\n",
                     f"class Testimonial(models.Model):\n    pass\nSMTP_PASS§WORD = \"{pw}\"\n"):
            with self.subTest(text=text[:30]):
                self.assertEqual(secrets(text, "src/db.py"), [pw])
        self.assertEqual(secrets(f"class TestDb:\n    def test_connection(self):\n        pass§word = \"{pw}\"\n"), [])

    def test_small_value_shapes_that_hid_a_real_value(self):
        self.assertEqual(secrets("PASS§WORD=*Qx7vR2mK9pLw"), ["*Qx7vR2mK9pLw"])
        self.assertEqual(found("  fields: &tok§en_fields\n"), [])
        for text in ('pass§word = "correctHorseBatteryStaple"', "pass§word: correctHorseBatteryStaple"):
            with self.subTest(text=text):
                self.assertEqual(secrets(text), ["correctHorseBatteryStaple"])
        for text in ("tok§en = tokenValue", "pass§word = defaultAdminPassword", "Schlüss§el: apiKey"):
            with self.subTest(identifier=text):
                self.assertEqual(secrets(text), [])
        self.assertEqual(secrets("PASS§WORD=Qx7vR2mK9pLwAb3dEf9!..."), ["Qx7vR2mK9pLwAb3dEf9!..."])
        self.assertEqual(found("tok§en: ghp_" + "1234567890ab..."), [], "a truncated token in a log is public")
        self.assertEqual(found("export API_K§EY=sk-..."), [])
        for text in ("tok§en_budget = 12000000", "TOK§EN_REFRESH_MS = 86400000"):
            with self.subTest(measure=text):
                self.assertEqual(found(text), [])
        self.assertEqual(secrets("user: max, pass§word: 48392011"), ["48392011"])
        self.assertEqual(found("const pass§word = credentials?.pass§word ?? '';"), [])
        for text in ("Kennw§ort: unverändert", "Tok§en: abgelaufen"):
            with self.subTest(status=text):
                self.assertEqual(found(text), [])

    def test_an_address_with_leading_zeros_or_inside_6to4_is_an_address(self):
        self.assertEqual([t for t, _ in found("from 085.214.132.005 port 22")], ["IP"])
        self.assertEqual([t for t, _ in found("from 2002:55d6:8405::1")], ["IP"])


class LastCommitReviewTests(unittest.TestCase):
    """The findings of the review of 3e5d53e (Fable, 2026-09-30)."""

    def test_a_two_megabyte_line_is_linear(self):
        import time
        text = "{" + ",".join(f'"id{i}":"{"x" * 1800}","tok§en":"t{i}"' for i in range(250)) + "}"
        text = text.replace("§", "")
        started = time.monotonic()
        detect.scan(text)
        small = time.monotonic() - started
        big = text[:-1] + "," + text[1:]
        started = time.monotonic()
        detect.scan(big)
        self.assertLess(time.monotonic() - started, 3.0 * small + 0.5, "twice the text, about twice the time")

    def test_an_earlier_label_outside_the_window_still_counts(self):
        prose = "the contoso mail relay of the contoso tenant " * 5
        self.assertEqual(secrets(f"smtp.user=svc {prose} smtp.pass§word=contoso"), ["contoso"])

    def test_a_test_method_in_a_diff_hunk_or_a_paste_is_test_code(self):
        pw = "Qx7vR2mK" + "9pLw!"
        hunk = ("diff --git a/tests/test_login.py b/tests/test_login.py\n--- a/tests/test_login.py\n"
                "+++ b/tests/test_login.py\n@@ -40,6 +40,7 @@ class TestLogin(unittest.TestCase):\n"
                f"     def test_login(self):\n-        pass§word = 'old'\n+        pass§word = '{pw}'\n")
        self.assertEqual(secrets(hunk), [])
        paste = f"    def test_login(self):\n        pass§word = '{pw}'\n        self.assertTrue(x)\n"
        self.assertEqual(secrets(paste), [])
        prod = f"class Db:\n    def test_connection(self):\n        pass\nPASS§WORD = '{pw}'\n"
        self.assertEqual(secrets(prod), [pw])
        # a production class between the test method and the value decides
        between = (f"    def test_a(self):\n        pass\nclass Db:\n    def __init__(self):\n"
                   f"        pass§word = '{pw}'\n")
        self.assertEqual(secrets(between), [pw])
        # a marker far above in a long test class, lines of 900 characters
        long = "class TestLogin:\n" + ("    x = '" + "a" * 890 + "'\n") * 10 + f"    pass§word = \"{pw}\"\n"
        self.assertEqual(secrets(long), [])

    def test_a_yaml_anchor_or_tag_before_the_value_does_not_hide_it(self):
        pw = "Qx7vR2mK" + "9pLw!"
        for text in (f"pass§word: &pw {pw}", f"x-db-pass§word: &dbpw {pw}", f"pass§word: !!str {pw}",
                     f"pass§word: !vault {pw}"):
            with self.subTest(text=text):
                self.assertEqual(secrets(text), [pw])
        self.assertEqual(found("pass§word: &creds_2024"), [])
        # a quoted scalar or a name with capitals is no anchor or tag (review of b4a7c54)
        for text in ('{"pass§word": "!Passw0rd2024xyz"}', '{"pass§word": "&Xk9v2Qm7Lp4Rt8Wz"}',
                     "pass§word: '*Xk9v2Qm7Lp4Rt8Wz'", "the pass§word: !Xk9v2Qm7Lp4Rt8Wz"):
            with self.subTest(text=text):
                self.assertTrue(secrets(text), "a real value")
        self.assertEqual(secrets('pass§word: &pw "Xk9v2Qm7Lp4Rt8Wz"'), ["Xk9v2Qm7Lp4Rt8Wz"], "without its quotes")
        # a quoted value with a lower-case name is a value too: quotes make a scalar, never an anchor
        self.assertEqual(secrets('{"pass§word": "&xk9v2qm7lp4rt8wz"}'), ["&xk9v2qm7lp4rt8wz"])

    def test_a_hit_that_starts_inside_a_taken_span_is_no_second_hit(self):
        # the keyword rule takes the whole value first; the token shape inside it starts within that span
        text = "tok§en: abc12345glpat-" + "Q7w8E9r0T1y2U3i4O5p6"
        self.assertEqual(len(detect.scan(text.replace("§", ""))), 1)
        self.assertEqual(found("  access_tok§en_fields: &gitlab_tok§en_fields"), [])

    def test_near_variants(self):
        uuid_ = UUID
        for label in ("secret_val§ue: ", "SECRET_VAL§UE=", "signing_k§ey: ", "passphr§ase: ", "app_k§ey: "):
            with self.subTest(label=label):
                self.assertEqual(secrets(label + uuid_), [uuid_])
        for key in ("DriverClassName:", "jdbcURL:", "s3Bucket:", "oauth2ClientId:"):
            with self.subTest(key=key):
                self.assertEqual(found(f"pass§word:\n    {key} x\n"), [])
        for text in ("cellphone = +4915112345678", "smartphone = +4915112345678", "Festnetz = +4915112345678",
                     "hotline = +4915112345678"):
            with self.subTest(text=text):
                self.assertIn(("PHONE", "+4915112345678"), found(text))
        self.assertEqual(found("handyman_id = +4294967296"), [])
        bearer = "Bearer " + "8f3kd9sLq2pX7mN4vB6cZ1aW5eR9tY0u"
        for path in ("tests/fixtures/recorded/login.json", "tests/tapes/login.json5", "test/__nock-fixtures__/l.json",
                     "tests/fixtures/login.har.json"):
            with self.subTest(path=path):
                self.assertTrue(secrets(f"authorization: {bearer}\n", path))
        for text in ("secr§et: loadFromEnvironmentVariable,", "tok§en = extractFromRequestHeader",
                     "pass§word = fetchFromVaultStore"):
            with self.subTest(identifier=text):
                self.assertEqual(found(text), [])
        for text in ("tok§en_exp = 1790000000", "pass§word_changed_at = 1790000000", "tok§en_counter = 48392011"):
            with self.subTest(measure=text):
                self.assertEqual(found(text), [])
        for text in ("Pass§wort: gesperrt", "Kenn§wort: geändert", "Tok§en: widerrufen", "Tok§en: ungueltig",
                     "Pass§wort: zurückgesetzt"):
            with self.subTest(status=text):
                self.assertEqual(found(text), [])
        for text in ("pass§word = opts.pass§word!;", "pass§word = this.#pass§word;"):
            with self.subTest(ts=text):
                self.assertEqual(found(text), [])


class WeakWordTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)

    def test_a_chosen_word_stays_hunted_and_a_common_word_does_not(self):
        self.assertFalse(Vault().put("Sommerwiese", "SECRET", "ds-keyword-equal-signs", session="s1").weak)
        self.assertFalse(Vault().put("sommerwiesenblume", "SECRET", "ds-keyword-equal-signs", session="s1").weak)
        self.assertTrue(Vault().put("postgres", "SECRET", "ds-keyword-equal-signs", session="s1").weak)
        hooks._live_cache.clear()
        out = hooks.user_prompt({"prompt": "use Sommerwiese as the database password", "session_id": "s2", **CLAUDE})
        self.assertEqual(out.get("decision"), "block")


if __name__ == "__main__":
    unittest.main()
