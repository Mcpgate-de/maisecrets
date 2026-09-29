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
        for label in ("POSTMARK_SERVER_TOK§EN=", "SCW_SECRET_K§EY=", "api_k§ey: ", "pass§word: "):
            with self.subTest(label=label):
                self.assertEqual(secrets(label + UUID), [UUID])
        for label in ("k§ey: ", "client_secr§et: ", "secret_i§d: "):
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
