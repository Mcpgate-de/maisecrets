"""Unit tests for detector, placeholder, vault and hook handlers.

Run: python3 -m unittest discover -s tests -v
Mutation probes: see docs/CONCEPT.md, section "Tests that cannot fail" — counts are
recorded per probe in harness/out/mutations.md when a probe has been run.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# isolate the vault for every test run
_TMP = tempfile.mkdtemp(prefix="maisecrets-test-")
os.environ["MAISECRETS_HOME"] = _TMP
# tests never touch the real keychain
Path(_TMP, "config.json").write_text('{"backend": "jsonfile"}')

from maisecrets import detect, hooks, placeholder  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402

GLPAT = "glpat-" + "A1b2C3d4E5f6G7h8I9j0"          # 20 chars after prefix
AKIA = "AKIA" + "ABCDEFGHIJKLMNOP"
GHP = "ghp_" + "a" * 36
GLRT = "glrt-" + "AbCdEfGhIjKlMnOpQrStUv.01.1a2b3c4d5"
# canonical public test values, assembled at runtime so no literal sits in the tree
IBAN_OK = " ".join(["DE89", "3704", "0044", "0532", "0130", "00"])
CARD_OK = " ".join(["4111"] + ["1111"] * 3)
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"])


class DetectTests(unittest.TestCase):
    def test_secret_shapes_are_found_with_the_exact_value(self):
        for kind, val in [("gitlab_pat", GLPAT), ("aws_key", AKIA), ("github_token", GHP), ("jwt", JWT),
                          ("gitlab_runner_token", GLRT)]:
            with self.subTest(kind=kind):
                ms = detect.scan(f"token is {val} ok")
                self.assertEqual([(m.kind, m.value) for m in ms], [(kind, val)])

    def test_named_credential_keeps_the_name_and_takes_the_value(self):
        ms = detect.scan("DB_PASSWORD=" + "Sup3rSecret" + "Value1234")
        self.assertEqual(len(ms), 1)
        self.assertEqual(ms[0].value, "Sup3rSecret" + "Value1234")
        self.assertEqual(ms[0].type, "SECRET")

    def test_email_iban_card_are_pii_and_validated(self):
        text = "mail max.mustermann@example.org iban " + IBAN_OK + " card " + CARD_OK
        kinds = {m.kind for m in detect.scan(text)}
        self.assertEqual(kinds, {"email", "iban", "credit_card"})

    def test_invalid_iban_and_luhn_failing_card_are_not_hits(self):
        self.assertEqual([m.kind for m in detect.scan(IBAN_OK[:-1] + "1")], [])
        self.assertEqual([m.kind for m in detect.scan(CARD_OK[:-1] + "2")], [])

    def test_private_ips_are_ignored_public_ips_are_hits(self):
        self.assertEqual(detect.scan("host 127.0.0.1 and 10.0.0.5 and 192.168.1.1"), [])
        self.assertEqual([m.value for m in detect.scan("edge 93.184.216.34")], ["93.184.216.34"])

    def test_placeholder_is_not_a_hit(self):
        self.assertEqual(detect.scan("send to <EMAIL_c1:ma***@example.org> now"), [])

    def test_a_short_prose_word_after_token_is_not_a_credential(self):
        self.assertEqual(detect.scan("the token expired yesterday"), [])


class PlaceholderTests(unittest.TestCase):
    def test_refs_round_trip_with_and_without_display(self):
        self.assertEqual(placeholder.key_of("<EMAIL_c3:ma***@x.de>"), "EMAIL_c3")
        self.assertEqual(placeholder.key_of("<SECRET_c1>"), "SECRET_c1")
        self.assertIsNone(placeholder.key_of("<EMAIL_3>"))  # gateway-minted, not ours

    def test_find_refs_reports_offsets(self):
        text = 'curl -H "Bearer <SECRET_c1>" https://x/<EMAIL_c2:a***@b.c>'
        self.assertEqual([k for k, _, _ in placeholder.find_refs(text)], ["SECRET_c1", "EMAIL_c2"])

    def test_secret_display_is_never_shown(self):
        self.assertIsNone(placeholder.display_for("SECRET", GLPAT))
        self.assertEqual(placeholder.display_for("EMAIL", "max@example.org"), "ma***@example.org")


class VaultTests(unittest.TestCase):
    def setUp(self):
        for f in Path(_TMP).glob("*"):
            f.unlink()
        self.v = Vault({"backend": "jsonfile", "ttl_seconds": {"default": 60},
                        "max_ttl_seconds": 120, "renew_on_use": True})

    def test_put_get_same_value_same_ref(self):
        a = self.v.put(GLPAT, "SECRET", "gitlab_pat")
        b = self.v.put(GLPAT, "SECRET", "gitlab_pat")
        self.assertEqual(a.key, b.key)
        self.assertEqual(self.v.get(a.key), (GLPAT, "ok"))

    def test_counter_is_per_type(self):
        self.v.put(GLPAT, "SECRET", "gitlab_pat")
        e = self.v.put("max@example.org", "EMAIL", "email")
        self.assertEqual(e.key, "EMAIL_c1")

    def test_expired_value_is_deleted_but_metadata_stays(self):
        e = self.v.put(AKIA, "SECRET", "aws_key")
        self.v._index["entries"][e.key]["expires"] = 0
        self.v._save_index()
        self.assertEqual(self.v.get(e.key), (None, "expired"))
        self.assertTrue(self.v._index["entries"][e.key]["purged"])
        self.assertIsNone(self.v.backend.get(e.key))
        self.assertEqual(self.v.get("SECRET_c99"), (None, "unknown"))

    def test_vault_file_is_private(self):
        self.v.put(AKIA, "SECRET", "aws_key")
        mode = os.stat(self.v.backend.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class HookTests(unittest.TestCase):
    def setUp(self):
        for f in Path(_TMP).glob("*"):
            f.unlink()
        hooks._clipboard = lambda text: True  # no real clipboard in tests

    def test_prompt_with_secret_is_blocked_and_stored(self):
        out = hooks.user_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1"})
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(GLPAT, json.dumps(out))
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(Vault().get("SECRET_c1"), (GLPAT, "ok"))

    def test_prompt_without_hit_passes(self):
        self.assertEqual(hooks.user_prompt({"prompt": "say hi"}), {})

    def test_at_mention_of_existing_file_is_blocked(self):
        with tempfile.NamedTemporaryFile(suffix=".env", delete=False) as f:
            f.write(b"X=1")
        out = hooks.user_prompt({"prompt": f"look at @{f.name}", "cwd": "/"})
        self.assertEqual(out["decision"], "block")

    def test_pre_tool_rehydrates_bash_and_denies_unknown(self):
        e = Vault().put(GLPAT, "SECRET", "gitlab_pat")
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": f'curl -H "PRIVATE-TOKEN: {e.ref}" u'}})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["command"], f'curl -H "PRIVATE-TOKEN: {GLPAT}" u')
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "echo <SECRET_c42>"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_pre_tool_leaves_gateway_tools_alone(self):
        out = hooks.pre_tool({"tool_name": "mcp__phase6-ai-gateway__x", "tool_input": {"q": "<EMAIL_c1>"},
                              "mcp_server": {"name": "phase6-ai-gateway", "source": "user"}})
        self.assertEqual(out, {})

    def test_post_tool_redacts_bash_output_keeping_shape(self):
        out = hooks.post_tool({"tool_name": "Bash", "tool_input": {"command": "cat .env"},
                               "tool_response": {"stdout": f"TOKEN={GLPAT}\n", "stderr": "",
                                                 "interrupted": False, "isImage": False}})
        upd = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(upd), {"stdout", "stderr", "interrupted", "isImage"})
        self.assertNotIn(GLPAT, upd["stdout"])
        self.assertIn("<SECRET_c1>", upd["stdout"])

    def test_post_tool_without_hit_returns_nothing(self):
        self.assertEqual(hooks.post_tool({"tool_response": {"stdout": "all good"}}), {})

    def test_main_fails_closed_on_bad_payload(self):
        sys.stdin = io.StringIO("not json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = hooks.main(["hook", "user-prompt"])
        sys.stdin = sys.__stdin__
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
