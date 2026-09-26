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
GHP = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"  # mixed: gitleaks needs entropy >= 3
GLRT = "glrt-" + "AbCdEfGhIjKlMnOpQrStUv.01.1a2b3c4d5"
# canonical public test values, assembled at runtime so no literal sits in the tree
IBAN_OK = " ".join(["DE89", "3704", "0044", "0532", "0130", "00"])
CARD_OK = " ".join(["4111"] + ["1111"] * 3)
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"])


class DetectTests(unittest.TestCase):
    def test_secret_shapes_are_found_with_the_exact_value(self):
        for kind, val in [("gitlab-pat", GLPAT), ("aws-access-token", AKIA), ("github-pat", GHP), ("jwt", JWT),
                          ("gitlab-runner-token", GLRT)]:
            with self.subTest(kind=kind):
                ms = detect.scan(f"token is {val} ok")
                self.assertEqual([(m.kind, m.value) for m in ms], [(kind, val)])

    def test_a_token_longer_than_its_fixed_shape_is_taken_whole(self):
        long_pat = GLPAT + "6789"                       # 24 chars after the prefix, the rule says 20
        ms = detect.scan(f"TOKEN={long_pat}\n")
        self.assertEqual([m.value for m in ms], [long_pat])
        ms = detect.scan(f"token {long_pat}, then text")
        self.assertEqual([m.value for m in ms], [long_pat])

    def test_webhook_signing_secret_on_a_bare_line_is_a_hit(self):
        import base64
        fake = "whsec_" + base64.b64encode(bytes(range(32))).decode()
        ms = detect.scan("https://example.org/api/webhooks/marketplace-push/marketplace_0123\n" + fake + "\n")
        self.assertEqual([(m.kind, m.value) for m in ms], [("webhook-signing-secret", fake)])

    def test_two_secrets_in_one_text_become_two_references(self):
        text = f"token {GLPAT} and key {AKIA} please"
        ms = detect.scan(text)
        self.assertEqual([m.value for m in ms], [GLPAT, AKIA])
        hooks._clipboard = lambda t: True
        out = hooks.user_prompt({"prompt": text, "session_id": "s2", "transcript_path": ""})
        self.assertEqual(out["decision"], "block")
        self.assertIn("SECRET_c1, SECRET_c2", out["reason"])
        self.assertNotIn(GLPAT, out["reason"])
        self.assertNotIn(AKIA, out["reason"])

    def test_named_credential_keeps_the_name_and_takes_the_value(self):
        ms = detect.scan("DB_PASSWORD=" + "Sup3rSecret" + "Value1234")
        self.assertEqual(len(ms), 1)
        self.assertEqual(ms[0].value, "Sup3rSecret" + "Value1234")
        self.assertEqual(ms[0].type, "SECRET")
        self.assertTrue(ms[0].kind.startswith("ds-keyword"))
        self.assertEqual(detect.scan('password = "${DB_PASSWORD}"'), [])     # templated, not a value
        self.assertEqual(detect.scan('password: "changeme"'), [])            # placeholder

    def test_email_iban_card_are_pii_and_validated(self):
        text = "mail max.mustermann@example.org iban " + IBAN_OK + " credit card " + CARD_OK
        types = [m.type for m in detect.scan(text)]
        self.assertEqual(types, ["EMAIL", "IBAN", "CARD"])

    def test_invalid_iban_and_luhn_failing_card_are_not_hits(self):
        self.assertEqual([m.type for m in detect.scan("IBAN " + IBAN_OK[:-1] + "1")], [])
        self.assertEqual([m.type for m in detect.scan("card " + CARD_OK[:-1] + "2")], [])

    def test_private_ips_are_ignored_public_ips_are_hits(self):
        self.assertEqual(detect.scan("host 127.0.0.1 and 10.0.0.5 and 192.168.1.1"), [])
        self.assertEqual([(m.type, m.value) for m in detect.scan("edge 93.184.216.34")], [("IP", "93.184.216.34")])

    def test_validators_never_raise_on_odd_shapes(self):
        for v in ("0/8", "999.1.1.1", "", "DE", "abc"):
            for name, fn in detect.VALIDATORS.items():
                with self.subTest(validator=name, value=v):
                    try:
                        self.assertIn(fn(v), (True, False))
                    except (ValueError, IndexError, TypeError):
                        self.fail(f"{name} raised on {v!r}")

    def test_a_span_that_contains_a_placeholder_is_not_a_hit(self):
        self.assertEqual(detect.scan('curl -u "app:⟦SECRET_c1⟧" https://h/x'), [])
        self.assertEqual(detect.scan("password = ⟦SECRET_c2:•••⟧"), [])

    def test_placeholder_is_not_a_hit(self):
        self.assertEqual(detect.scan("send to ⟦EMAIL_c1:ma•••@example.org⟧ now"), [])
        self.assertEqual(detect.scan("legacy <EMAIL_c1:ma***@example.org> form"), [])

    def test_url_userinfo_is_a_secret_not_an_email(self):
        ms = detect.scan("postgres://etl:" + "s3cretPassw0rd" + "@db.internal:5432/x")
        self.assertEqual([(m.kind, m.value) for m in ms], [("ds-basic-auth", "s3cretPassw0rd")])

    def test_query_parameter_secret(self):
        ms = detect.scan("GET https://x/api?api_key=" + "0123456789abcdef0123")
        self.assertEqual(ms[0].type, "SECRET")

    def test_gitleaks_ruleset_is_loaded(self):
        ids = {r.id for r in detect.rules()}
        self.assertGreater(len(ids), 200)
        self.assertTrue({"gitlab-pat", "aws-access-token", "private-key", "email", "ds-basic-auth"} <= ids)
        self.assertTrue(any(i.startswith("iban") for i in ids))

    def test_german_tax_id_needs_context_and_checksum(self):
        valid = "86095742719"   # the BZSt example number
        self.assertEqual([m.type for m in detect.scan("Meine Steuer-ID lautet " + valid)], ["DE_TAX_ID"])
        self.assertEqual(detect.scan("Bestellung " + valid + " ist raus"), [])           # no context word
        self.assertEqual(detect.scan("Steuer-ID " + valid[:-1] + "0"), [])                # checksum fails

    def test_german_vat_id_and_plz(self):
        self.assertEqual([m.type for m in detect.scan("USt-IdNr. DE123456789")], ["DE_VAT_ID"])
        self.assertEqual(detect.scan("10115 Berlin"), [])
        self.assertEqual([m.type for m in detect.scan("PLZ 10115")], ["DE_PLZ"])

    def test_presidio_regions_are_opt_in(self):
        ids = {r.id.split("#")[0] for r in detect.rules()}
        self.assertIn("de-tax-id", ids)
        self.assertNotIn("pl-pesel", ids)   # not in the default regions
        self.assertNotIn("in-pan", ids)     # Presidio tags it "en"; region is the switch

    def test_placeholder_types_with_underscores(self):
        self.assertEqual(placeholder.key_of("⟦DE_TAX_ID_c2⟧"), "DE_TAX_ID_c2")
        self.assertEqual(detect.scan("see ⟦DE_TAX_ID_c2⟧ above"), [])

    def test_a_keyword_inside_a_product_name_before_markdown_is_not_a_credential(self):
        self.assertEqual(detect.scan("| shown next to `/maisecrets:report` | the notice"), [])

    def test_a_short_prose_word_after_token_is_not_a_credential(self):
        self.assertEqual(detect.scan("the token expired yesterday"), [])


class PlaceholderTests(unittest.TestCase):
    def test_refs_round_trip_with_and_without_display(self):
        self.assertEqual(placeholder.key_of("⟦EMAIL_c3:ma•••@x.de⟧"), "EMAIL_c3")
        self.assertEqual(placeholder.key_of("⟦SECRET_c1⟧"), "SECRET_c1")
        self.assertEqual(placeholder.key_of("<SECRET_c1>"), "SECRET_c1")   # legacy form still resolves
        self.assertIsNone(placeholder.key_of("⟦EMAIL_3⟧"))  # gateway-minted, not ours
        self.assertEqual(placeholder.make_ref("EMAIL", 4, "ma•••@x.de"), "⟦EMAIL_c4:ma•••@x.de⟧")

    def test_find_refs_reports_offsets(self):
        text = 'curl -H "Bearer ⟦SECRET_c1⟧" https://x/⟦EMAIL_c2:a•••@b.c⟧'
        self.assertEqual([k for k, _, _ in placeholder.find_refs(text)], ["SECRET_c1", "EMAIL_c2"])

    def test_secret_display_is_never_shown(self):
        self.assertIsNone(placeholder.display_for("SECRET", GLPAT))
        # gateway rules (pii_display.py): the domain shows only for freemail providers at "standard"
        self.assertEqual(placeholder.display_for("EMAIL", "max.mustermann@example.org"), "ma•••@•••.org")
        self.assertEqual(placeholder.display_for("EMAIL", "max.mustermann@gmail.com"), "ma•••@gmail.com")
        self.assertEqual(placeholder.display_for("EMAIL", "max@gmail.com"), "m•••@gmail.com")   # 2 chars stay hidden
        self.assertEqual(placeholder.display_for("IBAN", "DE89 3704 0044 0532 0130 00"), "DE89••••••••••••••3000")


class VaultTests(unittest.TestCase):
    def setUp(self):
        for f in Path(_TMP).glob("*"):
            if f.name != "config.json":   # keep the jsonfile pin, or the default (keychain) takes over
                f.unlink()
        self.v = Vault({"backend": "jsonfile", "ttl_seconds": {"default": 60},
                        "max_ttl_seconds": 120, "renew_on_use": True})

    def test_put_get_same_value_same_ref(self):
        a = self.v.put(GLPAT, "SECRET", "gitlab-pat")
        b = self.v.put(GLPAT, "SECRET", "gitlab-pat")
        self.assertEqual(a.key, b.key)
        self.assertEqual(self.v.get(a.key, human=True), (GLPAT, "ok"))
        self.assertEqual(self.v.get(a.key), (None, "no-session"))   # hooks need a session

    def test_counter_is_per_type(self):
        self.v.put(GLPAT, "SECRET", "gitlab-pat")
        e = self.v.put("max@example.org", "EMAIL", "email")
        self.assertEqual(e.key, "EMAIL_c1")

    def test_expired_value_is_deleted_but_metadata_stays(self):
        e = self.v.put(AKIA, "SECRET", "aws-access-token")
        self.v._index["entries"][e.key]["expires"] = 0
        self.v._save_index()
        self.assertEqual(self.v.get(e.key, human=True), (None, "expired"))
        self.assertTrue(self.v._index["entries"][e.key]["purged"])
        self.assertIsNone(self.v.backend.get(e.key))
        self.assertEqual(self.v.get("SECRET_c99", human=True), (None, "unknown"))

    def test_non_default_home_uses_its_own_keychain_service(self):
        from maisecrets import vault as v
        self.assertNotEqual(v.SERVICE, "maisecrets")
        self.assertTrue(v.SERVICE.startswith("maisecrets@"))

    @unittest.skipIf(sys.platform == "win32", "no openssl on a stock Windows PATH; Windows uses the Credential Locker")
    def test_encrypted_file_backend_roundtrip_and_tamper(self):
        from maisecrets.vault import EncryptedFileBackend
        b = EncryptedFileBackend()
        b.put("SECRET_c9", GLPAT)
        self.assertEqual(b.get("SECRET_c9"), GLPAT)
        raw = Path(b.path).read_text()
        self.assertNotIn(GLPAT, raw)                       # encrypted at rest
        self.assertEqual(os.stat(b.key_file).st_mode & 0o777, 0o600)
        d = json.loads(raw)
        d["SECRET_c9"]["t"] = "0" * 64                     # tamper with the tag
        Path(b.path).write_text(json.dumps(d))
        self.assertIsNone(b.get("SECRET_c9"))               # fail closed
        b.delete("SECRET_c9")
        self.assertIsNone(b.get("SECRET_c9"))

    @unittest.skipIf(sys.platform == "win32", "POSIX file modes do not apply on Windows")
    def test_vault_file_is_private(self):
        self.v.put(AKIA, "SECRET", "aws-access-token")
        mode = os.stat(self.v.backend.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class HookTests(unittest.TestCase):
    def setUp(self):
        for f in Path(_TMP).glob("*"):
            if f.name != "config.json":   # keep the jsonfile pin, or the default (keychain) takes over
                f.unlink()
        hooks._clipboard = lambda text: True  # no real clipboard in tests

    def test_prompt_with_secret_is_blocked_and_stored(self):
        out = hooks.user_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1"})
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(GLPAT, json.dumps(out))
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(Vault().get("SECRET_c1", session="s1"), (GLPAT, "ok"))

    def test_prompt_without_hit_passes(self):
        self.assertEqual(hooks.user_prompt({"prompt": "say hi"}), {})

    def test_at_mention_of_existing_file_is_blocked(self):
        with tempfile.NamedTemporaryFile(suffix=".env", delete=False) as f:
            f.write(b"X=1")
        out = hooks.user_prompt({"prompt": f"look at @{f.name}", "cwd": "/"})
        self.assertEqual(out["decision"], "block")

    def test_pre_tool_rewrites_bash_to_a_granted_resolve_and_denies_unknown(self):
        e = Vault().put(GLPAT, "SECRET", "gitlab-pat", session="s1")
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1",
                              "tool_input": {"command": f'curl -H "PRIVATE-TOKEN: {e.ref}" u'}})
        cmd = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn(GLPAT, cmd)                     # the value is never spliced into the command
        self.assertIn("resolve.py", cmd)
        self.assertIn(f"{e.key} --grant ", cmd)
        self.assertTrue(cmd.startswith('curl -H "PRIVATE-TOKEN: $('))   # double-quote context: bare $(…)
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", "tool_input": {"command": "echo ⟦SECRET_c42⟧"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_pre_tool_resolves_gateway_tool_arguments_until_the_deposit_path_exists(self):
        e = Vault().put("max@example.org", "EMAIL", "email", session="s1")
        out = hooks.pre_tool({"tool_name": "mcp__phase6-ai-gateway__x", "tool_input": {"q": e.ref}, "session_id": "s1",
                              "mcp_server": {"name": "phase6-ai-gateway", "source": "user"}})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"], {"q": "max@example.org"})

    def test_post_tool_redacts_bash_output_keeping_shape(self):
        out = hooks.post_tool({"tool_name": "Bash", "tool_input": {"command": "cat .env"},
                               "tool_response": {"stdout": f"TOKEN={GLPAT}\n", "stderr": "",
                                                 "interrupted": False, "isImage": False}})
        upd = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(upd), {"stdout", "stderr", "interrupted", "isImage"})
        self.assertNotIn(GLPAT, upd["stdout"])
        self.assertIn("⟦SECRET_c1⟧", upd["stdout"])

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
