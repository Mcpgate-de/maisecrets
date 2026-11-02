"""maisecrets/sref_client.py against a fake gateway (harness/sref_server.py): discovery, the loopback login with PKCE,
the token in the store, the resolve into a file or a command, the whole-batch rule with counts, the refresh, a
withdrawn consent, the quota and a sink the gateway does not offer. The values are synthetic; no answer of the client
names a value or a reference id.

Run: python3 -m unittest tests.test_sref_client -v
"""
from __future__ import annotations

import os
import shutil
import ssl
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import sref_client as S  # noqa: E402
from maisecrets.vault import JsonFileBackend  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None
if HAS_OPENSSL:
    from sref_server import SrefServer  # noqa: E402
    from vault_server import make_cert  # noqa: E402

VALUE_MAIL, VALUE_NAME = "value-one@example.org", "Value Two"
_CERT: tuple | None = None


def _cert() -> tuple:
    global _CERT
    if _CERT is None:
        _CERT = make_cert(tempfile.mkdtemp(prefix="sref-cert-"))
    return _CERT


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


@unittest.skipUnless(HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class SrefClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = SrefServer(cert=_cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        self.cfg = {"client_vault_cafile": self.srv.cert}
        self.backend = JsonFileBackend()           # the store of the temp home of tests/_isolate.py
        self.found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.addCleanup(S.forget, self.backend, self.found["origin"])

    def browser(self, url: str, state: str | None = None) -> None:
        """The person in the browser: the authorize URL answers with a redirect to the loopback, which the browser
        follows. With `state`, the redirect is forged to carry another state."""
        ctx = ssl.create_default_context(cafile=self.srv.cert)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            opener.open(url)
        except urllib.error.HTTPError as exc:
            location = exc.headers["Location"]
            exc.close()
        if state is not None:
            location = location.split("state=")[0] + "state=" + state
        try:
            with urllib.request.urlopen(location, timeout=5) as answer:
                answer.read()
        except urllib.error.HTTPError as exc:
            exc.close()

    def login(self) -> None:
        S.login(self.cfg, self.backend, self.found, self.browser, wait=10)

    def test_discovery_names_the_resolver_and_its_sinks(self):
        self.assertIsNotNone(self.found)
        self.assertEqual(self.found["resolve"], self.srv.url + "/sensitive-references/resolve")
        self.assertEqual(sorted(self.found["sinks"]), ["local-file-1", "mcpgate-process-1"])

    def test_the_login_keeps_the_tokens_in_the_store_only(self):
        self.assertFalse(S.logged_in(self.backend, self.found["origin"]))
        self.login()
        self.assertTrue(S.logged_in(self.backend, self.found["origin"]))
        stored = self.backend.get(S._entry(self.found["origin"]))
        self.assertIn("srefr_", stored)

    def test_a_forged_state_ends_the_login_without_a_token(self):
        with self.assertRaises(S.Refused):
            S.login(self.cfg, self.backend, self.found, lambda url: self.browser(url, state="forged"), wait=10)
        self.assertFalse(S.logged_in(self.backend, self.found["origin"]))

    def test_a_file_and_a_command_get_their_values_and_the_gateway_learns_the_sink(self):
        self.login()
        mail, name = self.srv.mint("email", VALUE_MAIL), self.srv.mint("name", VALUE_NAME)
        got = S.resolve(self.cfg, self.backend, self.found, [mail, name], "local_file", "/tmp/invite.txt")
        self.assertEqual(got, {mail: VALUE_MAIL, name: VALUE_NAME})
        S.resolve(self.cfg, self.backend, self.found, [mail], "process", "curl")
        self.assertEqual([(r["sink_type"], r["destination"], r["count"]) for r in self.srv.resolved],
                         [("local_file", "/tmp/invite.txt", 2), ("process", "curl", 1)])

    def test_one_bad_reference_refuses_the_whole_batch_with_counts_only(self):
        self.login()
        good, gone = self.srv.mint("email", VALUE_MAIL), self.srv.mint("name", VALUE_NAME)
        self.srv.revoke(gone)
        unknown = "⟦sref:email:" + "x" * 24 + "⟧"
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [good, gone, unknown], "local_file", "/tmp/a.txt")
        msg = str(cm.exception)
        self.assertIn("1 revoked", msg)
        self.assertIn("1 unknown", msg)
        for leak in (VALUE_MAIL, VALUE_NAME, good, gone, unknown):
            self.assertNotIn(leak, msg)
        self.assertEqual(self.srv.resolved, [], "nothing released")

    def test_an_expired_access_token_is_refreshed_once_and_the_refresh_token_rotates(self):
        self.login()
        before = self.backend.get(S._entry(self.found["origin"]))
        self.srv.access.clear()                      # the access token died early on the server
        ref = self.srv.mint("email", VALUE_MAIL)
        self.assertEqual(S.resolve(self.cfg, self.backend, self.found, [ref], "process", "mail"), {ref: VALUE_MAIL})
        after = self.backend.get(S._entry(self.found["origin"]))
        self.assertNotEqual(before, after, "a new pair is kept")
        self.assertEqual(len(self.srv.refresh), 1, "the old refresh token is spent")

    def test_a_withdrawn_consent_asks_for_a_new_login(self):
        self.login()
        ref = self.srv.mint("email", VALUE_MAIL)
        self.srv.withdraw()
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [ref], "local_file", "/tmp/a.txt")
        self.assertIn("token", str(cm.exception))

    def test_the_daily_quota_is_named(self):
        self.login()
        self.srv.quota = 1
        refs = [self.srv.mint("email", VALUE_MAIL), self.srv.mint("name", VALUE_NAME)]
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, refs, "local_file", "/tmp/a.txt")
        self.assertIn("daily limit", str(cm.exception))

    def test_a_sink_the_gateway_does_not_offer_is_refused_before_a_request(self):
        self.srv.sinks = ["local-file-1"]
        found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.login()
        ref = self.srv.mint("email", VALUE_MAIL)
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, found, [ref], "process", "curl")
        self.assertIn("does not resolve into a command", str(cm.exception))
        self.assertEqual(self.srv.resolved, [])

    def test_no_login_no_request(self):
        ref = self.srv.mint("email", VALUE_MAIL)
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [ref], "local_file", "/tmp/a.txt")
        self.assertIn("not logged in", str(cm.exception))


class FindTests(unittest.TestCase):
    def test_a_reference_with_a_display_part_resolves_by_its_id(self):
        rid = "a" * 24
        text = f"mail to ⟦sref:email:{rid}:ma•••@x.de⟧ and ⟦sref:name:{rid}⟧"
        got = [(c, s, e) for _r, c, s, e in S.find(text)]
        self.assertEqual([c for c, _s, _e in got], [f"⟦sref:email:{rid}⟧", f"⟦sref:name:{rid}⟧"])
        self.assertEqual(text[got[0][1]:got[0][2]], f"⟦sref:email:{rid}:ma•••@x.de⟧")

    def test_a_short_id_is_no_reference(self):
        self.assertEqual(S.find("⟦sref:email:short⟧"), [])


if __name__ == "__main__":
    unittest.main()
