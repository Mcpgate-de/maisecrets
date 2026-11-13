"""The gateway of /maisecrets:sref login as the source of names (#33) against a fake gateway (harness/sref_server.py
with the name endpoint of ai-gateway #1819): the command, discovery, the login that asks for the name scope only while
the source is set, the token at each tool result, the gateway's refusals by name, and no prompt to this source (C30).
Synthetic values only.

Run: python3 -m unittest tests.test_ner_gateway -v
"""
from __future__ import annotations

import os
import shutil
import ssl
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import ner_gateway, ner_setup, remote_layer, sref_client as S  # noqa: E402
from maisecrets.vault import JsonFileBackend  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None
if HAS_OPENSSL:
    from sref_server import NER_SCOPE, SrefServer  # noqa: E402
    from vault_server import make_cert  # noqa: E402

_CERT: tuple | None = None
TEXT = "the ticket of Dana " + "Okafor is open"


def _cert() -> tuple:
    global _CERT
    if _CERT is None:
        _CERT = make_cert(tempfile.mkdtemp(prefix="ner-gw-cert-"))
    return _CERT


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class CommandTests(unittest.TestCase):
    def test_the_command_names_a_gateway_and_keeps_the_tuning(self):
        word = ner_setup.parse("/maisecrets:ner gateway https://gw.example.com/mcp")
        self.assertEqual(word, "gateway:https://gw.example.com/mcp")
        self.assertEqual(ner_setup.parse("maisecrets: ner gateway https://gw.example.com"), "gateway:https://gw.example.com")
        new = ner_setup.updated({"url": ner_setup.LOCAL_URL, "timeout_ms": 900}, word)
        self.assertEqual(new, {"timeout_ms": 900, "gateway": "https://gw.example.com",
                               "gateway_url": "https://gw.example.com/mcp", "url": "https://gw.example.com",
                               "format": "hf", "allow_network": True})
        self.assertIn("the gateway https://gw.example.com", ner_setup.describe(new))
        # another source takes the gateway keys away
        self.assertNotIn("gateway", ner_setup.updated(new, "local"))

    def test_a_tool_call_that_carries_the_sentence_is_refused_like_the_others(self):
        import re
        self.assertTrue(re.search(ner_setup.IN_A_COMMAND, "echo '/maisecrets:ner gateway https://gw.example.com'"))


@unittest.skipUnless(HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class GatewaySourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = SrefServer(cert=_cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        self.srv.ner = True
        self.backend = JsonFileBackend()           # the store of the temp home of tests/_isolate.py
        conf = ner_setup.updated({}, "gateway:" + self.srv.url + "/mcp")
        self.cfg = {"client_vault_cafile": self.srv.cert, "remote_detector": conf, "backend": "jsonfile",
                    "allow_plaintext_store": True}
        self.origin = conf["gateway"]
        self.addCleanup(S.forget, self.backend, self.origin)
        self.addCleanup(lambda: ner_gateway.CACHE.unlink(missing_ok=True))

    def browser(self, url: str) -> None:
        ctx = ssl.create_default_context(cafile=self.srv.cert)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            opener.open(url)
        except urllib.error.HTTPError as exc:
            location = exc.headers["Location"]
            exc.close()
        with urllib.request.urlopen(location, timeout=5) as answer:
            answer.read()

    def login(self, cfg: dict) -> None:
        S.login(cfg, self.backend, S.discover(cfg, self.srv.url + "/mcp"), self.browser, wait=10)

    def ask(self, text: str = TEXT, prompt: bool = False) -> tuple:
        cfg = self.cfg
        if prompt:     # the prompt path builds its detector with allow_network False (remote_layer.prompt_names)
            cfg = {**cfg, "remote_detector": {**cfg["remote_detector"], "allow_network": False}}
        det, why = remote_layer.from_config(cfg)
        if det is None:
            return None, why
        return det.ask(text, [])

    def test_discovery_names_the_endpoint_and_a_login_asks_for_its_scope_only_while_the_source_is_set(self):
        found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.assertEqual(found["ner"]["endpoint"], self.srv.url + "/sensitive-references/ner")
        self.assertIn(NER_SCOPE, found["scope"].split())
        other = S.discover({"client_vault_cafile": self.srv.cert}, self.srv.url + "/mcp")
        self.assertNotIn(NER_SCOPE, other["scope"].split(), "no source set: the login does not ask for it")

    def test_a_logged_in_source_finds_the_name_and_the_gateway_got_the_text(self):
        self.login(self.cfg)
        spans, status = self.ask()
        self.assertEqual(status.state, "ok", status)
        self.assertEqual([TEXT[s:e] for s, e, _t, _sc in spans], ["Okafor"])
        self.assertEqual(self.srv.ner_texts, [TEXT])

    def test_a_login_without_the_name_scope_gives_the_reason_and_sends_nothing(self):
        self.login({"client_vault_cafile": self.srv.cert})        # logged in before the source was set
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("/maisecrets:sref login", why)
        self.assertEqual(self.srv.ner_texts, [])

    def test_no_login_and_a_switched_off_gateway_give_reasons(self):
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("login", why)
        self.srv.ner = False
        ner_gateway.CACHE.unlink(missing_ok=True)
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("names no name detection", why)

    def test_a_prompt_never_goes_to_the_gateway(self):
        self.login(self.cfg)
        det, why = self.ask(prompt=True)
        self.assertIsNone(det)
        self.assertIn("C30", why)
        self.assertEqual(self.srv.ner_texts, [])

    def test_the_gateways_refusals_have_their_names(self):
        self.login(self.cfg)
        for code, reason in ((403, "forbidden"), (413, "too_long"), (429, "rate_limited"), (503, "busy"),
                             (500, "http")):
            with self.subTest(code=code):
                self.srv.ner_answer = (code, {"error": "x"})
                spans, status = self.ask()
                self.assertEqual((spans, status.state, status.reason), ([], "unavailable", reason))


class TokenTests(unittest.TestCase):
    def test_a_token_goes_only_over_https_and_holds_only_token_characters(self):
        from maisecrets.detection import remote
        good = "srefr_" + "a" * 30
        remote.RemoteDetector("https://gw.example.com/x", allow_network=True, token=good)
        for url, tok in (("http://127.0.0.1:9/x", good), ("https://gw.example.com/x", good + "\r\nX: y"),
                         ("https://gw.example.com/x", "short")):
            with self.subTest(n=len(tok), url=url[:5]):
                with self.assertRaises(ValueError):
                    remote.RemoteDetector(url, allow_network=True, token=tok)
        with self.assertRaises(ValueError):
            remote.RemoteDetector("https://gw.example.com/x", allow_network=True, token=good, bearer="a" * 64)
        self.assertNotIn(good, repr(remote.RemoteDetector("https://gw.example.com/x", allow_network=True,
                                                          token=good).__dict__.get("url")))


if __name__ == "__main__":
    unittest.main()
