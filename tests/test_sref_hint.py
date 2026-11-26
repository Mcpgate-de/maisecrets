"""#109: a gateway that offers Sensitive References and no login: the session start says once how to sign in.

The line comes from files only: the metadata answer that vault_refs.endpoint read already (it now also keeps whether
that answer names Sensitive References) and the login in the store. No request goes out for it.

Run: python3 -m unittest tests.test_sref_hint -v
"""
from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from maisecrets import ner_health as H, sref_client as S, vault_refs as V  # noqa: E402
from maisecrets.vault import JsonFileBackend  # noqa: E402

ORIGIN = "https://gw.example.test"
URL = ORIGIN + "/mcp"
SERVERS = {"team-gateway": URL, "other": "https://other.example.test/mcp"}
META = {"resource": URL, "sensitive_references": {"resolve_endpoint": ORIGIN + "/sref/resolve"}}
LINE = ("💡 maisecrets: the MCP server team-gateway can show you masked values on your screen. To allow it, type: "
        "/maisecrets sref login team-gateway")


def P(session: str, **extra) -> dict:
    return {"session_id": session, **extra}


def _answer(meta: dict):
    body = json.dumps(meta).encode("utf-8")
    return lambda *a, **kw: (200, {"content-type": "application/json"}, body)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = JsonFileBackend()
        for f in (H.STATE, H._WARNED, V.ENDPOINTS):
            f.unlink(missing_ok=True)
            self.addCleanup(f.unlink, missing_ok=True)
        self.addCleanup(S.forget, self.backend, ORIGIN)
        for target, value in (("maisecrets.vault_refs.user_servers", SERVERS), ("maisecrets.cowork.active", False)):
            p = mock.patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def seen(self, meta: dict = META, url: str = URL) -> None:
        """The anonymous metadata request that maisecrets makes for a token in a result of this server."""
        with mock.patch.object(V, "_request", _answer(meta)):
            V.endpoint({}, url, time.monotonic() + 5)

    def lines(self, payload: dict, cfg: dict | None = None, codex: bool = False) -> list:
        return H.sref_hint_lines(cfg or {"backend": "jsonfile"}, payload, self.backend, codex=codex)


class OffersTests(Base):
    def test_the_metadata_answer_keeps_whether_it_names_sensitive_references(self):
        self.assertFalse(V.offers_sref(URL), "never asked: nothing known")
        self.seen()
        self.assertTrue(V.offers_sref(URL))
        self.assertFalse(V.offers_sref(SERVERS["other"]))

    def test_no_block_or_a_resolver_on_another_origin_is_no_offer(self):
        for meta in ({"resource": URL},
                     {"sensitive_references": {"resolve_endpoint": "https://elsewhere.example.test/r"}},
                     {"sensitive_references": "yes"}):
            with self.subTest(meta=meta):
                V.ENDPOINTS.unlink(missing_ok=True)
                self.seen(meta)
                self.assertFalse(V.offers_sref(URL))

    def test_an_old_answer_is_no_offer(self):
        self.seen()
        with mock.patch.object(V.time, "time", return_value=time.time() + V.SREF_SEEN_KEEP + 60):
            self.assertFalse(V.offers_sref(URL))


class HintTests(Base):
    def test_once_per_session(self):
        self.seen()
        self.assertEqual(self.lines(P("s1")), [LINE])
        self.assertEqual(self.lines(P("s1")), [], "the same session: not again")
        self.assertEqual(self.lines(P("s2")), [LINE], "a new session hears it once")

    def test_no_line_without_an_offer(self):
        self.assertEqual(self.lines(P("s1")), [])
        self.seen({"resource": URL})
        self.assertEqual(self.lines(P("s1")), [])

    def test_no_line_with_a_login(self):
        self.seen()
        S._keep(self.backend, ORIGIN, {"refresh": "r-synthetic", "access": "a-synthetic", "scope": "x",
                                       "expires": time.time() + 3600})
        self.assertEqual(self.lines(P("s1")), [])

    def test_the_setting_turns_it_off_for_one_server(self):
        self.seen()
        cfg = {"backend": "jsonfile", "sref_hint_off": ["team-gateway"]}
        self.assertEqual(self.lines(P("s1"), cfg), [])
        cfg = {"backend": "jsonfile", "sref_hint_off": ["other"]}
        self.assertEqual(self.lines(P("s1"), cfg), [LINE])

    def test_the_name_source_gateway_gets_its_own_line_only(self):
        # start_line names the missing login of the gateway that is the name source: no second line for it
        self.seen()
        cfg = {"backend": "jsonfile", "remote_detector": {"url": ORIGIN, "gateway": ORIGIN, "gateway_url": URL}}
        self.assertEqual(self.lines(P("s1"), cfg), [])

    def test_only_where_a_person_sees_it(self):
        self.seen()
        self.assertEqual(self.lines(P("s1", agent_id="a1")), [], "a subagent")
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-py"}):
            self.assertEqual(self.lines(P("s2")), [], "a headless run")
        with mock.patch("maisecrets.cowork.active", return_value=True):
            self.assertEqual(self.lines(P("s3")), [], "Cowork: a login there lasts one task")
        self.assertEqual(self.lines(P("s1")), [LINE], "not claimed by the runs that did not show it")

    def test_codex_gets_its_prompt_form(self):
        self.seen()
        with mock.patch("maisecrets.settings.person_sees_hook_lines", return_value=True):
            self.assertEqual(self.lines(P("s1"), codex=True),
                             [LINE.replace("/maisecrets sref login", "maisecrets: sref login")])

    def test_no_request_goes_out_for_the_hint(self):
        self.seen()

        def no_request(*a, **kw):
            raise AssertionError("a request went out for the hint")
        with mock.patch.object(V, "_request", no_request), mock.patch.object(S, "_get_json", no_request), \
                mock.patch("urllib.request.urlopen", no_request), mock.patch("http.client.HTTPSConnection", no_request):
            self.assertEqual(self.lines(P("s1")), [LINE])


class SessionStartTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "run.sh: the session start of a POSIX launcher")
    def test_the_session_start_shows_the_line_once(self):
        import subprocess
        import tempfile
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            store = home / "store"
            (store / "vault-refs").mkdir(parents=True)
            (store / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
            (store / ".announced").write_text("x\n")          # not the first start: no welcome
            (store / "vault-refs" / "endpoints.json").write_text(json.dumps(
                {URL: {"endpoint": None, "t": time.time(), "sref": True}}))
            (home / ".claude.json").write_text(json.dumps({"mcpServers": {"team-gateway": {"type": "http",
                                                                                           "url": URL}}}))
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
            env.update({"HOME": str(home), "MAISECRETS_" + "HOME": str(store), "PYTHONDONTWRITEBYTECODE": "1",
                        "CLAUDECODE": "1"})

            def start() -> str:
                r = subprocess.run(["bash", str(root / "hooks" / "run.sh"), "session-" + "start"],
                                   input=json.dumps({"session_id": "S-start", "hook_event_name": "SessionStart"}),
                                   capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                return json.loads(r.stdout).get("systemMessage", "")
            self.assertIn(LINE, start())
            self.assertNotIn("can show you masked values", start(), "once per session")


if __name__ == "__main__":
    unittest.main()
