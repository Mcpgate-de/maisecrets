"""/maisecrets:ner at a glance (maisecrets/ner_view.py): a head line, one short line per check with the marks and the
arrow column of /maisecrets:status, the details under `all`; and the arguments of the command: an argument it does not
know is answered and changes nothing, a server name of the person's configuration sets the gateway source.

Run: python3 -m unittest tests.test_ner_view -v
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, hooks, ner_gateway, ner_setup, ner_view, remote_layer, settings  # noqa: E402
from maisecrets.detection import remote  # noqa: E402
from maisecrets.vault import HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
GW = "https://gw.example.com"
SERVERS = {"team-gateway": GW + "/mcp", "other": "https://other.example.org/mcp"}
TODAY = {"gateway": 40, "rules": 2, "why:too_long": 2}


def tearDownModule():  # noqa: N802 - unittest hook
    CONFIG.write_text(json.dumps(TEST_CONFIG))
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))


def _prompt(text: str, client: dict = CLAUDE) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **client})


def _conf() -> dict:
    return load_config().get("remote_detector")


class _Det:
    def __init__(self, status):
        self.st = status

    def ask(self, text, spans):
        return [], self.st


def _gateway(answers=True, why="", doc=None):
    """The gateway source without a gateway: the detector of the login and the status document, as the report meets
    them."""
    det = None if why else _Det(remote.RemoteStatus("hf", "", "ok" if answers else "unavailable",
                                                    "" if answers else "busy", ms=202.4))
    doc = doc if doc is not None else {"quota": {"requests_left": 58, "requests_per_minute": 60}}
    return (mock.patch.object(remote_layer, "from_config", return_value=(det, why)),
            mock.patch.object(ner_gateway, "status", return_value=(doc, "")),
            mock.patch.object(ner_setup, "gateway_server", return_value="team-gateway"))


class ViewTests(unittest.TestCase):
    def setUp(self):
        _reset()
        counts = mock.patch.object(ner_setup, "today_counts", return_value=dict(TODAY))
        counts.start()
        self.addCleanup(counts.stop)

    def render(self, conf, show_all=False, client="claude"):
        return ner_view.render(conf, 0.0, show_all, client)

    def test_off_is_one_line_and_how_to_turn_it_on(self):
        code, lines = self.render(None)
        self.assertEqual(code, 0)
        self.assertEqual(lines, ["names: off (the rules alone)",
                                 "to turn it on: /maisecrets:ner local, url URL or gateway URL"])
        self.assertEqual(self.render(None, client="codex")[1][1],
                         "to turn it on: maisecrets: ner local, url URL or gateway URL")

    def test_the_gateway_fits_on_one_screen(self):
        conf = ner_setup.updated({}, "gateway:" + GW + "/mcp")
        a, b, c = _gateway()
        with a, b, c:
            code, lines = self.render(conf)
        self.assertEqual(code, 0)
        self.assertEqual(lines, [
            "names: gateway gw.example.com · answers (202 ms) with your login", "",
            " ✓ source      gateway (tool results; prompts: rules alone)",
            " ✓ login       has the name scope",
            " ✓ quota       58 of 60 requests this minute",
            " ✓ today       40 of 42 texts checked by the service, 2 rules alone", "",
            "all details: /maisecrets:ner all"])
        self.assertTrue(all(len(x) <= 80 for x in lines))

    def test_a_gateway_without_the_name_scope_exits_4_and_names_the_login(self):
        conf = ner_setup.updated({}, "gateway:" + GW)
        a, b, c = _gateway(why="the login lacks the name scope; the person runs /maisecrets:sref login once more")
        with a, b, c:
            code, lines = self.render(conf)
            self.assertEqual(code, 4)
            self.assertIn(" ✗ login       lacks the name scope  →  /maisecrets:sref login team-gateway",
                          lines)
            self.assertIn("needs a login with the name scope", lines[0])
            code, lines = self.render(conf, client="codex")
        self.assertIn("→  maisecrets: sref login team-gateway", "\n".join(lines))
        self.assertEqual(lines[-1], "all details: maisecrets: ner all")

    def test_a_low_quota_and_a_busy_gateway_are_named(self):
        conf = ner_setup.updated({}, "gateway:" + GW)
        a, b, c = _gateway(answers=False, doc={"quota": {"requests_left": 2, "requests_per_minute": 60}})
        with a, b, c:
            code, lines = self.render(conf)
        self.assertEqual(code, 1)
        text = "\n".join(lines)
        self.assertIn("! quota       2 of 60 requests this minute", text)
        self.assertIn("✗ gateway     no result (busy)", text)
        self.assertIn("gives no result", lines[0])

    def test_the_local_service_shows_service_image_and_load(self):
        conf = {"url": ner_setup.LOCAL_URL, "format": "hf"}
        facts = {"local": True, "answers": True, "probe": "the service: answers (12 ms), model m, types PER",
                 "proof": "ok", "tool": "docker", "image": ("behind", "v2.0.3800", "v2.0.3916"),
                 "load": "load: 4 workers, 25 % in use, 0 waiting, CPU 3 % of 2 cores"}

        def report(conf, wait=0.0, facts_out=None):
            facts_out.update(facts)
            return 0, ["names from a service: (details)", "start: x", "login: y"]
        with mock.patch.object(ner_setup, "report", side_effect=report):
            code, lines = self.render(conf)
            self.assertEqual(code, 0)
            self.assertEqual(lines[:6], [
                "names: local 127.0.0.1:8765 · answers (12 ms)", "",
                " ✓ source      local (tool results and prompts)",
                " ✓ service     answers, proves its secret",
                " ! image       v2.0.3800, behind the pin  →  a new session updates it",
                " ✓ load        4 workers, 25 % in use"])
            # the details: the lines of the report, without those the checks already say
            code, lines = self.render(conf, show_all=True)
        self.assertEqual(lines[-2:], ["Details", "names from a service: (details)"])

    def test_the_local_service_not_running_exits_3(self):
        conf = {"url": ner_setup.LOCAL_URL, "format": "hf"}
        with mock.patch.object(ner_setup, "probe", return_value=(False, "the service: does not answer")), \
                mock.patch.object(ner_setup.shutil, "which", side_effect=lambda n: "/x/docker" if n == "docker"
                                  else None):
            code, lines = self.render(conf)
        self.assertEqual(code, 3)
        self.assertEqual(lines[0], "names: local 127.0.0.1:8765 · does not answer")
        self.assertIn(" ✗ service     not running  →  run.sh ner start (docker)", lines)

    def test_a_url_shows_whether_it_is_reachable(self):
        conf = {"url": "http://10.0.0.5:8765/", "format": "hf", "allow_network": True}
        with mock.patch.object(ner_setup, "probe", return_value=(True, "the service: answers (9 ms), model m")), \
                mock.patch("maisecrets.ner_metrics.load_line", return_value="load: no load data (none)"):
            code, lines = self.render(conf)
        self.assertEqual(code, 0)
        self.assertEqual(lines[:4], ["names: url 10.0.0.5:8765 · answers (9 ms)", "",
                                     " ✓ source      url (tool results; prompts: rules alone)",
                                     " ✓ reachable   answers (9 ms)"])
        with mock.patch.object(ner_setup, "probe", return_value=(False, "the service: does not answer (URLError)")):
            code, lines = self.render(conf)
        self.assertEqual(code, 1)
        self.assertIn(" ✗ reachable   does not answer (URLError)  →  check the address with its team", lines)

    def test_all_shows_the_details(self):
        conf = ner_setup.updated({}, "gateway:" + GW)
        a, b, c = _gateway()
        with a, b, c:
            code, lines = self.render(conf, show_all=True)
        self.assertEqual(code, 0)
        i = lines.index("Details")
        self.assertTrue(lines[i + 1].startswith("names from a service: the gateway https://gw.example.com"))
        self.assertTrue(any(x.startswith("load: your quota this minute: 58 of 60") for x in lines[i:]))
        self.assertNotIn("all details: /maisecrets:ner all", lines)

    def test_today_is_a_warn_only_for_a_notable_share(self):
        for counts, state in (({"gateway": 40, "rules": 9, "why:too_long": 9}, "ok"),       # under RULES_MIN
                              ({"gateway": 400, "rules": 60, "why:too_long": 60}, "ok"),    # under RULES_SHARE
                              ({"gateway": 2, "rules": 199, "why:too_long": 197, "why:timeout": 2}, "warn"),
                              ({}, "n/a")):
            with self.subTest(counts=counts), mock.patch.object(ner_setup, "today_counts", return_value=counts):
                self.assertEqual(ner_view.today_check().state, state)
        with mock.patch.object(ner_setup, "today_counts", return_value={"gateway": 2, "rules": 199,
                                                                        "why:too_long": 197}):
            self.assertEqual(ner_view.today_check().fact, "199 of 201 texts rules alone (197 too long)")

    def test_the_command_prints_the_view_and_all(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.cmd_ner([]), 0)
        self.assertTrue(buf.getvalue().startswith("names: off (the rules alone)\n"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.cmd_ner(["all"])
        self.assertIn("\nDetails\n", buf.getvalue())

