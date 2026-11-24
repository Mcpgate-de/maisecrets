"""The remote detector in the plugin (maisecrets/remote_layer.py, setting remote_detector): the real PostToolUse hook
against a fake service. It adds a name to a tool result, stores it so its placeholder resolves, never hunts it in
another text, asks once per hook call, leaves a typed prompt alone, and answers byte for byte as without it when the
service is off, down or not allowed."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault, is_weak, load_config  # noqa: E402
from test_remote_detector import NAME, PHONE, Service  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CONFIG = Path(HOME, "config.json")
OTHER = "Bartholomew Quist"
KEY = re.compile(r"NAME_c\d+")     # the key of a stored name; the brackets are left out on purpose


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in ("index.json", "vault.json", "audit.log", "events.log", "ner-rate.json"):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def _reset_keep_store(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    hooks._live_cache.clear()


def _post(response) -> dict:
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                            "tool_input": {"command": "cat notes.txt"}, "tool_response": response})


def _out(answer: dict):
    return answer.get("hookSpecificOutput", {}).get("updatedToolOutput")


class RemoteLayerTests(unittest.TestCase):
    def setUp(self):
        self.svc = Service("hf", answer=self.names)
        self.addCleanup(self.svc.close)

    @staticmethod
    def names(text: str):
        out = []
        for n in (NAME, OTHER):
            at = text.find(n)
            while at >= 0:
                out.append({"entity_group": "PER", "start": at, "end": at + len(n), "score": 0.9})
                at = text.find(n, at + 1)
        return out

    def on(self, **extra) -> None:
        _reset(remote_detector={"url": self.svc.url, "format": "hf", "model": "fake@1", **extra})

    def test_a_name_in_a_tool_result_is_masked_and_its_placeholder_resolves(self):
        _reset()
        self.assertEqual(_post({"stdout": f"please ask {NAME} today\n", "stderr": ""}), {},
                         "premise: the rules alone leave the name")
        self.on()
        out = _out(_post({"stdout": f"please ask {NAME} today\n", "stderr": ""}))
        self.assertNotIn(NAME, json.dumps(out))
        key = KEY.search(out["stdout"]).group(0)
        v = Vault(load_config())
        self.assertEqual(v.get(key, "S1"), (NAME, "ok"), "stored: the agent can write the name back")
        self.assertTrue(v._index["entries"][key]["weak"], "never hunted in other texts")

    def test_a_name_the_model_found_is_not_hunted_in_a_later_result(self):
        self.on()
        _post({"stdout": f"please ask {NAME} today\n", "stderr": ""})
        _reset_keep_store(remote_detector={})
        self.assertEqual(_post({"stdout": f"and ask {NAME} again\n", "stderr": ""}), {}, "no service now: no mask")

    def test_one_request_per_hook_call_and_each_string_gets_its_own_spans(self):
        self.on()
        out = _out(_post({"stdout": f"ask {NAME} first", "stderr": f"then {OTHER} later", "note": f"phone {PHONE}"}))
        self.assertEqual(len(self.svc.received), 1)
        self.assertNotIn(NAME, json.dumps(out))
        self.assertNotIn(OTHER, json.dumps(out))
        self.assertNotIn(PHONE, self.svc.received[0]["inputs"], "a finding of the rules goes out as filler")

    def test_a_dead_slow_or_refused_service_answers_as_without_it(self):
        _reset()
        response = {"stdout": f"ask {NAME}, call {PHONE}\n", "stderr": ""}
        baseline = _post(response)
        self.assertIn("PHONE", json.dumps(baseline), "premise: the rules mask the number")
        slow = Service("hf", answer=self.names, delay=1.0)
        self.addCleanup(slow.close)
        for name, conf in (("dead", {"url": "http://127.0.0.1:1/"}),
                           ("slow", {"url": slow.url, "timeout_ms": 100}),
                           ("not allowed", {"url": "http://10.0.0.5:9/"}),
                           ("a setting it cannot read", {"url": self.svc.url, "format": "xml"})):
            with self.subTest(name):
                _reset(remote_detector=conf)
                self.assertEqual(_post(response), baseline)
        self.assertEqual(self.svc.received, [], "the unreadable setting sent nothing")

    def test_only_a_service_on_this_computer_may_read_the_rules_findings(self):
        from maisecrets import remote_layer
        ner, _ = remote_layer.from_config({"remote_detector": {"url": self.svc.url, "mask": False}})
        self.assertFalse(ner.mask)
        ner, _ = remote_layer.from_config({"remote_detector": {"url": self.svc.url}})
        self.assertTrue(ner.mask, "the filler is the default")
        ner, _ = remote_layer.from_config({"remote_detector": {"url": "http://10.0.0.5:9/", "allow_network": True,
                                                              "mask": False}})
        self.assertTrue(ner.mask, "another host always gets the filler")
        self.on(mask=False)
        _post({"stdout": f"ask {NAME}, call {PHONE}\n", "stderr": ""})
        self.assertIn(PHONE, self.svc.received[0]["inputs"])

    def test_a_name_in_a_key_is_asked_in_the_same_request(self):
        self.on()
        out = _out(_post({"stdout": "ok", "stderr": "", "owners": {NAME: "lead"}}))
        self.assertEqual(len(self.svc.received), 1)
        self.assertNotIn(NAME, json.dumps(out))

    def test_a_stored_value_without_a_shape_goes_out_as_filler(self):
        self.on()
        stored = "plain" + "wordpass" + "2026"            # a value with no shape, stored by the person (put)
        Vault(load_config()).put(stored, "SECRET", "manual", session="S1")
        hooks._live_cache.clear()
        out = _out(_post({"stdout": f"ask {NAME}, the pass is {stored}\n", "stderr": ""}))
        sent = self.svc.received[0]["inputs"]
        self.assertNotIn(stored, sent)
        self.assertIn("_" * len(stored), sent)
        self.assertNotIn(stored, json.dumps(out), "premise: the hook masks it afterwards")

    def test_a_long_tool_result_waits_longer_and_gets_its_names(self):
        # 300 ms let a service on a laptop answer for almost no result above 2,000 characters (ner.log, #1764)
        slow = Service("hf", answer=self.names, delay=0.6)
        self.addCleanup(slow.close)
        response = {"stdout": f"please ask {NAME} today\n" + "plain words of a log line\n" * 320, "stderr": ""}
        for scales, masked in ((False, False), (True, True)):
            with self.subTest(timeout_scales=scales):
                _reset(remote_detector={"url": slow.url, "format": "hf", "timeout_ms": 300,
                                        "timeout_scales": scales})
                out = _out(_post(response))     # None: the output went out as it was, the name in it
                self.assertEqual(out is not None and NAME not in json.dumps(out), masked)

    def test_the_wait_grows_with_the_text_up_to_its_cap_and_the_rate_learns_from_this_computer(self):
        from maisecrets import remote_layer as R
        _reset()
        self.assertEqual(R.rate(), R.DEFAULT_RATE, "no answer yet: the rate of the reference host")
        self.assertEqual(R.wait_ms({"timeout_ms": 300}, 0), 300)
        self.assertAlmostEqual(R.wait_ms({"timeout_ms": 300}, 10000), 300 + R.SAFETY * R.DEFAULT_RATE * 10)
        self.assertEqual(R.wait_ms({"timeout_ms": 300}, 10 ** 6), R.MAX_TIMEOUT_MS)
        self.assertEqual(R.wait_ms({"timeout_ms": 300, "max_timeout_ms": 10 ** 6}, 10 ** 6), 5000)
        ok = type("S", (), {"available": True, "reason": "", "ms": 100.0})
        for _ in range(R.RATE_MIN):
            R.note_rate(10000, ok)                   # 10 ms per 1,000 characters on this computer
        self.assertEqual(R.rate(), 10.0)
        late = type("S", (), {"available": False, "reason": "timeout", "ms": 2000.0})
        for _ in range(R.RATE_SAMPLES):
            R.note_rate(10000, late)                 # a timeout counts with its wait: the rate grows
        self.assertEqual(R.rate(), 200.0)
        Path(HOME, "ner-rate.json").write_text(json.dumps([[500, 10 ** 400]] * 10))
        self.assertEqual(R.rate(), R.DEFAULT_RATE, "a damaged file keeps the default rate")
        Path(HOME, "ner-rate.json").unlink()

    def test_the_log_names_why_the_rules_ran_alone(self):
        from maisecrets import ner_setup
        slow = Service("hf", answer=self.names, delay=1.0)
        self.addCleanup(slow.close)
        Path(HOME, "ner.log").unlink(missing_ok=True)
        self.addCleanup(Path(HOME, "ner.log").unlink, True)
        _reset(remote_detector={"url": slow.url, "format": "hf", "timeout_ms": 100, "timeout_scales": False})
        _post({"stdout": f"ask {NAME}\n", "stderr": ""})
        # a text the service refuses as too long (413): a local service takes a long text in pieces since #105
        long_ = Service("hf", answer=self.names, status=413)
        self.addCleanup(long_.close)
        _reset(remote_detector={"url": long_.url, "format": "hf"})
        _post({"stdout": f"ask {NAME} about the long text\n", "stderr": ""})
        lines = [json.loads(x) for x in Path(HOME, "ner.log").read_text().splitlines()]
        self.assertEqual([(d["source"], d.get("why")) for d in lines], [("rules", "timeout"), ("rules", "too_long")])
        self.assertGreaterEqual(lines[0]["ms"], 90)
        self.assertIn("rules 2 (too_long 1, timeout 1)", ner_setup.counts_line())

    def test_a_tool_result_in_a_hook_waits_from_the_watchdog_start_not_the_cap(self):
        # #105, B8: min(8 s, half the watchdog) from its start, less the reserve, bounds the pieces together; each
        # piece still waits at most its own wait (review H1); outside a hook the text gets one wait
        from maisecrets import remote_layer, vault
        from test_remote_detector import Scripted
        self.addCleanup(vault.hook_deadline, None)
        vault.hook_deadline(16.0)
        start = vault.hook_window()[0]
        self.assertAlmostEqual(remote_layer.tool_deadline(0.0), start + 8.0 - remote_layer.RESERVE_MIN_S)
        self.assertAlmostEqual(remote_layer.tool_deadline(1.5), start + 8.0 - 1.5, msg="a slow scan: its own time")
        text = f"ask {NAME}\n" + "row of the log\n" * 140
        conf = {"format": "hf", "max_chars": 1000, "timeout_ms": 1000, "timeout_scales": False}
        for hook, want in ((True, "ok"), (False, "partial")):
            with self.subTest(hook=hook):
                svc = Scripted([(200, None, {}, 0.4)] * 4)     # each piece 0.4 s, within its own 1 s
                self.addCleanup(svc.close)
                _reset(remote_detector={"url": svc.url, **conf})
                vault.hook_deadline(6.0 if hook else None)     # the tests' watchdog: 3 s, less 0.5 s, from now
                if hook:
                    self.assertAlmostEqual(remote_layer.tool_deadline(0.0), vault.hook_window()[0] + 2.5)
                out = _out(_post({"stdout": text, "stderr": ""}))
                self.assertGreaterEqual(len(svc.received), 3 if hook else 2)
                self.assertEqual(remote_layer.NER_DOWN["state"], want)
                self.assertTrue(out and NAME not in json.dumps(out), "the first piece masked the name")
        vault.hook_deadline(None)
        self.assertIsNone(remote_layer.tool_deadline(0.0))
        hung = Scripted([(200, None, {}, 3.0)])
        self.addCleanup(hung.close)
        _reset(remote_detector={"url": hung.url, **conf, "timeout_ms": 300})
        vault.hook_deadline(16.0)
        t = time.monotonic()
        _post({"stdout": f"ask {NAME}\n", "stderr": ""})
        self.assertLess(time.monotonic() - t, 1.5, "a hung service holds a short result its own wait, not 7.5 s")

    def test_each_piece_waits_the_wait_of_its_own_size(self):
        # review H1: the scaled wait of a long text is the wait of one piece (max_chars), not of the whole text
        from maisecrets import remote_layer as R
        from test_remote_detector import Scripted
        text = "row of the log\n" * 330                      # about 5,000 characters, pieces of 500
        svc = Scripted([(200, [], {}, 0.35)] * 20)
        self.addCleanup(svc.close)
        _reset(remote_detector={"url": svc.url, "format": "hf", "timeout_ms": 100, "max_timeout_ms": 5000,
                                "max_chars": 500})
        conf = {"timeout_ms": 100, "max_timeout_ms": 5000}
        self.assertLess(R.wait_ms(conf, 500), 350, "premise: one piece's wait is shorter than the answer")
        self.assertGreater(R.wait_ms(conf, len(text)), 350, "premise: the whole text's wait is longer")
        _post({"stdout": text, "stderr": ""})
        self.assertEqual((R.NER_DOWN["state"], R.NER_DOWN["why"]), ("unavailable", "timeout"))

    def test_a_rate_sample_comes_only_from_a_wait_the_service_used_up(self):
        # review H1: a timeout of the hook's budget or of a text in pieces must not make the rate grow
        from maisecrets import remote_layer as R, vault
        from test_remote_detector import Scripted
        self.addCleanup(vault.hook_deadline, None)
        text = "row of the log\n" * 50                       # 750 characters: over RATE_MIN_CHARS
        slow = Scripted([(200, None, {}, 2.0)] * 3)
        self.addCleanup(slow.close)
        _reset(remote_detector={"url": slow.url, "format": "hf", "timeout_ms": 100, "max_timeout_ms": 100})
        _post({"stdout": text, "stderr": ""})
        self.assertEqual(len(R._samples()), 1, "a one-piece text that its own wait ended: a sample")
        _reset(remote_detector={"url": slow.url, "format": "hf", "timeout_ms": 300, "max_timeout_ms": 3000})
        vault.hook_deadline(1.2)                              # the budget: 0.6 s less 0.5 s, shorter than the wait
        _post({"stdout": text, "stderr": ""})
        self.assertEqual(R._samples(), [], "the budget ended it: no sample")
        vault.hook_deadline(None)
        _reset(remote_detector={"url": slow.url, "format": "hf", "timeout_ms": 100, "max_timeout_ms": 100,
                                "max_chars": 500})
        _post({"stdout": text, "stderr": ""})
        self.assertEqual(R._samples(), [], "a text in pieces that timed out: no sample")

    def test_pieces_only_where_the_text_stays_on_this_computer(self):
        # review M2: the url source and the fallback get pieces only for a loopback or Unix-socket service
        from maisecrets import remote_layer
        far = "https://ner.example.org/"
        for conf, fallback, want in (
                ({"url": self.svc.url}, False, True),
                ({"url": far, "allow_network": True}, False, False),
                ({"url": self.svc.url, "fallback": {"url": far, "allow_network": True}}, True, False),
                ({"url": far, "allow_network": True, "fallback": {"url": self.svc.url}}, True, True)):
            with self.subTest(conf=conf, fallback=fallback):
                det, why = remote_layer.from_config({"remote_detector": conf}, fallback=fallback)
                self.assertEqual((why, det.pieces), ("", want))

    def test_the_day_counts_a_text_checked_in_part_under_its_own_key(self):
        # review M3: a partial result is no full check of the source
        from maisecrets import ner_setup, ner_view
        Path(HOME, "ner.log").unlink(missing_ok=True)
        self.addCleanup(Path(HOME, "ner.log").unlink, True)
        ner_setup.log("local", "tool", 30000, 2, why="timeout", ms=8000, share=60)
        ner_setup.log("local", "tool", 100, 1, ms=50)
        c = ner_setup.today_counts()
        self.assertEqual((c.get("local"), c.get("partial"), c.get("partial_share")), (1, 1, 60))
        self.assertIn("local 1, in part 1 (60 % checked on average)", ner_setup.counts_line())
        self.assertEqual(ner_view.today_check().fact,
                         "1 of 2 texts checked by the service, 1 in part (60 % on average)")

    def test_a_long_text_whose_first_piece_failed_is_withheld_string_by_string(self):
        # #105 B9 (MR 2): `checked_to == 0` takes the path of a rest; a short one is withheld whole as before
        from test_remote_detector import Scripted
        down = Scripted([(500, {"error": "x"}, {}, 0.0)] * 4)
        self.addCleanup(down.close)
        _reset(remote_detector={"url": down.url, "format": "hf", "max_chars": 1000, "unavailable": "withhold"})

        def guarded(out: str) -> dict:
            return hooks._post_tool_guarded_rest({
                "hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                "tool_input": {"command": "cat notes.txt"}, "tool_response": {"stdout": out, "stderr": ""}})
        long_ = guarded("row of the log\n" * 100)
        out = long_["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(out), {"stdout", "stderr"}, "the Bash shape stays")
        self.assertTrue(out["stdout"].startswith("[maisecrets withheld this text from the AI"), out["stdout"])
        self.assertNotIn("row of the log", out["stdout"])
        self.assertIn("did not check this tool result", long_["hookSpecificOutput"]["additionalContext"])
        self.assertIn("withheld", json.dumps(guarded("a short row\n")))

    def test_no_test_starts_inside_a_hook_window(self):
        # review L7: tests/_isolate.py resets the window before each test
        from maisecrets import vault
        vault.hook_deadline(5.0)
        self.addCleanup(vault.hook_deadline, None)

        class Inner(unittest.TestCase):
            def test_outside(self):
                self.assertIsNone(vault.hook_window())
        result = unittest.TestResult()
        Inner("test_outside").run(result)
        self.assertTrue(result.wasSuccessful(), result.failures)

    def test_a_result_checked_in_part_names_the_share_to_the_model_and_the_person(self):
        # #105, B11: the first piece answered, the second did not in time
        from test_remote_detector import Scripted
        svc = Scripted([(200, None, {}, 0.0), (200, None, {}, 3.0)])
        self.addCleanup(svc.close)
        _reset(remote_detector={"url": svc.url, "format": "hf", "max_chars": 1000, "timeout_ms": 1000,
                                "timeout_scales": False})
        text = f"ask {NAME} first\n" + "row of the log\n" * 100

        def guarded(out: str) -> dict:          # the path that adds the notes (tool_withhold.with_unchecked_names)
            return hooks._post_tool_guarded_rest({
                "hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                "tool_input": {"command": "cat notes.txt"}, "tool_response": {"stdout": out, "stderr": ""}})
        answer = guarded(text)
        self.assertEqual(len(svc.received), 2)
        self.assertNotIn(NAME, json.dumps(answer), "the name of the checked piece is masked")
        line = answer.get("systemMessage", "")
        share = re.search(r"names (\d+) % checked by the name service", line)
        self.assertTrue(share, line)
        self.assertTrue(0 < int(share.group(1)) < 100)
        note = answer["hookSpecificOutput"]["additionalContext"]
        self.assertIn(f"checked only {share.group(1)} % of this tool result (no answer in time for the rest)", note)
        self.assertNotIn("checked", guarded("short\n").get("systemMessage", ""), "a full check: no share")

    def test_the_wait_is_capped_at_five_seconds(self):
        from maisecrets import remote_layer
        ner, _ = remote_layer.from_config({"remote_detector": {"url": self.svc.url, "timeout_ms": 3000000}})
        self.assertEqual(ner.timeout, 5.0)
        for bad in (10 ** 400, float("inf"), "300", True):
            ner, why = remote_layer.from_config({"remote_detector": {"url": self.svc.url, "timeout_ms": bad}})
            self.assertEqual((ner, why), (None, "timeout_ms is no number of milliseconds"))

    def test_off_sends_nothing_and_a_typed_prompt_is_not_sent(self):
        _reset()
        _post({"stdout": f"please ask {NAME} today\n", "stderr": ""})
        self.on()
        hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "session_id": "S1", **CLAUDE,
                           "prompt": f"please write to {NAME}"})
        self.assertEqual(self.svc.received, [])


class WeakMarkTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_model_finding_is_weak_until_a_rule_finds_the_value_too(self):
        self.assertTrue(is_weak("remote:hf", NAME, tool=True))
        v = Vault(load_config())
        (e,) = v.put_many([(NAME, "NAME", "remote:hf")], session="S1", tool=True)
        self.assertTrue(v._index["entries"][e.key]["weak"])
        v.put_many([(NAME, "NAME", "remote:presidio")], session="S1", tool=True)
        self.assertTrue(v._index["entries"][e.key]["weak"], "a second model finding is no evidence")
        v.put_many([(NAME, "NAME", "name-after-label")], session="S1", tool=True)
        self.assertFalse(v._index["entries"][e.key]["weak"], "a rule's finding is")

    def test_a_hunted_value_stays_hunted_when_the_model_finds_it(self):
        v = Vault(load_config())
        (e,) = v.put_many([(OTHER, "NAME", "name-after-label")], session="S1", tool=True)
        v.put_many([(OTHER, "NAME", "remote:hf")], session="S1", tool=True)
        self.assertFalse(v._index["entries"][e.key]["weak"])



def _guarded(tool: str, response, codex: bool = False) -> dict:
    """The answer of the PostToolUse hook with its notes (tool_withhold.with_unchecked_names)."""
    from _hygiene import CODEX
    return hooks._post_tool_guarded_rest({
        "hook_event_name": "PostToolUse", "tool_name": tool, "session_id": "S1", **(CODEX if codex else CLAUDE),
        "tool_input": {"file_path": "/work/notes.txt"} if tool == "Read" else {}, "tool_response": response})


LATE = f"late {NAME} here\n"
LONG = f"ask {NAME} first\n" + "row of the log\n" * 100 + LATE + "tail row\n" * 5


class RestWithheldTests(unittest.TestCase):
    """#105, B9 with `unavailable: withhold`: the first piece answers, the second does not in time. The checked part
    goes on masked, the rest is withheld with one line, and the result keeps its shape."""

    def setUp(self):
        from maisecrets import vault
        vault.hook_deadline(None)
        self.svc = self.service()

    def service(self):
        from test_remote_detector import Scripted
        svc = Scripted([(200, None, {}, 0.0), (200, None, {}, 3.0)])
        self.addCleanup(svc.close)
        return svc

    def on(self, withhold: bool = True) -> None:
        _reset(remote_detector={"url": self.svc.url, "format": "hf", "max_chars": 1000, "timeout_ms": 1000,
                                "timeout_scales": False, **({"unavailable": "withhold"} if withhold else {})})

    def assert_cut(self, text: str) -> None:
        """`text` is LONG cut at a line start: the masked first lines, then the line that names the rest."""
        self.assertNotIn(NAME, text)
        self.assertNotIn("late", text, "the unchecked rest never reaches the AI")
        m = re.search(r"\[maisecrets withheld lines (\d+) to (\d+) of this text from the AI: the name service did "
                      r"not check it \(no answer in time\).*Read with offset and limit", text)
        self.assertTrue(m, text)
        head = text[:m.start()]
        self.assertEqual(head.count("\n") + 1, int(m.group(1)), "the line names the first line it withheld")
        self.assertEqual(int(m.group(2)), LONG.count("\n"))
        self.assertGreater(head.count("row of the log"), 30, "the checked part goes on")

    def test_bash_keeps_its_shape_and_the_rest_is_withheld(self):
        self.on()
        answer = _guarded("Bash", {"stdout": LONG, "stderr": "", "interrupted": False})
        out = answer["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual((set(out), out["stderr"], out["interrupted"]),
                         ({"stdout", "stderr", "interrupted"}, "", False))
        self.assert_cut(out["stdout"])
        self.assertIn("maisecrets withheld the rest of this result from the AI", answer["systemMessage"])
        self.assertRegex(answer["systemMessage"], r"names \d+ % checked")
        self.assertIn("A line in the result names each withheld part",
                      answer["hookSpecificOutput"]["additionalContext"])
        self.assertEqual([d.get("kind") for d in self.svc.received], ["result", "result"], "kind goes with each piece")

    def test_without_withhold_nothing_changes(self):
        self.on(withhold=False)
        answer = _guarded("Bash", {"stdout": LONG, "stderr": ""})
        out = answer["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertIn(LATE, out, "the rest keeps the rules (MR 1)")
        self.assertNotIn("withheld", json.dumps(answer))
        self.assertIn("the rules alone masked the rest", answer["systemMessage"])

    def test_a_result_with_no_value_to_mask_is_still_cut(self):
        # post_tool answers {} when it masked nothing: a cut alone must replace the output (tool_withhold.rest_only)
        self.on()
        text = LONG.replace(f"ask {NAME} first", "ask nobody first")
        out = _guarded("Bash", {"stdout": text, "stderr": ""})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertNotIn("late", out)
        self.assertIn("[maisecrets withheld lines", out)

    def test_read_keeps_its_shape(self):
        from maisecrets.file_reads import text_result
        self.on()
        response = text_result("/work/notes.txt", LONG)
        out = _guarded("Read", response)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(out), set(response))
        self.assertEqual({k: v for k, v in out["file"].items() if k != "content"},
                         {k: v for k, v in response["file"].items() if k != "content"})
        self.assert_cut(out["file"]["content"])

    def test_an_mcp_result_of_many_leaves_keeps_each_leaf_and_key(self):
        self.on()
        rows = [{"who": f"person {i:03d}", "note": f"note {i:03d} of the list"} for i in range(60)]
        rows.append({"who": NAME, "note": "the last row"})
        answer = _guarded("mcp__notes__list", {"rows": rows, "count": 61})
        out = answer["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual((len(out["rows"]), out["count"]), (61, 61))
        self.assertTrue(all(set(r) == {"who", "note"} for r in out["rows"]), "no key is cut")
        flat = json.dumps(out)
        self.assertNotIn(NAME, flat)
        self.assertIn("person 000", flat, "the checked leaves go on")
        self.assertEqual(flat.count("from the AI: the name service did not check it"), 1, "one full line")
        self.assertIn("[maisecrets withheld this text: not checked by the name service]", flat)

    def test_codex_gets_the_cut_output_as_the_reason_of_its_block(self):
        self.on()
        answer = _guarded("Bash", LONG, codex=True)
        self.assertEqual(answer["decision"], "block")
        self.assert_cut(answer["reason"].split("\n\n", 1)[1])
        self.svc = self.service()
        self.on()
        text = LONG.replace(f"ask {NAME} first", "ask nobody first")     # no value to mask: the cut alone
        answer = _guarded("Bash", text, codex=True)
        self.assertEqual(answer["decision"], "block")
        self.assertNotIn("late", answer["reason"])
        self.assertIn("[maisecrets withheld lines", answer["reason"])

    def test_the_second_net_gets_the_same_number_of_texts(self):
        # a failed command (PostToolUseFailure) or a hook that did not run: the mod's second net
        from maisecrets import second_net
        self.on()
        texts = ["exit code 1", LONG, "after the output"]
        got = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": texts})
        self.assertEqual(len(got["texts"]), 3)
        self.assertTrue(got["changed"])
        self.assertEqual(got["texts"][0], "exit code 1", "a text the first piece checked goes on")
        self.assert_cut(got["texts"][1])
        self.assertEqual(got["texts"][2], "[maisecrets withheld this text: not checked by the name service]")
        self.assertIn("withheld part", got["note"])
        self.svc = self.service()
        self.on(withhold=False)
        got = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": texts})
        self.assertIn(LATE, got["texts"][1], "without withhold the rest keeps the rules")
        self.assertEqual(got["texts"][2], "after the output")

    def test_a_finding_or_a_placeholder_on_the_cut_moves_it_before_them(self):
        from maisecrets import remote_layer as R
        from maisecrets.detection.core import Match
        from maisecrets.detection.remote import RemoteStatus
        from maisecrets.tool_withhold import cut
        ref = "⟦" + "NAME_c1" + "⟧"
        s = "a" * 50 + "abcdefghijklmnopqrs and " + ref + " rest"       # the finding: 50 to 69, the reference: 74 to 83
        R.NER_DOWN.update(cut=0, why="timeout")
        for at, want in ((56, 50), (62, 50), (78, 74), (85, 84)):
            layer = R.Layer({}, RemoteStatus(state="partial", checked_to=at, total=len(s)), at={s: 0}, cut=True)
            found = [Match("rule", "SECRET", s[50:69], 50, 69, 1.0)]
            head, kept, line = cut(layer, s, found)
            self.assertEqual(len(head), want, at)
            self.assertEqual(kept, found if want >= 69 else [])
            self.assertIn(f"characters {want + 1} to {len(s)}", line)
        glued = "x" * 20 + ref + "y" * 10                       # no space before the reference
        layer = R.Layer({}, RemoteStatus(state="partial", checked_to=24, total=len(glued)), at={glued: 0}, cut=True)
        self.assertEqual(cut(layer, glued, [])[0], "x" * 20, "a placeholder is never split")

    def test_the_cut_moves_back_to_a_line_start_else_after_a_space(self):
        from maisecrets import remote_layer as R
        from maisecrets.detection.remote import RemoteStatus
        from maisecrets.tool_withhold import cut
        for s, at, head, part in (("line one\nline two\nline three", 13, "line one\n", "lines 2 to 3"),
                                  ("one long line of words", 10, "one long ", "characters 10 to 22"),
                                  ("x" * 40, 20, "x" * 20, "characters 21 to 40"),
                                  ("x" * 40, 0, "", "this text")):
            with self.subTest(s=s, at=at):
                R.NER_DOWN.update(cut=0, why="timeout")
                state = "partial" if at else "unavailable"
                layer = R.Layer({}, RemoteStatus(state=state, checked_to=at, total=len(s)), at={s: 0}, cut=True)
                got, _kept, line = cut(layer, s, [])
                self.assertEqual(got, head)
                self.assertIn(f"withheld {part}", line)
        layer = R.Layer({}, RemoteStatus(state="partial", checked_to=10, total=40), at={"x" * 40: 0}, cut=False)
        self.assertEqual(cut(layer, "x" * 40, []), ("x" * 40, [], ""), "no withhold: as it is")

    def test_a_prompt_keeps_the_rules_for_its_rest_and_codex_sends_none(self):
        # #105, B10: a name never blocks a prompt (C30), withhold or not; a Codex prompt never goes to the service
        from maisecrets import remote_layer as R
        self.on()
        cfg = load_config()
        names, why = R.prompt_names({**cfg, "remote_detector": {**cfg["remote_detector"], "prompt_timeout_ms": 1000}},
                                    LONG, [], lambda: (lambda s: []), typed=True)
        self.assertEqual([m.value for m in names], [NAME], "the checked piece's name only; the prompt is not cut")
        self.assertTrue(why.startswith("partial:") and why.endswith(":timeout"), why)
        self.assertEqual(self.svc.received[0].get("kind"), "prompt")
        self.assertIn("checked", R.unchecked_note("S-b10", why))
        self.svc = self.service()
        self.on()
        layer = R.prepare(load_config(), [LONG], lambda s: [], kind="prompt", deadline=time.monotonic() + 1.0)
        self.assertEqual(layer.status.state, "partial", "premise: a rest")
        self.assertFalse(layer.cut)
        n = len(self.svc.received)
        from _hygiene import CODEX
        hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "session_id": "S1", **CODEX,
                           "prompt": f"please write to {NAME}"})
        self.assertEqual(len(self.svc.received), n, "a Codex prompt goes to no name service")


class SecondNetWindowTests(unittest.TestCase):
    def test_the_second_net_gives_a_long_text_the_window_of_a_hook(self):
        # #105, MR 1 note: outside a hook all pieces shared the wait of one piece and the text ended partial
        from maisecrets import remote_layer as R, second_net, vault
        from test_remote_detector import Scripted
        vault.hook_deadline(None)
        svc = Scripted([(200, None, {}, 0.4)] * 4)          # each piece 0.4 s, its own wait 1 s
        self.addCleanup(svc.close)
        _reset(remote_detector={"url": svc.url, "format": "hf", "max_chars": 1000, "timeout_ms": 1000,
                                "timeout_scales": False})
        got = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": [LONG]})
        self.assertGreaterEqual(len(svc.received), 2)
        self.assertEqual(R.NER_DOWN["state"], "ok")
        self.assertNotIn(NAME, got["texts"][0])
        self.assertIsNone(vault.hook_window(), "the window ends with the call")

    def test_the_window_ends_well_before_the_mod_stops_waiting(self):
        from maisecrets import second_net
        mod = Path(__file__).resolve().parent.parent / "claude-mod" / "maisecrets-mod.mjs"
        result_ms = int(re.search(r"^const RESULT_MS = (\d+)$", mod.read_text(encoding="utf-8"), re.M).group(1))
        self.assertLessEqual(second_net.WINDOW_S + 4, result_ms / 1000)


if __name__ == "__main__":
    unittest.main()
