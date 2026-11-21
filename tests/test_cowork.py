"""Cowork (the Claude desktop app's Cowork tab) marks its sessions with CLAUDE_CODE_ENTRYPOINT=remote_cowork and knows
a plugin's commands by their short name only: `/maisecrets`, the entry (maisecrets/cowork.py). Measured live on
2026-11-21: a command typed in Cowork showed nothing, and Cowork shows no blocked or dropped prompt; the text form
`maisecrets: term add NAME` shows the hook's answer.

Synthetic values only.
Run: python3 -m unittest tests.test_cowork -v
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cowork, forms, hooks, prompt_commands  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
import _hygiene  # noqa: E402

SESSION = "0b6f1c2e-0000-4000-8000-0000000000c7"
COWORK = {"CLAUDE_CODE_ENTRYPOINT": cowork.ENTRYPOINT}


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


def _dispatch(*argv: str, env: dict, stdin: str = "") -> subprocess.CompletedProcess:
    full = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_ENTRYPOINT"}
    full.update(env, PYTHONUTF8="1")
    return subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), *argv], input=stdin,
                          capture_output=True, text=True, env=full, cwd=str(ROOT), timeout=120)


class FormsTests(unittest.TestCase):
    """Cowork shows no answer of the prompt hook to a slash command; it shows one for the text form."""

    def test_a_command_the_hook_answers_is_named_as_text(self):
        for slash, text in (("/maisecrets term add NAME", "maisecrets: term add NAME"),
                            ("/maisecrets term remove NAME", "maisecrets: term remove NAME"),
                            ("/maisecrets not-a-secret KEY", "maisecrets: not a secret KEY"),
                            ("/maisecrets not-a-secret undo KEY", "maisecrets: undo not a secret KEY"),
                            ("/maisecrets demo on", "maisecrets: demo on"),
                            ("/maisecrets settings ssh_consent on", "maisecrets: set ssh_consent on"),
                            ("/maisecrets settings rule_dirs add DIR", "maisecrets: set rule_dirs add DIR"),
                            ("/maisecrets settings ssh_autonomous_hosts add HOST", "maisecrets: ssh autonomous HOST"),
                            ("/maisecrets settings ssh_autonomous_hosts remove HOST", "maisecrets: ssh ask HOST"),
                            ("/maisecrets settings hints reset", "maisecrets: reset hints"),
                            ("/maisecrets forget import:ID", "maisecrets: forget import:ID"),
                            ("/maisecrets ner local", "maisecrets: ner local"),
                            ("/maisecrets report incident", "maisecrets: report incident"),
                            ("/maisecrets sref login gw", "maisecrets: sref login gw"),
                            ("/maisecrets:sref", "maisecrets: sref")):
            with self.subTest(slash):
                self.assertEqual(forms.cowork(f"→ {slash}."), f"→ {text}.")

    def test_each_text_form_is_one_the_mod_answers(self):
        # the parsers the mod's command branch reads (prompt_commands.mod_command)
        from maisecrets import demo, incidents, not_a_secret, settings, term_files, value_files
        for text in ("maisecrets: term add Wibbleton Q", "maisecrets: not a secret NAME_c1",
                     "maisecrets: undo not a secret NAME_c1", "maisecrets: demo on", "maisecrets: set ssh_consent on",
                     "maisecrets: ssh autonomous web1", "maisecrets: reset hints", "maisecrets: forget import:abc",
                     "maisecrets: ner local", "maisecrets: set rule_dirs add /tmp/rules",
                     "maisecrets: report incident"):
            with self.subTest(text):
                self.assertTrue(term_files.parse_command(text) or not_a_secret.parse(text) or demo.parse(text)
                                or settings.parse_prompt(text) or value_files.parse_removal(text)
                                or incidents.recognize(text, "claude"), text)

    def test_a_sentence_after_settings_and_a_key_is_no_change(self):
        # the session start of hooks/dispatch.py: the key shows its card, nothing changes
        line = "/maisecrets settings clean_dirs shows which, and the real folder to add."
        self.assertEqual(forms.cowork(line), line)
        for text in ("/maisecrets settings ssh_consent on.", "/maisecrets settings max_keys_per_session 300",
                     "/maisecrets settings KEY VALUE", "/maisecrets settings ttl_seconds 7d",
                     "/maisecrets settings ssh_consent default", "/maisecrets settings regions de"):
            with self.subTest(text):
                self.assertTrue(forms.cowork(text).startswith("maisecrets: set "), forms.cowork(text))

    def test_a_command_its_file_shows_keeps_the_slash(self):
        for text in ("/maisecrets status test", "/maisecrets list", "/maisecrets term", "/maisecrets settings",
                     "/maisecrets settings all", "/maisecrets forget SECRET_c1",
                     "/maisecrets ner", "/maisecrets ner all", "maisecrets: list"):
            self.assertEqual(forms.cowork(text), text)

    def test_codex_gets_its_form(self):
        self.assertEqual(forms.codex("run /maisecrets status test or /maisecrets:list; /maisecrets:secret-hygiene"),
                         "run maisecrets: status test or maisecrets: list; /maisecrets:secret-hygiene")

    def test_active_reads_the_entry_point(self):
        with mock.patch.dict(os.environ, COWORK):
            self.assertTrue(cowork.active())
            self.assertEqual(forms.for_this_client("/maisecrets demo on"), "maisecrets: demo on")
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "cli"}):
            self.assertFalse(cowork.active())
            self.assertEqual(forms.for_this_client("/maisecrets demo on"), "/maisecrets demo on")


class ModCommandTests(unittest.TestCase):
    """Cowork draws no dropped-prompt line: a typed command goes on to the command file, which shows its output."""

    def _mod(self, prompt: str) -> dict | None:
        hooks._live_cache.clear()
        return prompt_commands.mod_command({"prompt": prompt, "session_id": SESSION, "cwd": "", "origin": "composer"})

    def test_a_typed_command_is_answered_by_the_mod_outside_cowork(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "cli"}):
            self.assertIsNotNone(self._mod("/maisecrets:list"))

    def test_in_cowork_the_mod_leaves_it_to_the_command_file(self):
        with mock.patch.dict(os.environ, COWORK):
            self.assertIsNone(self._mod("/maisecrets:list"))

    def test_a_slash_sref_in_cowork_runs_nothing(self):
        # the engine sends a slash line as typed (#44): an answer of the mod would never reach the model, so nothing
        # runs for it, and the hints in Cowork name the text form
        with mock.patch.dict(os.environ, COWORK), mock.patch("subprocess.run", side_effect=AssertionError("ran")):
            for prompt in ("/maisecrets:sref", "/maisecrets:sref status", "/maisecrets:sref login gw"):
                with self.subTest(prompt):
                    self.assertIsNone(self._mod(prompt))


class HookAnswerTests(unittest.TestCase):
    """Cowork does not show a dropped prompt: the answer of a command the hook answers goes to the model to show."""

    def setUp(self):
        import test_mod_commands as tm
        self.tm = tm
        tm._reset()
        self.addCleanup(tm._reset)
        env = mock.patch.dict(os.environ, COWORK)
        env.start()
        self.addCleanup(env.stop)
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **k: None)

    def test_a_term_add_becomes_a_request_to_show_its_answer_without_the_term(self):
        out = self.tm._mod(f"maisecrets: term add {self.tm.NAME}")
        self.assertNotIn("drop", out)
        self.assertIn("on your list now", out["text"])
        self.assertTrue(out["text"].startswith(cowork._SHOW))
        self.assertIn("/maisecrets term shows them", out["text"])
        self.assertNotIn("/maisecrets:", out["text"])
        self.assertNotIn(self.tm.NAME, out["text"], "the model gets the answer, never the term")
        masked = self.tm._mod(f"write to {self.tm.NAME} today")
        self.assertNotIn(self.tm.NAME, masked.get("text", self.tm.NAME), "the term was added")

    def test_the_incident_report_never_reaches_the_model_and_a_fixed_line_shows(self):
        # docs/DIAGNOSTICS.md: the model sees neither the typed command nor the report
        from maisecrets import incidents
        record = {"version": 1, "groups": {"store.lock/lock": {
            "code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit",
            "tool_class": "-", "client": "claude", "days": [time.strftime("%Y-%m-%d")], "count": 3,
            "plugin_version": "0.6.9"}}}
        incidents.record_path().write_text(json.dumps(record), encoding="utf-8")
        self.addCleanup(incidents.record_path().unlink, missing_ok=True)
        for prompt in ("maisecrets: report incident", "/maisecrets report incident", "/maisecrets:report incident",
                       "maisecrets: report incident store.lock/lock"):
            with self.subTest(prompt):
                out = self.tm._mod(prompt)
                self.assertIn("is not shown here", out["text"])
                self.assertIn("recorded 1 incident group(s)", out["text"])
                self.assertNotIn("store.lock", out["text"])
                self.assertNotIn("lock/", out["text"])

    def test_a_value_in_an_answer_reaches_the_model_masked(self):
        token = "ghp_" + "R7kQ2mZx9VbT4nLp8WcY3sHd6FjA1uEo5GiN"
        out = cowork.show_answer({"session_id": self.tm.SESSION, "cwd": "", "origin": "composer"},
                                 f"maisecrets: done with {token}")
        self.assertNotIn(token, out["text"])
        self.assertIn("done with", out["text"])

    def test_the_request_reads_as_no_command_to_the_prompt_hook(self):
        out = self.tm._mod(f"maisecrets: term add {self.tm.NAME}")
        request = {"prompt": out["text"], "session_id": self.tm.SESSION, "cwd": "", "origin": "composer"}
        self.assertIsNone(prompt_commands.mod_command(request))
        self.assertIs(prompt_commands.with_canonical({**request, "prompt_id": "t"})["prompt"], out["text"])
        from maisecrets import demo, not_a_secret, settings, term_files, value_files
        for parse in (term_files.parse_command, settings.parse_prompt, not_a_secret.parse, demo.parse,
                      value_files.parse_removal):
            self.assertFalse(parse(out["text"]), parse)
        from maisecrets.vault import HOME
        store = ("index.json", "vault.json", "terms.txt", "allowed.json", "allow.txt", "demo.json")

        def snapshot():
            return {f: Path(HOME, f).read_bytes() for f in store if Path(HOME, f).is_file()}
        before = snapshot()
        hooks._live_cache.clear()
        answer = hooks.user_prompt({"prompt": out["text"], "session_id": self.tm.SESSION, "cwd": "",
                                    "prompt_id": "t", "transcript_path": ""})
        self.assertNotEqual(answer.get("decision"), "block", answer)
        self.assertEqual(snapshot(), before, "the request stores and changes nothing")

    def test_a_placeholder_in_the_answer_is_no_placeholder_the_person_typed(self):
        ref = OPEN + "SECRET" + "_c1" + CLOSE
        out = cowork.show_answer({"session_id": self.tm.SESSION, "cwd": "", "origin": "composer"},
                                 f"maisecrets: deleted {ref}")
        self.assertEqual(hooks.find_refs(out["text"]), [])
        self.assertIn("[SECRET" + "_c1]", out["text"])

    def test_an_answer_that_could_not_be_checked_is_not_sent(self):
        token = "ghp_" + "R7kQ2mZx9VbT4nLp8WcY3sHd6FjA1uEo5GiN"
        for payload in ({"session_id": "no valid id", "cwd": "", "origin": "composer"},
                        {"cwd": "", "origin": "composer"}):
            out = cowork.show_answer(payload, f"maisecrets: done with {token}")
            self.assertEqual(out["text"], cowork.UNCHECKED)


class OutputTests(unittest.TestCase):
    def test_a_command_output_names_the_text_form_in_cowork(self):
        r = _dispatch("terms", env=COWORK)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("maisecrets: term add", r.stdout)
        self.assertNotIn("/maisecrets term add", r.stdout)
        self.assertNotIn("/maisecrets:", r.stdout + r.stderr)

    def test_the_output_keeps_the_slash_form_elsewhere(self):
        r = _dispatch("terms", env={})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/maisecrets term add", r.stdout)
        r = _dispatch("status", env={})
        self.assertIn("/maisecrets status all", r.stdout)

    def test_a_tool_hook_keeps_the_tool_output_as_it_is(self):
        # a file that names a command (a README, a command file) reaches the model unchanged, so an edit of it matches
        token = "ghp_" + "R7kQ2mZx9VbT4nLp8WcY3sHd6FjA1uEo5GiN"     # a token shape the hook masks, so it answers
        text = f"run /maisecrets:status test and /maisecrets demo on to check it\ntoken={token}"
        payload = {"session_id": SESSION, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                   "tool_input": {"command": "cat README.md"}, "tool_response": {"stdout": text, "stderr": ""},
                   "cwd": str(ROOT)}
        r = _dispatch("post-tool", env=COWORK, stdin=json.dumps(payload))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(token, r.stdout)
        self.assertIn("run /maisecrets:status test and /maisecrets demo on", r.stdout)

    def _isolated(self, env: dict) -> dict:
        import tempfile
        cfg = tempfile.mkdtemp(prefix="ms-cowork-cfg-")
        return {**env, "CLAUDE_CONFIG_DIR": cfg, "CODEX_HOME": cfg}

    def test_list_names_no_terminal_in_cowork(self):
        r = _dispatch("list", env=COWORK)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("In Cowork each new task starts with an empty store.", r.stdout)
        self.assertNotIn("run in a terminal", r.stdout)
        self.assertIn("run in a terminal", _dispatch("list", env={}).stdout)

    def test_sref_says_in_cowork_that_it_is_not_tested_there(self):
        r = _dispatch("sref", env=self._isolated(COWORK))
        self.assertIn("not tested in Cowork", r.stdout)
        self.assertNotIn("in Claude Code (after a result", r.stdout)
        self.assertIn("use your gateway once in Claude Code", _dispatch("sref", env=self._isolated({})).stdout)

    def test_the_lock_setting_says_in_cowork_that_no_lock_is_drawn(self):
        r = _dispatch("settings", env=COWORK)
        self.assertIn("Values with a lock (Cowork draws no lock yet)", r.stdout)
        self.assertNotIn("Cowork draws no lock", _dispatch("settings", env={}).stdout)

    def test_a_typed_sref_in_cowork_is_run_by_maisecrets_and_a_login_gets_its_line(self):
        with mock.patch.dict(os.environ, self._isolated(COWORK)):
            hooks._live_cache.clear()
            login = prompt_commands.mod_command({"prompt": "maisecrets: sref login gw", "session_id": SESSION,
                                                 "cwd": "", "origin": "composer"})
            status = prompt_commands.mod_command({"prompt": "maisecrets: sref", "session_id": SESSION,
                                                  "cwd": "", "origin": "composer"})
        self.assertIn("a gateway login from Cowork is not tested yet", login["text"])
        self.assertTrue(login["text"].startswith(cowork._SHOW))
        self.assertIn("not tested in Cowork", status["text"])

    def test_a_sref_that_runs_too_long_in_cowork_is_ended_and_says_so(self):
        import re
        seen = {}

        def slow(argv, **kw):
            seen["timeout"] = kw.get("timeout")
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        with mock.patch.dict(os.environ, self._isolated(COWORK)), mock.patch("subprocess.run", slow):
            hooks._live_cache.clear()
            out = prompt_commands.mod_command({"prompt": "maisecrets: sref", "session_id": SESSION, "cwd": "",
                                               "origin": "composer"})
        self.assertIn("the gateway did not answer in time", out["text"])
        self.assertTrue(out["text"].startswith(cowork._SHOW))
        mod = (ROOT / "claude-mod" / "maisecrets-mod.mjs").read_text(encoding="utf-8")
        budget = int(re.search(r"const BUDGET_MS = (\d+)", mod).group(1)) / 1000
        # the start of Python and the mask of the answer need the rest of the mod's budget
        self.assertLessEqual(seen["timeout"] + 2, budget)

    def test_the_sref_discovery_in_cowork_ends_before_the_run_is_ended(self):
        from contextlib import redirect_stdout
        from maisecrets import cli, sref_client, vault_refs
        left = []

        def discover(cfg, url, end=None, **kw):
            left.append(end - time.monotonic())
            return None, "timeout"
        with mock.patch.dict(os.environ, self._isolated(COWORK)), \
                mock.patch.object(vault_refs, "user_servers", lambda: {"gw": "https://gw.example/mcp"}), \
                mock.patch.object(vault_refs, "connectors", lambda **kw: {}), \
                mock.patch.object(sref_client, "discover_typed", discover), redirect_stdout(io.StringIO()):
            cli.cmd_sref([])
        self.assertEqual(len(left), 1)
        self.assertLessEqual(left[0], cli.SREF_COWORK_DISCOVERY_S)
        self.assertLess(cli.SREF_COWORK_DISCOVERY_S + 1, prompt_commands.COWORK_SREF_S)

    def test_a_refusal_the_ai_relays_names_the_text_form_in_cowork(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, COWORK), mock.patch.object(sys, "stdout", out):
            hooks._out({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                               "permissionDecisionReason": "type /maisecrets demo on yourself"}})
        self.assertIn("type maisecrets: demo on yourself", out.getvalue())


if __name__ == "__main__":
    unittest.main()
