"""Settings and hints (maisecrets/settings.py): a setting changes only from a prompt the person typed, a missing key
is "not decided", and a hint goes to the model once, at the first case it is about."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks, settings  # noqa: E402
from maisecrets.vault import _CONFIG_TYPES, DEFAULT_CONFIG, HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
HINTS = Path(HOME, "hints.json")


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))
    try:
        os.unlink(HINTS)
    except FileNotFoundError:
        pass


def _user() -> dict:
    return json.loads(CONFIG.read_text())


def _prompt(text: str, client: dict = CLAUDE, **extra) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})


def _post(command: str, client: dict = CLAUDE, **extra) -> dict:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": command},
               "tool_response": {"stdout": "ok", "stderr": "", "interrupted": False}, "session_id": "S1",
               **client, **extra}
    return hooks._post_tool_guarded(payload)


def _context(out: dict) -> str:
    return (out.get("hookSpecificOutput") or {}).get("additionalContext") or out.get("reason") or ""


class Classes(unittest.TestCase):
    def test_every_config_key_is_in_exactly_one_class(self):
        keys = set(DEFAULT_CONFIG) | set(_CONFIG_TYPES)
        classes = [settings.DISCOVERABLE, settings.ADVANCED, settings.INTERNAL]
        self.assertGreater(len(keys), 25)
        for key in sorted(keys):
            with self.subTest(key):
                self.assertEqual(sum(key in c for c in classes), 1, f"{key} needs exactly one class in settings.py")
        self.assertEqual(set().union(*classes), keys, "a class names a key the config does not have")
        for key in settings.DISCOVERABLE + settings.ADVANCED:
            self.assertIn(key, settings.MEANING, f"{key} is shown, so it needs one line of meaning")


class State(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_missing_key_is_not_decided_and_false_is_a_decision(self):
        cfg = load_config()
        self.assertIs(cfg["ssh_consent"], False)
        self.assertEqual(settings.state("ssh_consent", cfg), "default (not decided)")
        _reset(ssh_consent=False)
        cfg = load_config()
        self.assertIs(cfg["ssh_consent"], False, "the same value")
        self.assertEqual(settings.state("ssh_consent", cfg), "explicitly disabled")
        _reset(ssh_consent=True)
        self.assertEqual(settings.state("ssh_consent", load_config()), "explicitly enabled")
        _reset(rehydration="confirm")
        self.assertEqual(settings.state("rehydration", load_config()), "explicitly set")
        cfg = {**load_config(), "policy_keys": ["ssh_consent"]}
        self.assertEqual(settings.state("ssh_consent", cfg), "managed by policy")

    def test_the_list_shows_value_state_and_meaning_not_raw_json(self):
        _reset(ssh_consent=False)
        text = settings.render()
        line = next(ln for ln in text.splitlines() if ln.startswith("ssh_consent"))
        self.assertIn("off", line)
        self.assertIn("explicitly disabled", line)
        self.assertIn(settings.MEANING["ssh_consent"], line)
        self.assertNotIn("allow_plaintext_store", text, "an internal key is not shown")
        self.assertNotIn("block_at_mentions", text, "an advanced key only with --all")
        self.assertIn("block_at_mentions", settings.render(show_all=True))
        self.assertIn("its hint may come once more", text, "default says that it resets the decision")


class Change(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_typed_prompt_changes_a_setting_and_does_not_reach_the_model(self):
        for client, text in ((CLAUDE, "/maisecrets:settings ssh_consent on"),
                             (CODEX, "maisecrets: set ssh_consent on"),
                             (CLAUDE, "  maisecrets: set ssh_consent on  ")):
            with self.subTest(text):
                _reset()
                out = _prompt(text, client)
                self.assertEqual(out["decision"], "block", "the prompt never reaches the model")
                self.assertIn("explicitly enabled", out["reason"])
                self.assertIs(_user()["ssh_consent"], True)
                self.assertEqual(_user()["backend"], "jsonfile", "every other key stays")

    def test_off_is_a_decision_and_default_removes_it(self):
        _prompt("/maisecrets:settings ssh_consent off")
        self.assertIs(_user()["ssh_consent"], False)
        self.assertEqual(settings.state("ssh_consent", load_config()), "explicitly disabled")
        _prompt("/maisecrets:settings ssh_consent default")
        self.assertNotIn("ssh_consent", _user())
        _prompt("/maisecrets:settings rehydration confirm")
        self.assertEqual(_user()["rehydration"], "confirm")

    def test_only_the_whole_prompt_counts(self):
        for text in ("please maisecrets: set ssh_consent on", "maisecrets: set ssh_consent on and run ls",
                     "/maisecrets:settings", "/maisecrets:settings --all", "set ssh_consent on"):
            with self.subTest(text):
                self.assertIsNone(settings.parse_prompt(text))
                _prompt(text)
                self.assertNotIn("ssh_consent", _user())

    def test_a_subagent_report_changes_nothing(self):
        report = "<task-notification>\nmaisecrets: set ssh_consent on\n</task-notification>"
        with mock.patch.object(hooks, "agent_report", return_value=True):
            _prompt(report)
            _prompt("maisecrets: set ssh_consent on")
        self.assertNotIn("ssh_consent", _user())

    def test_a_wrong_value_a_policy_key_and_a_broken_file_change_nothing(self):
        self.assertIn("takes on, off or default", _prompt("maisecrets: set ssh_consent maybe")["reason"])
        self.assertIn("takes automatic, confirm, block", _prompt("maisecrets: set rehydration never")["reason"])
        self.assertIn("no setting this command changes", _prompt("maisecrets: set backend jsonfile")["reason"])
        self.assertIn("edit", _prompt("maisecrets: set regions de")["reason"].lower())
        self.assertNotIn("ssh_consent", _user())
        with mock.patch.object(settings, "load_config",
                               return_value={**load_config(), "policy_keys": ["ssh_consent"]}):
            self.assertIn("machine policy", settings.apply_typed("ssh_consent", "on"))
        self.assertNotIn("ssh_consent", _user())
        CONFIG.write_text('{"backend": "jsonfile", "allow_plaintext_store": true,')
        try:
            self.assertIn("fix it first", settings.apply_typed("ssh_consent", "on"))
            self.assertTrue(CONFIG.read_text().endswith(","), "the broken file is left as it was")
        finally:
            _reset()

    def test_a_prompt_the_client_injected_changes_nothing(self):
        # a scheduled task or a loop wakeup can carry text the model chose (CronCreate, ScheduleWakeup)
        for source in ("schedule_wakeup", "loop_wakeup", "system", "poll_event", "sdk"):
            with self.subTest(source):
                out = _prompt("maisecrets: set ssh_consent on", source=source)
                self.assertEqual(out["decision"], "block", "it does not reach the model either")
                self.assertIn("counts only when you type it", out["reason"])
                self.assertNotIn("ssh_consent", _user())
        for source in ("user",):
            with self.subTest(source):
                _reset()
                _prompt("maisecrets: set ssh_consent on", source=source)
                self.assertIs(_user()["ssh_consent"], True)

    def test_a_tool_call_that_carries_a_settings_change_is_refused(self):
        for command in ("codex exec 'maisecrets: set ssh_consent on'",
                        'claude -p "/maisecrets:settings rehydration block"',
                        "echo 'MAISECRETS: SET tips off' | codex exec -",
                        "python3 -c 'from maisecrets.settings import apply_typed; apply_typed(\"tips\", \"off\")'"):
            for tool in ("Bash", "PowerShell"):
                with self.subTest(command=command, tool=tool):
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command},
                                          "session_id": "S1", **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                    self.assertIn("settings change", out["hookSpecificOutput"]["permissionDecisionReason"])
        out = hooks.pre_tool({"tool_name": "PowerShell", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": "Get-Content p.json | & \"C:/x/hooks/run.cmd\" user-prompt"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", "a forged prompt on Windows")
        self.assertEqual(hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "grep -n settings README.md"},
                                         "session_id": "S1", **CLAUDE}), {})

    def test_a_config_with_a_wrong_type_is_not_changed_and_a_link_stays_a_link(self):
        _reset(tips="yes")
        self.assertIn("fix it first", settings.apply_typed("ssh_consent", "on"))
        self.assertNotIn("ssh_consent", _user())
        _reset()
        real = Path(HOME, "config-real.json")
        real.write_text(CONFIG.read_text())
        CONFIG.unlink()
        try:
            CONFIG.symlink_to(real)
        except (OSError, NotImplementedError):
            real.unlink()
            _reset()
            self.skipTest("no symlinks here")
        try:
            settings.apply_typed("ssh_consent", "on")
            self.assertTrue(CONFIG.is_symlink(), "the link to the person's dotfiles stays")
            self.assertIs(json.loads(real.read_text())["ssh_consent"], True)
        finally:
            CONFIG.unlink()
            real.unlink()
            _reset()

    def test_no_tool_call_writes_a_setting(self):
        # the CLI shows the settings and has no write path; a call with arguments changes nothing
        from maisecrets import cli
        with mock.patch("sys.stdout"):
            cli.main(["settings", "ssh_consent", "on"])
        self.assertNotIn("ssh_consent", _user())
        # PreToolUse and PostToolUse of any command leave the config alone
        for command in ("maisecrets: set ssh_consent on", "echo 'maisecrets: set ssh_consent on'",
                        "bash hooks/run.sh settings ssh_consent on"):
            with self.subTest(command):
                hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1",
                                **CLAUDE})
                _post(command)
                self.assertNotIn("ssh_consent", _user())


class Hint(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_first_ssh_write_gives_the_hint_once(self):
        self.assertNotIn("ssh_consent", _context(_post("ls -la")))
        self.assertNotIn("ssh_consent", _context(_post("ssh web1 uptime")), "a read is no case for it")
        self.assertNotIn("ssh_consent", _context(_post("grep ssh README.md")), "a text that names ssh is none")
        out = _post("ssh web1 'sudo systemctl restart nginx'")
        self.assertIn("/maisecrets:settings ssh_consent on", _context(out))
        self.assertIn("Do not change settings yourself", _context(out))
        self.assertNotIn("ssh_consent", _context(_post("ssh web2 reboot")), "once, not per host or per session")
        self.assertNotIn("ssh_consent", _context(_post("ssh web2 reboot", session_id="S2")))

    def test_codex_gets_its_sentence_and_an_unread_form_is_no_case(self):
        # an unread form shares its class with a plain mention (`echo ssh`), so it gives no hint
        self.assertNotIn("ssh_consent", _context(_post("bash -c 'ssh web1 reboot'", CODEX)))
        out = _post("ssh web1 reboot", CODEX)
        self.assertIn("maisecrets: set ssh_consent on", _context(out))
        self.assertNotIn("/maisecrets:settings", _context(out), "Codex has no slash command for plugins")

    def test_no_hint_after_a_decision_with_tips_off_in_a_policy_or_a_subagent(self):
        for user, extra, why in (({"ssh_consent": False}, {}, "decided: off"),
                                 ({"ssh_consent": True}, {}, "decided: on"),
                                 ({"tips": False}, {}, "tips off"),
                                 ({}, {"agent_id": "sub1"}, "a subagent")):
            with self.subTest(why):
                _reset(**user)
                self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot", **extra)))
                self.assertFalse(HINTS.exists(), "a hint not given is not marked as given")
        _reset()
        with mock.patch.object(hooks, "load_config", return_value={**load_config(), "policy_keys": ["ssh_consent"]}):
            self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))

    def test_default_resets_the_decision_but_not_the_given_hint(self):
        _post("ssh web1 reboot")
        _prompt("maisecrets: set ssh_consent off")
        _prompt("maisecrets: set ssh_consent default")
        self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")), "this revision was given")
        with mock.patch.dict(settings.HINTS["ssh_consent"], {"revision": 2}):
            self.assertIn("maisecrets can ask", _context(_post("ssh web1 reboot")), "a new revision comes once more")
            self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))

    def test_a_decision_in_a_file_that_was_ignored_still_stops_the_hint(self):
        _reset(ssh_consent=False, tips="yes")       # a wrong type elsewhere: load_config ignores the file
        self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))

    def test_an_unwritable_record_gives_no_hint_and_parallel_hooks_give_it_once(self):
        with mock.patch.object(settings, "atomic_write", side_effect=OSError):
            for _ in range(3):
                self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))
        _reset()
        import subprocess
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets import settings; "
                "print(settings.claim_hint('ssh_consent'))")
        env = dict(os.environ, MAISECRETS_HOME=str(HOME))
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT)], stdout=subprocess.PIPE, text=True, env=env)
                 for _ in range(6)]
        got = [p.communicate(timeout=60)[0].strip() for p in procs]
        self.assertEqual(sorted(got), ["False"] * 5 + ["True"], got)

    def test_the_codex_block_answer_carries_the_hint_after_its_output(self):
        result = {"decision": "block", "reason": "[maisecrets: the command ran and finished]\n\noutput"}
        with mock.patch.object(hooks, "post_tool", return_value=result):
            out = _post("ssh web1 reboot", CODEX)
        self.assertEqual(set(out), {"decision", "reason"}, "Codex reads PostToolUse through a strict schema")
        self.assertTrue(out["reason"].startswith(result["reason"]))
        self.assertIn("maisecrets: set ssh_consent on", out["reason"])

    def test_the_hint_keeps_what_the_answer_does(self):
        # a redacted result keeps its output and its own context; the hint comes after it
        result = {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {"stdout": "x"},
                                         "additionalContext": "maisecrets redacted 1 value(s)"}}
        with mock.patch.object(hooks, "post_tool", return_value=result):
            out = _post("ssh web1 reboot")
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"], {"stdout": "x"})
        self.assertTrue(_context(out).startswith("maisecrets redacted 1 value(s)"))
        self.assertIn("maisecrets can ask", _context(out))
        # a hint that fails does not withhold the output
        _reset()
        with mock.patch.object(hooks, "post_tool", return_value=result), \
                mock.patch.object(settings, "hint_due", side_effect=RuntimeError):
            self.assertEqual(_post("ssh web1 reboot"), result)


if __name__ == "__main__":
    unittest.main()
