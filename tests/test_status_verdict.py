"""The verdict on top of /maisecrets:status (maisecrets/status_verdict.py): each line ok, warn or FAIL, from temp
fakes of hooks.log, the marketplace copies of Claude Code and Codex, the store and the incident record.
Never the real paths.

Run: python3 -m unittest tests.test_status_verdict -v
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, incidents, status_verdict as sv  # noqa: E402

HOME = Path(os.environ["MAISECRETS_HOME"])
SESSION = "abcdef12-3456-7890"


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))


def plugin(folder: Path, version: str, codex: bool = False) -> Path:
    d = folder / (".codex-plugin" if codex else ".claude-plugin")
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.json").write_text(json.dumps({"name": "maisecrets", "version": version}))
    return folder


def marketplace(checkout: Path, version: str) -> None:
    plugin(checkout, version)
    plugin(checkout, version, codex=True)
    (checkout / ".claude-plugin" / "marketplace.json").write_text(json.dumps(
        {"name": "maisecrets", "plugins": [{"name": "maisecrets", "source": "./", "version": "0.0.1"}]}))


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.claude = self.tmp / "claude"
        self.codex = self.tmp / "codex"


class HooksLineTests(_Tmp):
    def log(self, rows) -> Path:
        p = self.tmp / "hooks.log"
        p.write_text("".join(f"{stamp(t)}\t{ev}\tclaude\t{sess}\tBash\tpass\t5ms\tok\n" for t, ev, sess in rows))
        return p

    def test_ok_when_the_tool_call_hook_of_this_session_just_ran(self):
        now = time.time()
        log = self.log([(now - 180, "user-prompt", SESSION), (now - 2, "pre-tool", SESSION)])
        state, text = sv.hooks_verdict(log, SESSION, now)
        self.assertEqual(state, "ok")
        self.assertIn("the prompt hook 3 min ago", text)
        self.assertIn("the tool-result hook not yet", text)

    def test_fail_when_no_hook_of_this_session_ran(self):
        now = time.time()
        log = self.log([(now - 2, "pre-tool", "otherses")])
        state, text = sv.hooks_verdict(log, SESSION, now)
        self.assertEqual(state, "FAIL")
        self.assertIn("/reload-plugins", text)

    def test_warn_when_this_command_has_no_tool_call_hook(self):
        now = time.time()
        log = self.log([(now - 900, "user-prompt", SESSION), (now - 900, "pre-tool", SESSION)])
        state, text = sv.hooks_verdict(log, SESSION, now)
        self.assertEqual(state, "warn")
        self.assertIn("Next:", text)

    def test_fail_when_only_the_tool_call_hook_ran(self):
        # the session's prompts (/maisecrets:status itself, in Claude Code) fired UserPromptSubmit: no row is a failure
        now = time.time()
        state, text = sv.hooks_verdict(self.log([(now - 5, "pre-tool", SESSION)]), SESSION, now)
        self.assertEqual(state, "FAIL")
        self.assertIn("the prompt hook did not run", text)

    def test_two_sessions_with_the_same_first_characters_are_told_apart(self):
        # Codex thread ids (UUIDv7) share their first characters for about a minute
        now = time.time()
        other = SESSION[:8] + "-other-thread"
        log = self.log([(now - 5, "user-prompt", other), (now - 2, "pre-tool", other)])
        self.assertEqual(sv.hooks_verdict(log, SESSION, now)[0], "FAIL")

    def test_the_session_whose_tool_call_hook_just_ran_is_this_one(self):
        # Claude Code started from a Codex shell inherits CODEX_THREAD_ID; the hooks ran under the Claude session
        now = time.time()
        log = self.log([(now - 60, "user-prompt", SESSION), (now - 2, "pre-tool", SESSION),
                        (now - 3000, "user-prompt", "outer-codex-thread"),
                        (now - 3000, "pre-tool", "outer-codex-thread")])
        self.assertEqual(sv.hooks_verdict(log, ["outer-codex-thread", SESSION], now)[0], "ok")
        self.assertEqual(sv.hooks_verdict(log, [SESSION, "outer-codex-thread"], now)[0], "ok")

    def test_warn_outside_a_session(self):
        now = time.time()
        state, text = sv.hooks_verdict(self.log([(now - 5, "pre-tool", "x")]), None, now)
        self.assertEqual(state, "warn")
        self.assertIn("Next:", text)


class VersionLineTests(_Tmp):
    def claude_install(self, installed: str, newest: str | None) -> Path:
        root = plugin(self.claude / "plugins" / "cache" / "maisecrets" / "maisecrets" / installed, installed)
        if newest:
            checkout = self.claude / "plugins" / "marketplaces" / "maisecrets"
            marketplace(checkout, newest)
            (self.claude / "plugins" / "known_marketplaces.json").write_text(json.dumps({"maisecrets": {
                "installLocation": str(checkout), "lastUpdated": "2026-11-15T10:00:00.000Z"}}))
        return root

    def codex_install(self, installed: str, newest: str | None) -> Path:
        root = plugin(self.codex / "plugins" / "cache" / "maisecrets" / "maisecrets" / installed, installed,
                      codex=True)
        if newest:
            marketplace(self.codex / ".tmp" / "marketplaces" / "maisecrets", newest)
        return root

    def verdict(self, root: Path) -> tuple[str, str]:
        return sv.version_verdict(sv.newest(root, self.claude, self.codex))

    def test_claude_code_warns_with_the_update_command_when_the_copy_is_newer(self):
        state, text = self.verdict(self.claude_install("0.9.10", "0.9.11"))
        self.assertEqual(state, "warn")
        self.assertIn("0.9.11", text)
        self.assertIn("claude plugin update maisecrets@maisecrets", text)

    def test_ok_when_the_copy_holds_the_same_version(self):
        state, text = self.verdict(self.claude_install("0.9.11", "0.9.11"))
        self.assertEqual(state, "ok")
        self.assertIn("2026-11-15 10:00", text)

    def test_newest_unknown_without_a_copy_is_no_ok(self):
        state, text = self.verdict(self.claude_install("0.9.11", None))
        self.assertEqual(state, "warn")
        self.assertIn("newest unknown", text)

    def test_a_checkout_is_newest_unknown(self):
        state, text = self.verdict(plugin(self.tmp / "src", "0.9.11"))
        self.assertEqual(state, "warn")
        self.assertIn("newest unknown", text)

    def test_an_unreadable_or_pre_release_installed_version_is_no_ok(self):
        for inst in ("?", "0.9.0-rc1"):
            info = {"installed": inst, "newest": "0.9.1", "kind": "claude", "market": "m", "fetched": None,
                    "where": "Claude Code"}
            self.assertEqual(sv.version_verdict(info)[0], "warn", inst)

    def test_codex_warns_with_its_own_command(self):
        state, text = self.verdict(self.codex_install("0.9.10", "0.9.12"))
        self.assertEqual(state, "warn")
        self.assertIn("codex plugin add maisecrets@maisecrets", text)

    def test_a_marketplace_entry_that_points_elsewhere_gives_no_version(self):
        root = self.codex_install("0.9.10", "0.9.12")
        mkt = self.codex / ".tmp" / "marketplaces" / "maisecrets" / ".claude-plugin" / "marketplace.json"
        mkt.write_text(json.dumps({"plugins": [{"name": "maisecrets", "source": {"source": "url", "url": "x"}}]}))
        self.assertIn("newest unknown", self.verdict(root)[1])

    def test_a_source_outside_the_checkout_is_not_read(self):
        root = self.claude_install("0.9.10", "0.9.12")
        plugin(self.tmp / "elsewhere", "9.9.9")
        mkt = self.claude / "plugins" / "marketplaces" / "maisecrets" / ".claude-plugin" / "marketplace.json"
        mkt.write_text(json.dumps({"plugins": [{"name": "maisecrets", "source": "../../../../elsewhere"}]}))
        self.assertIn("newest unknown", self.verdict(root)[1])

    def test_the_session_start_note_names_the_newer_version_only(self):
        self.assertIn("0.9.11", sv.newer_version_note(self.claude_install("0.9.10", "0.9.11"), self.claude,
                                                      self.codex))
        shutil.rmtree(self.claude)
        self.assertIsNone(sv.newer_version_note(self.claude_install("0.9.11", "0.9.11"), self.claude, self.codex))


class CodexLineTests(_Tmp):
    def test_not_applicable_without_a_codex_install(self):
        self.assertEqual(sv.codex_verdict(self.tmp / "src", self.codex)[0], "n/a")

    def test_fail_when_the_hooks_are_not_trusted(self):
        root = self.codex / "plugins" / "cache" / "maisecrets" / "maisecrets" / "0.9.12"
        shutil.copytree(ROOT / "hooks", root / "hooks")
        plugin(root, "0.9.12", codex=True)
        (self.codex / "config.toml").write_text('[plugins."maisecrets@maisecrets"]\nenabled = true\n')
        lines = ["WARNING: maisecrets does not protect Codex now: codex hooks: 3 of 8 not trusted: open /hooks"]
        with mock.patch("maisecrets.codex_trust.status_lines", return_value=lines):
            state, text = sv.codex_verdict(self.tmp / "src", self.codex)
        self.assertEqual(state, "FAIL")
        self.assertIn("Next: open /hooks", text)

    def test_ok_when_trusted(self):
        root = self.codex / "plugins" / "cache" / "maisecrets" / "maisecrets" / "0.9.12"
        (root / "hooks").mkdir(parents=True)
        (root / "hooks" / "hooks.json").write_text("{}")
        with mock.patch("maisecrets.codex_trust.status_lines", return_value=["codex hooks: trusted (8 of 8)"]):
            self.assertEqual(sv.codex_verdict(root, self.codex)[0], "ok")


class StoreLineTests(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def test_the_test_store_answers_and_says_test_mode(self):
        state, text = sv.store_verdict()
        self.assertEqual(state, "warn")
        self.assertIn("answered a read", text)

    def test_ok_for_a_real_store_that_answers(self):
        with mock.patch("maisecrets.vault.JsonFileBackend.test_mode", False):
            self.assertEqual(sv.store_verdict()[0], "ok")

    def test_fail_when_the_store_does_not_answer(self):
        with mock.patch("maisecrets.vault.JsonFileBackend.get", side_effect=OSError("locked")):
            state, text = sv.store_verdict()
        self.assertEqual(state, "FAIL")
        self.assertIn("Next:", text)


class IncidentLineTests(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        incidents.clear(HOME)
        self.addCleanup(lambda: incidents.clear(HOME))

    def test_ok_without_incidents(self):
        self.assertEqual(sv.incidents_verdict()[0], "ok")

    def test_warn_with_the_report_command_and_what_it_means(self):
        today = time.strftime("%Y-%m-%d")
        (HOME / "incidents.json").write_text(json.dumps({"version": 1, "groups": {"store.lock/lock": {
            "code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit",
            "tool_class": "-", "client": "claude", "days": [today], "count": 3, "plugin_version": "0.9.12"}}}))
        state, text = sv.incidents_verdict()
        self.assertEqual(state, "warn")
        self.assertIn("/maisecrets:report incident", text)
        self.assertIn("3 times maisecrets refused a call", text)


class StatusOutputTests(unittest.TestCase):
    def test_at_most_six_verdict_lines_then_the_details(self):
        buf = io.StringIO()
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        # the client folders are temp fakes: never the real ones
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": tmp + "/claude",
                                                                "CODEX_HOME": tmp + "/codex"}):
            cli.cmd_status([])
        out = buf.getvalue().splitlines()
        head = out[1:out.index("Details") - 1]
        self.assertLessEqual(len(head), 6)
        for line in head:
            state = line.split()[0]
            self.assertIn(state, ("ok", "warn", "FAIL", "n/a"))
            if state in ("warn", "FAIL"):
                self.assertIn("Next:", line)
        self.assertTrue(any(line.startswith("maisecrets ") for line in out[out.index("Details"):]))


if __name__ == "__main__":
    unittest.main()
