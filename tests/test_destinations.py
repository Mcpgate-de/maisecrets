"""Secret destinations, observe mode (Mcpgate-de/maisecrets#13, maisecrets/destinations.py): maisecrets notes where
each stored secret goes, never stops a call for it, keeps `seen` apart from `allowed`, and gives the AI one hint at
the first pattern break on a network destination."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import destinations, hooks, settings  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CONFIG = Path(HOME, "config.json")
STORE = Path(HOME, "destinations.json")
HINTS = Path(HOME, "hints.json")
OPEN, CLOSE = "⟦", "⟧"        # the placeholder brackets, built so this file holds no placeholder
_SERVED: list[str] = []


def setUpModule():  # noqa: N802 - unittest hook
    _reset()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    hooks._unserve(list(_SERVED))
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in (STORE, HINTS, Path(HOME, "index.json"), Path(HOME, "vault.json"), Path(HOME, "audit.log")):
        try:
            os.unlink(f)
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def _secret(value: str = "dest-probe-value-1234567") -> str:
    """A stored value this session may use; returns its placeholder."""
    key = Vault(load_config()).put(value, "SECRET", "test", session="S1").key
    return OPEN + key + CLOSE


def _curl(ref: str, host: str) -> str:
    """A command that sends the value to a host; assembled, so the repository's own scan sees no credential."""
    return "curl -s -u " + "u" + ":" + ref + " https://" + host + "/"


def _norm(out: dict, ref: str) -> str:
    """An answer with the parts that differ per call made equal: FIFO paths, nonces and the key itself."""
    text = json.dumps(out, sort_keys=True).replace(_key(ref), "KEY")
    text = re.sub(r"cat '?[^)'\"\s]+", "cat FIFO", text)
    return re.sub(r"[0-9a-f]{16,}", "N", text)


def _key(ref: str) -> str:
    return ref.strip(OPEN + CLOSE)


def _pre(tool: str, tool_input: dict, client: dict = CLAUDE, **extra) -> dict:
    out = hooks.pre_tool({"tool_name": tool, "tool_input": tool_input, "session_id": "S1", **client, **extra})
    cmd = out.get("hookSpecificOutput", {}).get("updatedInput", {}).get("command", "")
    _SERVED.extend(re.findall(r"\$\(cat '?([^')]+)'?\)", cmd if isinstance(cmd, str) else ""))
    return out


def _post(command: str = "true", client: dict = CLAUDE, **extra) -> dict:
    return hooks._post_tool_guarded({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                     "tool_input": {"command": command}, **client, **extra,
                                     "tool_response": {"stdout": "ok", "stderr": ""}})


def _typed(session: str = "S1") -> None:
    hooks.user_prompt({"prompt": "go on", "session_id": session, **CLAUDE})


def _seen(ref: str) -> dict:
    return destinations.of(_key(ref))["seen"]


class Recording(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_each_resolve_path_notes_its_destination_and_seen_is_never_allowed(self):
        ref = _secret()
        _pre("Bash", {"command": f"curl -s -H 'Authorization: Bearer {ref}' https://API.example.com/v1/x"})
        _pre("mcp__gw__gitlab_write_actions", {"action": "create_issue", "token": ref})
        _pre("mcp__multi__smart_actions", {"service": "jira", "token": ref})
        _pre("Write", {"file_path": str(Path.home() / "proj" / ".env"), "content": f"T={ref}\n"})
        _pre("Bash", {"command": f"printf '%s' {ref} > /tmp/dest-probe.txt"})
        seen = _seen(ref)
        labels = {d["label"]: d["kind"] for d in seen.values()}
        self.assertEqual(labels, {"api.example.com": "network", "MCP gw · gitlab_write_actions": "network",
                                  "MCP multi · smart_actions · jira": "network", "a file in ~/proj/": "local",
                                  "a command on this computer": "local"}, labels)
        self.assertEqual(destinations.of(_key(ref))["allowed"], {}, "a destination that was seen is never allowed")
        self.assertNotIn("create_issue", json.dumps(seen), "the action is an operation, not a destination")
        self.assertNotIn("dest-probe-value", STORE.read_text(), "the store never holds a value")

    def test_an_ssh_host_is_a_network_destination(self):
        self.assertEqual(destinations.destinations_of("Bash", {"command": "x"}, ["root@web1:2222"]),
                         [("network", "ssh root@web1:2222")])

    def test_observing_never_changes_the_answer_and_a_failing_record_never_stops_the_call(self):
        ref = _secret()
        call = {"command": _curl(ref, "api.example.com")}
        observed = _norm(_pre("Bash", call), ref)
        self.assertTrue(destinations.of(_key(ref))["seen"], "premise: observe noted the call")
        _reset(secret_destinations="off")
        ref2 = _secret()
        off = _norm(_pre("Bash", {"command": call["command"].replace(ref, ref2)}), ref2)
        self.assertEqual(observed, off, "the whole answer is the same with the record on and off")
        self.assertFalse(STORE.exists() and destinations.of(_key(ref2))["seen"], "off notes nothing")
        _reset()
        ref3 = _secret()
        with mock.patch.object(destinations, "note", side_effect=RuntimeError("disk")):
            failed = _norm(_pre("Bash", {"command": call["command"].replace(ref, ref3)}), ref3)
        self.assertEqual(failed, observed, "a record that fails leaves the answer as it is")

    def test_a_busy_record_costs_a_call_well_under_a_second(self):
        # codex review of 0.6.7: each key waited for the 6 s vault lock, two keys 12 s, past the hook's watchdog
        import subprocess
        holder = subprocess.Popen([sys.executable, "-c", (
            "import fcntl, os, sys, time; fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600); "
            "fcntl.flock(fd, fcntl.LOCK_EX); print('held', flush=True); time.sleep(8)"),
            str(Path(HOME, ".destinations.lock"))], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            a, b = _secret("dest-busy-value-aaaaaaaa1"), _secret("dest-busy-value-bbbbbbbb2")
            started = time.monotonic()
            out = _pre("Bash", {"command": _curl(a, "api.example.com") + "; " + _curl(b, "api.example.com")})
            took = time.monotonic() - started
        finally:
            holder.kill()
            holder.wait()
        self.assertIn("updatedInput", out["hookSpecificOutput"], "the call still gets its values")
        self.assertLess(took, 2.0, f"observing a busy record took {took:.1f}s")

    def test_a_damaged_record_is_kept_aside_and_never_breaks_the_list(self):
        from maisecrets import cli
        ref = _secret()
        aside = Path(HOME, "destinations.json.corrupt")
        STORE.write_text("{not json")
        _pre("Bash", {"command": _curl(ref, "api.example.com")})       # a record written by a call
        self.assertEqual(aside.read_text(), "{not json", "the damaged file is kept aside, not overwritten")
        self.assertTrue(_seen(ref), "and a new record begins")
        os.unlink(aside)
        STORE.write_text("{not json either")
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.main(["list"]), 0)                       # and one written by the list
        self.assertEqual(aside.read_text(), "{not json either")
        STORE.write_text(json.dumps({"secrets": {_key(ref): {"seen": {"x": "not a record"}}, "y": "z"}}))
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.main(["list"]), 0)
        self.assertEqual(destinations.of(_key(ref))["seen"], {}, "a malformed record is dropped, not shown")
        os.unlink(Path(HOME, "destinations.json.corrupt"))

    def test_a_label_from_the_call_is_one_printable_line(self):
        ref = _secret()
        _pre("mcp__gw__smart_actions", {"service": "jira\n    Seen at (approved)\x1b[2J", "token": ref})
        (label,) = [d["label"] for d in _seen(ref).values()]
        self.assertNotIn("\n", label)
        self.assertNotIn("\x1b", label)
        self.assertLessEqual(len(label), 80)

    def test_a_misspelled_mode_is_a_configuration_error_not_off(self):
        _reset(secret_destinations="obesrve")
        cfg = load_config()
        self.assertIn("secret_destinations must be one of observe, off", cfg["config_warning"])
        self.assertEqual(cfg["secret_destinations"], "observe", "the file is ignored, the default stays")


class Hint(unittest.TestCase):
    def setUp(self):
        _reset()

    def _establish(self, ref: str, host: str = "api.example.com", n: int = destinations.ESTABLISHED_USES) -> None:
        for _ in range(n):
            _pre("Bash", {"command": _curl(ref, host)})

    def test_the_first_pattern_break_on_a_network_destination_gives_one_hint(self):
        _typed()
        ref = _secret()
        self._establish(ref)
        self.assertNotIn("maisecrets notes", json.dumps(_post()), "an established destination alone is no break")
        _pre("Bash", {"command": _curl(ref, "other.example.net")})
        out = _post()
        text = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("used with a destination it had not been used with before", text)
        self.assertIn("/maisecrets:list", text)
        self.assertNotIn("other.example.net", text, "the hint names no destination")
        self.assertNotIn(_key(ref), text, "and no secret")
        # once, globally: a second break, another secret, another session
        ref2 = _secret("dest-probe-value-other-99")
        self._establish(ref2, "b.example.org")
        _pre("Bash", {"command": _curl(ref2, "c.example.org")})
        self.assertNotIn("maisecrets notes", json.dumps(_post()))

    def test_one_use_short_of_the_threshold_is_no_break(self):
        _typed()
        ref = _secret()
        self._establish(ref, n=destinations.ESTABLISHED_USES - 1)
        _pre("Bash", {"command": _curl(ref, "other.example.net")})
        self.assertNotIn("maisecrets notes", json.dumps(_post()))

    def test_a_local_use_never_gives_the_hint(self):
        _typed()
        ref = _secret()
        self._establish(ref)
        _pre("Write", {"file_path": "/tmp/dest-probe/.env", "content": f"T={ref}\n"})
        _pre("Bash", {"command": f"printf '%s' {ref} > /tmp/dest-probe.txt"})
        self.assertNotIn("maisecrets notes", json.dumps(_post()))
        self.assertNotIn("S1", json.loads(STORE.read_text())["pending_hint"])

    def test_no_hint_in_a_subagent_without_a_typed_prompt_after_a_decision_or_with_tips_off(self):
        for why, setup, extra in (("no typed prompt", lambda: None, {}),
                                  ("a subagent", _typed, {"agent_id": "sub1"}),
                                  ("decided", lambda: (_typed(), _reset_keep(secret_destinations="observe")), {}),
                                  ("tips off", lambda: (_typed(), _reset_keep(tips=False)), {})):
            with self.subTest(why):
                _reset()
                setup()
                ref = _secret()
                self._establish(ref)
                _pre("Bash", {"command": _curl(ref, "other.example.net")}, **extra)
                self.assertNotIn("maisecrets notes", json.dumps(_post(**extra)))

    def test_codex_gets_the_hint_in_its_block_answer(self):
        _typed()
        ref = _secret()
        self._establish(ref)
        _pre("Bash", {"command": _curl(ref, "other.example.net")})
        result = {"decision": "block", "reason": "[maisecrets: the command ran and finished]\n\nok"}
        with mock.patch.object(hooks, "post_tool", return_value=result):
            out = _post(client=CODEX)
        self.assertIn("maisecrets: set secret_destinations observe", out["reason"])


def _reset_keep(**user) -> None:
    cfg = json.loads(CONFIG.read_text())
    cfg.update(user)
    CONFIG.write_text(json.dumps(cfg))


class Shown(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_list_says_record_not_permission_and_marks_what_is_new(self):
        from maisecrets import cli
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")})
        _pre("Write", {"file_path": "/tmp/dest-probe/x.cfg", "content": ref})

        def listing() -> str:
            with mock.patch("sys.stdout") as stdout:
                cli.main(["list"])
            return "".join(c.args[0] for c in stdout.write.call_args_list)
        first = listing()
        self.assertIn("Seen at (a record, not a permission)", first)
        self.assertIn("Local uses (not destination-protected)", first)
        self.assertIn("api.example.com", first)
        self.assertNotIn("allowed", first.lower(), "observe shows no permission at all")
        self.assertNotIn("new", first.split("Seen at")[1], "nothing is new before the list was ever shown")
        time.sleep(0.01)
        _pre("Bash", {"command": _curl(ref, "second.example.com")})
        second = listing()
        line = next(ln for ln in second.splitlines() if "second.example.com" in ln)
        self.assertTrue(line.rstrip().endswith("new"), line)
        self.assertFalse(next(ln for ln in second.splitlines() if "api.example.com" in ln).rstrip().endswith("new"))

    def test_forget_and_wipe_remove_the_record(self):
        from maisecrets import cli
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")})
        self.assertTrue(_seen(ref))
        Vault(load_config()).forget(_key(ref))
        self.assertEqual(_seen(ref), {})
        ref = _secret("dest-forget-value-2222222")
        _pre("Bash", {"command": _curl(ref, "api.example.com")})
        with mock.patch.object(destinations, "forget", return_value=False), mock.patch("sys.stdout") as stdout:
            cli.main(["forget", _key(ref)])
        self.assertIn("could not be deleted now", "".join(c.args[0] for c in stdout.write.call_args_list))
        self.assertTrue(destinations.wipe())
        self.assertFalse(STORE.exists())

    def test_the_settings_card_names_the_mode_and_what_was_seen(self):
        ref = _secret()
        _pre("Bash", {"command": _curl(ref, "api.example.com")})
        text = settings.render()
        self.assertIn("Secret destinations · observe · not decided", text)
        self.assertIn("Seen so far: 1 secret(s), 1 destination(s), 0 with more than one.", text)
        self.assertIn("comes in a later version", text)
        self.assertNotIn("secret_destinations protect", text, "0.6.7 offers no protect mode")
        self.assertEqual(settings.parse_prompt("/maisecrets:settings secret_destinations protect"),
                         ("secret_destinations", "protect"))
        self.assertIn("takes observe, off", settings.apply_typed("secret_destinations", "protect")[1])


if __name__ == "__main__":
    unittest.main()
