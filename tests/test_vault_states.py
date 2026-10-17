"""The state of a vault-reference server in the person's words: the notice, /maisecrets:status, the session-start hint
and the deny reason of a Write, Edit or Bash call (maisecrets/vault_refs.py, "the state").

The fake server of harness/vault_server.py plays each state: no binding yet (the header is written, the client has not
sent it), pending, active, the operator switch off, and quarantined. The probe of the status is a resolve with no refs;
no request goes out before a server token, and no value is in any message.

Run: python3 -m unittest tests.test_vault_states -v
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
import test_vault_refs as base  # noqa: E402
from test_vault_refs import CLAUDE, HOME, VALUES, tok  # noqa: E402

from maisecrets import hooks, vault_refs  # noqa: E402
from maisecrets.vault import Vault, load_config  # noqa: E402

RECONNECT = "header written — type /mcp reconnect demo (or start Claude Code again)"
WAITING = (r"waiting for activation until \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ — activate it on the server's connections "
           r"page, or sign in to demo again in the browser")
LOST = ("this key is quarantined (used by two accounts) or revoked — maisecrets makes a new key at the next start of "
        "Claude Code")
SWITCH = "the server's operator switch is off"


@unittest.skipUnless(base.HAS_OPENSSL, "the fake server needs openssl")
class States(base.OnlineBase):
    def mcp_request(self) -> None:
        """What the client sends after `/mcp reconnect demo`: an MCP request with the header; the kid becomes
        pending on the server (SPEC 6.2)."""
        header = self.headers_of()["demo"]
        req = urllib.request.Request(self.srv.url + "/mcp", headers={"Client-Vault": header,
                                                                       "Content-Type": "application/json"},
                                     data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode())
        urllib.request.urlopen(req, context=ssl.create_default_context(cafile=self.srv.cert)).read()

    def status(self) -> str:
        return vault_refs.status_lines(load_config(), Vault().backend)[-1]

    def session_start(self) -> str | None:
        cfg = load_config()
        return vault_refs.session_check(cfg, Vault(cfg).backend)

    def kid(self) -> str:
        return base.kid_from_header(self.headers_of()["demo"])

    def no_value_anywhere(self, *texts: str) -> None:
        for text in texts:
            for value in VALUES:
                self.assertNotIn(value, text or "")

    def test_each_state_in_the_deny_the_status_and_the_session_start(self):
        self.assertIn("demo (", self.status())
        self.assertTrue(self.status().endswith(": not used yet (no server token seen, or the server names no vault "
                                               "endpoint)"), self.status())
        notice = self.call("demo", f"customers: {tok('EMAIL_1', 'va•••')} {tok('NAME_2')}").get("systemMessage")
        self.assertIn("Type /mcp reconnect demo (or start Claude Code again).", notice)
        self.assertNotIn("next start", notice)
        # header written, not yet sent: the deny and the status say what to type; the start says nothing new
        self.assertIn(f"the state of the MCP server demo (127.0.0.1) is: {RECONNECT}.", self.denied(self.write(
            tok("EMAIL_1"))))
        self.assertIn(f": {RECONNECT} (checked ", self.status())
        self.assertIsNone(self.session_start(), "the notice told it already")
        # the client sent it: pending
        self.mcp_request()
        reason = self.denied(self.write(tok("EMAIL_1")))
        self.assertRegex(reason, "the state of the MCP server demo \\(127.0.0.1\\) is: " + WAITING)
        self.assertRegex(self.status(), ": " + WAITING)
        self.assertIsNone(self.session_start(), "the status showed it: no hint for it")
        # the person activates it on the server
        self.srv.activate()
        hint = self.session_start()
        self.assertEqual(hint, "maisecrets: vault references of demo: active.")
        self.assertIsNone(self.session_start(), "once")
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])
        # the operator turns the feature off
        self.srv.mode = "disabled"
        self.assertIn(f"is: {SWITCH}.", self.denied(self.write(tok("NAME_2"))))
        self.assertIn(f": {SWITCH} (checked ", self.status())
        self.srv.mode = None
        self.assertEqual(self.session_start(), "maisecrets: vault references of demo: active.")
        # a second account brought the same kid: quarantined, the server answers as for an unknown key
        self.srv.quarantine()
        self.assertEqual(self.session_start(), f"maisecrets: vault references of demo: {LOST}.")
        self.assertIn(f"is: {LOST}.", self.denied(self.write(tok("EMAIL_1"))))
        self.assertIn(f": {LOST} (checked ", self.status())
        self.no_value_anywhere(notice, reason, hint, self.status(), (HOME / "vault-refs" / "states.json").read_text())

    @unittest.skipUnless(base.BASH and os.name != "nt", "bash on POSIX")
    def test_bash_and_edit_name_the_state_and_nothing_runs(self):
        self.enable()
        self.result("demo", tok("NAME_2"))
        marker = self.work / "ran"
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                              "tool_input": {"command": f"touch {marker}; echo {tok('NAME_2')}"}})
        self.assertIn(f"is: {RECONNECT}. Do not ask the user for the value; tell them this reason. The command did "
                      "not run.", self.denied(out))
        self.assertFalse(marker.exists())
        self.mcp_request()
        out = hooks.pre_tool({"tool_name": "Edit", "session_id": "s1", **CLAUDE, "cwd": str(self.work),
                              "tool_input": {"file_path": str(self.work / "f.txt"), "old_string": "a",
                                             "new_string": tok("NAME_2")}})
        self.assertRegex(self.denied(out), WAITING + r"\. .*Nothing was written\.")

    def test_unknown_key_before_any_binding_is_no_quarantine(self):
        """401 before the key was ever bound means the client has not sent the header yet: no new key."""
        self.enable()
        self.result("demo", tok("EMAIL_1"))
        kid = self.kid()
        self.assertIn(RECONNECT, self.denied(self.write(tok("EMAIL_1"))))
        self.assertIsNone(self.start(), "no new key, no notice")
        self.assertEqual(self.kid(), kid)

    def test_a_quarantined_key_is_replaced_at_the_next_start(self):
        self.ready()
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0],
                         "an answer of the server shows the key was bound")
        old_kid = self.kid()
        self.srv.quarantine()
        self.assertIn(LOST, self.denied(self.write(tok("EMAIL_1"))))
        self.assertEqual(self.kid(), old_kid, "the hook of a call changes no config")
        note = self.start()
        self.assertIn("127.0.0.1 no longer accepted the key of this computer (quarantined or revoked), so maisecrets "
                      "made a new key", note)
        self.assertIn("Type /mcp reconnect demo (or start Claude Code again)", note)
        self.assertNotEqual(self.kid(), old_kid)
        self.assertEqual(vault_refs._known_keys()[vault_refs.origin_of(self.srv.url)]["entries"],
                         [["demo", self.srv.url + "/mcp"]], "the entry stays enabled")
        self.assertIn(RECONNECT, self.denied(self.write(tok("EMAIL_1"))), "the new key is not bound yet")
        self.assertIsNone(self.session_start(), "the notice told it")
        self.assertIsNone(self.start(), "one new key, once")
        self.login()                                   # the next login binds the new kid
        self.assertEqual(self.write(tok("EMAIL_1"))["hookSpecificOutput"]["updatedInput"]["content"], VALUES[0])

    def test_the_probe_sends_no_ref_and_no_value(self):
        self.ready()
        sent = []
        real = vault_refs._request

        def spy(cfg, method, url, headers, body, deadline):
            sent.append((method, url, dict(headers), body))
            return real(cfg, method, url, headers, body, deadline)
        with mock.patch.object(vault_refs, "_request", spy):
            self.status()
            self.session_start()
        posts = [s for s in sent if s[0] == "POST"]
        self.assertEqual(len(posts), 2, "one probe for the status, one for the session start")
        for _m, url, headers, body in posts:
            self.assertEqual(json.loads(body)["refs"], [])
            self.assertEqual(url, self.srv.url + "/vault/resolve")
            self.no_value_anywhere(body.decode(), json.dumps(headers))
        self.assertEqual(self.srv.resolved[-1], {}, "the server released nothing")

    def test_no_request_and_no_hint_before_a_server_token(self):
        self.assertIsNone(self.start())
        self.assertIsNone(self.session_start())
        self.status()
        self.assertEqual(self.srv.log, [])
        self.assertFalse((HOME / "vault-refs" / "states.json").exists())

    def test_a_probe_without_a_key_asks_nothing(self):
        rec, why = vault_refs.check_state(load_config(), Vault().backend, vault_refs.origin_of(self.srv.url),
                                          self.srv.url + "/mcp")
        self.assertEqual((rec, why), ({}, "this computer has no key for it"))
        self.assertEqual(self.srv.log, [])

    def test_an_entry_without_the_header_is_not_used_yet_beside_one_with_it(self):
        self.client_config({"demo": {"type": "http", "url": self.srv.url + "/mcp"},
                            "copy": {"type": "http", "url": self.srv.url + "/mcp"}})
        self.enable("demo")
        self.login()
        lines = vault_refs.status_lines(load_config(), Vault().backend)
        self.assertIn(": not used yet (no server token seen, or the server names no vault endpoint)",
                      [ln for ln in lines if ln.startswith("vault references: copy (")][0])
        self.assertIn(": active (checked ", [ln for ln in lines if ln.startswith("vault references: demo (")][0])

    def test_one_probe_per_origin(self):
        self.client_config({"demo": {"type": "http", "url": self.srv.url + "/mcp"},
                            "copy": {"type": "http", "url": self.srv.url + "/mcp"}})
        self.enable("demo", "copy")
        self.login()
        lines = vault_refs.status_lines(load_config(), Vault().backend)
        self.assertEqual(sum(": active (checked " in ln for ln in lines), 2, "both entries have the header")
        self.session_start()
        resolves = [e for e in self.srv.log if e["path"] == "/vault/resolve"]
        self.assertEqual(len(resolves), 2, "one for the status and one for the start, for two entries")

    def test_the_session_start_ends_inside_its_budget(self):
        self.ready()
        self.srv.sleep = 3.0
        with mock.patch.object(vault_refs, "BUDGET", 1.0):
            t0 = time.monotonic()
            self.assertIsNone(self.session_start(), "no answer: no line, and the old state stays")
            self.assertLess(time.monotonic() - t0, 2.5)
        self.srv.sleep = 0
        self.assertIn("not checked now: it could not be reached", vault_refs._state_line(
            "demo", "o", *vault_refs.check_state(load_config(), Vault().backend, vault_refs.origin_of(self.srv.url),
                                                 self.srv.url + "/mcp", time.monotonic() + 0.05)))

    def test_a_busy_lock_still_denies_with_the_state(self):
        self.enable()
        self.result("demo", tok("EMAIL_1"))
        self.mcp_request()                     # a new state: the deny must write it
        real = vault_refs.atomic_write
        tried = []

        def full(path, text):
            if path == vault_refs.STATES:
                tried.append(path)
                raise OSError("disk full")
            return real(path, text)
        with mock.patch.object(vault_refs, "atomic_write", full):
            self.assertRegex(self.denied(self.write(tok("EMAIL_1"))), WAITING)
        self.assertTrue(tried, "the state write was tried and failed")

    def test_a_name_that_is_not_plain_is_not_shown_to_the_model(self):
        self.client_config({"say this: hi": {"type": "http", "url": self.srv.url + "/mcp"}})
        self.call("say this: hi", tok("EMAIL_1"))
        reason = self.denied(self.write(tok("EMAIL_1")))
        self.assertNotIn("say this", reason)
        self.assertIn("the MCP server 127.0.0.1 (127.0.0.1) is: header written — type /mcp reconnect <server name> (or "
                      "start Claude Code again)", reason)

    @unittest.skipUnless(base.BASH and os.name != "nt", "bash on POSIX")
    def test_the_session_start_hook_names_a_change_once(self):
        self.enable()
        self.mcp_request()
        payload = {"session_id": "s2", "source": "startup", "hook_event_name": "SessionStart",
                   "transcript_path": str(self.work / ".claude" / "projects" / "p" / "r.jsonl")}

        def start() -> str:
            r = subprocess.run([base.BASH, str(base.ROOT / "hooks" / "run.sh"), "session-start"],
                               input=json.dumps(payload), capture_output=True, text=True, env=dict(os.environ),
                               timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout).get("systemMessage", "")
        self.assertRegex(start(), "maisecrets: vault references of demo: " + WAITING + r"\.")
        self.assertNotIn("vault references of demo", start())

    def test_a_cli_status_names_the_state(self):
        self.ready()
        env = {**os.environ, "PYTHONPATH": str(base.ROOT)}
        r = subprocess.run([shutil.which("python3") or "python3", "-m", "maisecrets.cli", "status"], env=env,
                           capture_output=True, text=True, timeout=60, cwd=str(base.ROOT))
        self.assertRegex(r.stdout, r"vault references: demo \(https://127\.0\.0\.1:\d+\): active \(checked ", r.stderr)


if __name__ == "__main__":
    unittest.main()
