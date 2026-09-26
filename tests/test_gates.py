"""The gates around a resolve: session rule, one-time grant, quoting contexts, limiter,
store-read backstop, MCP arguments, exact-match redaction, keyed fingerprint.

Every test that claims "the value arrives" runs the rewritten command through a real
bash and compares bytes; every test that claims "the value does not leak" searches the
artefact for the literal value.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# the vault home is fixed at the first import of maisecrets.vault (another test module may have
# imported it first); the resolve subprocess must see the same home, so it is taken from there
os.environ.setdefault("MAISECRETS_HOME", tempfile.mkdtemp(prefix="maisecrets-gates-"))
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile"}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, INDEX, Vault  # noqa: E402

os.environ["MAISECRETS_HOME"] = str(HOME)
_TMP = str(HOME)

BASH = shutil.which("bash")
# quotes, a command substitution, a backtick, a backslash and spaces: everything a splice would break on
NASTY = "pa$s'w\"ord`x $(echo no) y\\z"
PLAIN = "plain-secret-value-" + "42"


def _reset() -> None:
    for f in ("index.json", "vault.json", "audit.log"):
        try:
            os.unlink(Path(_TMP, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def _bash_pre(command: str, session: str = "S1") -> dict:
    return hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": session})


def _run(command: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, "-c", command], capture_output=True, text=True)


class GrantTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    @unittest.skipIf(BASH is None, "no bash")
    def test_value_arrives_byte_for_byte_in_every_quoting_context(self):
        for name, cmd, want in [
            ("unquoted", "printf '%s' " + self.e.ref, NASTY),
            ("single", "printf '%s' 'a-" + self.e.ref + "-b'", "a-" + NASTY + "-b"),
            ("double", 'printf \'%s\' "a-' + self.e.ref + '-b"', "a-" + NASTY + "-b"),
            ("two refs", "printf '%s|%s' " + self.e.ref + " '" + self.e.ref + "'", NASTY + "|" + NASTY),
        ]:
            with self.subTest(name):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                new = out["updatedInput"]["command"]
                self.assertNotIn("permissionDecision", out)
                self.assertNotIn(NASTY, new, "the value must not be spliced into the command")
                self.assertNotIn(NASTY[:6], new)
                r = _run(new)
                self.assertEqual(r.stdout, want, r.stderr)

    @unittest.skipIf(BASH is None, "no bash")
    def test_grant_is_single_use_and_bound_to_its_key(self):
        new = _bash_pre("printf '%s' " + self.e.ref)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(_run(new).stdout, NASTY)
        second = _run(new)
        self.assertEqual(second.stdout, "")
        self.assertIn("grant-used", second.stderr)
        # the nonce of one key does not open another key
        e2 = Vault().put(PLAIN, "SECRET", "manual", session="S1")
        nonce = new.split("--grant ")[1].split(")")[0]
        value, status = Vault().redeem(e2.key, nonce)
        self.assertEqual((value, status), (None, "no-grant"))

    def test_reference_resolves_only_in_a_session_that_saw_it(self):
        out = _bash_pre("echo " + self.e.ref, session="S2")["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("foreign-session", out["permissionDecisionReason"])
        self.assertIn("paste", out["permissionDecisionReason"])
        # no session id at all: nothing resolves
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "echo " + self.e.ref}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        # a human types the reference into S2: from now on S2 may resolve it
        hooks.user_prompt({"prompt": "use " + self.e.ref, "session_id": "S2", "transcript_path": ""})
        out = _bash_pre("echo " + self.e.ref, session="S2")["hookSpecificOutput"]
        self.assertIn("updatedInput", out)

    def test_entry_written_before_the_sessions_list_resolves_in_its_creating_session(self):
        v = Vault()
        meta = v._index["entries"][self.e.key]
        meta["sessions"] = []            # the shape a 0.2.0 hook left behind: creator known, no list
        meta["session"] = "S1"
        v._save_index()
        self.assertEqual(Vault().status(self.e.key, "S1"), "ok")
        self.assertEqual(Vault().status(self.e.key, "S2"), "foreign-session")

    def test_agent_reads_of_the_store_are_denied(self):
        for cmd in ["python3 -m maisecrets.cli get SECRET_c1",
                    "security find-generic-password -s maisecrets -a SECRET_c1 -w",
                    "cat ~/.maisecrets/vault.json"]:
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"]["permissionDecision"], "deny")
        # the granted resolve call itself is not a store read
        new = _bash_pre("echo " + self.e.ref)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(_bash_pre(new), {})

    def test_limiter_caps_distinct_keys_per_session_and_resolves_per_hour(self):
        v = Vault()
        v.cfg["max_keys_per_session"] = 2
        v.cfg["max_resolves_per_hour"] = 3
        e2 = v.put("second-secret-value-1", "SECRET", "manual", session="S1")
        e3 = v.put("third-secret-value-22", "SECRET", "manual", session="S1")
        self.assertEqual(v.grant(self.e.key, "S1", "Bash", "a")[1], "ok")
        self.assertEqual(v.grant(e2.key, "S1", "Bash", "b")[1], "ok")
        self.assertIn("max_keys_per_session", v.grant(e3.key, "S1", "Bash", "c")[1])
        self.assertEqual(v.grant(self.e.key, "S1", "Bash", "d")[1], "ok")       # a known key still passes
        self.assertIn("max_resolves_per_hour", v.grant(self.e.key, "S1", "Bash", "e")[1])

    def test_audit_line_names_key_tool_and_context_but_no_value(self):
        _bash_pre("curl -H 'x: " + self.e.ref + "' https://example.org")
        log = Path(HOME, "audit.log").read_text(encoding="utf-8")
        self.assertIn("SECRET_c1\tBash\tcurl -H 'x: ⟦SECRET_c1⟧' https://example.org", log)
        self.assertNotIn(NASTY, log)


class McpTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="S1")

    def test_mcp_arguments_are_resolved_in_place_keeping_the_shape(self):
        payload = {"tool_name": "mcp__x__y", "session_id": "S1",
                   "tool_input": {"to": "a " + self.e.ref, "n": 1, "list": [self.e.ref, 2]}}
        out = hooks.pre_tool(payload)["hookSpecificOutput"]
        self.assertEqual(out["updatedInput"], {"to": "a " + PLAIN, "n": 1, "list": [PLAIN, 2]})
        self.assertNotIn("permissionDecision", out)

    def test_mcp_foreign_session_is_denied_and_nothing_is_partially_resolved(self):
        out = hooks.pre_tool({"tool_name": "mcp__x__y", "session_id": "S9",
                              "tool_input": {"to": self.e.ref}})["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertNotIn("updatedInput", out)


class RedactionTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_shapeless_value_is_redacted_by_exact_match(self):
        e = Vault().put(NASTY, "SECRET", "manual", session="S1")
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1",
                               "tool_response": {"stdout": "PW=" + NASTY + "\ngot:" + NASTY + "\n", "stderr": ""}})
        text = json.dumps(out)
        self.assertNotIn(NASTY, text)
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], f"PW={e.ref}\ngot:{e.ref}\n")

    def test_index_carries_no_reversible_fingerprint(self):
        import hashlib
        Vault().put(PLAIN, "SECRET", "manual", session="S1")
        idx = INDEX.read_text()
        self.assertNotIn(hashlib.sha256(PLAIN.encode()).hexdigest()[:12], idx)
        self.assertNotIn(PLAIN, idx)
        # the key lives in the backend, not in the index
        self.assertNotIn(Vault().fp_key().hex(), idx)

    def test_output_without_live_entries_is_untouched(self):
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1",
                               "tool_response": {"stdout": "nothing here 12345678", "stderr": ""}})
        self.assertEqual(out, {})


class ReportTests(unittest.TestCase):
    def setUp(self):
        _reset()
        try:
            os.unlink(Path(HOME, "events.log"))
        except FileNotFoundError:
            pass
        hooks._clipboard = lambda text: True

    def test_block_records_an_event_and_the_issue_link_carries_no_value(self):
        from maisecrets import events
        token = "glpat-" + "ReportProbeAbc123456789x"
        out = hooks.user_prompt({"prompt": f"token {token}", "session_id": "S1", "transcript_path": ""})
        self.assertIn("/maisecrets:report", out["reason"])
        ev = events.load()[-1]
        self.assertEqual(ev["hook"], "UserPromptSubmit")
        self.assertEqual(ev["hits"][0]["kind"], "gitlab-pat")
        self.assertNotIn(token, json.dumps(ev))
        url = events.issue_url(ev, "a build id")
        self.assertTrue(url.startswith(events.ISSUES_URL + "?"))
        self.assertNotIn("ReportProbe", url)
        self.assertIn("gitlab-pat", url)
        self.assertIn("a+build+id", url)


    def test_bug_and_feature_links_carry_the_text_and_no_event(self):
        from maisecrets import events
        url = events.generic_issue_url("feature", "ask before a persistent value resolves")
        self.assertIn("labels=enhancement", url)
        self.assertIn("Feature%3A+ask+before", url)
        url = events.generic_issue_url("bug", "the block notice hides the clipboard hint")
        self.assertIn("labels=bug", url)
        self.assertNotIn("hits", url)


if __name__ == "__main__":
    unittest.main()
