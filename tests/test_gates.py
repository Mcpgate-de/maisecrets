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
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, INDEX, Vault  # noqa: E402

os.environ["MAISECRETS_HOME"] = str(HOME)
_TMP = str(HOME)
# the value FIFOs live under the temp dir (or $XDG_RUNTIME_DIR); the tests must never touch
# the directory the installed plugin uses on this machine
os.environ.pop("XDG_RUNTIME_DIR", None)
tempfile.tempdir = _TMP

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
    shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
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
    def test_value_is_delivered_once_and_a_missing_delivery_fails_the_whole_command(self):
        out = _bash_pre("printf '%s' " + self.e.ref + " | tr a-z A-Z; echo tail")["hookSpecificOutput"]
        cmd = out["updatedInput"]["command"]
        self.assertTrue(cmd.startswith('__ms_1="$('), cmd)             # read up front, in the main shell
        self.assertNotIn(NASTY, cmd)
        r = _run(cmd)
        self.assertEqual(r.stdout, NASTY.upper() + "tail\n", r.stderr)   # the value reached a pipeline element
        if sys.platform == "win32":
            return   # Git Bash reads through the resolver script under a grant (up to 3 reads), not a FIFO
        # the FIFO delivered once and is gone: the same command again fails closed as a whole,
        # no "" reaches the pipeline, nothing after it runs
        r2 = _run(cmd)
        self.assertEqual(r2.returncode, 97)
        self.assertEqual(r2.stdout, "")
        self.assertIn("not delivered", r2.stderr)

    def test_two_references_to_one_key_share_one_delivery(self):
        out = _bash_pre("echo " + self.e.ref + " and '" + self.e.ref + "'")["hookSpecificOutput"]
        cmd = out["updatedInput"]["command"]
        self.assertEqual(cmd.count("__ms_1="), 1)
        self.assertEqual(cmd.count("${__ms_1}"), 2)
        if BASH:
            self.assertEqual(_run(cmd).stdout, NASTY + " and " + NASTY + "\n")

    def test_a_model_written_grant_or_resolver_call_is_denied(self):
        for cmd in ('python3 /x/hooks/resolve.py SECRET_c1 --grant abc', 'resolve.py SECRET_c1 --grant abc'):
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_blocked_prompt_is_kept_for_send_and_taken_once(self):
        hooks._clipboard = lambda text: False                       # SSH: no clipboard
        token = "glpat-" + "PendingProbeAbc123456789x"
        out = hooks.user_prompt({"prompt": f"deploy with {token} now", "session_id": "S7", "transcript_path": ""})
        self.assertIn("/maisecrets:send", out["reason"])
        self.assertNotIn(token, out["reason"])
        text = hooks.take_pending("S7")
        self.assertEqual(text, "deploy with ⟦SECRET_c2⟧ now")
        self.assertIsNone(hooks.take_pending("S7"))                 # taken once

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
        # the rewritten command never comes back through PreToolUse (the model's own input does);
        # if it does, the model copied a nonce from the transcript, and that is denied too
        new = _bash_pre("echo " + self.e.ref)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(_bash_pre(new)["hookSpecificOutput"]["permissionDecision"], "deny")

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


class ContextTests(unittest.TestCase):
    """The rewrite places a variable only where bash expands it exactly once; every other
    context is refused with the reason (review, 2026-09-26: bash -c spliced the value as code)."""

    def setUp(self):
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    @unittest.skipIf(BASH is None, "no bash")
    def test_value_arrives_inside_a_command_substitution_and_an_unquoted_heredoc(self):
        for name, cmd, want in [
            ("sq in $()", 'printf \'%s\' "$(printf \'%s\' \'' + self.e.ref + '\')"', NASTY),
            ("unquoted heredoc", "cat <<EOF\nkey: " + self.e.ref + "\nEOF\n", "key: " + NASTY + "\n"),
            ("after a comment with an apostrophe", "true # don't\nprintf '%s' " + self.e.ref, NASTY),
        ]:
            with self.subTest(name):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertNotIn("permissionDecision", out, out)
                new = out["updatedInput"]["command"]
                self.assertNotIn(NASTY[:6], new)
                r = _run(new)
                self.assertEqual(r.stdout, want, r.stderr)

    def test_contexts_the_rewrite_cannot_place_are_refused_with_the_reason(self):
        before = set(os.listdir(hooks._run_dir()))
        marker_value = "x$(touch " + str(Path(_TMP, "MARKER")) + ")y"
        e2 = Vault().put(marker_value, "SECRET", "manual", session="S1")
        for name, cmd in [
            ("bash -c", "bash -c 'printf \"%s\" \"" + e2.ref + "\"'"),
            ("sh -lc", "sh -lc \"echo " + e2.ref + "\""),
            ("ssh", "ssh host \"cmd " + e2.ref + "\""),
            ("eval", "eval \"echo " + e2.ref + "\""),
            ("quoted heredoc", "cat <<'EOF'\nkey: " + e2.ref + "\nEOF\n"),
            ("ansi-c", "printf '%s' $'it\\'s " + e2.ref + "'"),
            ("backtick", "echo `cat " + e2.ref + "`"),
        ]:
            with self.subTest(name):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
                self.assertIn("did not run", out["permissionDecisionReason"])
        self.assertFalse(Path(_TMP, "MARKER").exists(), "a value must never run as code")
        self.assertEqual(set(os.listdir(hooks._run_dir())) - before, set(), "a refused command leaves no value waiting")

    def test_a_command_that_would_transform_the_value_is_refused(self):
        for cmd in ("printf '%s' " + self.e.ref + " | base64", "x=" + self.e.ref + "; echo ${x:0:4}",
                    "PS4='+$x '; x=" + self.e.ref + "; set -x; true", "bash -x run.sh; echo " + self.e.ref,
                    "printf '%s' " + self.e.ref + " | xxd -p"):
            with self.subTest(cmd[:30]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
                self.assertIn("refused in this command", out["permissionDecisionReason"])
        # a plain pipeline stays allowed
        plain = _bash_pre("curl -H 'X-Token: " + self.e.ref + "' h | jq .")["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", plain)

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_a_refused_key_leaves_no_value_waiting(self):
        before = set(os.listdir(hooks._run_dir()))
        out = _bash_pre("echo " + self.e.ref + " ⟦SECRET_c99⟧")["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("(unknown)", out["permissionDecisionReason"])
        self.assertIn("do not guess", out["permissionDecisionReason"])
        self.assertEqual(set(os.listdir(hooks._run_dir())) - before, set())

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_the_run_dir_is_private_and_refused_when_it_is_not(self):
        d = hooks._run_dir()
        st = os.stat(d)
        self.assertEqual(st.st_mode & 0o777, 0o700)
        os.chmod(d, 0o755)
        try:
            out = _bash_pre("echo " + self.e.ref)["hookSpecificOutput"]
            self.assertEqual(out.get("permissionDecision"), "deny", out)
        finally:
            os.chmod(d, 0o700)

    def test_client_is_read_from_the_payload_before_the_environment(self):
        os.environ["CODEX_HOME"] = "/tmp/x"
        try:
            self.assertEqual(hooks.client_of({"prompt_id": "p"}), "claude")
            self.assertEqual(hooks.client_of({"turn_id": "t"}), "codex")
            self.assertEqual(hooks.client_of({}), "codex")
            out = hooks.pre_tool({"tool_name": "Bash", "prompt_id": "p", "session_id": "S1",
                                  "tool_input": {"command": "echo " + self.e.ref}})["hookSpecificOutput"]
            self.assertNotIn("permissionDecision", out, "a Claude payload is never auto-approved")
        finally:
            del os.environ["CODEX_HOME"]
        self.assertEqual(hooks.client_of({}), "claude")

    def test_file_tools_resolve_like_mcp_and_the_home_is_off_limits(self):
        out = hooks.pre_tool({"tool_name": "Write", "session_id": "S1",
                              "tool_input": {"file_path": "/tmp/x.env", "content": "K=" + self.e.ref}})
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["content"], "K=" + NASTY)
        audit = Path(_TMP, "audit.log").read_text(encoding="utf-8")
        self.assertIn("Write /tmp/x.env", audit)
        self.assertNotIn(NASTY, audit)
        out = hooks.pre_tool({"tool_name": "Edit", "session_id": "S2",
                              "tool_input": {"file_path": "/tmp/x.env", "old_string": "a", "new_string": self.e.ref}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("Nothing was written", out["hookSpecificOutput"]["permissionDecisionReason"])
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "resolve_in_files": false}')
        try:
            out = hooks.pre_tool({"tool_name": "Write", "session_id": "S1",
                                  "tool_input": {"file_path": "/tmp/x.env", "content": "K=" + self.e.ref}})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertIn("resolve_in_files", out["hookSpecificOutput"]["permissionDecisionReason"])
        finally:
            Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        out = hooks.pre_tool({"tool_name": "Edit", "session_id": "S1",
                              "tool_input": {"file_path": str(Path(_TMP, "config.json")),
                                             "old_string": "a", "new_string": "b"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        harmless = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/y", "content": "hi"}}
        self.assertEqual(hooks.pre_tool(harmless), {})
        out = _bash_pre("echo x > ~/.maisecrets/config.json")["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("home directory", out["permissionDecisionReason"])

    def test_backstop_false_positives_of_the_old_patterns_pass(self):
        for cmd in ("python3 -m pytest tests/test_resolve.py", "grep -rn PasswordVault src/", "echo x --grant abc"):
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd), {})


class ScannerEdgeTests(unittest.TestCase):
    """Cases the second review round found: nested-shell spellings, ordinary commands that must
    pass, here-strings, arithmetic, backslash-quoted heredocs, the value next to a letter."""

    def setUp(self):
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    def test_nested_shell_spellings_are_refused_and_a_value_never_runs(self):
        marker = Path(_TMP, "MARKER2")
        e2 = Vault().put("x$(touch " + str(marker) + ")y", "SECRET", "manual", session="S1")
        for cmd in ("/bin/bash -c 'echo " + e2.ref + "'", "bash --norc -c 'echo " + e2.ref + "'",
                    "bash -o pipefail -c 'echo " + e2.ref + "'", "bash <<EOF\necho " + e2.ref + "\nEOF\n",
                    "echo 'echo " + e2.ref + "' | sh", "/usr/bin/ssh host echo " + e2.ref,
                    "sudo bash -c 'echo " + e2.ref + "'", "docker run img sh -c \"echo " + e2.ref + "\"",
                    "python3 -c 'print(\"" + e2.ref + "\")'", "set -euxo pipefail; echo " + e2.ref,
                    "bash -xe run.sh " + e2.ref, "/usr/bin/base64 <<< " + e2.ref, "x=" + e2.ref + "; echo ${x^^}",
                    "awk -v v=" + e2.ref + " 'BEGIN{print v}'", "echo $((" + e2.ref + "))"):
            with self.subTest(cmd[:40]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
        self.assertFalse(marker.exists())

    @unittest.skipIf(BASH is None, "no bash")
    def test_ordinary_commands_pass_and_the_value_arrives(self):
        for cmd, want in [
            ("printf '%s' " + self.e.ref + " # watch out for eval", NASTY),
            ("VAR=" + self.e.ref + " sh -c 'printf %s \"$VAR\"'", None),   # sh -c: refused, see below
            ("printf '%s' \"${PORT:-8080}-" + self.e.ref + "\"", "8080-" + NASTY),
            ("printf '%s' \"" + self.e.ref + "b\"", NASTY + "b"),
            ("cat <<<x >/dev/null; printf '%s' " + self.e.ref, NASTY),
            ("echo $((1<<2)) >/dev/null; printf '%s' '" + self.e.ref + "'", NASTY),
            ("cat <<-EOF\n\tk: " + self.e.ref + "\n\tEOF\n", "k: " + NASTY + "\n"),
            ("cat <<EOF\r\nk: " + self.e.ref + "\r\nEOF\r\n", None),   # CRLF: bash itself takes EOF\r as the tag
        ]:
            with self.subTest(cmd[:40]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                if want is None:
                    continue
                self.assertNotIn("permissionDecision", out, out)
                r = _run(out["updatedInput"]["command"])
                self.assertEqual(r.stdout, want, r.stderr)
        for cmd in ("python3 script.py --token " + self.e.ref, "docker run --rm -e TOKEN=" + self.e.ref + " alpine env",
                    "git clone https://oauth2:" + self.e.ref + "@host/x.git ssh-keys",
                    "npm run watch -- --token " + self.e.ref,
                    "grep eval file.txt; curl -H 'X: " + self.e.ref + "' h", "bash script.sh " + self.e.ref):
            with self.subTest(cmd[:40]):
                self.assertNotIn("permissionDecision", _bash_pre(cmd)["hookSpecificOutput"])

    def test_backslash_quoted_heredoc_is_refused_like_a_quoted_one(self):
        for cmd in ("cat <<\\EOF\nk: " + self.e.ref + "\nEOF\n", "cat <<E\"O\"F\nk: " + self.e.ref + "\nEOF\n",
                    "cat <<EOF\nv=$(date) " + self.e.ref + "\nEOF\n"):
            with self.subTest(cmd[:20]):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny")

    @unittest.skipIf(os.name == "nt", "Windows uses the resolver and its grant")
    def test_no_grant_is_redeemable_after_a_posix_rewrite(self):
        _bash_pre("printf '%s' " + self.e.ref)
        v = Vault()
        self.assertEqual(v._index.get("grants", {}), {}, "POSIX mints no grant")
        for cmd in ("python3 -m maisecrets.cli resolve SECRET_c1 --grant abc", "resolve SECRET_c1 --grant abc",
                    "python3 -c 'from maisecrets.cli import cmd_resolve'", "ls \"$XDG_RUNTIME_DIR/maisecrets\"",
                    "security dump-keychain -d login.keychain", "cat ~/.MAISECRETS/index.json"):
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"]["permissionDecision"], "deny")

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_a_second_key_that_cannot_be_served_takes_the_first_back(self):
        from unittest import mock
        e2 = Vault().put(PLAIN, "SECRET", "manual", session="S1")
        before = set(os.listdir(hooks._run_dir()))
        calls = {"n": 0}
        real = hooks._serve_value_later

        def flaky(fifo, value, seconds=120.0):
            calls["n"] += 1
            return real(fifo, value, seconds) if calls["n"] == 1 else False
        with mock.patch.object(hooks, "_serve_value_later", flaky):
            out = _bash_pre("echo " + self.e.ref + " " + e2.ref)["hookSpecificOutput"]
        self.assertEqual(out.get("permissionDecision"), "deny")
        import time as _t
        _t.sleep(0.3)
        self.assertEqual(set(os.listdir(hooks._run_dir())) - before, set(), "the first value must not wait")

    def test_a_refused_command_writes_no_audit_line(self):
        audit = Path(_TMP, "audit.log")
        _bash_pre("echo " + self.e.ref + " ⟦SECRET_c99⟧")
        self.assertFalse(audit.exists() and self.e.key in audit.read_text(encoding="utf-8"))

    def test_hooks_log_records_every_run_without_values(self):
        import io
        from unittest import mock
        buf = io.StringIO()
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "printf '%s' " + self.e.ref},
                              "session_id": "S1", "prompt_id": "p"})
        with mock.patch.object(hooks.sys, "stdin", io.StringIO(payload)), mock.patch.object(hooks.sys, "stdout", buf):
            hooks.main(["hook", "pre-tool"])
        log = Path(_TMP, "hooks.log").read_text(encoding="utf-8")
        self.assertIn("pre-tool\tclaude\tS1\tBash\trewrite", log)
        self.assertNotIn(NASTY, log)
        self.assertNotIn("printf", log)


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_exactly_one_answer_leaves_the_process_when_the_watchdog_fires(self):
        import io
        from unittest import mock
        def slow(payload):
            import time as _t
            _t.sleep(0.6)
            return {"decision": "block", "reason": "handler"}
        buf = io.StringIO()
        with mock.patch.dict(hooks.HANDLERS, {"user-prompt": slow}), \
                mock.patch.dict(hooks.WATCHDOG_SECONDS, {"user-prompt": 0.2}), \
                mock.patch.object(hooks.os, "_exit", lambda code: None), \
                mock.patch.object(hooks.sys, "stdin", io.StringIO('{"prompt": "x", "prompt_id": "p"}')), \
                mock.patch.object(hooks.sys, "stdout", buf):
            hooks.main(["hook", "user-prompt"])
        out = buf.getvalue()
        obj = json.loads(out)      # one object, not two concatenated
        self.assertIn("took longer", obj["reason"])

    def test_fail_closed_texts_say_whether_the_tool_ran(self):
        pre = hooks._fail_closed("pre-tool", {}, "x")["hookSpecificOutput"]
        self.assertIn("did NOT run", pre["permissionDecisionReason"])
        post = hooks._fail_closed("post-tool", {}, "x")["hookSpecificOutput"]
        self.assertIn("ran and finished", post["updatedToolOutput"])
        self.assertIn("ran and finished", hooks._fail_closed("post-tool", {"turn_id": "t"}, "x")["reason"])

    def test_config_error_in_the_policy_names_the_key_in_the_answer(self):
        import io
        from unittest import mock
        from maisecrets import vault as vmod
        buf = io.StringIO()
        with mock.patch.dict(vmod.POLICY_PATHS, {__import__("platform").system(): Path(_TMP, "policy.json")}):
            Path(_TMP, "policy.json").write_text('{"max_ttl_seconds": "x"}')
            try:
                with mock.patch.object(hooks.sys, "stdin", io.StringIO('{"prompt": "hi", "prompt_id": "p"}')), \
                        mock.patch.object(hooks.sys, "stdout", buf):
                    hooks.main(["hook", "user-prompt"])
            finally:
                Path(_TMP, "policy.json").unlink()
        out = json.loads(buf.getvalue())
        self.assertEqual(out["decision"], "block")
        self.assertIn("max_ttl_seconds", out["reason"])
        self.assertNotIn("locked store", out["reason"])

    def test_policy_keys_win_over_the_user_file(self):
        from unittest import mock
        from maisecrets import vault as vmod
        with mock.patch.dict(vmod.POLICY_PATHS, {__import__("platform").system(): Path(_TMP, "policy.json")}):
            Path(_TMP, "policy.json").write_text('{"max_keys_per_session": 3, "scrub_transcript": false}')
            Path(_TMP, "config.json").write_text(
                '{"backend": "jsonfile", "allow_plaintext_store": true, "max_keys_per_session": 99}')
            try:
                cfg = vmod.load_config()
            finally:
                Path(_TMP, "policy.json").unlink()
                Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        self.assertEqual(cfg["max_keys_per_session"], 3)
        self.assertFalse(cfg["scrub_transcript"])
        self.assertEqual(sorted(cfg["policy_keys"]), ["max_keys_per_session", "scrub_transcript"])

    def test_post_tool_with_a_broken_payload_withholds_instead_of_failing_open(self):
        import io
        from unittest import mock
        buf = io.StringIO()
        with mock.patch.object(hooks.sys, "stdin", io.StringIO("{not json")), \
                mock.patch.object(hooks.sys, "stdout", buf):
            rc = hooks.main(["hook", "post-tool"])
        self.assertEqual(rc, 0)
        self.assertIn("withheld", json.loads(buf.getvalue())["hookSpecificOutput"]["updatedToolOutput"])

    def test_damaged_index_stays_damaged_until_repaired(self):
        Vault().put(PLAIN, "SECRET", "manual", session="S1")
        INDEX.write_text("{not json", encoding="utf-8")
        for _ in range(2):
            with self.assertRaises(RuntimeError):
                Vault().put("second-value-9876", "SECRET", "manual", session="S1")
        self.assertEqual(json.loads(Path(_TMP, "vault.json").read_text())["SECRET_c1"], PLAIN,
                         "the first value is never overwritten")
        from maisecrets.vault import make_backend
        v = Vault.__new__(Vault)
        v.cfg = hooks.load_config()
        v.backend = make_backend(v.cfg)
        info = v.repair()
        self.assertEqual(info["counters"].get("SECRET"), 1)

        class Opaque:
            test_mode = True

            def get(self, k):
                return None
        v2 = Vault.__new__(Vault)
        v2.cfg, v2.backend = v.cfg, Opaque()
        with self.assertRaises(RuntimeError):
            v2.repair()
        e = Vault().put("third-value-5555", "SECRET", "manual", session="S1")
        self.assertEqual(e.key, "SECRET_c2", "counters continue after a repair")

    def test_config_with_a_wrong_type_names_the_key_and_defaults_stay_untouched(self):
        from maisecrets import vault as vmod
        before = json.dumps(vmod.DEFAULT_CONFIG, sort_keys=True)
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "ttl_seconds": 3600}')
        try:
            # a wrong type in the USER file never locks the user out: the strict defaults apply and
            # the warning names the key (it reaches the user at session start and in `status`)
            cfg = vmod.load_config()
            self.assertIn("ttl_seconds", cfg["config_warning"])
            self.assertEqual(cfg["ttl_seconds"], vmod.DEFAULT_CONFIG["ttl_seconds"])
            Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true, "colour": 1}')
            self.assertIn("colour", vmod.load_config()["config_warning"])
            self.assertEqual(vmod.load_config()["backend"], "jsonfile")
        finally:
            Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        os.environ["CLAUDE_PLUGIN_OPTION_TTL_HOURS"] = "1"
        try:
            vmod.load_config()
        finally:
            del os.environ["CLAUDE_PLUGIN_OPTION_TTL_HOURS"]
        self.assertEqual(json.dumps(vmod.DEFAULT_CONFIG, sort_keys=True), before)

    def test_transcript_scrub_keeps_every_record_valid_json(self):
        cases = ["Secr3tValue\\", 'pässwörd"123', "plain-value-0001", "a\"b\\c"]
        path = Path(_TMP, "t.jsonl")
        lines = [json.dumps({"type": "user", "message": {"content": "token " + v + " end"}}, ensure_ascii=asc)
                 for v in cases for asc in (True, False)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertTrue(hooks._scrub_transcript(str(path), cases, ["⟦X⟧"] * len(cases)))
        data = path.read_text(encoding="utf-8")
        for line in data.splitlines():
            rec = json.loads(line)
            content = rec["message"]["content"]
            for v in cases:
                self.assertNotIn(v, content)
                self.assertNotIn(v, line)


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


class ResolvedValueRedactionTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.v = Vault()
        self.e = self.v.put("Zq7kP2mX9vR4tL8w", "SECRET", "manual", session="S1")
        # the session resolved it (an MCP call), so it is expected back in any position
        self.assertEqual(self.v.record_resolve(self.e.key, "S1", "mcp__x__y", "{}"), "ok")

    def _post(self, text: str) -> str:
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
                               "tool_response": {"stdout": text}})
        return out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if out else text

    def test_value_in_url_path_query_prefix_and_encodings_is_redacted(self):
        import base64
        raw = "Zq7kP2mX9vR4tL8w"
        for text in ("https://x.example/?k=" + raw + "&z=1", "path/" + raw + "/x", "x" + raw,
                     base64.b64encode(raw.encode()).decode(), raw.encode().hex(), "+" + raw + " :",
                     '{"pw": "' + raw + '"}'):
            with self.subTest(text[:20]):
                out = self._post(text)
                self.assertNotIn(raw, out)
                self.assertNotIn(base64.b64encode(raw.encode()).decode(), out)
                self.assertIn(self.e.ref, out)

    def test_a_result_above_the_cap_is_masked_without_storing(self):
        _reset()
        emails = " ".join(f"user{i}@corp-example.org" for i in range(130))
        res = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
                               "tool_response": {"stdout": emails}})
        out = res["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertNotIn("@corp-example.org", out)
        self.assertIn("⟦EMAIL⟧", out)
        self.assertLessEqual(len([e for e in Vault().list() if not e.purged]), 100)


class ShortcutTests(unittest.TestCase):
    @unittest.skipIf(BASH is None, "no bash")
    def test_shortcut_installs_command_and_wrapper_that_finds_the_newest_copy(self):
        from unittest import mock
        from maisecrets import cli
        home = Path(tempfile.mkdtemp(prefix="maisecrets-shortcut-"))
        cfg_dir = home / ".claude"
        # two installed copies; the wrapper must pick 0.3.10 over 0.3.9 (numeric, not lexical)
        for v in ("0.3.9", "0.3.10"):
            d = home / ".claude" / "plugins" / "cache" / "mp" / "maisecrets" / v
            (d / ".claude-plugin").mkdir(parents=True)
            (d / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "maisecrets", "version": v}))
            (d / "hooks").mkdir()
            (d / "hooks" / "run.sh").write_text('#!/usr/bin/env bash\necho "ran $0 $*"\n')
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(cfg_dir), "HOME": str(home)}):
            self.assertEqual(cli.cmd_shortcut([]), 0)
            cmd = (cfg_dir / "commands" / "ms.md").read_text(encoding="utf-8")
            self.assertIn("allowed-tools: Bash(bash ~/.maisecrets/bin/ms.sh*)", cmd)
            self.assertIn("!`bash ~/.maisecrets/bin/ms.sh`", cmd)
            self.assertIn("Sent: ", cmd)
            wrapper = Path(_TMP, "bin", "ms.sh")
            self.assertTrue(wrapper.exists())
            r = subprocess.run([BASH, str(wrapper)], capture_output=True, text=True,
                               env={**os.environ, "HOME": str(home)})
        self.assertIn("/0.3.10/hooks/run.sh pending", r.stdout.replace("\\", "/"), r.stderr)
        self.assertNotIn("$(", cmd.split("---")[2].split("\n")[1], "the ! line is a fixed path, never a substitution")

    def test_session_start_installs_the_shortcut_once_and_keeps_a_users_own(self):
        from unittest import mock
        cfg_dir = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        (cfg_dir / "commands").mkdir()
        (cfg_dir / "commands" / "ms.md").write_text("# mine\n")
        marker = Path(_TMP, ".shortcut")
        marker.unlink(missing_ok=True)
        env = {"CLAUDE_CONFIG_DIR": str(cfg_dir), "CLAUDE_PLUGIN_ROOT": str(ROOT)}
        with mock.patch.dict(os.environ, env):
            r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                               input="{}", capture_output=True, text=True, env={**os.environ, **env})
        self.assertEqual((cfg_dir / "commands" / "ms.md").read_text(), "# mine\n", "a user's own /ms stays")
        self.assertEqual(marker.read_text().strip(), "kept")
        (cfg_dir / "commands" / "ms.md").unlink()
        marker.unlink()
        with mock.patch.dict(os.environ, env):
            r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                               input="{}", capture_output=True, text=True, env={**os.environ, **env})
        self.assertIn("/ms", json.loads(r.stdout)["systemMessage"], r.stderr)
        self.assertIn("ms.sh", (cfg_dir / "commands" / "ms.md").read_text())
        self.assertEqual(marker.read_text().strip(), "installed")
        # the way back: remove, and a later session start does not bring it back
        from maisecrets import cli
        with mock.patch.dict(os.environ, env):
            self.assertEqual(cli.cmd_shortcut(["--remove"]), 0)
        self.assertFalse((cfg_dir / "commands" / "ms.md").exists())
        self.assertFalse(Path(_TMP, "bin", "ms.sh").exists())
        self.assertEqual(marker.read_text().strip(), "removed")
        with mock.patch.dict(os.environ, env):
            subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                           input="{}", capture_output=True, text=True, env={**os.environ, **env})
        self.assertFalse((cfg_dir / "commands" / "ms.md").exists(), "removed stays removed")


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


class ConcurrencyTests(unittest.TestCase):
    def test_parallel_hook_processes_do_not_lose_the_index_or_each_other(self):
        _reset()
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
                "e = Vault().put('parallel-value-' + sys.argv[2] + '-abcdef', 'SECRET', 'manual', session='S1'); "
                "print(e.key)")
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT), str(i)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=dict(os.environ)) for i in range(12)]
        outs = [p.communicate(timeout=60) for p in procs]
        errors = [err for _o, err in outs if err.strip()]
        self.assertEqual(errors, [], errors[:2])
        keys = sorted(o.strip() for o, _e in outs)
        self.assertEqual(len(set(keys)), 12, keys)                        # twelve distinct references
        live = [e for e in Vault().list() if not e.purged]
        self.assertEqual(len(live), 12)                                    # nothing lost in the index


class TipTests(unittest.TestCase):
    def test_one_tip_per_day_rotating_and_switchable_off(self):
        from maisecrets import tips
        try:
            os.unlink(Path(HOME, ".tip"))
        except FileNotFoundError:
            pass
        first = tips.tip_of_the_day()
        self.assertTrue(first and first.startswith("maisecrets:"))
        self.assertIsNone(tips.tip_of_the_day())          # same day: silent
        Path(HOME, ".tip").write_text("2000-01-01 0\n")   # another day: the next tip
        self.assertEqual(tips.tip_of_the_day(), tips.TIPS[1])
        cfg = Path(HOME, "config.json")
        old = cfg.read_text()
        cfg.write_text('{"backend": "jsonfile", "allow_plaintext_store": true, "tips": false}')
        try:
            Path(HOME, ".tip").write_text("2000-01-01 0\n")
            self.assertIsNone(tips.tip_of_the_day())
        finally:
            cfg.write_text(old)


if __name__ == "__main__":
    unittest.main()
