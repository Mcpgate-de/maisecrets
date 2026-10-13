"""Terms (maisecrets/terms.py, C26) through the hook entry points: the typed command, the inline marker, a tool result,
a tool call (mask only), the transcript, and every place a term must never be written.

Based on the hook and leak tests of the personal-terms design by @danszymkowiak (tests/test_terms_hooks.py and
tests/test_terms_leaks.py of his fork). A placeholder here is built from OPEN and CLOSE, so the file holds none.

Run: python3 -m unittest tests.test_terms_hooks -v
Synthetic names only.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import cli, detect, hooks, incidents, settings, terms  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

NAME = "Zbigniew " + "Testowski"
PIECES = ("zbigniew", "testowsk")          # every piece of the term that would show it, lower case
STATE = ("index.json", "vault.json", "audit.log", "hooks.log", "events.log", "terms.txt", "terms.marked.json",
         ".terms-state", ".terms-cache")
REF_RE = re.compile(re.escape(OPEN) + r"NAME_c\d+" + re.escape(CLOSE))


def _clean() -> None:
    for f in STATE:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    incidents.clear(Path(HOME))
    hooks._live_cache.clear()
    detect.reset_rules()


def setUpModule():  # noqa: N802 - unittest hook
    Path(HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


def _write_terms(text: str) -> None:
    terms.PERSONAL.write_text(text, encoding="utf-8")
    os.chmod(terms.PERSONAL, 0o600)
    detect.reset_rules()


def _home_text() -> str:
    """Every file under the home but terms.txt, terms.marked.json and the index .terms-cache (which hold the terms by
    design), as text."""
    parts = []
    for p in Path(HOME).rglob("*"):
        if p.is_file() and p.name not in ("terms.txt", "terms.marked.json", ".terms-cache"):
            parts.append(f"--- {p.name}\n" + p.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _bash(stdout: str, session: str = "S1") -> dict:
    hooks._live_cache.clear()
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": session,
                            "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                            "tool_response": {"stdout": stdout, "stderr": ""}})


def _out(answer: dict) -> str:
    return answer["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def _prompt(prompt: str, source: str | None = "user", session: str = "S1", client=CLAUDE) -> dict:
    hooks._live_cache.clear()
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": session,
               "transcript_path": "", **client}
    if source is not None:
        payload["source"] = source
    return hooks.user_prompt(payload)


class _Base(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)

    def assertNoTerm(self, text: str, where: str) -> None:  # noqa: N802 - unittest style
        low = text.lower()
        for piece in PIECES:
            self.assertNotIn(piece, low, f"{where} shows a term")


class TypedCommandTests(_Base):
    def test_term_add_writes_a_private_file_and_the_next_tool_result_is_masked(self):
        out = _prompt(f"/maisecrets:term add {NAME}")
        self.assertEqual(out["decision"], "block", "the prompt carries the name: it never reaches the model")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertIn("NAME_1", out["reason"])
        self.assertNoTerm(out["reason"], "the answer")
        if os.name != "nt":
            self.assertEqual(os.stat(terms.PERSONAL).st_mode & 0o777, 0o600)
        masked = _out(_bash(f"Dear {NAME}, your file is ready."))
        self.assertRegex(masked, r"\ADear " + REF_RE.pattern + r", your file is ready\.\Z")

    def test_add_twice_and_remove(self):
        _prompt(f"/maisecrets:term add {NAME}")
        again = _prompt(f"/maisecrets:term add {NAME.upper()}")
        self.assertIn("already on your list (NAME_1", again["reason"])
        gone = _prompt(f"/maisecrets:term remove {NAME}")
        self.assertIn("removed NAME_1", gone["reason"])
        self.assertEqual(_bash(f"Dear {NAME}"), {})

    def test_a_common_word_is_added_with_a_note(self):
        self.assertIn("is a common word", _prompt("/maisecrets:term add Jan")["reason"])
        self.assertNotIn("common word", _prompt(f"/maisecrets:term add {NAME}")["reason"])

    def test_remove_by_the_placeholder_the_person_copied(self):
        _prompt(f"/maisecrets:term add {NAME} | Testowsk*")
        ref = REF_RE.search(_out(_bash("Pan Testowskiego"))).group()
        gone = _prompt(f"/maisecrets:term remove {ref}")
        self.assertIn("removed NAME_1", gone["reason"])
        self.assertEqual(_bash(f"Pan {NAME}"), {})

    def test_codex_form(self):
        out = _prompt(f"maisecrets: term add {NAME}", source=None, client=CODEX)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertRegex(_out(_bash(NAME)), REF_RE)

    def test_a_prompt_the_client_injected_changes_nothing(self):
        out = _prompt(f"/maisecrets:term add {NAME}", source="scheduled")
        self.assertEqual(out["decision"], "block")
        self.assertIn("nothing was changed", out["reason"])
        self.assertFalse(terms.PERSONAL.exists())
        _prompt(f"/maisecrets:term add {NAME}")
        out = _prompt(f"/maisecrets:term remove {NAME}", source="loop")
        self.assertIn("nothing was changed", out["reason"])
        self.assertRegex(_out(_bash(NAME)), REF_RE)

    def test_the_name_of_a_term_command_is_masked_in_the_transcript(self):
        tmp = Path(tempfile.mkdtemp(prefix="transcript-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "session.jsonl"
        record = json.dumps({"type": "user", "message": {"content": f"/maisecrets:term add {NAME}"}}) + "\n"
        path.write_text(record, encoding="utf-8")
        with mock.patch.object(hooks, "_scrub_transcript_later", lambda *a, **k: None):
            hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "prompt": f"/maisecrets:term add {NAME}",
                               "session_id": "S1", "source": "user", "transcript_path": str(path), **CLAUDE})
        self.assertNoTerm(path.read_text(encoding="utf-8"), "the transcript")
        self.assertEqual(len(path.read_bytes()), len(record.encode()), "masked in place, same length")

    def test_a_term_command_without_add_or_remove_is_blocked_with_the_usage(self):
        out = _prompt(f"/maisecrets:term {NAME}")
        self.assertEqual(out["decision"], "block")
        self.assertIn("/maisecrets:term add NAME", out["reason"])
        self.assertFalse(terms.PERSONAL.exists())

    def test_a_removal_in_a_tool_call_is_refused(self):
        # a nested client would type it for the model (C22); adding is stricter and stays allowed
        self.assertTrue(settings.IN_A_COMMAND_RE.search(f"claude -p '/maisecrets:term remove {NAME}'"))
        self.assertTrue(settings.IN_A_COMMAND_RE.search("codex exec 'maisecrets: term remove X'"))
        self.assertFalse(settings.IN_A_COMMAND_RE.search(f"claude -p '/maisecrets:term add {NAME}'"))

    def test_the_mod_leaves_a_term_command_to_the_hook(self):
        _prompt(f"/maisecrets:term add {NAME}")
        self.assertEqual(hooks.rewrite_prompt({"prompt": f"/maisecrets:term remove {NAME}", "session_id": "S1",
                                               "cwd": ""}), {})


class TermHookTests(_Base):
    def setUp(self):
        super().setUp()
        _write_terms(f"PERSON_A  {NAME} | Testowsk*\nCASE_A  *sygn-0042*\n")

    def test_every_spelling_of_an_entity_gets_its_one_placeholder(self):
        text = _out(_bash(f"Pan Testowskiego i {NAME}, akta X-sygn-0042-B; TESTOWSKI."))
        refs = REF_RE.findall(text)
        self.assertEqual(len(refs), 4)
        person, case = refs[0], refs[2]
        self.assertEqual(refs, [person, person, case, person], "one entity, one placeholder")
        self.assertNotEqual(person, case)
        self.assertNoTerm(text, "the tool result")
        self.assertNotIn("sygn", text)
        again = REF_RE.findall(_out(_bash(f"{NAME}", session="S2")))
        self.assertEqual(again, refs[:1], "the same placeholder in another session while the entry lives")

    def test_the_term_is_never_copied_into_the_store_or_the_index(self):
        _bash(f"{NAME} and Testowskiego")
        self.assertNoTerm(_home_text(), "a file of the home")
        store = json.loads(Path(HOME, "vault.json").read_text(encoding="utf-8"))
        values = [v for v in json.dumps(store).split('"') if v.startswith(terms.STORE_PREFIX)]
        self.assertTrue(values, "the store holds the entity id")

    def test_mask_only_a_placeholder_in_a_tool_call_stays_as_written(self):
        ref = REF_RE.search(_out(_bash(NAME))).group()
        for tool, tool_input in (("Bash", {"command": f"echo 'Dear {ref}' > letter.txt"}),
                                 ("Write", {"file_path": "/tmp/letter.txt", "content": f"Dear {ref},\n"}),
                                 ("mcp__mail__draft", {"to": "x", "body": f"Dear {ref}"})):
            with self.subTest(tool=tool):
                out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "S1",
                                      "transcript_path": "", **CLAUDE, "tool_input": tool_input, "cwd": "/tmp"})
                self.assertNotEqual(out.get("hookSpecificOutput", {}).get("permissionDecision"), "deny", out)
                self.assertNoTerm(json.dumps(out), "the tool call")
                updated = out.get("hookSpecificOutput", {}).get("updatedInput")
                if updated is not None:
                    self.assertEqual(updated, tool_input)

    def test_the_model_is_told_the_placeholder_is_never_resolved(self):
        out = _bash(NAME)
        self.assertIn("never puts the name back", out["hookSpecificOutput"]["additionalContext"])

    def test_a_term_in_a_typed_prompt_does_not_reach_the_model(self):
        out = _prompt(f"write to {NAME}")
        self.assertEqual(out.get("decision"), "block")
        self.assertNoTerm(json.dumps(out), "the prompt answer")
        mod = hooks.rewrite_prompt({"prompt": f"write to {NAME}", "session_id": "S1", "cwd": ""})
        self.assertRegex(mod["text"], r"\Awrite to " + REF_RE.pattern + r"\Z")

    def test_a_shape_keeps_its_span_before_a_term(self):
        _write_terms("PERSON_A  *testowski*\n")
        token = "glpat-" + "TestowskiXyz1234567890"
        self.assertEqual([m.type for m in detect.scan(f"token {token} and Testowski")], ["SECRET", "NAME"])

    def test_a_bad_terms_file_fails_closed_without_a_term(self):
        _write_terms(f"PERSON_A  {NAME}\nPERSON_A  Testowsk*\n")
        out = hooks._post_tool_guarded({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1",
                                        "tool_input": {"command": "cat notes.txt"}, **CLAUDE,
                                        "tool_response": {"stdout": NAME, "stderr": ""}})
        self.assertIn("terms.txt: line 2", json.dumps(out))
        self.assertNoTerm(json.dumps(out), "the answer of a hook that failed closed")
        self.assertNoTerm(_home_text(), "the incident record and the logs")


class StoredValueTests(_Base):
    """A listed term inside a value the store holds (a password without a shape): the stored value is taken out
    whole, before the term matcher can split it (gate review of block 2, B1)."""
    VALUE = "Testowski#Sommer" + "2024"
    REST = "sommer2024"

    def setUp(self):
        super().setUp()
        self.assertEqual(_prompt(f"password: {self.VALUE}")["decision"], "block")
        _write_terms("PERSON_A  Testowski\n")
        self.secret = re.compile(re.escape(OPEN) + r"SECRET_c\d+" + re.escape(CLOSE))

    def test_a_tool_result_masks_the_stored_value_whole(self):
        for text in (self.VALUE, f"the value is {self.VALUE} ok", f"echo {self.VALUE}"):
            with self.subTest(text=text):
                out = _out(_bash(text))
                self.assertNotIn(self.REST, out.lower(), "the rest of the stored value is in clear")
                self.assertRegex(out, self.secret)

    def test_a_prompt_and_the_mod_mask_the_stored_value_whole(self):
        out = _prompt(f"try {self.VALUE} again")
        self.assertEqual(out["decision"], "block")
        sent = hooks.take_pending("S1")
        self.assertNotIn(self.REST, sent.lower(), "/maisecrets:send would send the rest")
        self.assertRegex(sent, r"\Atry " + self.secret.pattern + r" again\Z")
        mod = hooks.rewrite_prompt({"prompt": f"try {self.VALUE} again", "session_id": "S1", "cwd": ""})
        self.assertRegex(mod["text"], r"\Atry " + self.secret.pattern + r" again\Z")

    def test_a_failed_call_cleans_the_stored_value_whole_from_the_transcript(self):
        tmp = Path(tempfile.mkdtemp(prefix="transcript-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "session.jsonl"
        path.write_text(json.dumps({"type": "tool_result", "content": f"bad: {self.VALUE}"}) + "\n", encoding="utf-8")
        with mock.patch.object(hooks, "_scrub_transcript_later", lambda *a, **k: None):
            out = hooks.post_tool_failure({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                           "session_id": "S1", "transcript_path": str(path), **CLAUDE,
                                           "tool_input": {"command": "x"}, "error": f"bad: {self.VALUE}"})
        self.assertNotIn(self.REST, json.dumps(out).lower())
        self.assertNotIn(self.REST, path.read_text(encoding="utf-8").lower(), "the transcript keeps the rest")


class MarkerHookTests(_Base):
    def test_a_marked_name_is_masked_in_its_prompt_and_in_later_output(self):
        out = _prompt(f"draft a letter to {{{{{NAME}}}}}; {NAME} asked for it")
        self.assertEqual(out["decision"], "block")
        self.assertNoTerm(json.dumps(out), "the prompt answer")
        sent = hooks.take_pending("S1")
        self.assertRegex(sent, r"\Adraft a letter to (" + REF_RE.pattern + r"); \1 asked for it\Z",
                         "/maisecrets:send sends the name as its placeholder, without the braces")
        self.assertRegex(_out(_bash(f"Re: {NAME}")), r"\ARe: " + REF_RE.pattern + r"\Z")
        self.assertFalse(terms.PERSONAL.exists(), "a mark is not permanent: only term add writes terms.txt")

    def test_the_mod_takes_the_marker_out(self):
        mod = hooks.rewrite_prompt({"prompt": f"letter to {{{{{NAME}}}}}", "session_id": "S1", "cwd": ""})
        self.assertRegex(mod["text"], r"\Aletter to " + REF_RE.pattern + r"\Z")

    def test_a_marker_from_the_client_or_a_template_stays_text(self):
        self.assertEqual(_prompt(f"letter to {{{{{NAME}}}}}", source="scheduled"), {})
        self.assertFalse(terms.MARKED.exists())
        self.assertEqual(_prompt("set {{ .Values.image.tag }} and {{ item }}"), {})
        self.assertFalse(terms.MARKED.exists())


class LeakTests(_Base):
    def _cli(self, *argv: str) -> str:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main(list(argv))
            except SystemExit:
                pass
        return out.getvalue() + err.getvalue()

    def test_status_list_audit_report_and_terms_show_no_term(self):
        _prompt(f"/maisecrets:term add {NAME} | Testowsk*")
        _bash("Pan Testowskiego")
        _prompt("see {{Anna Testowska}}")
        for argv in (("list",), ("status",), ("audit",), ("report",), ("report", "last"), ("terms",), ("rules",)):
            with self.subTest(argv):
                self.assertNoTerm(self._cli(*argv).replace("testowska", ""), "maisecrets " + " ".join(argv))
        self.assertIn("terms: 1 of your own, 0 from 0 team file(s), 1 marked in prompts", self._cli("status"))
        self.assertNoTerm(_home_text(), "a file of the home")

    def test_suggest_prints_names_only_to_a_terminal(self):
        tmp = Path(tempfile.mkdtemp(prefix="suggest-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        doc = tmp / "letter.txt"
        doc.write_text(f"Sehr geehrter Herr {NAME},\nPan Testowskiego i Testowskiej.\nName: Anna Kowalska\n",
                       encoding="utf-8")
        piped = self._cli("terms", "suggest", str(doc))
        self.assertIn("candidate(s)", piped)
        self.assertNoTerm(piped, "suggest into a pipe")
        buf = io.StringIO()
        buf.isatty = lambda: True          # a terminal
        with contextlib.redirect_stdout(buf):
            cli.main(["terms", "suggest", str(doc)])
        shown = buf.getvalue()
        self.assertIn(f"{NAME} | Testowski*", shown, "Testowski, Testowskiego, Testowskiej: one stem")
        self.assertNotIn("Pan ", shown, "a salutation is no part of a name")
        self.assertIn("Anna Kowalska", shown)
        self.assertIn("Nothing was written", shown)
        self.assertFalse(terms.PERSONAL.exists())


class EndToEndTests(_Base):
    """The path of a new user, through the real entry point (hooks/dispatch.py) in child processes with the temp
    home: one typed command, then the next tool result is masked."""

    def run_hook(self, event: str, payload: dict) -> dict:
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=json.dumps(payload),
                           capture_output=True, text=True, timeout=60, env=dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def test_one_typed_command_then_the_next_tool_output_is_masked(self):
        start = self.run_hook("session-start", {"hook_event_name": "SessionStart", "session_id": "E1", **CLAUDE})
        self.assertNoTerm(json.dumps(start), "the session start")
        added = self.run_hook("user-prompt", {"hook_event_name": "UserPromptSubmit", "session_id": "E1",
                                              "source": "user", "transcript_path": "", **CLAUDE,
                                              "prompt": f"/maisecrets:term add {NAME}"})
        self.assertEqual(added["decision"], "block")
        self.assertIn("is on your list now as NAME_1", added["reason"])
        result = self.run_hook("post-tool", {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                             "session_id": "E1", "transcript_path": "", **CLAUDE,
                                             "tool_input": {"command": "cat crm-export.txt"},
                                             "tool_response": {"stdout": f"Customer: {NAME}\n", "stderr": ""}})
        shown = result["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertRegex(shown, r"\ACustomer: " + REF_RE.pattern + r"\n\Z")
        self.assertIn("NAME_c", result["systemMessage"], "the person sees what was replaced")
        call = self.run_hook("pre-tool", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "E1",
                                          "transcript_path": "", **CLAUDE, "cwd": "/tmp",
                                          "tool_input": {"command": f"echo {REF_RE.search(shown).group()}"}})
        self.assertNotEqual(call.get("hookSpecificOutput", {}).get("permissionDecision"), "deny")
        self.assertNoTerm(json.dumps(call), "the tool call")


if __name__ == "__main__":
    unittest.main()
