"""The one entry of every client (commands/maisecrets.md and commands/ms.md): `/maisecrets NAME ARGS` (Cowork and the
mod's /maisecrets in the terminal), `/ms NAME ARGS` (Cowork, and the personal shortcut in the terminal),
`/maisecrets:maisecrets NAME ARGS` and `/maisecrets:ms NAME ARGS` (the plugin's names in the terminal). Each path reads
them as `/maisecrets:NAME ARGS` (prompt_commands.canonical). The single command files are hidden from the menus
(`user-invocable: false`), except where the person alone may start them.

Measured on Claude Code 2.1.330: a hidden command that the person types is refused by the client ("This skill can only
be invoked by Claude"), and the mod's command.run hook sees it first (tests/mod.test.ts).

Synthetic values only.
Run: python3 -m unittest tests.test_entry -v
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, events, hooks, prompt_commands  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CODEX  # noqa: E402

SESSION = "0b6f1c2e-0000-4000-8000-0000000000e1"
NAME = "Wibbleton" + " Quorrel"                         # a synthetic person
PASSWORD = "Kx7-" + "plmQ29zr"
KEY = "SECRET" + "_c1"
ENTRY_FORMS = ("/maisecrets {}", "/ms {}", "/maisecrets:maisecrets {}", "/maisecrets:ms {}")

# each command file and who may start it: "entry" (the person, in every client), "person" (the person only, and the
# menu shows it), "model" (hidden from the menus: the person reaches it through the entry, the model through its name)
INVOCABLE = {
    "maisecrets": "entry", "ms": "entry",
    # the AI may not start these: a report or a login that binds a claude.ai connector is the person's act
    "report": "person", "sref": "person",
    # a person-only change in these is the prompt hook's answer to the typed text; the file itself only shows
    "demo": "model", "not-a-secret": "model", "term": "model", "settings": "model", "forget": "model", "ner": "model",
    "audit": "model", "guard": "model", "list": "model", "put": "model", "rules": "model", "send": "model",
    "shortcut": "model", "status": "model",
}


def _frontmatter(name: str) -> list[str]:
    text = (ROOT / "commands" / f"{name}.md").read_text(encoding="utf-8")
    return text.split("\n---\n", 1)[0].splitlines()


class CanonicalTests(unittest.TestCase):
    def test_each_entry_form_is_the_colon_form(self):
        for form in ENTRY_FORMS:
            for args, colon in (("status test", "/maisecrets:status test"), ("Term add " + NAME,
                                                                             "/maisecrets:term add " + NAME),
                                ("not-a-secret undo " + KEY, "/maisecrets:not-a-secret undo " + KEY),
                                ("list", "/maisecrets:list")):
                with self.subTest(form=form, args=args):
                    self.assertEqual(prompt_commands.canonical("  " + form.format(args) + " "), colon)

    def test_other_prompts_stay_as_they_are(self):
        for prompt in ("/maisecrets", "/ms", "/maisecrets:maisecrets", "/maisecrets:ms", "/maisecrets:status",
                       "/maisecrets wibble on", "/ms secret-hygiene", "/msx list", "/mss list", "/maisecretsx list",
                       "/maisecrets:list list", "please run /ms list", "/ms list\nand more", "maisecrets: list", None):
            with self.subTest(prompt=prompt):
                self.assertIs(prompt_commands.canonical(prompt), prompt)

    def test_the_entry_alone_is_known(self):
        for prompt in ("/maisecrets", "/ms ", "/maisecrets:maisecrets", " /maisecrets:ms"):
            self.assertTrue(prompt_commands.entry_alone(prompt), prompt)
        for prompt in ("/ms list", "/msx", "/maisecrets:status"):
            self.assertFalse(prompt_commands.entry_alone(prompt), prompt)

    def test_codex_keeps_its_prompt(self):
        payload = {"prompt": "/ms list", **CODEX}
        self.assertIs(prompt_commands.with_canonical(payload), payload)
        self.assertEqual(prompt_commands.with_canonical({"prompt": "/ms list", "prompt_id": "p"})["prompt"],
                         "/maisecrets:list")


class _HookBase(unittest.TestCase):
    def setUp(self):
        (Path(HOME) / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
        for f in ("index.json", "vault.json", "terms.txt", "events.log", "allowed.json", "typed.json"):
            (Path(HOME) / f).unlink(missing_ok=True)
        hooks._live_cache.clear()
        self.addCleanup(hooks._live_cache.clear)
        self.claude_dir = tempfile.mkdtemp(prefix="ms-claude-config-")
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.claude_dir})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDE_CODE_ENTRYPOINT", None)
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **k: None)

    def hook(self, prompt: str, source: str | None = "user", **client) -> dict:
        hooks._live_cache.clear()
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": SESSION,
                   "transcript_path": "", "cwd": "", **(client or {"prompt_id": "p1"})}
        if source is not None:
            payload["source"] = source
        return hooks.user_prompt(payload)

    def mod(self, prompt: str) -> dict:
        hooks._live_cache.clear()
        return hooks.rewrite_prompt({"prompt": prompt, "session_id": SESSION, "cwd": "", "origin": "composer"})


class PersonOnlyThroughTheEntryTests(_HookBase):
    """A command only the person may give, typed through the entry, counts as typed: on the hook path (Cowork, a
    client without the mod) and on the mod's path."""

    def test_a_term_add_through_each_entry_form_is_the_hooks_answer(self):
        for form in ENTRY_FORMS:
            with self.subTest(form=form):
                (Path(HOME) / "terms.txt").unlink(missing_ok=True)
                out = self.hook(form.format("term add " + NAME))
                self.assertEqual(out["decision"], "block")
                self.assertIn("on your list now", out["reason"])
                self.assertNotIn(NAME, out["reason"])
                self.assertNotIn(NAME, self.mod(f"write to {NAME} today").get("text", NAME), "the term was added")

    def test_a_forget_through_the_entry_leaves_the_typed_note_the_cli_takes(self):
        Vault().put(PASSWORD, "SECRET", "manual", session=SESSION)
        out = self.hook("/ms forget " + KEY)
        self.assertNotEqual(out.get("decision"), "block", out)
        self.assertTrue(events.take_typed_forget(KEY, [SESSION]))

    def test_a_login_through_the_entry_leaves_the_typed_note(self):
        self.hook("/maisecrets:maisecrets sref login Team_GW")
        self.assertTrue(events.take_typed_login("Team_GW", [SESSION]))

    def test_a_prompt_the_person_did_not_type_changes_nothing(self):
        out = self.hook("/ms term add " + NAME, source="cron")
        self.assertEqual(out["decision"], "block")
        self.assertFalse((Path(HOME) / "terms.txt").exists() and NAME in (Path(HOME) / "terms.txt").read_text())

    def test_the_mod_answers_each_entry_form_as_the_colon_form(self):
        for form in ENTRY_FORMS:
            with self.subTest(form=form):
                self.assertEqual(self.mod(form.format("list")),
                                 {"run": {"argv": ["list", "--args-stdin"], "stdin": ""}})
                self.assertEqual(self.mod(form.format("status test")), {"entry": "status test"})
        # the mod gives the entry alone (`/ms`, `/maisecrets:ms`) as `/maisecrets:maisecrets` (tests/mod.test.ts)
        self.assertEqual(self.mod("/maisecrets:maisecrets"), {"run": {"argv": ["entry"], "view": "panel"}})

    def test_codex_keeps_its_answer_for_the_slash_form(self):
        # Codex has no slash commands: its prompt is not read as the entry, and it adds nothing
        out = self.hook("/ms term add " + NAME, source=None, **CODEX)
        self.assertEqual(out.get("decision"), "block")
        self.assertNotIn("on your list now", out["reason"])
        self.assertFalse((Path(HOME) / "terms.txt").exists() and NAME in (Path(HOME) / "terms.txt").read_text())


class ForeignMsTests(_HookBase):
    """A /ms of the person's own (not the maisecrets shortcut) keeps `/ms NAME`: maisecrets does not take it over."""

    def own_ms(self, text: str) -> None:
        d = Path(self.claude_dir, "commands")
        d.mkdir(parents=True, exist_ok=True)
        (d / "ms.md").write_text(text, encoding="utf-8")

    def test_a_foreign_ms_keeps_its_prompt(self):
        self.own_ms("---\ndescription: my own\n---\nmy own command\n")
        self.assertTrue(prompt_commands.foreign_ms())
        payload = {"prompt": "/ms term add " + NAME, "prompt_id": "p"}
        self.assertIs(prompt_commands.with_canonical(payload), payload)
        out = self.hook("/ms term add " + NAME)
        self.assertNotIn("on your list now", out.get("reason", ""))
        self.assertEqual(hooks.rewrite_prompt({"prompt": "/maisecrets:list", "session_id": SESSION, "cwd": "",
                                               "origin": "composer", "via_ms": True}), {})
        # the other entry forms are maisecrets' own
        self.assertEqual(prompt_commands.with_canonical({"prompt": "/maisecrets list", "prompt_id": "p"})["prompt"],
                         "/maisecrets:list")

    def test_the_shortcut_and_no_ms_at_all_are_the_entry(self):
        self.assertFalse(prompt_commands.foreign_ms())
        self.assertEqual(self.mod("/ms list"), {"run": {"argv": ["list", "--args-stdin"], "stdin": ""}})
        from maisecrets import cli
        self.own_ms(cli._shortcut_text())
        self.assertFalse(prompt_commands.foreign_ms())
        self.assertEqual(hooks.rewrite_prompt({"prompt": "/maisecrets:list", "session_id": SESSION, "cwd": "",
                                               "origin": "composer", "via_ms": True}),
                         {"run": {"argv": ["list", "--args-stdin"], "stdin": ""}})


class CommandRouteTests(_HookBase):
    """The mod's command.run route (its own /maisecrets NAME, a hidden /maisecrets:NAME): the engine stamps every local
    command run `composer`, so Python makes no change there that only the person's own prompt may make (C22)."""

    def route(self, prompt: str) -> dict:
        hooks._live_cache.clear()
        return hooks.rewrite_prompt({"prompt": prompt, "session_id": SESSION, "cwd": "",
                                     "origin": prompt_commands.COMMAND_ROUTE})

    def test_a_person_only_change_is_not_made_and_names_the_prompt_to_send(self):
        config = (Path(HOME) / "config.json").read_text()
        for prompt, form in (("/maisecrets:settings ssh_consent on", "maisecrets: set ssh_consent on"),
                             ("/maisecrets:term add " + NAME, "maisecrets: term add " + NAME),
                             ("/maisecrets:not-a-secret " + KEY, "maisecrets: not a secret " + KEY),
                             ("/maisecrets:demo on", "maisecrets: demo on"),
                             ("/maisecrets:forget import:abc", "maisecrets: forget import:abc"),
                             ("/maisecrets:ner local", "maisecrets: ner local"),
                             ("/maisecrets:forget " + KEY, "/maisecrets:maisecrets forget " + KEY),
                             ("/maisecrets:sref login gw", "/maisecrets:sref login gw"),
                             ("/maisecrets:report incident", "maisecrets: report incident")):
            with self.subTest(prompt):
                out = self.route(prompt)
                self.assertTrue(out["drop"].endswith("Send it as a prompt: " + form), out)
                self.assertIn("Nothing was changed", out["drop"])
        self.assertEqual((Path(HOME) / "config.json").read_text(), config)
        self.assertFalse((Path(HOME) / "terms.txt").exists())
        from maisecrets import demo
        self.assertFalse(demo.active(SESSION))
        self.assertFalse(events.take_typed_forget(KEY, [SESSION]))
        self.assertFalse(events.take_typed_login("gw", [SESSION]))

    def test_the_refusal_names_the_text_form_of_a_change(self):
        # outside Cowork too: `/maisecrets NAME` reaches only command.run, so the slash form would be refused again
        for prompt, form in (("/maisecrets:term add " + NAME, "maisecrets: term add " + NAME),
                             ("/maisecrets:settings ssh_consent on", "maisecrets: set ssh_consent on"),
                             ("/maisecrets:settings max_keys_per_session abc",
                              "maisecrets: set max_keys_per_session abc"),
                             ("/maisecrets:ner Team_GW", "maisecrets: ner Team_GW"),
                             ("/maisecrets:demo on", "maisecrets: demo on")):
            with self.subTest(prompt):
                out = self.route(prompt)
                self.assertTrue(out["drop"].endswith("Send it as a prompt: " + form), out)
                # the person types it: the stamp composer is no proof, so nothing goes into the input box
                self.assertEqual(sorted(out), ["drop"], out)
        # the person's own prompt of the named form makes the change (the mod sends it as composer, not the route)
        self.assertIn("on your list now", self.mod("maisecrets: term add " + NAME).get("drop", ""))

    def test_only_a_login_or_a_logout_may_wait_in_the_input_box(self):
        # live probe 2026-11-22: `/maisecrets sref login` and `logout` typed were refused. A logout loosens nothing;
        # a login needs the consent in the browser and binds a connector only with its proof
        for form in ("/maisecrets:sref login", "/maisecrets:sref login gw", "/maisecrets:sref logout",
                     "/maisecrets:sref logout gw"):
            with self.subTest(form):
                out = self.route(form)
                self.assertEqual(out.get("box"), form, out)
                self.assertTrue(out["drop"].endswith("Send it as a prompt: " + form), out)
        # a forget ends the search for a value, and every other change loosens or sets something: named only
        for prompt in ("/maisecrets:forget " + KEY, "/maisecrets:settings ssh_consent on", "/maisecrets:ner local",
                       "/maisecrets:not-a-secret " + KEY, "/maisecrets:sref login gw; status"):
            with self.subTest(prompt):
                self.assertNotIn("box", self.route(prompt))
        # a server name that is a stored value: the refusal names the type, and nothing waits in the box
        Vault().put(PASSWORD, "SECRET", "manual", session=SESSION)
        for form in ("/maisecrets:sref login " + PASSWORD, "/maisecrets:sref logout " + PASSWORD):
            with self.subTest(form):
                out = self.route(form)
                self.assertNotIn("box", out)
                self.assertNotIn(PASSWORD, json.dumps(out))
        self.assertFalse(events.take_typed_login("gw", [SESSION]))

    def test_a_text_form_the_prompt_hook_does_not_parse_keeps_the_slash_form(self):
        for prompt, form in (("/maisecrets:ner local --model x", "/maisecrets:maisecrets ner local --model x"),
                             ("/maisecrets:ner local; status", "/maisecrets:maisecrets ner local; status")):
            with self.subTest(prompt):
                out = self.route(prompt)
                self.assertTrue(out["drop"].endswith("Send it as a prompt: " + form), out)

    def test_a_value_or_placeholder_is_no_argument_to_copy(self):
        # a copied placeholder would store its own text, not the value: the person types the words
        token = "glpat-" + "ROUTExxxx1234567890abcd"         # split: the repository scan stays clean
        ref = "\u27e6NAME" + "_c9\u27e7"
        for prompt, form in (("/maisecrets:term add " + token, "maisecrets: term add SECRET"),
                             ("/maisecrets:term add " + ref + " Q", "maisecrets: term add NAME"),
                             ("/maisecrets:settings ner_token " + token, "maisecrets: set ner_token SECRET")):
            with self.subTest(form):
                out = self.route(prompt)
                self.assertNotIn(token, json.dumps(out))
                self.assertNotIn("\u27e6", out["drop"])
                self.assertTrue(out["drop"].endswith(f"Send it as a prompt: {form} (type the words yourself)"), out)

    def test_any_other_command_runs_and_counts_as_no_typed_prompt(self):
        self.assertEqual(self.route("/maisecrets:list"), {"run": {"argv": ["list", "--args-stdin"], "stdin": ""}})
        self.assertEqual(self.route("/maisecrets:status test"), {"entry": "status test"})
        with mock.patch.object(hooks, "user_prompt", wraps=hooks.user_prompt) as seen:
            self.route("/maisecrets:list")
        self.assertEqual(seen.call_args.args[0]["source"], "mod-command-run", "never a typed source")


class InvocabilityTests(unittest.TestCase):
    """Every command file has a deliberate invocability, and every command stays reachable by the person."""

    def test_every_command_file_has_its_decision(self):
        self.assertEqual(sorted(INVOCABLE), sorted(p.stem for p in (ROOT / "commands").glob("*.md")))
        for name, who in INVOCABLE.items():
            with self.subTest(name):
                fm = _frontmatter(name)
                hidden, user_only = "user-invocable: false" in fm, "disable-model-invocation: true" in fm
                self.assertFalse(hidden and user_only, "reachable by nobody")
                self.assertEqual((hidden, user_only), {"entry": (False, True), "person": (False, True),
                                                       "model": (True, False)}[who])

    def test_the_entry_knows_every_other_command(self):
        self.assertEqual(sorted(prompt_commands.COMMANDS),
                         sorted(n for n in INVOCABLE if n not in prompt_commands.ENTRIES))
        self.assertEqual(prompt_commands.ENTRIES, tuple(n for n, w in INVOCABLE.items() if w == "entry"))

    def test_the_two_entry_files_are_the_same(self):
        self.assertEqual((ROOT / "commands" / "maisecrets.md").read_text(encoding="utf-8"),
                         (ROOT / "commands" / "ms.md").read_text(encoding="utf-8"))

    def test_the_entry_description_names_every_command(self):
        desc = next(line for line in _frontmatter("maisecrets") if line.startswith("description:"))
        for name in prompt_commands.COMMANDS:
            self.assertRegex(desc, rf"(?<![\w-]){re.escape(name)}(?![\w-])", name)

    def test_the_refusals_read_every_slash_form(self):
        # a tool call that carries a command only the person may give is refused in each form the hook reads
        from maisecrets import demo, forms, not_a_secret, settings, value_files
        self.assertEqual(value_files._SLASH, forms.SLASH)
        for form in ENTRY_FORMS + ("/maisecrets:{}",):
            with self.subTest(form=form):
                self.assertTrue(demo.in_a_command(f"claude -p '{form.format('demo on')}'"))
                change = form.format("settings ssh_consent on")
                self.assertTrue(settings.IN_A_COMMAND_RE.search(f"claude -p '{change}'"))
                self.assertTrue(settings.IN_A_COMMAND_RE.search(f"claude -p '{form.format('term remove Bob')}'"))
                self.assertTrue(settings.IN_A_COMMAND_RE.search(f"claude -p '{form.format('ner local')}'"))
                weaker = form.format("not-a-secret " + KEY)
                self.assertTrue(not_a_secret.IN_A_COMMAND_RE.search(f"claude -p '{weaker}'"))
                self.assertTrue(value_files.removal_in_command(f"claude -p '{form.format('forget import:abc')}'"))
        # a path that ends in /ms is no command
        self.assertFalse(demo.IN_A_COMMAND_RE.search("ls /tmp/ms demo"))

    def test_the_lint_refuses_a_command_reachable_by_nobody(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import lint_plugin
        root = Path(tempfile.mkdtemp(prefix="ms-lint-"))
        (root / "commands").mkdir()
        for both in ('disable-model-invocation: true\nuser-invocable: false\n',
                     'disable-model-invocation: True\nuser-invocable: "false"  # hidden\n',
                     "disable-model-invocation: 'true'   \nuser-invocable: False\n"):
            with self.subTest(both):
                (root / "commands" / "x.md").write_text('---\ndescription: "x"\n' + both + '---\nbody\n',
                                                        encoding="utf-8")
                errors, _ = lint_plugin.check_frontmatter(root)
                self.assertTrue(any("unreachable" in e for e in errors), errors)
        (root / "commands" / "x.md").write_text('---\ndescription: "x"\ndisable-model-invocation: true\n'
                                                'user-invocable: true\n---\nbody\n', encoding="utf-8")
        self.assertFalse(any("unreachable" in e for e in lint_plugin.check_frontmatter(root)[0]))


class PendingTests(unittest.TestCase):
    """The panel and the overview offer a blocked prompt that waits; neither takes it (/ms alone sends nothing)."""

    def test_the_panel_status_says_whether_a_prompt_waits_and_takes_nothing(self):
        from maisecrets import hub
        session = "0b6f1c2e-0000-4000-8000-0000000000e9"
        path = hooks._pending_path(session)
        path.unlink(missing_ok=True)
        self.addCleanup(path.unlink, missing_ok=True)
        self.assertFalse(hub.pane_status(session)["pending"])
        hooks._save_pending("deploy with the key", session)
        self.assertTrue(hooks.pending_waits(session))
        self.assertTrue(hub.pane_status(session)["pending"])
        self.assertEqual(hooks.take_pending(session), "deploy with the key", "the status took nothing")


class EntryCliTests(unittest.TestCase):
    def test_every_name_runs_its_command(self):
        called = []
        with mock.patch.dict(cli.COMMANDS, {n: (lambda a, n=n: called.append((n, a)) or 0) for n in cli.COMMANDS}):
            for name in ("status", "list", "audit", "rules", "guard", "shortcut", "forget", "settings", "sref"):
                called.clear()
                self.assertEqual(cli.cmd_entry([name, "x"]), 0)
                self.assertEqual(called, [(name, ["x"])])
            # the AI may not start a report or a login, and the entry file runs through the model
            for args in (["report"], ["report", "bug", "x"], ["sref", "login", "gw"], ["sref", "LOGOUT"]):
                called.clear()
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(cli.cmd_entry(args), 2)
                self.assertEqual(called, [])
                self.assertIn("as your own prompt", out.getvalue())
                self.assertNotIn("Cowork", out.getvalue())

    def test_in_cowork_the_refusal_names_the_text_form_and_no_slash_form(self):
        # Cowork answers sref only in its text form (prompt_commands._cowork_sref): a slash form there does nothing
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "remote_cowork"}):
            for args, form in ((["sref", "login", "gw"], prompt_commands.COWORK_SREF_LOGIN),
                               (["sref", "LOGOUT"], "maisecrets: sref logout as your own prompt"),
                               (["report", "bug", "x"], "maisecrets: report incident as your own prompt")):
                with self.subTest(args):
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        self.assertEqual(cli.cmd_entry(args), 2)
                    said = out.getvalue()
                    self.assertIn(form, said)
                    self.assertNotIn("/", said.replace("maisecrets: ", ""))
                    self.assertNotIn("gw", said)
                    self.assertNotIn("start a login. Send", said)


if __name__ == "__main__":
    unittest.main()
