"""Values from your own tools (maisecrets/value_import.py, C26): the JSON-lines contract, `maisecrets values import`,
the caps that keep an agent's import from slowing every hook or pushing out the person's values, the lifetime of an
imported value, the setting value_files that only a typed prompt changes, the session-start import, the per-import
view in /maisecrets:list and its removal with /maisecrets:forget import:NAME, and the phrase match of the hooks for a
stored value of several words.

Every value is made up; the names are invented and name nobody. A placeholder is built at run time (ref()), so the
file holds none."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import cli, hooks, value_import, vault  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
NAME = "Quilla Examplestein"                      # an invented name of two words
LONG_NAME = "Quilla Mara Examplestein"            # three words that start like NAME
SHAPELESS = "synthetic-" + "Zq7" * 4 + "-value"      # no known shape


def ref(key: str) -> str:
    return OPEN + key + CLOSE


def _clean() -> None:
    CONFIG.write_text(json.dumps(TEST_CONFIG))
    for name in ("index.json", "vault.json", ".values-state", "audit.log", "events.log"):
        try:
            (HOME / name).unlink()
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


def lines(*objs) -> str:
    return "\n".join(o if isinstance(o, str) else json.dumps(o) for o in objs) + "\n"


def redact(text: str, session: str = "S1") -> str:
    hooks._live_cache.clear()
    return hooks._exact_redact(text, Vault(), session, {"n": 0}, [], [], [])


def synth_names(n: int) -> list[dict]:
    return [{"value": f"Synth{i:05d} Persona", "type": "NAME"} for i in range(n)]


class Base(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        self.tmp = Path(tempfile.mkdtemp(prefix="values-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def file(self, text: str, name: str = "names.jsonl") -> Path:
        p = self.tmp / name
        p.write_text(text, encoding="utf-8")
        return p

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(list(args))
        return rc, out.getvalue(), err.getvalue()


class Contract(Base):
    def test_a_line_takes_a_value_and_a_type_and_the_type_defaults_to_secret(self):
        items, refused, dup = value_import.parse(lines({"value": NAME, "type": "name"}, {"value": SHAPELESS}, "",
                                                       "# a comment"))
        self.assertEqual([(v, t) for v, t, _n in items], [(NAME, "NAME"), (SHAPELESS, "SECRET")])
        self.assertEqual((refused, dup), ([], 0))

    def test_a_refused_line_is_named_by_number_and_reason_never_by_its_text(self):
        text = lines({"value": NAME, "type": "NAME"}, "not json {", ["a", "list"], {"type": "NAME"},
                     {"value": "Kurz1"}, {"value": "x" * 600}, {"value": SHAPELESS, "type": "Quillastein"},
                     {"value": "lowercaseword"}, {"value": NAME, "type": "NAME"})
        items, refused, dup = value_import.parse(text)
        self.assertEqual(len(items), 1)
        self.assertEqual(dup, 1)
        self.assertEqual([n for n, _why in refused], [2, 3, 4, 5, 6, 7, 8])
        reasons = dict(refused)
        self.assertEqual(reasons[2], "not JSON")
        self.assertIn("too short", reasons[5])
        self.assertIn("too long", reasons[6])
        self.assertIn("unknown type", reasons[7])
        self.assertIn("ordinary word", reasons[8])
        result = value_import.Result(source="names.jsonl", new={"NAME": 1}, refused=refused, duplicates=dup)
        line = value_import.summary(result)
        self.assertTrue(line.startswith("imported 1 value(s) from names.jsonl (NAME 1)"), line)
        self.assertIn("7 line(s) refused: line 2 not JSON; line 3 not a JSON object", line)
        self.assertIn("and 2 more", line)
        for text_of_a_line in (NAME, SHAPELESS, "Quillastein", "lowercaseword", "Kurz1"):
            self.assertNotIn(text_of_a_line, line + json.dumps(refused))

    def test_a_name_with_two_spaces_is_the_same_name_and_a_secret_keeps_its_spaces(self):
        items, _r, _d = value_import.parse(lines({"value": "Quilla  Examplestein ", "type": "NAME"},
                                                 {"value": "pass  phrase  synth"}))
        self.assertEqual([v for v, _t, _n in items], [NAME, "pass  phrase  synth"])


class ImportCommand(Base):
    def test_import_prints_counts_and_masks_the_values_in_tool_output(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}, {"value": SHAPELESS}, {"value": "short"}))
        rc, out, _ = self.run_cli("values", "import", str(f))
        self.assertEqual(rc, 1, "a refused line makes the exit code 1, for a script")
        self.assertIn("imported 2 value(s) from names.jsonl (SECRET 1, NAME 1), 1 line(s) refused: line 3 too short",
                      out)
        self.assertIn("/maisecrets:forget import:names.jsonl removes it", out)
        self.assertNotIn(NAME, out)
        self.assertNotIn(SHAPELESS, out)
        masked = redact(f"owner {NAME}, token {SHAPELESS}")
        self.assertNotIn("Examplestein", masked)
        self.assertNotIn(SHAPELESS, masked)
        self.assertTrue(masked.startswith(f"owner {ref('NAME_c1')}, token {OPEN}SECRET_c"), masked)

    def test_a_second_import_of_the_same_file_stores_nothing_new(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        self.run_cli("values", "import", str(f))
        rc, out, _ = self.run_cli("values", "import", str(f))
        self.assertEqual(rc, 0)
        self.assertIn("imported 0 value(s) from names.jsonl, 1 already stored", out)
        self.assertEqual(len(Vault().list()), 1)

    def test_a_file_that_cannot_be_used_names_why_and_stores_nothing(self):
        for name, data, why in (("big.jsonl", b"{}\n" * (value_import.MAX_FILE_BYTES // 3 + 1), "over the limit"),
                                ("bin.jsonl", b"\xff\xfe\x00", "not UTF-8")):
            p = self.tmp / name
            p.write_bytes(data)
            rc, _out, err = self.run_cli("values", "import", str(p))
            self.assertEqual(rc, 1)
            self.assertIn(why, err)
        rc, _out, err = self.run_cli("values", "import", str(self.tmp / "missing.jsonl"))
        self.assertIn("cannot be read", err)
        self.assertEqual(Vault().list(), [])

    def test_the_usage_names_the_contract(self):
        rc, _out, err = self.run_cli("values", "bogus")
        self.assertEqual(rc, 2)
        self.assertIn('{"value": "...", "type": "NAME"}', err)


class Caps(Base):
    """The agent may run the import (it only adds); the caps keep it from slowing every hook or filling the vault."""

    def test_at_most_max_values_per_file_are_read(self):
        with mock.patch.object(value_import, "MAX_VALUES_PER_FILE", 20):
            result = value_import.import_file(self.file(lines(*synth_names(30))))
        self.assertEqual(result.stored, 20)
        self.assertIn("line 21 and later not read: at most 20 values per import", value_import.summary(result))

    def test_a_full_vault_refuses_the_import_and_drops_nothing_it_holds(self):
        mine = Vault().put(SHAPELESS, "SECRET", "manual")
        values = synth_names(12)
        with mock.patch.object(value_import, "MAX_IMPORTED", 10):
            first = value_import.import_file(self.file(lines(*values[:8]), "a.jsonl"))
            second = value_import.import_file(self.file(lines(*values[8:]), "b.jsonl"))
            third = value_import.import_file(self.file(lines(*values[10:]), "c.jsonl"))
        self.assertEqual((first.stored, second.stored, third.stored), (8, 2, 0))
        self.assertIn("the vault holds 10 imported values, the limit", value_import.summary(third))
        entries = {e.key: e for e in Vault().list()}
        self.assertIn(mine.key, entries, "the person's own value stays")
        self.assertFalse(entries[mine.key].purged)
        self.assertEqual(sum(1 for e in entries.values() if e.source == "a.jsonl" and not e.purged), 8)

    def test_the_import_holds_the_vault_lock_for_one_batch_at_a_time(self):
        sizes = []
        real = Vault.put_many

        def spy(self, items, *a, **kw):
            sizes.append(len(items))
            return real(self, items, *a, **kw)
        with mock.patch.object(Vault, "put_many", spy):
            value_import.import_file(self.file(lines(*synth_names(60))))
        self.assertEqual(sum(sizes), 60)
        self.assertLessEqual(max(sizes), 25, "a hook waits for one batch, never for the whole file")

    def test_an_import_never_shortens_or_retypes_a_value_the_vault_holds(self):
        mine = Vault().put(NAME, "NAME", "manual")
        before = Vault()._index["entries"][mine.key]
        result = value_import.import_file(self.file(lines({"value": NAME, "type": "SECRET"})))
        after = Vault()._index["entries"][mine.key]
        self.assertEqual(result.known, 1)
        self.assertEqual((after["type"], after["source"]), ("NAME", ""))
        self.assertGreaterEqual(after["expires"], before["expires"])


class Lifetime(Base):
    def test_an_imported_value_lives_max_ttl_and_a_use_does_not_cut_it_to_its_types_lifetime(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        entry = Vault().list()[0]
        month = load_config()["max_ttl_seconds"]
        self.assertGreater(entry.expires - time.time(), month - 60)
        redact(f"hello {NAME}")                  # a hit admits the entry; a renewal must not cut it
        v = Vault()
        v._touch(v.list()[0])
        entry = Vault().list()[0]
        self.assertGreater(entry.uses, 0)
        self.assertGreater(entry.expires - time.time(), month - 60, "a use keeps the import's lifetime")

    def test_a_person_with_a_shorter_cap_gets_the_shorter_lifetime(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "max_ttl_seconds": 7200}))
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        self.assertLess(Vault().list()[0].expires - time.time(), 7201)


class SeeAndRemove(Base):
    def test_list_shows_each_import_with_counts_and_forget_removes_it(self):
        Vault().put(SHAPELESS, "SECRET", "manual")
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"},
                                                 {"value": "other-" + SHAPELESS})))
        rc, out, _ = self.run_cli("list")
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"import:names\.jsonl +2 value\(s\) \(SECRET 1, NAME 1\), imported 0m ago, "
                              r"expire in 29d")
        self.assertIn("SECRET_c1", out, "the person's own value keeps its row")
        self.assertNotIn("NAME_c1", out, "an import is one line, not a row per value")
        rc, out, _ = self.run_cli("forget", "import:names.jsonl")
        self.assertEqual(rc, 0)
        self.assertIn("import:names.jsonl: 2 value(s) deleted", out)
        self.assertEqual([e.key for e in Vault().list()], ["SECRET_c1"])
        self.assertEqual(redact(f"hello {NAME}"), f"hello {NAME}")
        rc, out, _ = self.run_cli("forget", "import:names.jsonl")
        self.assertEqual(rc, 1)
        self.assertIn("not found", out)

    def test_values_remove_is_the_same_as_forget_import(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        rc, out, _ = self.run_cli("values", "remove", "import:names.jsonl")
        self.assertEqual(rc, 0, out)
        self.assertEqual(Vault().list(), [])

    def test_two_files_of_one_name_are_two_imports(self):
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir()
        b.mkdir()
        (a / "names.jsonl").write_text(lines({"value": NAME, "type": "NAME"}))
        (b / "names.jsonl").write_text(lines({"value": LONG_NAME, "type": "NAME"}))
        first = value_import.import_file(a / "names.jsonl")
        second = value_import.import_file(b / "names.jsonl")
        self.assertEqual(first.source, "names.jsonl")
        self.assertRegex(second.source, r"names\.jsonl~[0-9a-f]{6}")
        self.assertEqual(value_import.import_file(a / "names.jsonl").source, "names.jsonl", "a file keeps its name")


class Phrases(Base):
    def put(self, *values: str, type_: str = "NAME") -> None:
        v = Vault()
        for value in values:
            v.put(value, type_, "manual")

    def test_a_stored_name_of_two_words_is_found_in_running_text(self):
        self.put(NAME)
        for text in (f"Report by {NAME}.", f'"author": "{NAME}"', f"set owner={NAME} today", f"({NAME})",
                     "Quilla\nExamplestein wrote it", f"{NAME}, {NAME}!"):
            with self.subTest(text=text):
                out = redact(text)
                self.assertNotIn("Examplestein", out)
                self.assertNotIn("Quilla", out)
                self.assertIn(ref("NAME_c1"), out)

    def test_the_longest_stored_phrase_wins_and_no_part_of_it_stays(self):
        self.put("Quilla Mara", LONG_NAME, NAME)        # the first is the start of the second
        self.assertEqual(redact(f"{LONG_NAME} and {NAME} and Quilla Mara"),
                         f"{ref('NAME_c2')} and {ref('NAME_c3')} and {ref('NAME_c1')}")

    def test_a_phrase_takes_its_words_before_a_stored_single_word_does(self):
        self.put("Examplestein", NAME)
        self.assertEqual(redact(f"by {NAME} and Examplestein"), f"by {ref('NAME_c2')} and {ref('NAME_c1')}")

    def test_a_different_case_or_a_word_between_is_no_match(self):
        self.put(NAME)
        for text in ("quilla examplestein", "Quilla B. Examplestein", "Quilla Examplesteiner"):
            self.assertEqual(redact(text), text)

    def test_a_value_of_seven_words_is_not_a_phrase_and_still_matches_as_a_line(self):
        seven = "one two three four five six seven-" + "Zq7Zq7"
        self.put(seven, type_="SECRET")
        self.assertEqual(Vault()._index["entries"]["SECRET_c1"]["words"], 0)
        self.assertNotIn(seven, redact(seven))

    def test_the_index_holds_only_keyed_fingerprints_of_a_phrase(self):
        self.put(NAME)
        raw = (HOME / "index.json").read_text()
        for word in ("Quilla", "Examplestein"):
            self.assertNotIn(word, raw)
        meta = json.loads(raw)["entries"]["NAME_c1"]
        self.assertEqual(meta["words"], 2)
        self.assertEqual(meta["head"], Vault().fingerprint("Quilla"))

    def test_the_hits_of_one_text_write_the_index_once_and_a_known_session_not_at_all(self):
        self.put(NAME, LONG_NAME)
        Vault().put(SHAPELESS, "SECRET", "manual")
        text = f"{NAME}, {LONG_NAME} and {SHAPELESS}"
        writes = []
        real = Vault._save_index

        def count(self):
            writes.append(1)
            return real(self)
        with mock.patch.object(Vault, "_save_index", count):
            out = redact(text, "S9")
            self.assertEqual(len(writes), 1, "one write admits every key of the text")
            redact(text, "S9")
            self.assertEqual(len(writes), 1, "the session holds the keys already: no write")
        self.assertNotIn("Examplestein", out)
        entries = Vault()._index["entries"]
        self.assertTrue(all("S9" in entries[k]["sessions"] for k in ("NAME_c1", "NAME_c2", "SECRET_c1")))

    def test_an_agent_report_with_a_stored_name_is_not_passed(self):
        self.put(NAME)
        hooks._live_cache.clear()
        found = hooks._inserted_values(f"summary: {NAME} asked", Vault())
        self.assertEqual([v for v, _r in found], [NAME])


class SingleTokensUnchanged(Base):
    """The phrase pass runs only for stored values of several words: for single-token values the output is the same,
    with and without it, on the same texts."""

    TEXTS = ("token={s} and {s}x and x{s} in ({s}), 'q{s}' \"{s}\"",
             "path/{s}/x?k={s}&z=1 user:{s}@host",
             "{s}\n{s}.\n  {s}  \nkey: {s}")

    def put_values(self, values, type_="SECRET"):
        v = Vault()
        for value in values:
            v.put(value, type_, "manual")

    def test_the_output_is_the_same_with_and_without_the_phrase_pass(self):
        values = [SHAPELESS, "Other" + SHAPELESS[5:], "third-" + SHAPELESS]
        self.put_values(values)
        self.put_values([NAME], "NAME")          # a phrase in the vault, so the pass runs
        for template in self.TEXTS:
            for value in values:
                text = template.format(s=value)
                with self.subTest(text=text):
                    with_pass = redact(text)
                    with mock.patch.object(hooks, "_phrase_spans", lambda *_a: []):
                        without = redact(text)
                    self.assertEqual(with_pass, without)
                    self.assertNotIn(value, with_pass)

    def test_a_vault_without_phrases_costs_no_fingerprint_in_the_phrase_pass(self):
        self.put_values([SHAPELESS])
        calls = []
        real = Vault.fingerprint

        def count(self, value):
            calls.append(value)
            return real(self, value)
        with mock.patch.object(Vault, "fingerprint", count):
            self.assertEqual(hooks._phrase_spans("a b c " * 100, Vault()), [])
        self.assertEqual(calls, [])

    def test_a_phrase_costs_one_fingerprint_per_distinct_word_and_a_few_per_head(self):
        self.put_values([NAME], "NAME")
        text = ("lorem ipsum dolor sit amet " * 400) + f"and {NAME} here"
        calls = []
        real = Vault.fingerprint

        def count(self, value):
            calls.append(value)
            return real(self, value)
        v = Vault()
        with mock.patch.object(Vault, "fingerprint", count):
            spans = hooks._phrase_spans(text, v)
        self.assertEqual(len(spans), 1)
        distinct = len(set(text.split()))
        self.assertLessEqual(len(calls), distinct + 2 * vault.MAX_PHRASE_WORDS)


class ValueFilesSetting(Base):
    def _prompt(self, text: str, client: dict = CLAUDE, **extra) -> dict:
        return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})

    def _files(self) -> list:
        return json.loads(CONFIG.read_text()).get("value_files", [])

    def test_a_typed_prompt_adds_and_removes_a_file(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}), "team names.jsonl")
        out = self._prompt(f"/maisecrets:settings value_files add {f}")
        self.assertNotEqual(out.get("decision"), "block", out)
        self.assertIn("Value files is", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self._files(), [str(f)], "a path with a space stays one file")
        self._prompt(f"maisecrets: set value_files add {f}", CODEX)
        self.assertEqual(len(self._files()), 1, "the same file once")
        self._prompt(f"maisecrets: set value_files remove {f}", CODEX)
        self.assertEqual(self._files(), [])
        out = self._prompt(f"/maisecrets:settings value_files add {self.tmp}")
        self.assertIn("it is a folder", out["reason"])
        out = self._prompt("/maisecrets:settings value_files add names.jsonl")
        self.assertIn("not an absolute path", out["reason"])
        self.assertEqual(self._files(), [])

    def test_only_a_typed_prompt_adds_a_value_file(self):
        f = str(self.tmp / "names.jsonl")
        for text, extra in ((f"/maisecrets:settings value_files add {f}\nand then deploy", {}),
                            (f"please maisecrets: set value_files add {f}", {}),
                            (f"/maisecrets:settings value_files add {f}", {"source": "schedule_wakeup"})):
            with self.subTest(text=text, **extra):
                self._prompt(text, **extra)
                self.assertEqual(self._files(), [])
        refused = hooks.pre_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                                  "tool_input": {"command": f"echo '/maisecrets:settings value_files add {f}'"}})
        self.assertEqual(refused["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_a_file_ignored_for_a_wrong_type_keeps_its_value_files(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "tips": "yes", "value_files": [str(self.tmp / "n.jsonl")]}))
        self.assertEqual(load_config()["value_files"], [str(self.tmp / "n.jsonl")])


class SessionStartImport(Base):
    def test_a_value_file_is_imported_when_it_changed_and_not_again_when_it_did_not(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        cfg = {**load_config(), "value_files": [str(f)]}
        note = value_import.session_import(cfg)
        self.assertIn("imported 1 value(s) from names.jsonl (NAME 1)", note)
        self.assertNotIn("Examplestein", note)
        uses = Vault().list()[0].uses
        self.assertIsNone(value_import.session_import(cfg), "unchanged: nothing to say")
        self.assertEqual(Vault().list()[0].uses, uses, "unchanged: nothing done")
        f.write_text(lines({"value": NAME, "type": "NAME"}, {"value": LONG_NAME, "type": "NAME"}))
        self.assertIn("imported 1 value(s)", value_import.session_import(cfg))
        self.assertEqual(len(Vault().list()), 2)

    def test_an_unchanged_file_is_imported_again_after_a_day_which_renews_it(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        cfg = {**load_config(), "value_files": [str(f)]}
        value_import.session_import(cfg)
        state = json.loads(value_import.STATE_FILE.read_text())
        state["sources"]["names.jsonl"]["at"] -= value_import.REIMPORT_AFTER + 1
        value_import.STATE_FILE.write_text(json.dumps(state))
        uses = Vault().list()[0].uses
        value_import.session_import(cfg)
        self.assertEqual(Vault().list()[0].uses, uses + 1, "touched again, so renewed")

    def test_the_time_budget_leaves_the_rest_for_the_next_start(self):
        f = self.file(lines(*synth_names(60)))
        cfg = {**load_config(), "value_files": [str(f)]}
        with mock.patch.object(value_import, "SESSION_BUDGET", -1):
            note = value_import.session_import(cfg)
        self.assertIn("60 more follow at the next session start", note)
        self.assertNotIn("hash", json.loads(value_import.STATE_FILE.read_text())["sources"]["names.jsonl"])
        self.assertIn("imported 60 value(s)", value_import.session_import(cfg))

    def test_a_missing_file_is_named_and_stops_nothing(self):
        cfg = {**load_config(), "value_files": [str(self.tmp / "gone.jsonl")]}
        self.assertIn("gone.jsonl: cannot be read", value_import.session_import(cfg))


class EndToEnd(Base):
    """Through the real entry points with the temp home: the launcher imports, the hooks mask."""

    def env(self) -> dict:
        return dict(os.environ)          # _isolate removed the client variables and set the temp home

    def hook(self, event: str, payload: dict) -> dict:
        # a blocked prompt goes to the clipboard: a fake tool takes it, never the real one
        fake = self.tmp / "fakebin"
        fake.mkdir(exist_ok=True)
        for tool in ("pbcopy", "xclip"):
            (fake / tool).write_text(f'#!/bin/sh\ncat > "{self.tmp}/clipboard"\n')
            (fake / tool).chmod(0o755)
        env = self.env()
        env["PATH"] = str(fake) + os.pathsep + env.get("PATH", "")
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def test_an_imported_value_comes_back_masked_from_a_tool(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}, {"value": SHAPELESS}))
        launcher = (["bash", str(ROOT / "hooks" / "run.sh")] if os.name != "nt"
                    else [sys.executable, str(ROOT / "hooks" / "dispatch.py")])
        r = subprocess.run(launcher + ["values", "import", str(f)], capture_output=True, text=True, env=self.env(),
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("imported 2 value(s) from names.jsonl (SECRET 1, NAME 1).", r.stdout)
        self.assertNotIn(NAME, r.stdout + r.stderr)
        out = self.hook("post-tool", {"session_id": "S1", "tool_name": "Bash", "tool_input": {"command": "cat x"},
                                      "tool_response": {"stdout": f"by {NAME}.\nkey={SHAPELESS}\n", "stderr": ""}})
        text = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("Examplestein", text)
        self.assertNotIn(SHAPELESS, text)
        self.assertIn(f"by {ref('NAME_c1')}.", out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])
        prompt = self.hook("user-prompt", {"session_id": "S2", "prompt": f"write to {NAME} today", **CODEX})
        self.assertNotIn("Examplestein", json.dumps(prompt, ensure_ascii=False))
        self.assertEqual(prompt.get("decision"), "block", "Codex blocks a prompt with a stored name")

    def test_the_session_start_imports_a_value_file(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "value_files": [str(f)]}))
        out = self.hook("session-start", {"session_id": "S1"})
        self.assertIn("maisecrets value files: imported 1 value(s) from names.jsonl (NAME 1)", out["systemMessage"])
        out = self.hook("post-tool", {"session_id": "S1", "tool_name": "Bash", "tool_input": {"command": "cat x"},
                                      "tool_response": {"stdout": f"{NAME} wrote", "stderr": ""}})
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], f"{ref('NAME_c1')} wrote")
        rc, said, _ = self.run_cli("forget", "import:names.jsonl")
        self.assertIn(f"/maisecrets:settings value_files remove {f} stops that", said, "the forget names the file")


if __name__ == "__main__":
    unittest.main()
