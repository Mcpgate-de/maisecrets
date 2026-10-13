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
import unicodedata
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

    def iid(self, name: str = "names.jsonl") -> str:
        """The id of the import of a file in self.tmp (value_import.source_name)."""
        return value_import.source_name(self.tmp / name)

    def forget_as_person(self, *args: str) -> tuple[int, str]:
        """The removal as the prompt hook runs it for the person's typed prompt (cli.forget_typed_by_the_person)."""
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            rc = cli.forget_typed_by_the_person(list(args))
        return rc, out.getvalue()

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
                                                 {"value": "Pass  phrase  synth"}))
        self.assertEqual([v for v, _t, _n in items], [NAME, "Pass  phrase  synth"])


class ImportCommand(Base):
    def test_import_prints_counts_and_masks_the_values_in_tool_output(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}, {"value": SHAPELESS}, {"value": "short"}))
        rc, out, _ = self.run_cli("values", "import", str(f))
        self.assertEqual(rc, 1, "a refused line makes the exit code 1, for a script")
        self.assertIn(f"imported 2 value(s) from {self.iid()} (SECRET 1, NAME 1), 1 line(s) refused: line 3 too short",
                      out)
        self.assertIn(f"/maisecrets:forget import:{self.iid()} removes it", out)
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
        self.assertIn(f"imported 0 value(s) from {self.iid()}, 1 already stored", out)
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
        with mock.patch.object(value_import, "MAX_IMPORTED", 10), mock.patch.object(value_import, "RUN_SHARE", 1):
            first = value_import.import_file(self.file(lines(*values[:8]), "a.jsonl"))
            second = value_import.import_file(self.file(lines(*values[8:]), "b.jsonl"))
            third = value_import.import_file(self.file(lines(*values[10:]), "c.jsonl"))
        self.assertEqual((first.stored, second.stored, third.stored), (8, 2, 0))
        self.assertIn("the vault holds 10 imported values, the limit", value_import.summary(third))
        entries = {e.key: e for e in Vault().list()}
        self.assertIn(mine.key, entries, "the person's own value stays")
        self.assertFalse(entries[mine.key].purged)
        self.assertEqual(sum(1 for e in entries.values() if e.source == self.iid("a.jsonl") and not e.purged), 8)

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
        self.assertRegex(out, rf"import:{self.iid()} +2 value\(s\) \(SECRET 1, NAME 1\), imported 0m ago, "
                              r"expire in 29d  run by a command")
        self.assertNotIn("names.jsonl", out, "no file name: it can be one of its values")
        self.assertIn("SECRET_c1", out, "the person's own value keeps its row")
        self.assertNotIn("NAME_c1", out, "an import is one line, not a row per value")
        rc, out, _ = self.run_cli("forget", f"import:{self.iid()}")
        self.assertEqual(rc, 1, "a command removes no import")
        self.assertIn("removing an import takes your own prompt", out)
        rc, out = self.forget_as_person(f"import:{self.iid()}")
        self.assertEqual(rc, 0)
        self.assertIn(f"import:{self.iid()}: 2 value(s) deleted", out)
        self.assertEqual([e.key for e in Vault().list()], ["SECRET_c1"])
        self.assertEqual(redact(f"hello {NAME}"), f"hello {NAME}")
        rc, out = self.forget_as_person(f"import:{self.iid()}")
        self.assertEqual(rc, 1)
        self.assertIn("not found", out)

    def test_values_remove_only_names_the_prompt(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        rc, _out, err = self.run_cli("values", "remove", f"import:{self.iid()}")
        self.assertEqual(rc, 1)
        self.assertIn("/maisecrets:forget import:NAME", err)
        self.assertEqual(len(Vault().list()), 1)

    def test_two_files_of_one_name_are_two_imports(self):
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir()
        b.mkdir()
        (a / "names.jsonl").write_text(lines({"value": NAME, "type": "NAME"}))
        (b / "names.jsonl").write_text(lines({"value": LONG_NAME, "type": "NAME"}))
        first = value_import.import_file(a / "names.jsonl")
        second = value_import.import_file(b / "names.jsonl")
        self.assertRegex(first.source, r"\Af[0-9a-f]{8}\Z")
        self.assertNotEqual(first.source, second.source)
        self.assertEqual(value_import.import_file(a / "names.jsonl").source, first.source, "a file keeps its name")


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

    # Opus H3, Fable M3: markup, quotes of any script, a possessive, NFD, invisible characters and JSON escapes
    def test_a_stored_name_is_found_in_markup_quotes_and_encodings(self):
        umlaut = "Qu" + chr(0xEF) + "lla Examplestein"          # a name with a letter outside ASCII
        self.put(NAME, umlaut)
        nfd = unicodedata.normalize("NFD", umlaut)
        self.assertNotEqual(nfd, umlaut)
        cases = {
            "bold": f"**{NAME}**", "italic": f"*{NAME}*", "underscore": f"_{NAME}_",
            "table cell": f"<td>{NAME}</td>", "tag between": "Quilla <b>Examplestein</b>",
            "German quotes": chr(0x201E) + NAME + chr(0x201C), "guillemets": chr(0xAB) + NAME + chr(0xBB),
            "possessive": f"{NAME}'s report", "typographic possessive": NAME + chr(0x2019) + "s report",
            "NFD": f"by {nfd}.", "soft hyphen": "Quil" + chr(0xAD) + "la Exam" + chr(0xAD) + "plestein",
            "zero width": "Quilla" + chr(0x200B) + " Examplestein", "JSON escape": json.dumps({"n": umlaut}),
        }
        for what, text in cases.items():
            with self.subTest(what):
                out = redact(text)
                self.assertNotIn("plestein", out)
                self.assertIn(OPEN + "NAME_c", out)
        self.assertEqual(redact("Quilla Examplesteiner"), "Quilla Examplesteiner")
        # a compound after the name is cut at its hyphen: stricter, the name goes and "-Day" stays
        self.assertEqual(redact("Quilla Examplestein-Day"), OPEN + "NAME_c1" + CLOSE + "-Day")
        # round 2: compact JSON and a Markdown link put no space after the name
        for what, text in {"compact JSON": '{"n":"' + NAME + '","y":1}',
                           "Markdown link": "[" + NAME + "](mailto:x@example.com)"}.items():
            with self.subTest(what):
                self.assertNotIn("plestein", redact(text))

    def test_a_json_emoji_or_lone_surrogate_never_withholds_the_tool_result(self):
        self.put(NAME, "Ren" + chr(0xE9) + "e M" + chr(0xFC) + "llerstein")
        bs = chr(92)
        pair = bs + "ud83d" + bs + "ude00"
        lone = bs + "ud800"
        escaped = "Ren" + bs + "u00e9e M" + bs + "u00fcllerstein"
        for what, text in {"emoji + name": '{"t": "' + pair + ' hi", "n": "' + NAME + '"}',
                           "emoji + escaped name": '{"t": "' + pair + '", "n": "' + escaped + '"}',
                           "lone surrogate + escaped name": '{"t": "' + lone + ' x", "n": "' + escaped + '"}',
                           "a lone surrogate character": chr(0xD800) + " " + NAME}.items():
            with self.subTest(what):
                out = hooks.post_tool({"session_id": "S1", "tool_name": "Bash", "tool_input": {"command": "cat x"},
                                       "tool_response": {"stdout": text, "stderr": ""}})
                body = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
                self.assertNotIn("plestein", body)
                self.assertNotIn("llerstein", body)
                if pair in text:
                    self.assertIn(pair, body, "the emoji escape stays as it was")
        plain, _segs = hooks._unescape(pair + " " + lone + " x")
        self.assertEqual(plain, chr(0x1F600) + " " + lone + " x", "a pair is one character, a lone one stays text")

    # Fable H2: a common first word repeated costs no fingerprint per occurrence
    def test_a_repeated_head_word_costs_a_bounded_number_of_fingerprints(self):
        self.put("the alpha", "the alpha beta", "the alpha beta gamma", "the alpha beta gamma delta",
                 "the alpha beta gamma delta eps", type_="SECRET")
        calls = []
        real = Vault.fingerprint

        def count(self, value):
            calls.append(value)
            return real(self, value)
        v = Vault()
        edges = []
        real_starts = hooks._starts

        def starts(word):
            edges.append(word)
            return real_starts(word)
        for text in ("the " * 10_000, "the alpha " * 10_000, "the, " * 10_000):
            calls.clear()
            edges.clear()
            with mock.patch.object(Vault, "fingerprint", count), mock.patch.object(hooks, "_starts", starts):
                hooks._phrase_spans(text, v)
            with self.subTest(text=text[:10]):
                self.assertLessEqual(len(calls), 12, "a fingerprint per distinct candidate, not per occurrence")
                self.assertLessEqual(len(edges), 4, "the edge work once per distinct word pair")

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
        self.assertEqual(meta["head"], Vault().fingerprint(NAME))

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
        words = text.split()
        distinct = len(set(zip(words, words[1:])))
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
        self.assertIn(f"imported 1 value(s) from {self.iid()} (NAME 1)", note)
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
        state["sources"][self.iid()]["at"] -= value_import.REIMPORT_AFTER + 1
        value_import.STATE_FILE.write_text(json.dumps(state))
        uses = Vault().list()[0].uses
        value_import.session_import(cfg)
        self.assertEqual(Vault().list()[0].uses, uses + 1, "touched again, so renewed")

    def test_the_time_budget_leaves_the_rest_for_the_next_start(self):
        f = self.file(lines(*synth_names(60)))
        cfg = {**load_config(), "value_files": [str(f)]}
        with mock.patch.object(value_import, "SESSION_BUDGET", -1):
            note = value_import.session_import(cfg)
        self.assertIn("value file 1 and later follow at the next session start", note)
        self.assertEqual(Vault().list(), [], "past the deadline no file is read")
        result = value_import.import_file(f, deadline=time.time() - 1, origin="file")
        self.assertEqual(result.pending, 60)
        self.assertIn("60 more follow at the next session start", value_import.summary(result))
        self.assertNotIn("hash", json.loads(value_import.STATE_FILE.read_text()).get("sources", {}).get(self.iid(), {}))
        self.assertIn("imported 60 value(s)", value_import.session_import(cfg))

    def test_a_missing_file_is_named_and_stops_nothing(self):
        cfg = {**load_config(), "value_files": [str(self.tmp / "gone.jsonl")]}
        self.assertIn("value file 1: cannot be read", value_import.session_import(cfg))


class ReviewFixes(Base):
    """The findings of the block 3 review (Gate A Fable, Gate B Opus): each test names its finding."""

    def blocked_for_a_value(self, prompt: str, client: dict) -> bool:
        hooks._live_cache.clear()
        with mock.patch.object(hooks, "_clipboard", return_value=False):   # never the real clipboard tool
            r = hooks.user_prompt({"prompt": prompt, "session_id": "S2", "source": "user", **client})
        return r.get("decision") == "block" and "maisecrets: a settings" not in r.get("reason", "") and (
            OPEN in r.get("reason", "") or "placeholder" in r.get("reason", ""))

    # Opus H1: an import cannot lock the person out of the controls
    def test_an_import_refuses_text_of_maisecrets_itself(self):
        texts = ["/maisecrets:forget", "/maisecrets:send", "maisecrets: set", "import:helper.jsonl",
                 "Use " + ref("SECRET_c1") + " now", "x" + OPEN + "SECRET_c2", "MAISECRETS-Synth-Value"]
        items, refused, _d = value_import.parse(lines(*({"value": t} for t in texts)))
        self.assertEqual(items, [])
        self.assertEqual({why for _n, why in refused}, {"holds text of maisecrets itself (a placeholder bracket, "
                                                         "maisecrets or import:)"})

    def test_an_agent_import_of_control_text_leaves_the_controls_working(self):
        f = self.file(lines(*({"value": t} for t in ("/maisecrets:forget", "/maisecrets:send", "maisecrets: set",
                                                     "import:helper.jsonl"))), "helper.jsonl")
        self.assertEqual(value_import.import_file(f).stored, 0)
        for client in (CLAUDE, CODEX):
            for prompt in ("/maisecrets:send", "/maisecrets:forget import:helper.jsonl"):
                with self.subTest(prompt=prompt, client=client):
                    self.assertFalse(self.blocked_for_a_value(prompt, client))

    def test_a_stored_value_in_any_control_form_is_still_taken_out(self):
        # round 2: a skip of the command part of a control prompt let a stored value through in these forms
        pw, pwh = "Zq7PwSynthValue9x", "Zq7Pw-Synth-Value9x"
        Vault().put_many([(pw, "SECRET", "put"), (pwh, "SECRET", "put"), (NAME, "NAME", "manual")])
        forms = [f"/maisecrets:send\nmy password is {pw}", f"/maisecrets:forget import:people\nalso {pw}",
                 f"maisecrets: {pw} is the key", f"maisecrets:\n{pw}\nthat is the key", f"MAISECRETS: {pw}",
                 f"/maisecrets:{pw}", f"/maisecrets:{pwh} please", f"/maisecrets:list import:people,{pw}",
                 f"/maisecrets:list import:{pw}", f"maisecrets: {NAME} wrote the report",
                 f"maisecrets: {pwh}\nother: 1", f"   maisecrets:{pw}"]
        for client in (CLAUDE, CODEX):
            for prompt in forms:
                with self.subTest(prompt=prompt.replace(pw, "PW").replace(pwh, "PWH"), client=client):
                    self.assertTrue(self.blocked_for_a_value(prompt, client))

    # Fable H1: a listed file is checked before a byte is read
    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFO on this system")
    def test_a_fifo_in_value_files_does_not_hang_the_session_start(self):
        fifo = self.tmp / "names.jsonl"
        os.mkfifo(fifo)
        cfg = {**load_config(), "value_files": [str(fifo)]}
        import threading
        out: list = []
        t = threading.Thread(target=lambda: out.append(value_import.session_import(cfg)), daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "the session start waited for a writer of the FIFO")
        self.assertIn("value file 1: not a file", out[0])
        with self.assertRaisesRegex(ValueError, "not a file"):
            value_import.import_file(fifo)

    def test_a_large_file_is_refused_before_a_byte_is_read(self):
        big = self.tmp / "big.jsonl"
        with open(big, "wb") as f:
            f.truncate(400 * 1024 * 1024)          # sparse: no disk, but a read would take 400 MB of memory
        read: list[int] = []
        real = os.read

        def spy(fd, n):
            data = real(fd, n)
            read.append(len(data))
            return data
        cfg = {**load_config(), "value_files": [str(big)]}
        with mock.patch.object(value_import.os, "read", spy):
            note = value_import.session_import(cfg)
            with self.assertRaisesRegex(ValueError, "over the limit"):
                value_import.import_file(big)
        self.assertIn("over the limit", note)
        self.assertEqual(sum(read), 0)

    def test_a_file_that_grows_past_the_cap_is_read_to_the_cap_plus_one_byte(self):
        f = self.file(lines(*synth_names(3)))
        real = os.fstat

        class Small:
            def __init__(self, st):
                self.st_mode, self.st_size = st.st_mode, 10
        with open(f, "ab") as fh:
            fh.write(b"#" * (value_import.MAX_FILE_BYTES + 10))
        read: list[int] = []
        real_read = os.read

        def spy(fd, n):
            data = real_read(fd, n)
            read.append(len(data))
            return data
        with mock.patch.object(value_import.os, "fstat", lambda fd: Small(real(fd))), \
                mock.patch.object(value_import.os, "read", spy):
            with self.assertRaisesRegex(ValueError, "over the limit"):
                value_import.read_capped(f)
        self.assertEqual(sum(read), value_import.MAX_FILE_BYTES + 1, "the read stops one byte past the cap")

    # Fable M2: an agent cannot mask ordinary text silently
    def test_a_secret_of_lower_case_words_is_refused(self):
        items, refused, _d = value_import.parse(lines({"value": "the meeting is at noon"},
                                                      {"value": "the meeting is at noon", "type": "NAME"},
                                                      {"value": "pass-phrase synth"}, {"value": "Pass phrase synth"}))
        self.assertEqual([v for v, _t, _n in items], ["the meeting is at noon", "pass-phrase synth",
                                                       "Pass phrase synth"])
        self.assertEqual(refused, [(1, "ordinary text (a SECRET needs an upper-case letter, a digit or a symbol)")])

    def test_each_import_writes_one_events_line_and_the_next_start_names_a_new_import_once(self):
        self.run_cli("values", "import", str(self.file(lines({"value": NAME, "type": "NAME"}), "agent.jsonl")))
        events = [json.loads(x) for x in (HOME / "events.log").read_text().splitlines()]
        self.assertEqual([(e["hook"], e["client"], e["hits"][0]["key"]) for e in events],
                         [("ValueImport", "run", f"import:{self.iid('agent.jsonl')}")])
        self.assertNotIn("Examplestein", (HOME / "events.log").read_text())
        note = value_import.session_import(load_config())
        self.assertIn(f"import:{self.iid('agent.jsonl')} (NAME 1)", note)
        self.assertNotIn("Examplestein", note)
        self.assertIsNone(value_import.session_import(load_config()), "said once")

    # Fable H2 / Opus M1: a re-import renews past max_ttl, and before the values expire
    def test_a_reimport_renews_the_lifetime_past_the_first_max_ttl(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        value_import.import_file(f, origin="file")
        v = Vault()
        with v._exclusive():
            meta = v._index["entries"]["NAME_c1"]
            meta["expires"] = meta["max_expires"] = time.time() + 100      # day 30 of the first import
        value_import.import_file(f, origin="file")
        meta = Vault()._index["entries"]["NAME_c1"]
        month = load_config()["max_ttl_seconds"]
        self.assertGreater(meta["max_expires"] - time.time(), month - 60)
        self.assertGreater(meta["expires"] - time.time(), month - 60)
        self.assertLessEqual(meta["max_expires"] - time.time(), month, "never past the person's max_ttl_seconds")

    def test_only_a_value_file_renews_and_never_past_a_shorter_max_ttl(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        value_import.import_file(f, origin="file")
        v = Vault()
        with v._exclusive():
            meta = v._index["entries"]["NAME_c1"]
            meta["expires"] = meta["max_expires"] = time.time() + 100
        value_import.import_file(f)                                    # an agent's run import of the same file
        self.assertLess(Vault()._index["entries"]["NAME_c1"]["max_expires"] - time.time(), 101)
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "max_ttl_seconds": 7200}))
        value_import.import_file(f, origin="file")
        self.assertLessEqual(Vault()._index["entries"]["NAME_c1"]["max_expires"] - time.time(), 7200)

    def test_a_value_file_is_imported_again_when_a_value_expires_soon_or_one_is_gone(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}, {"value": LONG_NAME, "type": "NAME"}))
        cfg = {**load_config(), "value_files": [str(f)]}
        value_import.session_import(cfg)
        self.assertIsNone(value_import.session_import(cfg))
        Vault().forget("NAME_c2")
        self.assertIn("imported 1 value(s)", value_import.session_import(cfg), "a value is gone: imported again")
        v = Vault()
        with v._exclusive():
            v._index["entries"]["NAME_c1"]["expires"] = time.time() + 3600
        value_import.session_import(cfg)
        self.assertGreater(Vault()._index["entries"]["NAME_c1"]["expires"] - time.time(), 86400 * 2,
                           "expiring within two days: imported again, which renews it")

    # Opus M1: the imports an agent runs cannot take the room of the person's value files
    def test_a_run_import_finds_no_room_when_the_value_files_filled_the_cap(self):
        with mock.patch.object(value_import, "MAX_IMPORTED", 10):
            f = self.file(lines(*synth_names(10)), "team.jsonl")
            value_import.session_import({**load_config(), "value_files": [str(f)]})
            run = value_import.import_file(self.file(lines(*synth_names(14)[10:]), "agent.jsonl"))
        self.assertEqual(run.stored, 0)
        self.assertIn(f"import:{self.iid('team.jsonl')} holds the most of them", value_import.summary(run))

    def test_a_value_known_from_elsewhere_or_a_short_lifetime_does_not_import_at_every_start(self):
        rows = synth_names(5)
        Vault().put(rows[0]["value"], "NAME", "put")
        f = self.file(lines(*rows))
        cfg = {**load_config(), "value_files": [str(f)]}
        value_import.session_import(cfg)
        self.assertIsNone(value_import.session_import(cfg), "a value from a /maisecrets:put is no missing value")
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "max_ttl_seconds": 86400}))
        cfg = {**load_config(), "value_files": [str(f)]}
        f.write_text(lines(*synth_names(6)))          # changed: imported, and its values now live one day
        value_import.session_import(cfg)
        events = (HOME / "events.log").read_text().count("ValueImport")
        value_import.session_import(cfg)
        self.assertEqual((HOME / "events.log").read_text().count("ValueImport"), events,
                         "a lifetime of one day: no import at the next start")

    def test_run_imports_leave_room_for_the_value_files(self):
        with mock.patch.object(value_import, "MAX_IMPORTED", 10):          # an import that is no file: 6 of 10
            run = value_import.import_file(self.file(lines(*synth_names(10)[:8]), "agent.jsonl"))
            f = self.file(lines(*synth_names(14)[10:]), "team.jsonl")
            value_import.session_import({**load_config(), "value_files": [str(f)]})
        self.assertEqual(run.stored, 6)
        self.assertIn("the limit of imports that are no value file", value_import.summary(run))
        self.assertEqual(value_import.counts_by_source(Vault())[self.iid("team.jsonl")], {"NAME": 4})

    # Opus M2: a value two imports list stays when one of them is removed
    def test_a_value_in_two_imports_stays_until_both_are_removed(self):
        a, b = self.iid("a.jsonl"), self.iid("b.jsonl")
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"}), "a.jsonl"), origin="file")
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"}), "b.jsonl"), origin="file")
        self.assertEqual(value_import.counts_by_source(Vault()), {a: {"NAME": 1}, b: {"NAME": 1}})
        rc, out = self.forget_as_person(f"import:{a}")
        self.assertIn(f"import:{a}: no value deleted. 1 value(s) stay masked because another import lists them "
                      f"too: import:{b} (1)", out)
        self.assertNotIn("no longer masks", out)
        self.assertNotIn("Examplestein", redact(f"by {NAME}"))
        self.assertEqual(value_import.remove(Vault(), b), (1, 0, {}, 0))
        self.assertEqual(redact(f"by {NAME}"), f"by {NAME}")

    # Opus M3: removing an import writes the index once per batch, not once per value
    def test_removing_an_import_writes_the_index_once_per_batch(self):
        value_import.import_file(self.file(lines(*synth_names(450))))
        writes = []
        real = Vault._save_index

        def count(self):
            writes.append(1)
            return real(self)
        with mock.patch.object(Vault, "_save_index", count):
            result = value_import.remove(Vault(), self.iid())
        self.assertEqual(result, (450, 0, {}, 0))
        self.assertLessEqual(len(writes), 2 * (450 // value_import.FORGET_BATCH + 2))

    def test_remove_counts_only_values_deleted_now(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"}, {"value": LONG_NAME,
                                                                                    "type": "NAME"})))
        v = Vault()
        with v._exclusive():
            v._index["entries"]["NAME_c1"]["expires"] = time.time() - 1
        Vault().expire(limit=None)
        self.assertEqual(value_import.remove(Vault(), self.iid()), (1, 0, {}, 0))

    # LOWs of the review
    def test_a_locked_vault_gives_a_message_not_a_traceback(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        with mock.patch.object(value_import, "import_file", side_effect=vault.LockTimeout("the vault lock is busy")):
            rc, out, err = self.run_cli("values", "import", str(f))
        self.assertEqual(rc, 1)
        self.assertIn("maisecrets: the import failed: the vault lock is busy", err)

    def test_the_printed_command_is_the_launcher_and_runs_as_printed(self):
        rc, _out, err = self.run_cli("values", "bogus")
        self.assertEqual(rc, 2)
        launcher = str(ROOT / "hooks" / ("run.cmd" if os.name == "nt" else "run.sh"))
        self.assertIn(f"usage: {launcher} values [import FILE | remove NAME]", err)
        self.assertNotIn("maisecrets values import FILE", err)
        spaced = "/tmp/Jan Example/plugin/maisecrets/value_import.py"
        if os.name != "nt":
            with mock.patch.object(value_import, "__file__", spaced):
                self.assertEqual(value_import.command("import FILE"),
                                 "'/tmp/Jan Example/plugin/hooks/run.sh' values import FILE")
        if os.name == "nt":
            return
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        r = subprocess.run([launcher, "values", "import", str(f)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"imported 1 value(s) from {self.iid()} (NAME 1).", r.stdout)

    def test_the_session_start_bounds_the_expire_work(self):
        v = Vault()
        v.put_many([(f"Synth{i:05d} Persona", "NAME", "manual") for i in range(520)], cap=10_000)
        with v._exclusive():
            for meta in v._index["entries"].values():
                meta["expires"] = time.time() - 1
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                           input=json.dumps({"session_id": "S1"}), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        purged = sum(1 for m in Vault()._index["entries"].values() if m.get("purged"))
        self.assertEqual(purged, 500, "at most 500 deletes per start; the rest go with later hook calls")


class Round3(Base):
    """The findings of the codex review of block 3 at 45a2f4d."""

    def prompt(self, text: str, client: dict = CLAUDE, **extra) -> dict:
        hooks._live_cache.clear()
        with mock.patch.object(hooks, "_clipboard", return_value=False):
            return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})

    # BLOCKER 1: only the person removes an import
    def test_a_tool_call_that_removes_an_import_is_refused(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        iid = self.iid()
        run = '"/x/hooks/run.sh"'
        END = "MAISECRETS_" + "ARGS_END"
        for command in (f"bash {run} values remove import:{iid}", f"bash {run} forget import:{iid}",
                        f"bash {run} forget --args-stdin <<'{END}'\nimport:{iid}\n{END}",
                        f"python3 -c 'from maisecrets import value_import; value_import.remove(None, \"{iid}\")'",
                        f"codex exec 'maisecrets: forget import:{iid}'"):
            for tool in ("Bash", "PowerShell"):
                with self.subTest(command=command, tool=tool):
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command},
                                          "session_id": "S1", **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                    self.assertIn("removes an import", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(hooks.pre_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                                         "tool_input": {"command": f"bash {run} forget SECRET_c1"}}), {})
        rc, out, _ = self.run_cli("values", "remove", f"import:{iid}")
        self.assertEqual(rc, 1, "the CLI outside the person's terminal removes nothing")
        self.assertNotIn("Examplestein", redact(f"by {NAME}"))

    def test_the_persons_typed_prompt_removes_an_import(self):
        for client, form in ((CLAUDE, "/maisecrets:forget import:{}"), (CODEX, "maisecrets: forget import:{}")):
            with self.subTest(client=client):
                _clean()
                value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
                out = self.prompt(form.format(self.iid()), client)
                self.assertEqual(out["decision"], "block", "the answer is the result; the prompt goes nowhere")
                self.assertIn(f"import:{self.iid()}: 1 value(s) deleted", out["reason"])
                self.assertEqual(redact(f"by {NAME}"), f"by {NAME}")
        _clean()
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        out = self.prompt(f"/maisecrets:forget import:{self.iid()}", CLAUDE, source="scheduled")
        self.assertIn("counts only when you type it", out["reason"])
        self.assertNotIn("Examplestein", redact(f"by {NAME}"), "a prompt the client injected removes nothing")

    # BLOCKER 2: a file named like one of its values never prints the value
    def test_a_file_named_like_its_value_never_shows_the_value(self):
        word = "ProjectCode99"
        f = self.file(lines({"value": word}), word)
        rc, out, err = self.run_cli("values", "import", str(f))
        cfg = {**load_config(), "value_files": [str(f)]}
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "value_files": [str(f)]}))
        f.write_text(lines({"value": word}, {"value": "Other" + word}))
        note = value_import.session_import(cfg)
        _rc, listed, _ = self.run_cli("list")
        texts = {"cli import": out + err, "session start": note or "", "list": listed,
                 "events.log": (HOME / "events.log").read_text()}
        for where, text in texts.items():
            with self.subTest(where):
                self.assertNotIn(word, text)
        self.assertIn(f"import:{self.iid(word)}", note)

    # HIGH 3: a value past its lifetime is not hunted, deleted by the sweep or not
    def test_a_value_past_its_lifetime_is_not_masked_before_the_sweep_deletes_it(self):
        v = Vault()
        v.put_many([(f"Synth{i:05d} Persona", "NAME", "manual") for i in range(501)], cap=10_000)
        with v._exclusive():
            for meta in v._index["entries"].values():
                meta["expires"] = time.time() - 1
        v = Vault()
        v.expire(limit=500)
        last = [k for k, m in Vault()._index["entries"].items() if not m.get("purged")]
        self.assertEqual(len(last), 1, "the 501st is still in the store")
        self.assertEqual(redact("by Synth00500 Persona"), "by Synth00500 Persona")
        self.assertEqual(Vault().status(last[0], "S1"), "expired")

    # HIGH 4: bounds on sources, records and concurrent imports
    def test_a_value_that_any_value_file_lists_stays_until_the_last_is_removed(self):
        ids = []
        for i in range(10):
            value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"}), f"p{i}.jsonl"), origin="file")
            ids.append(self.iid(f"p{i}.jsonl"))
        for iid in ids[:-1]:
            value_import.remove(Vault(), iid)
        self.assertNotIn("Examplestein", redact(f"by {NAME}"), "the tenth file still lists it")
        self.assertEqual(value_import.counts_by_source(Vault()), {ids[-1]: {"NAME": 1}})

    def test_an_agents_import_of_known_values_links_nothing_and_leaves_no_record(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"}), "team.jsonl"), origin="file")
        for i in range(5):
            value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"}), f"copy{i}.jsonl"))
        self.assertEqual(Vault()._index["entries"]["NAME_c1"]["also"], [])
        self.assertEqual(list(json.loads(value_import.STATE_FILE.read_text())["sources"]), [self.iid("team.jsonl")])

    def test_imports_that_are_no_value_file_are_bounded_in_number(self):
        with mock.patch.object(value_import, "MAX_RUN_IMPORTS", 3):
            for i in range(3):
                value_import.import_file(self.file(lines({"value": f"Synth{i:05d} Persona", "type": "NAME"}),
                                                   f"r{i}.jsonl"))
            with self.assertRaisesRegex(ValueError, "3 imports that are no value file, the limit"):
                value_import.import_file(self.file(lines({"value": LONG_NAME, "type": "NAME"}), "r9.jsonl"))

    def test_concurrent_run_imports_stay_inside_the_cap(self):
        # the first process counts its room and then waits a second before it writes; the second imports meanwhile.
        # Counted outside the lock, both saw the same room and together passed the cap
        code = ("import sys, time; sys.path.insert(0, sys.argv[1]); from maisecrets import value_import as v; "
                "v.MAX_IMPORTED = 10\n"
                "if sys.argv[3] == 'slow':\n"
                "    real = v._room\n"
                "    def slow(*a):\n"
                "        out = real(*a); time.sleep(1.0); return out\n"
                "    v._room = slow\n"
                "v.import_file(sys.argv[2])")
        procs = []
        for i, mode in enumerate(("slow", "fast")):
            f = self.file(lines(*({"value": f"Proc{i}x{j:03d} Persona", "type": "NAME"} for j in range(5))),
                          f"proc{i}.jsonl")
            procs.append(subprocess.Popen([sys.executable, "-c", code, str(ROOT), str(f), mode],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            time.sleep(0.4)
        for p in procs:
            _o, err = p.communicate(timeout=60)
            self.assertEqual(p.returncode, 0, err)
        live = [m for m in Vault()._index["entries"].values() if m.get("source")]
        self.assertLessEqual(len(live), 6, "the run share of a cap of 10")
        self.assertEqual(len(live), 6, "the second import filled what the first left")

    # MEDIUM 5: one deadline for the session start, and a bound on files per start
    def test_a_session_start_reads_a_bounded_number_of_files(self):
        files = [self.file(lines({"value": f"Synth{i:05d} Persona", "type": "NAME"}), f"v{i}.jsonl") for i in range(4)]
        cfg = {**load_config(), "value_files": [str(f) for f in files]}
        with mock.patch.object(value_import, "MAX_FILES_PER_START", 2):
            note = value_import.session_import(cfg)
            self.assertIn("value file 3 and later follow at the next session start", note)
            self.assertEqual(len(value_import.counts_by_source(Vault())), 2)
            value_import.session_import(cfg)
        self.assertEqual(len(value_import.counts_by_source(Vault())), 4)

    def test_the_expire_sweep_stops_at_its_deadline(self):
        v = Vault()
        v.put_many([(f"Synth{i:05d} Persona", "NAME", "manual") for i in range(30)], cap=10_000)
        with v._exclusive():
            for meta in v._index["entries"].values():
                meta["expires"] = time.time() - 1
        self.assertEqual(Vault().expire(limit=500, deadline=time.time() - 1), 0)


class Round4(Base):
    """The verification of block 3 at a989775."""

    def test_no_command_removes_an_import_even_with_a_terminal(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        tty = mock.patch.object(sys.stdin, "isatty", return_value=True)
        with tty, mock.patch.object(sys.stdout, "isatty", return_value=True, create=True):
            rc, out, err = self.run_cli("forget", f"import:{self.iid()}")
            rc2, _o, err2 = self.run_cli("values", "remove", f"import:{self.iid()}")
        self.assertEqual((rc, rc2), (1, 1))
        self.assertIn("removing an import takes your own prompt", out + err2)
        self.assertNotIn("Examplestein", redact(f"by {NAME}"), "`script` gives a terminal; nothing was removed")

    def test_the_guard_refuses_maisecrets_calls_and_lets_ordinary_commands_run(self):
        run = '"/x/hooks/run.sh"'
        refused = (f"bash {run} forget import:fabcdef01", f"bash {run} values remove import:fabcdef01",
                   "python3 -m maisecrets.cli forget import:fabcdef01",
                   "claude -p '/maisecrets:forget import:fabcdef01'")
        allowed = ('git commit -m "do not forget the import: it matters"', "grep -n forget README.md | grep import:",
                   "ls  # values remove later", "echo values remove")
        for command in refused:
            with self.subTest(refused=command):
                out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1",
                                      **CLAUDE})
                self.assertIn("removes an import", out["hookSpecificOutput"]["permissionDecisionReason"])
        for command in allowed:
            with self.subTest(allowed=command):
                out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1",
                                      **CLAUDE})
                self.assertNotIn("removes an import", json.dumps(out))

    def test_wipe_takes_the_import_state(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        self.assertTrue(value_import.STATE_FILE.exists())
        vault.wipe_everything(load_config())
        self.assertFalse(value_import.STATE_FILE.exists())

    def test_a_run_import_reserves_its_place_under_the_state_lock_before_it_works(self):
        seen = []
        real = value_import.parse

        def spy(text):
            seen.append(json.loads(value_import.STATE_FILE.read_text())["sources"].get(self.iid(), {}))
            return real(text)
        with mock.patch.object(value_import, "parse", spy):
            value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        self.assertTrue(seen[0].get("reserved"), "the place is taken before the work")
        self.assertNotIn("reserved", json.loads(value_import.STATE_FILE.read_text())["sources"][self.iid()])

    def test_a_long_removal_stops_at_its_deadline_and_says_how_many_are_left(self):
        value_import.import_file(self.file(lines(*synth_names(450))))
        self.assertEqual(value_import.remove(Vault(), self.iid(), deadline=time.time() - 1), (0, 0, {}, 450))
        self.assertIn(self.iid(), json.loads(value_import.STATE_FILE.read_text())["sources"])
        with mock.patch.object(value_import, "remove", return_value=(200, 0, {}, 250)):
            rc, out = self.forget_as_person(f"import:{self.iid()}")
        self.assertIn("200 value(s) deleted, 250 left; send the same prompt again to finish", out)
        self.assertEqual(value_import.remove(Vault(), self.iid()), (450, 0, {}, 0))


class Round5(Base):
    """The codex verification of block 3 at 2594c00."""

    def test_the_typed_removal_by_name_and_an_imported_key_are_refused_to_a_command(self):
        value_import.import_file(self.file(lines({"value": NAME, "type": "NAME"})))
        for command in ("python3 -c 'from maisecrets import cli; cli.forget_typed_by_the_person([\"import:fab01\"])'",
                        "python3 -c 'from maisecrets import cli; cli._forget([\"import:fabcdef01\"], True, None)'",
                        "python3 -c 'import maisecrets.cli as c; c.cmd_forget(x, person=True)'"):
            with self.subTest(command=command):
                out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1",
                                      **CLAUDE})
                self.assertIn("removes an import", out["hookSpecificOutput"]["permissionDecisionReason"])
        rc, out, _ = self.run_cli("forget", "NAME_c1")
        self.assertEqual(rc, 1)
        self.assertIn(f"NAME_c1: not deleted; it belongs to import:{self.iid()}", out)
        self.assertNotIn("Examplestein", redact(f"by {NAME}"))

    def test_a_failed_import_gives_its_reserved_place_back(self):
        f = self.file(lines({"value": NAME, "type": "NAME"}))
        with mock.patch.object(Vault, "expire", side_effect=vault.LockTimeout("busy")):
            with self.assertRaises(vault.LockTimeout):
                value_import.import_file(f)
        self.assertNotIn(self.iid(), json.loads(value_import.STATE_FILE.read_text()).get("sources", {}))

    def test_a_removal_checks_its_deadline_before_every_delete(self):
        value_import.import_file(self.file(lines(*synth_names(20))))
        v = Vault()
        real = v.backend.delete

        def slow(key):
            time.sleep(0.05)
            return real(key)
        with mock.patch.object(v.backend, "delete", slow):
            deleted, refused, _kept, left = value_import.remove(v, self.iid(), deadline=time.time() + 0.12)
        self.assertGreaterEqual(deleted, 1)
        self.assertLess(deleted, 6, "the batch stopped at the deadline, not at its end")
        self.assertEqual(deleted + left, 20)
        self.assertEqual(value_import.remove(Vault(), self.iid())[0], 20 - deleted)


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
        self.assertIn(f"imported 2 value(s) from {self.iid()} (SECRET 1, NAME 1).", r.stdout)
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
        self.assertIn(f"maisecrets value files: imported 1 value(s) from {self.iid()} (NAME 1)", out["systemMessage"])
        out = self.hook("post-tool", {"session_id": "S1", "tool_name": "Bash", "tool_input": {"command": "cat x"},
                                      "tool_response": {"stdout": f"{NAME} wrote", "stderr": ""}})
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], f"{ref('NAME_c1')} wrote")
        rc, said = self.forget_as_person(f"import:{self.iid()}")
        self.assertIn("still in value_files, so the next session start imports it again; /maisecrets:settings "
                      "value_files shows the entry to remove", said)
        self.assertNotIn(str(f), said, "no path: its file name can be one of its values")


if __name__ == "__main__":
    unittest.main()
