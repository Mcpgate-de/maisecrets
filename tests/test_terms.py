"""Terms (maisecrets/terms.py, C26): the parser, the matcher, the floor of a team list and the inline marker.

Based on the tests of the personal-terms design by @danszymkowiak (tests/test_terms.py and tests/test_term_match.py
of his fork); the cases that differ here say why.

Run: python3 -m unittest tests.test_terms -v
Synthetic names only (Jan Kowalski, Zbigniew Testowski, ul. Przykladowa 12).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect, terms  # noqa: E402
from maisecrets.terms import Entity, TermsError, Variant  # noqa: E402
import _hygiene  # noqa: E402

SAMPLE = """\
# label      variants
PERSON_A     Jan Kowalski | Kowalsk* | Jan

ADDRESS_A    ul.  Przykladowa 12   |  *przykladowa*
CASE_A       *sygn
"""


def tearDownModule():  # noqa: N802 - unittest hook
    for p in (terms.PERSONAL, terms.MARKED, terms.STATE_FILE):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    detect.reset_rules()
    _hygiene.assert_pristine()


def matcher(text: str) -> terms.Matcher:
    return terms.Matcher(terms.parse(text)[0])


def runs(m: terms.Matcher, text: str) -> list:
    return [(text[s:e], ent.label) for s, e, ent in m.find(text)]


class ParseTests(unittest.TestCase):
    def test_label_and_variants_blank_lines_and_comments(self):
        got = terms.parse(SAMPLE)[0]
        self.assertEqual([e.label for e in got], ["PERSON_A", "ADDRESS_A", "CASE_A"])
        self.assertEqual([v.text for v in got[0].variants], ["Jan Kowalski", "Kowalsk", "Jan"])
        self.assertEqual((got[0].line, got[1].line), (2, 4))
        self.assertEqual([v.text for v in got[1].variants], ["ul. Przykladowa 12", "przykladowa"])

    def test_the_four_modes(self):
        got = terms.parse("PERSON_A  Jan | Kowalsk* | *kowalski | *kowalski*\n")[0]
        self.assertEqual(got[0].variants, (Variant("Jan", terms.WORD), Variant("Kowalsk", terms.STARTS),
                                           Variant("kowalski", terms.ENDS), Variant("kowalski", terms.INSIDE)))

    def test_tabs_separate_the_label_and_a_label_may_hold_digits(self):
        self.assertEqual(terms.parse("NAME_1\tJan\n")[0][0], Entity("NAME_1", (Variant("Jan", terms.WORD),), 1))

    def test_the_type_is_name_unless_the_label_names_a_type(self):
        got = terms.parse("PERSON_A  Jan\nEMAIL_BOSS  boss-at-work\nSECRET  Bluebird\nNAME_3  Nowak\n")[0]
        self.assertEqual([e.type for e in got], ["NAME", "EMAIL", "SECRET", "NAME"])

    def test_the_id_names_source_and_label_never_the_term(self):
        e = terms.parse("PERSON_A  Zbigniew Testowski\n")[0][0]
        self.assertEqual(len(e.id), 12)
        self.assertNotIn("testowsk", e.id)
        self.assertNotEqual(e.id, terms.parse("PERSON_A  Jan\n", source="team/x.terms")[0][0].id)

    def test_no_content_no_entities(self):
        self.assertEqual(terms.parse("")[0], [])
        self.assertEqual(terms.parse("# only a comment\n\n   \n")[0], [])


class RejectTests(unittest.TestCase):
    """The person's own list: the first bad line raises, and the message names the line, never its text."""

    def assertRejected(self, text: str, line: int, words: tuple = ()):  # noqa: N802 - unittest style
        with self.assertRaises(TermsError) as cm:
            terms.parse(text)
        msg = str(cm.exception)
        self.assertIn(f"line {line}", msg)
        self.assertEqual(cm.exception.line, line)
        for word in words:
            self.assertNotIn(word.lower(), msg.lower(), "an error must not show a term")

    def test_missing_or_bad_label(self):
        self.assertRejected("# x\nKowalski | Jan\n", 2, ("Kowalski", "Jan"))
        for label in ("person_a", "Kowalski", "P" * 33, "_PERSON", "1PERSON"):
            with self.subTest(label=label):
                self.assertRejected(f"{label}  Jan Nowak\n", 1, (label, "Nowak"))

    def test_empty_variant_and_inner_star(self):
        for rest in ("Jan || Kowalski", "Jan | ", "*", "**", "Jan | * | Kowalski", "Kow*ski", "+++"):
            with self.subTest(rest=rest):
                self.assertRejected(f"PERSON_A  {rest}\n", 1, ("Jan", "Kowalski", "Kow"))
        self.assertRejected("PERSON_A\n", 1)

    def test_short_anywhere_and_short_stems(self):
        # Dan's fork accepted `*an`: it masks every word that ends in "an" (plan, can, Jan). Here a stem needs 3
        self.assertRejected("PERSON_A  Jan | *jan*\n", 1, ("jan",))
        self.assertRejected("PERSON_A  *an\n", 1)
        self.assertRejected("PERSON_A  Ko*\n", 1)
        self.assertEqual(len(terms.parse("PERSON_A  *nowa* | jan* | *ski | Al\n")[0][0].variants), 4)

    def test_duplicate_label_and_the_first_bad_line(self):
        self.assertRejected("PERSON_A  Jan\n\nPERSON_A  Nowak\n", 3, ("Jan", "Nowak"))
        self.assertRejected("PERSON_A  Jan\nbad line\nPERSON_A  Nowak\n", 2, ("bad",))


class TeamFloorTests(unittest.TestCase):
    """A team list (not strict, with the stop list): a bad line or variant is left out, the rest loads."""

    def test_short_and_common_entries_are_left_out_and_the_rest_loads(self):
        text = ("ACME_A  Acme Holding | AC | report\nCLIENT_B  Zbigniew Testowski\nbad line\n"
                "CLIENT_C  Montag\nCLIENT_D  Testowsk*\n")
        ents, refused = terms.parse(text, "team/x.terms", strict=False, floor=terms.stoplist())
        self.assertEqual([(e.label, [v.text for v in e.variants]) for e in ents],
                         [("ACME_A", ["Acme Holding"]), ("CLIENT_B", ["Zbigniew Testowski"]),
                          ("CLIENT_D", ["Testowsk"])])
        self.assertEqual([(r.line, r.reason) for r in refused], [
            (1, "a team entry needs at least 3 characters"),
            (1, "a common word (rules/term_stoplist.txt) in a team list"),
            (3, "the line must start with a label of capital letters, digits and _ (at most 32), then the variants"),
            (4, "a common word (rules/term_stoplist.txt) in a team list")])
        for r in refused:
            self.assertNotIn("montag", r.reason.lower())

    def test_a_team_affix_needs_a_long_stem_that_common_words_do_not_share(self):
        text = ("A_1  *ing\nA_2  fil*\nA_3  *tion*\nA_4  ret*\nA_5  con*\nA_6  of the\nA_7  count*\nA_8  *thing\n"
                "A_9  *ation*\nOK_1  Testowsk*\nOK_2  *sygn-0042*\nOK_3  Acme of the North\n")
        ents, refused = terms.parse(text, "team/x.terms", strict=False, floor=terms.stoplist())
        self.assertEqual([e.label for e in ents], ["OK_1", "OK_2", "OK_3"])
        self.assertEqual([r.line for r in refused], list(range(1, 10)))
        self.assertIn("only common words", refused[5].reason)
        self.assertIn("common words (rules/term_stoplist.txt) share", refused[8].reason)

    def test_the_personal_list_has_no_floor(self):
        self.assertEqual(len(terms.parse("PERSON_A  report | Al\n")[0][0].variants), 2)

    def test_the_stop_list_holds_the_closed_classes_of_both_languages(self):
        stop = terms.stoplist()
        for w in ("the", "und", "montag", "january", "jan", "herr", "dear", "report"):
            self.assertIn(w, stop)
        self.assertLess(len(stop), 5000, "small, and each word has a named source")


class MatchTests(unittest.TestCase):
    def test_a_word_matches_with_no_letter_digit_or_underscore_around(self):
        m = matcher("PERSON_A  Jan\n")
        for text in ("Jan", "Jan, hello", "(Jan)", "Jan's car", "x\nJan\ny", "| Jan |", "|Jan|", "-Jan-"):
            with self.subTest(text=text):
                self.assertEqual(runs(m, text), [("Jan", "PERSON_A")])
        for text in ("January", "Janek", "Dajan", "Jan2", "2Jan", "Janö", "öJan"):
            with self.subTest(text=text):
                self.assertEqual(runs(m, text), [])

    def test_an_underscore_is_part_of_the_word(self):
        # Dan's fork took `_` as a boundary; here Kowalski_report.pdf stays one word: no part of it is masked alone
        self.assertEqual(runs(matcher("PERSON_A  Kowalski\n"), "_Kowalski_ Kowalski_report.pdf jan_kowalski"), [])
        self.assertEqual(runs(matcher("PERSON_A  Kowalsk*\n"), "Kowalski_report.pdf"),
                         [("Kowalski_report", "PERSON_A")])
        self.assertEqual(runs(matcher("PERSON_A  *kowalski*\n"), "akta_JanKowalskiego2.pdf"),
                         [("akta_JanKowalskiego2", "PERSON_A")])

    def test_word_start_any_ending(self):
        m = matcher("PERSON_A  Kowalsk*\n")
        for word in ("Kowalski", "Kowalskiego", "Kowalskiej"):
            with self.subTest(word=word):
                self.assertEqual(runs(m, f"dla {word}."), [(word, "PERSON_A")])
        self.assertEqual(runs(m, "Nowakowalski"), [])
        self.assertEqual(runs(matcher("PERSON_A  Jan Kowalsk*\n"), "Jan Kowalskiego, Kowalskiego"),
                         [("Jan Kowalskiego", "PERSON_A")])

    def test_any_start_word_end(self):
        m = matcher("PERSON_A  *kowalski\n")
        self.assertEqual(runs(m, "Kowalski JanKowalski"), [("Kowalski", "PERSON_A"), ("JanKowalski", "PERSON_A")])
        self.assertEqual(runs(m, "Kowalskiego"), [])

    def test_anywhere_takes_the_whole_word_also_in_an_email_address(self):
        m = matcher("PERSON_A  *kowalski*\n")
        address = "jan." + "kowalski1984" + "@" + "example.com"
        self.assertEqual(runs(m, f"<{address}>"), [("kowalski1984", "PERSON_A")])

    def test_case_insensitive_with_polish_and_turkish_letters(self):
        m = matcher("CITY_A  łódź | Żółć*\n")
        self.assertEqual(runs(m, "ŁÓDŹ i Łódź"), [("ŁÓDŹ", "CITY_A"), ("Łódź", "CITY_A")])
        self.assertEqual(runs(m, "ŻÓŁCIĄ"), [])
        self.assertEqual(runs(m, "żółćą"), [("żółćą", "CITY_A")])
        self.assertEqual(runs(matcher("FIRM_A  İzmir Ltd\n"), "İZMİR LTD, İzmir Ltd"),
                         [("İZMİR LTD", "FIRM_A"), ("İzmir Ltd", "FIRM_A")])

    def test_whitespace_in_a_term_matches_any_whitespace_run(self):
        m = matcher("PERSON_A  Jan Kowalski\n")
        for text in ("Jan Kowalski", "Jan\tKowalski", "Jan\nKowalski", "Jan \r\n  Kowalski"):
            with self.subTest(text=text):
                self.assertEqual(runs(m, text), [(text, "PERSON_A")])
        self.assertEqual(runs(m, "JanKowalski"), [])

    def test_longest_variant_wins_across_entities(self):
        m = matcher("FIRST_A  Jan\nPERSON_A  Kowalski | Jan Kowalski\n")
        self.assertEqual(runs(m, "Jan Kowalski, Jan"), [("Jan Kowalski", "PERSON_A"), ("Jan", "FIRST_A")])

    def test_punctuation_in_a_variant_is_literal(self):
        m = matcher("ADDRESS_A  ul. Przykladowa 12 | a+b (c)\n")
        self.assertEqual(runs(m, "ul. Przykladowa 12"), [("ul. Przykladowa 12", "ADDRESS_A")])
        self.assertEqual(runs(m, "ulX Przykladowa 12 ul Przykladowa 12"), [])
        self.assertEqual(runs(m, "x a+b (c) y"), [("a+b (c)", "ADDRESS_A")])
        self.assertEqual(runs(m, "aab (c) a b c"), [])

    def test_at_most_fifty_anywhere_variants(self):
        lines = "".join(f"CASE_{chr(65 + i // 26)}{chr(65 + i % 26)}  *zq{i:03d}x*\n" for i in range(60))
        m = matcher(lines)
        self.assertEqual(len(m.inside), terms.MAX_INSIDE)

    def test_no_entities_match_nothing(self):
        self.assertEqual(terms.Matcher([]).find("Jan Kowalski"), [])


class GateReviewMatchTests(unittest.TestCase):
    """The matcher findings of the gate review of block 2."""

    def test_a_spaced_anywhere_variant_matches(self):
        # r"\\s+" was a backslash and an s: every *…* variant with a space never matched
        m = matcher("FIRM_A  *acme corp*\n")
        self.assertEqual(runs(m, "the ACME   Corp deal"), [("ACME   Corp", "FIRM_A")])
        self.assertEqual(runs(m, "İ: acme\tcorp"), [("acme\tcorp", "FIRM_A")], "a text that lower() makes longer")

    def test_overlapping_entities_become_one_run(self):
        m = matcher("PERSON_A  Anna Maria\nPERSON_B  Maria Kowalski\n")
        self.assertEqual(runs(m, "Anna Maria Kowalski"), [("Anna Maria Kowalski", "PERSON_A")])
        self.assertEqual(runs(m, "Maria Kowalski"), [("Maria Kowalski", "PERSON_B")])

    def test_nfd_text_and_format_characters_match(self):
        m = matcher("PERSON_A  Müller | Jürgen*\n")
        nfd = "Mu\u0308ller"
        for text, want in ((nfd, nfd), ("Ju\u0308rgens_bericht.pdf", "Ju\u0308rgens_bericht"),
                           ("Mül\u00adler", "Mül\u00adler"), ("M\u200büller", "M\u200büller"),
                           ("Herr Mu\u0308ller, Jürgen", None)):
            with self.subTest(text=text):
                got = runs(m, text)
                if want is None:
                    self.assertEqual([t for t, _ in got], ["Mu\u0308ller", "Jürgen"])
                else:
                    self.assertEqual(got, [(want, "PERSON_A")])
        self.assertEqual(runs(matcher("PERSON_A  Mu\u0308ller\n"), "Müller"), [("Müller", "PERSON_A")],
                         "a list written in NFD matches NFC text")
        # Hangul in jamo: the vowel and the final consonant are of class 0 and still compose
        jamo = "\u1112\u1161\u11ab\u1100\u116e\u11a8"          # 한국 in NFD
        self.assertEqual(runs(matcher("PLACE_A  한국\n"), f"in {jamo}."), [(jamo, "PLACE_A")])

    def test_joined_forms_of_a_full_name(self):
        m = matcher("PERSON_A  Jan Kowalski\n")
        for text in ("jan.kowalski", "Jan-Kowalski", "jan_kowalski"):
            with self.subTest(text=text):
                self.assertEqual(runs(m, f"see {text}.pdf"), [(text, "PERSON_A")])
        self.assertEqual(runs(m, "jan_kowalski_report.pdf"), [], "`_` is no boundary: one word, not the name")

    def test_one_lookup_per_stem_length_not_a_walk_over_a_bucket(self):
        m = terms.Matcher([Entity(f"C{i}", (Variant(f"abc{i:06d}", terms.STARTS),), i) for i in range(100000)])
        words = " ".join(f"abc{i:07d}x" for i in range(1000))
        t = time.perf_counter()
        self.assertEqual(len(m.find(words)), 1000)
        self.assertLess(time.perf_counter() - t, 1.0, "16 s before: each word walked 100,000 candidates")

    def test_the_id_holds_the_variants(self):
        a = terms.parse("NAME_1  Jan Kowalski\n")[0][0]
        b = terms.parse("NAME_1  Anna Nowak\n")[0][0]
        self.assertNotEqual(a.id, b.id, "a label freed by a removal gives another name another placeholder")
        self.assertEqual(terms.Matcher([a]).find("Jan Kowalski")[0][2].id, a.id)


class InsideCapTests(unittest.TestCase):
    LINES = "".join(f"CASE_{chr(65 + i // 26)}{chr(65 + i % 26)}  *zq{i:03d}x*\n" for i in range(51))

    def test_the_51st_anywhere_variant_of_the_own_list_stops_with_its_line(self):
        with self.assertRaises(TermsError) as cm:
            terms._parse_personal(self.LINES.encode())
        self.assertIn("line 51", str(cm.exception))
        self.assertEqual(len(terms._parse_personal(self.LINES.encode()[:-len(self.LINES.splitlines()[-1]) - 1])), 50)

    def test_a_team_list_names_the_variant_it_leaves_out(self):
        out = terms.Loaded()
        terms._parse_team([("team/x.terms", self.LINES.encode())], out)
        self.assertEqual(len(out.entities), 50)
        self.assertEqual([(r.line, r.reason) for r in out.refused], [(51, "more than 50 *…* variants in all the term "
                                                                          "lists")])


class MarkerTests(unittest.TestCase):
    def test_a_marked_name_is_one_to_five_words_with_a_capital(self):
        got = terms.markers("write to {{Jan Kowalski}} and {{ Anna-Maria O'Neil }} and {{jan}}")
        self.assertEqual([n for _a, _b, n in got], ["Jan Kowalski", "Anna-Maria O'Neil"])

    def test_template_syntax_stays_text(self):
        for text in ("{{ .Values.image.tag }}", "{{ item }}", "{{ item.name }}", "{{ x | default('a') }}",
                     "{{ $labels.instance }}", "{{ One Two Three Four Five Six }}", "{{ Jan2 }}", "{{}}"):
            with self.subTest(text=text):
                self.assertEqual(terms.markers(text), [])

    def test_take_markers_records_the_name_until_its_lifetime_ends(self):
        self.addCleanup(lambda: terms.MARKED.unlink() if terms.MARKED.exists() else None)
        self.addCleanup(terms.reset)
        out, n = terms.take_markers("write to {{Zbigniew Testowski}} today", 3600)
        self.assertEqual((out, n), ("write to Zbigniew Testowski today", 1))
        label = terms._marked()[0].label
        self.assertEqual(runs(terms.matcher(), "Zbigniew  Testowski"), [("Zbigniew  Testowski", label)])
        data = json.loads(terms.MARKED.read_text(encoding="utf-8"))
        data["terms"][0]["expires"] = time.time() - 1
        terms.MARKED.write_text(json.dumps(data), encoding="utf-8")
        terms.reset()
        self.assertEqual(terms.matcher().find("Zbigniew Testowski"), [], "an expired mark masks nothing")


class CommandTests(unittest.TestCase):
    def test_the_command_forms(self):
        self.assertEqual(terms.parse_command("/maisecrets:term add Jan Kowalski"), ("add", "Jan Kowalski"))
        self.assertEqual(terms.parse_command("  /maisecrets:term  remove  Jan  Kowalski "), ("remove", "Jan Kowalski"))
        self.assertEqual(terms.parse_command("maisecrets: term add Jan | Kowalsk*"), ("add", "Jan | Kowalsk*"))
        self.assertEqual(terms.parse_command("/maisecrets:term Jan Kowalski"), ("usage", "Jan Kowalski"))
        self.assertEqual(terms.parse_command("/maisecrets:term add"), ("usage", "add"))
        for text in ("/maisecrets:term", "/maisecrets:term list", "please /maisecrets:term add Jan", None):
            with self.subTest(text=text):
                self.assertIsNone(terms.parse_command(text))


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(lambda: terms.PERSONAL.unlink() if terms.PERSONAL.exists() else None)
        self.addCleanup(terms.reset)
        terms.reset()

    def write(self, text: str, mode: int = 0o600) -> None:
        terms.PERSONAL.write_text(text, encoding="utf-8")
        os.chmod(terms.PERSONAL, mode)

    def test_missing_file_is_no_terms(self):
        self.assertEqual(terms._personal(), [])

    @unittest.skipIf(os.name == "nt", "POSIX mode bits")
    def test_a_file_others_can_read_is_set_to_0600_and_loads(self):
        # Dan's fork failed closed here; an editor writes 0644 by default, and the file is in maisecrets' own folder
        self.write(SAMPLE, 0o644)
        self.assertEqual(len(terms._personal()), 3)
        self.assertEqual(os.stat(terms.PERSONAL).st_mode & 0o777, 0o600)

    def test_a_bad_line_fails_closed_and_names_the_line(self):
        self.write("PERSON_A  Zbigniew Testowski\nPERSON_A  Testowsk*\n")
        with self.assertRaises(TermsError) as cm:
            terms.matcher()
        self.assertIn("terms.txt: line 2", str(cm.exception))
        self.assertNotIn("testowsk", str(cm.exception).lower())
        with self.assertRaises(TermsError):
            detect.scan("hello")      # every scan, so every hook, fails closed

    def test_not_utf8_is_refused_without_its_bytes(self):
        terms.PERSONAL.write_bytes("PERSON_A  Łukasz\n".encode("utf-16"))
        with self.assertRaises(TermsError) as cm:
            terms._personal()
        self.assertNotIn("0x", str(cm.exception))


class CacheTests(unittest.TestCase):
    def setUp(self):
        for f in (terms.PERSONAL, terms.CACHE_FILE):
            self.addCleanup(lambda f=f: f.unlink() if f.exists() else None)
        self.addCleanup(terms.reset)

    def test_the_index_is_cached_and_an_edit_builds_it_again(self):
        terms.PERSONAL.write_text("PERSON_A  Zbigniew Testowski\n", encoding="utf-8")
        os.chmod(terms.PERSONAL, 0o600)
        terms.reset()
        self.assertEqual(len(terms.matcher().find("Zbigniew Testowski")), 1)
        self.assertTrue(terms.CACHE_FILE.exists())
        if os.name != "nt":
            self.assertEqual(os.stat(terms.CACHE_FILE).st_mode & 0o777, 0o600)
        terms.reset()
        self.assertEqual(len(terms.matcher().find("Zbigniew Testowski")), 1, "from the cache")
        terms.PERSONAL.write_text("PERSON_A  Anna Nowak\n", encoding="utf-8")
        terms.reset()
        self.assertEqual(terms.matcher().find("Zbigniew Testowski"), [], "the old index is not used")
        self.assertEqual(len(terms.matcher().find("Anna Nowak")), 1)

    def test_a_damaged_cache_is_a_miss(self):
        terms.PERSONAL.write_text("PERSON_A  Zbigniew Testowski\n", encoding="utf-8")
        os.chmod(terms.PERSONAL, 0o600)
        terms.CACHE_FILE.write_bytes(b"\x00garbage")
        terms.reset()
        self.assertEqual(len(terms.matcher().find("Zbigniew Testowski")), 1)


class TeamFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="team-terms-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg = {"rule_dirs": [str(self.dir)]}

    def test_a_team_file_loads_with_its_refused_lines(self):
        (self.dir / "clients.terms").write_text("CLIENT_A  Zbigniew Testowski\nCLIENT_B  und\n", encoding="utf-8")
        (self.dir / "notes.txt").write_text("CLIENT_C  Not Read\n", encoding="utf-8")
        own = Path(terms.HOME, "rules.d")     # the person's list is terms.txt, not rules.d
        own.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, own, True)
        (own / "mine.terms").write_text("CLIENT_D  Not Read Either\n", encoding="utf-8")
        loaded = terms.load(self.cfg)
        self.assertEqual([e.label for e in loaded.entities], ["CLIENT_A"])
        self.assertEqual([(r.line, r.reason) for r in loaded.refused],
                         [(2, "a common word (rules/term_stoplist.txt) in a team list")])
        self.assertEqual([f.entities for f in loaded.files], [1])

    def test_a_team_file_that_is_not_text_is_left_out_whole(self):
        (self.dir / "bad.terms").write_bytes(b"\xff\xfe\x00")
        loaded = terms.load(self.cfg)
        self.assertEqual([r.reason for r in loaded.refused], ["a file that cannot be read as UTF-8"])

    def test_session_start_says_a_changed_team_list_once(self):
        self.addCleanup(lambda: terms.STATE_FILE.unlink() if terms.STATE_FILE.exists() else None)
        (self.dir / "clients.terms").write_text("CLIENT_A  Zbigniew Testowski\n", encoding="utf-8")
        from unittest import mock
        with mock.patch("maisecrets.user_rules._config", return_value=self.cfg):
            first = terms.session_note()
            self.assertIn("the team term lists changed: 1 term(s) in 1 file(s)", first)
            self.assertIsNone(terms.session_note(), "unchanged: nothing again")
            (self.dir / "clients.terms").write_text("CLIENT_A  Zbigniew Testowski\nCLIENT_B  Acme Holding\n",
                                                    encoding="utf-8")
            self.assertIn("2 term(s) in 1 file(s) (before: 1)", terms.session_note())
        self.assertNotIn("testowsk", first.lower())


    def test_session_start_builds_the_index_so_a_tool_hook_only_loads_it(self):
        self.addCleanup(lambda: terms.STATE_FILE.unlink() if terms.STATE_FILE.exists() else None)
        self.addCleanup(lambda: terms.CACHE_FILE.unlink() if terms.CACHE_FILE.exists() else None)
        (self.dir / "clients.terms").write_text("CLIENT_A  Zbigniew Testowski\n", encoding="utf-8")
        if terms.CACHE_FILE.exists():
            terms.CACHE_FILE.unlink()
        from unittest import mock
        with mock.patch("maisecrets.user_rules._config", return_value=self.cfg):
            terms.session_note()
            self.assertTrue(terms.CACHE_FILE.exists(), "the session start (30 s) builds the index")
            terms.reset()
            with mock.patch.object(terms, "Matcher", wraps=terms.Matcher) as built:
                terms.matcher()
                self.assertTrue(all(c.kwargs.get("data") for c in built.call_args_list), "a tool hook loads it")
            self.assertEqual([e.label for _s, _e, e in terms.matcher().find("Dear Zbigniew Testowski")], ["CLIENT_A"])


class ScanTreeTests(unittest.TestCase):
    def test_the_tree_check_never_reads_the_developers_term_list(self):
        import subprocess
        tree = Path(tempfile.mkdtemp(prefix="scan-tree-"))
        self.addCleanup(shutil.rmtree, tree, True)
        (tree / "notes.txt").write_text("Zbigniew Testowski wrote this\n", encoding="utf-8")
        # a SECRET label: the tree check counts it, and it must not see the list at all
        terms.PERSONAL.write_text("SECRET_A  Zbigniew Testowski\n", encoding="utf-8")
        os.chmod(terms.PERSONAL, 0o600)
        self.addCleanup(terms.PERSONAL.unlink)
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "scan_tree.py"), str(tree)], capture_output=True,
                           text=True, timeout=120, env=dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 secret-shaped value(s)", r.stdout)

if __name__ == "__main__":
    unittest.main()
