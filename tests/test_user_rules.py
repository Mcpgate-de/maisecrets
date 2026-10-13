"""Rules of your own (maisecrets/user_rules.py, C25): rule folders with static checks and a quarantine, the allow
list of exact values and rule ids, the rule_dirs setting that only a typed prompt changes, the NAME type, the extension
point detect.extra_matchers, and `maisecrets rules`.

Every value is made up and built from parts at run time, so scripts/scan_tree.py finds no shape in this file."""
from __future__ import annotations

import io
import json
import os
import platform
import shutil
import sys
import tempfile
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

from maisecrets import cli, detect, events, hooks, placeholder, settings, user_rules, vault  # noqa: E402
from maisecrets.vault import HOME, ConfigError, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
OWN = Path(HOME, "rules.d")
ALLOW = Path(HOME, "allow.txt")
TAIL = "".join(["Rq4L", "m8Zt", "Kw2P"]) * 2          # 24 characters, no known shape
ADDRESS = "ada" + "@" + "firma-xyz.de"
OTHER_ADDRESS = "bob" + "@" + "firma-xyz.de"


def token(prefix: str = "tkx") -> str:
    return prefix + "_" + TAIL


def _clean() -> None:
    CONFIG.write_text(json.dumps(TEST_CONFIG))
    shutil.rmtree(OWN, ignore_errors=True)
    for p in (ALLOW, user_rules.STATE_FILE, events.EVENTS):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    detect.reset_rules()


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    _hygiene.assert_pristine()


def write_rules(folder: Path, rules: list, name: str = "team.json") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(json.dumps({"rules": rules}), encoding="utf-8")


def kinds(text: str) -> list[str]:
    return [m.kind for m in detect.scan(text)]


class Base(unittest.TestCase):
    def setUp(self):
        _clean()
        self.addCleanup(_clean)
        self.tmp = Path(tempfile.mkdtemp(prefix="rules-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)


class RuleFolders(Base):
    def test_a_rule_in_the_own_folder_finds_its_shape_after_the_built_in_rules(self):
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        (OWN / "more.prefixes").write_text("# a comment\nbuild-key  bkx-[0-9a-f]{32}\n", encoding="utf-8")
        detect.reset_rules()
        found = detect.scan(f"deploy with {token()} now")
        self.assertEqual([(m.kind, m.type, m.value) for m in found], [("user:team-token", "SECRET", token())])
        self.assertEqual(kinds("key bkx-" + "0123456789abcdef" * 2), ["user:build-key"])
        ids = [r.id for r in detect.rules()]
        self.assertLess(ids.index("own_secret_rules" if "own_secret_rules" in ids else ids[0]),
                        ids.index("user:team-token"))
        first_pii = next(i for i, r in enumerate(detect.rules()) if r.type != "SECRET" and not r.id.startswith("user:"))
        self.assertLess(ids.index("user:team-token"), first_pii, "user rules run before the PII rules")
        # a built-in shape stays the built-in's: the user rule never takes the span first
        write_rules(OWN, [{"id": "my-webhook", "regex": r"whsec_[A-Za-z0-9+/=_-]{24,}", "keywords": ["whsec_"]}])
        detect.reset_rules()
        self.assertEqual(kinds("whsec_" + TAIL), ["webhook-signing-secret"])

    def test_a_rule_that_fails_a_check_is_quarantined_and_the_rest_load(self):
        good = {"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}
        bad = {
            "nested": ({"id": "nested", "regex": r"tky_(?:[a-z]+)+"}, "a nested quantifier"),
            "leading": ({"id": "leading", "regex": r"\w+tkz_secret"}, "starts with a quantifier"),
            "short": ({"id": "short", "regex": r"ab[0-9]{30}"}, "no keyword or literal of 4"),
            "long": ({"id": "long", "regex": "tkq_" + "a" * 300}, "longer than 300"),
            "broken": ({"id": "broken", "regex": r"tkw_(unclosed"}, "does not compile"),
            "bad-id": ({"id": "bad id!", "regex": r"tkv_[a-z]{20}"}, "an id that is not"),
            "bad-type": ({"id": "bad-type", "type": "PASSWORD", "regex": r"tku_[a-z]{20}"}, "a type that is not"),
            "short-kw": ({"id": "short-kw", "regex": r"[a-z]{3}_[0-9]{20}", "keywords": ["ab"]}, "no keyword or"),
        }
        write_rules(OWN, [good] + [r for r, _ in bad.values()])
        (OWN / "broken.json").write_text("{not json", encoding="utf-8")
        (OWN / "huge.prefixes").write_text("# x\n" * (user_rules.MAX_FILE_BYTES // 4 + 10), encoding="utf-8")
        detect.reset_rules()
        loaded = user_rules.load()
        self.assertEqual([r.id for r in loaded.rules], ["user:team-token"])
        reasons = {(q.file, q.rule): q.reason for q in loaded.quarantined}
        for rid, (rule, why) in bad.items():
            with self.subTest(rid):
                shown = "?" if rid == "bad-id" else rule["id"]
                self.assertIn(why, reasons.get(("team.json", shown), ""), reasons)
        self.assertIn("not valid JSON", reasons[("broken.json", "")])
        self.assertIn("larger than 64 KB", reasons[("huge.prefixes", "")])
        self.assertEqual(kinds(token()), ["user:team-token"], "the good rule of the same file still works")
        for q in loaded.quarantined:
            self.assertNotIn("tky_", q.reason + q.rule, "a reason names the check, never the regex")

    def test_bounded_repeats_and_lookarounds_pass_the_checks(self):
        for rx in (r"(?<![a-z])tkb_(?:-[a-z0-9]{4}){3}", r"\btkc_[a-z]{1,63}(?:\.[a-z]{1,63}){1,5}",
                   r"(?i)acme[_-]?key[=:]\s?([a-f0-9]{32})", r"[A-Z]{4}-tkd_[0-9]{8}"):
            with self.subTest(rx):
                why, compiled, prefilter = user_rules.check_regex(rx)
                self.assertIsNone(why)
                self.assertTrue(prefilter and all(len(k) >= 4 for k in prefilter), prefilter)

    def test_a_folder_holds_at_most_500_rules_and_an_id_names_one_rule(self):
        many = [{"id": f"r{i}", "regex": f"tk{i:03d}_[A-Za-z0-9]{{24}}"}
                for i in range(user_rules.MAX_RULES_PER_FOLDER + 7)]
        (OWN).mkdir(parents=True)
        for part in range(0, len(many), 200):      # several files, one limit for the folder
            write_rules(OWN, many[part:part + 200], f"part{part:04d}.json")
        team = self.tmp / "team"
        write_rules(team, [{"id": "r0", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        loaded = user_rules.load({"rule_dirs": [str(team)]})
        self.assertEqual(len(loaded.rules), user_rules.MAX_RULES_PER_FOLDER)
        reasons = [q.reason for q in loaded.quarantined]
        self.assertIn("7 rule(s) past the limit of 500 per folder", reasons)
        self.assertIn("an id that an earlier rule has", reasons, "r0 of the second folder")

    def test_a_folder_inside_the_maisecrets_home_or_a_relative_one_is_not_read(self):
        for shown, why in ((str(HOME), "inside the maisecrets folder"), ("relative/rules", "not an absolute path")):
            with self.subTest(shown):
                loaded = user_rules.load({"rule_dirs": [shown]})
                (folder,) = [f for f in loaded.folders if f.shown == shown]
                self.assertIn(why, folder.state)
        loaded = user_rules.load({"rule_dirs": [str(self.tmp / "not-yet")]})
        self.assertEqual([f.state for f in loaded.folders if f.source == "setting"], ["missing"])

    def test_a_folder_reads_only_rule_files_never_an_allow_list(self):
        team = self.tmp / "team"
        write_rules(team, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24}", "keywords": ["tkx_"]}])
        (team / "allow.txt").write_text(token() + "\nrule: email\n", encoding="utf-8")
        (team / "notes.txt").write_text("tkx_ is ours\n", encoding="utf-8")
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
        detect.reset_rules()
        self.assertEqual(kinds(f"{token()} and {ADDRESS}"), ["user:team-token", "email"])
        self.assertEqual(user_rules.load().quarantined, [], "the other files are not even read")

    def test_policy_folders_come_first_and_stay_when_the_person_removes_theirs(self):
        team, admin = self.tmp / "team", self.tmp / "admin"
        write_rules(team, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}])
        write_rules(admin, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}", "type": "NAME"}])
        policy = self.tmp / "policy.json"
        policy.write_text(json.dumps({"rule_dirs": [str(admin)], "allow": ["rule: url-query-secret"]}))
        with mock.patch.dict(vault.POLICY_PATHS, {platform.system(): policy}):
            CONFIG.write_text(json.dumps({**TEST_CONFIG, "rule_dirs": [str(team)]}))
            cfg = load_config()
            self.assertNotIn("rule_dirs", cfg["policy_keys"], "the person keeps their own folders")
            loaded = user_rules.load(cfg)
            self.assertEqual([(f.source, f.rules) for f in loaded.folders], [("policy", 1), ("own", 0), ("setting", 0)])
            self.assertEqual(loaded.rules[0].type, "NAME", "on one id the administrator's rule stays")
            self.assertEqual(user_rules.allow_list(cfg)[1], frozenset({"url-query-secret"}))
            self.assertIn(str(admin), settings.render(show_all=True, only="rule_dirs"))
            for broken in ({"rule_dirs": "not a list"}, {"rule_dirs": [1]}, {"allow": "rule: email"}):
                policy.write_text(json.dumps(broken))
                with self.assertRaises(ConfigError, msg="a broken policy still fails closed"):
                    load_config()


class AllowList(Base):
    def setUp(self):
        super().setUp()
        write_rules(OWN, [{"id": "team-token", "regex": r"tkx_[A-Za-z0-9]{24,}", "keywords": ["tkx_"]}])

    def test_an_allow_entry_is_one_exact_value(self):
        ALLOW.write_text(f"# my own build token\n{token()}\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"use {token()} here"), [], "the exact value is never a hit")
        self.assertEqual(kinds(f"use {token()}XYZ here"), ["user:team-token"], "a longer value is another value")
        self.assertEqual(kinds(f"use tkx_{TAIL[1:]}Q here"), ["user:team-token"])
        ALLOW.write_text("tkx_.*\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"use {token()} here"), ["user:team-token"], "an entry is never a pattern")

    def test_an_allowed_value_keeps_its_span_so_no_later_rule_reports_a_part(self):
        address = ADDRESS
        ALLOW.write_text(address + "\n", encoding="utf-8")
        detect.reset_rules()
        self.assertEqual(kinds(f"mail {address} today"), [])
        self.assertEqual(kinds("mail " + OTHER_ADDRESS), ["email"])

        def first_name(t: str) -> list:      # a later matcher that finds a part of the allowed address
            at = t.find(address)
            return [detect.Match("term:person", "NAME", "ada", at, at + 3)] if at >= 0 else []
        with mock.patch.object(detect, "extra_matchers", [first_name]):
            self.assertEqual(kinds(f"mail {address} today"), [])

    def test_a_rule_id_switches_the_rule_off(self):
        ALLOW.write_text("rule: user:team-token\nrule: email\n", encoding="utf-8")
        detect.reset_rules()
        ids = {r.id for r in detect.rules()}
        self.assertNotIn("email", ids)
        self.assertNotIn("user:team-token", ids)
        self.assertEqual(kinds(f"{token()} {ADDRESS}"), [])
        self.assertIn("iban", {r.id.split("#")[0] for r in detect.rules()}, "only the named rules go")

    def test_an_unreadable_allow_list_allows_nothing(self):
        ALLOW.write_bytes(b"\xff\xfe" + token().encode())
        detect.reset_rules()
        self.assertEqual(kinds(token()), ["user:team-token"])


class RuleDirsSetting(Base):
    def _prompt(self, text: str, client: dict = CLAUDE, **extra) -> dict:
        return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})

    def _dirs(self) -> list:
        return json.loads(CONFIG.read_text()).get("rule_dirs", [])

    def test_a_typed_prompt_adds_and_removes_a_folder(self):
        team = self.tmp / "team rules"
        team.mkdir()
        out = self._prompt(f"/maisecrets:settings rule_dirs add {team}")
        self.assertNotEqual(out.get("decision"), "block", out)
        self.assertIn("Rule folders is", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self._dirs(), [str(team)], "a path with a space stays one folder")
        self._prompt(f"maisecrets: set rule_dirs add {team}/", CODEX)
        self.assertEqual(len(self._dirs()), 1, "the same folder once")
        self._prompt(f"maisecrets: set rule_dirs remove {team}", CODEX)
        self.assertEqual(self._dirs(), [])
        out = self._prompt(f"/maisecrets:settings rule_dirs add {HOME}")
        self.assertIn("not added", out["reason"])
        self.assertEqual(self._dirs(), [])

    def test_only_a_typed_prompt_adds_a_rule_folder(self):
        team = str(self.tmp / "team")
        for text, extra in ((f"/maisecrets:settings rule_dirs add {team}\nand then deploy", {}),
                            (f"please maisecrets: set rule_dirs add {team}", {}),
                            (f"/maisecrets:settings rule_dirs add {team}", {"source": "schedule_wakeup"})):
            with self.subTest(text=text, **extra):
                self._prompt(text, **extra)
                self.assertEqual(self._dirs(), [])
        refused = hooks.pre_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                                  "tool_input": {"command": f"echo '/maisecrets:settings rule_dirs add {team}'"}})
        self.assertEqual(refused["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_a_file_ignored_for_a_wrong_type_keeps_its_folders(self):
        CONFIG.write_text(json.dumps({**TEST_CONFIG, "tips": "yes", "rule_dirs": [str(self.tmp)]}))
        cfg = load_config()
        self.assertTrue(cfg["config_warning"])
        self.assertEqual(cfg["rule_dirs"], [str(self.tmp)], "more rules only make detection stricter")


class NameType(unittest.TestCase):
    def test_name_is_a_type_everywhere_types_are_listed(self):
        self.assertEqual(hooks.TYPE_WORDS["NAME"], ("name", "names"))
        self.assertEqual(placeholder.ENTITY_OF_TYPE["NAME"], "person")
        self.assertIsNone(placeholder.display_for("NAME", "Ada Lovelace"), "a display shows nothing of a name")
        self.assertIn("NAME", user_rules.TYPES)
        ref = placeholder.make_ref("NAME", 3, placeholder.display_for("NAME", "Ada Lovelace"))
        self.assertEqual(ref, chr(0x27E6) + "NAME_c3" + chr(0x27E7))
        self.assertEqual(placeholder.key_of(ref), "NAME_c3")


class ExtraMatchers(Base):
    def test_an_extra_matcher_runs_after_the_rules_and_keeps_their_spans(self):
        address = ADDRESS
        text = f"Ada Lovelace wrote to {address}"

        def names(t: str) -> list:
            out = [detect.Match("term:person", "NAME", "Ada Lovelace", 0, 12)]
            at = t.index(address)
            out.append(detect.Match("term:person", "NAME", address, at, at + len(address)))   # taken by email
            return out
        self.assertEqual(detect.extra_matchers, [detect._term_matches], "the terms (block 2) only")
        with mock.patch.object(detect, "extra_matchers", [names]):
            found = detect.scan(text)
            # a term that a rule took keeps the rule's span and type, and becomes the term (block 2: the store keeps
            # the entity id, and the placeholder is never resolved)
            self.assertEqual([(m.kind, m.type, m.value) for m in found],
                             [("term:person", "NAME", "Ada Lovelace"), ("term:person", "EMAIL", address)])
            self.assertEqual(detect.scan(text, enabled={"email"})[0].kind, "email", "enabled holds for them too")
            ALLOW.write_text("Ada Lovelace\n", encoding="utf-8")
            detect.reset_rules()
            self.assertEqual([m.value for m in detect.scan(text)], [address], "the allow list holds for them too")


class Quarantine(Base):
    def test_the_session_start_names_a_new_quarantine_once_and_events_log_records_it(self):
        write_rules(OWN, [{"id": "nested", "regex": r"tky_(?:[a-z]+)+"}])
        detect.reset_rules()
        note = user_rules.session_note()
        self.assertIn("1 rule(s) of your own were left out", note)
        (line,) = events.load()
        self.assertEqual(line["hits"], [{"key": "", "type": "RULE", "kind": "user:nested"}])
        self.assertIn("a nested quantifier", line["outcome"])
        self.assertIsNone(user_rules.session_note(), "unchanged: said once")
        with redirect_stdout(io.StringIO()) as out:
            cli.cmd_report(["last"])
        self.assertIn("no detection recorded yet", out.getvalue(), "a quarantine is no false alarm to report")


class RulesCommand(Base):
    def run_cli(self, *args: str, stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        stdin_file = io.TextIOWrapper(io.BytesIO(stdin.encode("utf-8")), encoding="utf-8")
        with redirect_stdout(out), redirect_stderr(err), mock.patch("sys.stdin", stdin_file):
            rc = cli.main(["rules", *args])
        return rc, out.getvalue(), err.getvalue()

    def test_init_writes_a_folder_that_its_own_check_passes(self):
        top = self.tmp / "team-rules"
        rc, out, _ = self.run_cli("init", str(top))
        self.assertEqual(rc, 0)
        for name in ("README.md", "rules/example.json", "rules/example.prefixes", "samples.txt",
                     ".github/workflows/rules.yml", ".gitlab-ci.yml"):
            self.assertTrue((top / name).is_file(), name)
        readme = (top / "README.md").read_text()
        self.assertIn("/maisecrets:settings rule_dirs add ~/src/team-rules/rules", readme)
        self.assertIn("No names", readme)
        rc, out, _ = self.run_cli("check", str(top))
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"ok      example-internal-token  \d+\.\d ms")
        self.assertIn("samples: all pass", out)
        self.assertEqual(self.run_cli("init", str(top))[0], 1, "never over a folder that has the files")

    def test_check_fails_on_a_refused_rule_and_on_a_sample_and_names_no_text(self):
        top = self.tmp / "t"
        write_rules(top / "rules", [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"},
                                    {"id": "nested", "regex": r"tky_(?:[a-z]+)+"}])
        (top / "samples.txt").write_text(f"hit tok {token()}\nmiss plain words\nmiss {token()}\n", encoding="utf-8")
        rc, out, _ = self.run_cli("check", str(top))
        self.assertEqual(rc, 1)
        self.assertIn("refused team.json:nested  a nested quantifier", out)
        self.assertIn("samples.txt line 3: a hit of user:tok where none belongs", out)
        self.assertNotIn(TAIL, out, "a sample's text is never printed")

    def test_show_and_test_print_no_value(self):
        write_rules(OWN, [{"id": "tok", "regex": r"tkx_[A-Za-z0-9]{24}"}, {"id": "bad", "regex": r"\w+x"}])
        ALLOW.write_text(token() + "\nrule: email\n", encoding="utf-8")
        detect.reset_rules()
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"rules\.d \(own\) · 1 rule\(s\) · hash [0-9a-f]{12}")
        self.assertIn("team.json · bad · a regex that starts with a quantifier", out)
        self.assertIn("1 exact value(s), 1 rule id(s) switched off (email)", out)
        self.assertNotIn(TAIL, out)
        ALLOW.unlink()
        detect.reset_rules()
        rc, out, _ = self.run_cli("test", stdin=f"run {token()}\n")
        self.assertEqual(rc, 0)
        self.assertIn("user:tok", out)
        self.assertNotIn(TAIL, out)

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib is Python 3.11+")
    def test_import_converts_the_gitleaks_form_and_refuses_what_it_cannot_read(self):
        toml = self.tmp / "gitleaks.toml"
        toml.write_text(
            '[[rules]]\nid = "acme"\nregex = \'\'\'acme_[a-z0-9]{32}\'\'\'\nkeywords = ["acme_"]\nentropy = 3.5\n'
            '[[rules.allowlists]]\nstopwords = ["example"]\n'
            '[[rules]]\nid = "filtered"\nregex = \'\'\'fltr_[a-z]{20}\'\'\'\n'
            'filter = \'\'\'len(finding["secret"]) > 3\'\'\'\n'
            '[[rules]]\nid = "floor"\nregex = \'\'\'flor_[a-z]{20}\'\'\'\n'
            'filter = \'\'\'entropy(finding["secret"]) <= 3\'\'\'\n'
            '[[rules]]\nid = "slow"\nregex = \'\'\'\\w+slow\'\'\'\n', encoding="utf-8")
        rc, out, err = self.run_cli("import", str(toml))
        self.assertEqual(rc, 1)
        rules = json.loads(out)["rules"]
        self.assertEqual([r["id"] for r in rules], ["acme", "floor"])
        self.assertEqual(rules[0]["allowlists"], [{"stopwords": ["example"]}])
        self.assertEqual(rules[1]["entropy"], 3.0)
        self.assertIn("refused filtered: a filter maisecrets cannot read", err)
        self.assertIn("refused slow: a regex that starts with a quantifier", err)
        team = self.tmp / "imported"
        write_rules(team, rules)
        self.assertEqual(len(user_rules.load_folder(team, "x")[0]), 2, "the output loads")


if __name__ == "__main__":
    unittest.main()
