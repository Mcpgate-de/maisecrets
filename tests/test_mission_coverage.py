"""scripts/mission_coverage.py joins mission/*.toml, beliefs/*.toml, docs/THREAT-MODEL.md and the promises of
README.md and PRIVACY.md. Each finding class is checked on a small tree of its own, so a check that finds nothing
fails here."""
import contextlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib  # noqa: F401
except ImportError:     # Python < 3.11: the script needs tomllib, like replay_can_fail.py
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT / "scripts"))

THREAT_MODEL = """| # | control | defends against | ends where |
|---|---|---|---|
| C1 | a | A1 | x |
| C2 | b | A1 | x |
| C3 | c | A2 | x |

- **I1** an invariant
"""
README = """# x

## What it does

- **Masks output** before the model
  reads it.
- **Checks a value first:** without sending it.

## What the Claude Code mod does

- **Rewrites a prompt.**

## What it does not protect

- A name without a label.

## Other

- not gated
"""
PRIVACY = """# p

## What it reads

- **Only the prompt.**

## What it stores, and where

- Nothing on disk.

## What leaves the machine

- Nothing, unless
  you ask.
"""
CLAIMS = """[[claim]]
source = "README.md"
quote = "**Rewrites a prompt.**"
kind = "feature"

[[claim]]
source = "PRIVACY.md"
quote = "Nothing on disk."
kind = "feature"

[[claim]]
source = "PRIVACY.md"
quote = "**Only the prompt.**"
kind = "feature"

[[claim]]
source = "PRIVACY.md"
quote = "Nothing, unless you ask."
kind = "promise"
mission = "M1"

[[claim]]
source = "README.md"
quote = "**Masks output** before the model reads it."
kind = "promise"
mission = "M1"

[[claim]]
source = "README.md"
quote = "**Checks a value first:**"
kind = "feature"

[[claim]]
source = "README.md"
quote = "A name without a label."
kind = "limit"
mission = "M1"
"""


def toml_list(xs):
    return "[" + ", ".join(f'"{x}"' for x in xs) + "]"


def belief(name, control, serves=("M1.1",)):
    line = "" if serves is None else f'serves = "{serves}"\n' if isinstance(serves, str) \
        else f"serves = {toml_list(serves)}\n"
    return f'belief = "{name}"\ncontrol = "{control}"\n{line}statement = "s"\nrunner = ["t"]\n[proof]\nfile = "f"\n'


def mission(mid, controls, invariants=(), parts=("all",), measure='none = "a yes or no"'):
    """parts: the sentence of each part; its id is <mid>.<n> unless the item is (sentence, extra TOML lines)."""
    text = (f'mission = "{mid}"\npromise = "p"\ncontrols = {toml_list(controls)}\n'
            f'invariants = {toml_list(invariants)}\n')
    for i, part in enumerate(parts, 1):
        says, extra = (part, f'id = "{mid}.{i}"\n') if isinstance(part, str) else part
        text += f'\n[[part]]\n{extra}says = "{says}"\n'
    if measure is not None:
        text += f'\n[measure]\n{measure}\n'
    return text


def quiet(fn, argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(argv)


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+; the other CI Pythons run the script")
class MissionCoverageTests(unittest.TestCase):
    def tree(self, missions, beliefs, claims=CLAIMS, readme=README, privacy=PRIVACY):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-mission-"))
        self.addCleanup(shutil.rmtree, root, True)
        for d in ("docs", "mission", "beliefs"):
            (root / d).mkdir()
        (root / "docs" / "THREAT-MODEL.md").write_text(THREAT_MODEL, encoding="utf-8")
        (root / "README.md").write_text(readme, encoding="utf-8")
        (root / "PRIVACY.md").write_text(privacy, encoding="utf-8")
        (root / "mission" / "claims.toml").write_text(claims, encoding="utf-8")
        for name, text in missions.items():
            (root / "mission" / f"{name}.toml").write_text(text, encoding="utf-8")
        # each belief: its control, which serves M1.1, or (control, serves); serves None leaves the key out
        for i, b in enumerate(beliefs):
            control, serves = (b, ("M1.1",)) if isinstance(b, str) else b
            (root / "beliefs" / f"b{i}.toml").write_text(belief(f"b{i}", control, serves), encoding="utf-8")
        return root

    def covered(self):
        return {"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"])}

    def test_a_covered_tree_has_no_finding_and_passes_strict(self):
        import mission_coverage
        root = self.tree(self.covered(), ["C1", "C2", "C3", "I1"])
        r = mission_coverage.analyse(root)
        for key in ("gaps", "thin", "no_invariant", "orphans", "unknown", "claims", "undocumented_belief_controls"):
            self.assertEqual(r[key], [], key)
        self.assertEqual(r["unowned_beliefs"], {})
        self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 0)

    def test_each_mission_finding_class_is_named(self):
        import mission_coverage
        missions = {"M1-x": mission("M1", ["C1", "C2", "C9"], parts=("one", "none", "many")),
                    "M7-y": mission("M2", [], parts=())}
        root = self.tree(missions, [("C1", ["M1.1"]), ("C2", ["M1.3"]), ("C2", ["M1.3"]), ("operations", [])])
        r = mission_coverage.analyse(root)
        self.assertEqual(r["thin"], ["M1.1: one belief: one"])
        self.assertIn("M1.2: no belief: none", r["gaps"])
        self.assertIn("M2: no part names a belief", r["gaps"])
        self.assertIn("M1: C9 is not in docs/THREAT-MODEL.md", r["unknown"])
        self.assertIn("M7-y.toml: the file name does not start with M2-", r["unknown"])
        self.assertEqual(r["no_invariant"], ["M1", "M2"])
        self.assertEqual(r["orphans"], ["C3 serves no mission", "I1 serves no mission"])
        self.assertEqual(r["unowned_beliefs"], {"operations": 1})
        self.assertEqual(r["undocumented_belief_controls"], ["operations"])

    def test_each_broken_link_between_a_belief_and_a_part_is_named(self):
        import mission_coverage
        parts = ("all", ("two", 'id = "M1.1"\n'), ("odd", 'id = "M2.7"\n'), ("glob", 'id = "M1.4"\nbeliefs = ["b*"]\n'))
        missions = {"M1-x": mission("M1", ["C1", "C2"], ["I1"], parts=parts)}
        beliefs = [("C1", ["M1.1"]), ("C1", None), ("C2", ["M9.1"]), ("C3", ["M1.1"]), ("C1", "M1.1"),
                   ("detector", ["M1.1"]), ("I1", ["M1.4"])]
        r = mission_coverage.analyse(self.tree(missions, beliefs))
        self.assertIn("M1.1: 2 parts have this id", r["unknown"])
        self.assertIn("M1, part 3: the id 'M2.7' is not M1.<number>", r["unknown"])
        self.assertIn("M1.4: a part names no beliefs; each belief names its parts in serves", r["unknown"])
        self.assertIn("b1: no serves list of part ids (serves = [] when it serves no promise)", r["unknown"])
        self.assertIn("b2: serves M9.1, which no mission has", r["unknown"])
        self.assertIn("b3: serves M1.1, but M1 does not name its control C3", r["unknown"])
        self.assertIn("b4: no serves list of part ids (serves = [] when it serves no promise)", r["unknown"])
        self.assertIn("b5: serves M1.1, but M1 does not name its control detector", r["unknown"])
        self.assertFalse(any(u.startswith(("b0:", "b6:")) for u in r["unknown"]),
                         "a served part whose mission names the belief's control is no finding")
        self.assertEqual(len(r["unknown"]), 8, r["unknown"])
        self.assertEqual(r["unowned_beliefs"], {}, "serves = [] is the only way to serve no promise")

    def test_ids_are_unique_over_all_missions_and_a_label_needs_its_mission(self):
        import mission_coverage
        labelled = mission("M1", ["C1", "C2", "C3"], ["I1"]).replace('invariants = ["I1"]\n',
                                                                     'invariants = ["I1"]\nlabels = ["ops", "C2"]\n')
        missions = {"M1-x": labelled, "M1-y": mission("M1", [], parts=(("again", 'id = "M1.1"\n'),)),
                    "M2-z": mission("M2", [], parts=(("own", 'id = "M2.1"\n'),))}
        beliefs = ["C1", "C2", "C3", "I1", ("ops", ["M1.1"]), ("ops", ["M2.1"])]
        r = mission_coverage.analyse(self.tree(missions, beliefs))
        self.assertIn("M1: 2 files name this mission", r["unknown"])
        self.assertIn("M1.1: 2 parts have this id", r["unknown"])
        self.assertIn("M1: C2 is a control; name it in controls or invariants, not labels", r["unknown"])
        self.assertIn("b5: serves M2.1, but M2 does not name its control ops", r["unknown"])
        self.assertFalse(any(u.startswith("b4:") for u in r["unknown"]), "M1 names the label ops")

    def test_a_belief_counts_only_for_the_parts_it_serves(self):
        import mission_coverage
        missions = {"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], parts=("a", "b", "c"))}
        beliefs = [("C1", ["M1.1", "M1.2"]), ("C2", ["M1.2"]), ("C3", ["M1.2"]), ("I1", [])]
        r = mission_coverage.analyse(self.tree(missions, beliefs))
        self.assertEqual(r["missions"], [("M1", "p", [("M1.1", "a", 1), ("M1.2", "b", 3), ("M1.3", "c", 0)])])
        self.assertEqual(r["gaps"], ["M1.3: no belief: c"])
        self.assertEqual(r["unowned_beliefs"], {"I1": 1})

    def test_a_part_tested_elsewhere_is_still_a_gap_and_says_where(self):
        import mission_coverage
        m = mission("M1", ["C1", "C2", "C3"], ["I1"])
        m += '\n[[part]]\nid = "M1.2"\nsays = "the mod"\ntests = ["tests/mod.test.ts"]\n'
        r = mission_coverage.analyse(self.tree({"M1-x": m}, ["C1", "C2", "C3", "I1"]))
        self.assertEqual(r["gaps"], ["M1.2: no belief (tested only in tests/mod.test.ts, which no mutation proves): "
                                     "the mod"])

    def test_a_reworded_promise_and_an_unmapped_bullet_are_claim_findings(self):
        import mission_coverage
        readme = README.replace("before the model\n  reads it.", "before the model sees it.")
        readme = readme.replace("- A name without a label.", "- A name without a label.\n- A new limit.")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], readme=readme))
        self.assertIn("claim not found in README.md: **Masks output** before the model reads it.", r["claims"])
        self.assertIn('README "What it does" bullet no claim maps: **Masks output** before the model sees it.',
                      r["claims"])
        self.assertIn('README "What it does not protect" bullet no claim maps: A new limit.', r["claims"])
        self.assertFalse(any("not gated" in c for c in r["claims"]), "a section outside the gate is free text")

    def test_privacy_bullets_are_gated_and_a_gated_section_cannot_go(self):
        import mission_coverage
        privacy = PRIVACY.replace("- Nothing, unless", "- A crash report goes out.\n- Nothing, unless")
        privacy = privacy.replace("## What it stores, and where", "## What it keeps")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], privacy=privacy))
        self.assertEqual(r["claims"], ['PRIVACY.md has no section "What it stores, and where" with a bullet '
                                       '(GATED_SECTIONS)',
                                       'PRIVACY "What leaves the machine" bullet no claim maps: '
                                       'A crash report goes out.'])
        readme = README.replace("## What the Claude Code mod does\n\n", "")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], readme=readme))
        self.assertEqual(r["claims"], ['README.md has no section "What the Claude Code mod does" with a bullet '
                                       '(GATED_SECTIONS)'])
        # the bullets moved out of a gated section: the claims still stand in the file, the section is empty
        privacy = PRIVACY.replace("- **Only the prompt.**\n", "").replace("# p\n", "# p\n\n- **Only the prompt.**\n")
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], privacy=privacy))
        self.assertEqual(r["claims"], ['PRIVACY.md has no section "What it reads" with a bullet (GATED_SECTIONS)'])
        root = self.tree(self.covered(), ["C1", "C2", "C3", "I1"])
        (root / "mission" / "claims.toml").unlink()
        self.assertEqual(mission_coverage.analyse(root)["claims"],
                         ["mission/claims.toml not found: no promise of README.md or PRIVACY.md is checked"])

    def test_a_claim_needs_a_kind_and_an_existing_mission(self):
        import mission_coverage
        claims = CLAIMS.replace('kind = "limit"\nmission = "M1"', 'kind = "limit"\nmission = "M9"')
        claims = claims.replace('kind = "feature"', 'kind = "wish"')
        r = mission_coverage.analyse(self.tree(self.covered(), ["C1", "C2", "C3", "I1"], claims=claims))
        self.assertIn("claim names no existing mission (M9): A name without a label.", r["claims"])
        self.assertIn("claim kind 'wish' is not one of promise, limit, feature: **Checks a value first:**",
                      r["claims"])

    def test_strict_fails_on_each_blocking_class_and_the_report_alone_does_not(self):
        import mission_coverage
        cases = {"claim": (self.covered(), ["C1", "C2", "C3", "I1"], CLAIMS.replace("A name without", "A cat with")),
                 "orphan": ({"M1-x": mission("M1", ["C1", "C2"], ["I1"])}, ["C1", "C2", "I1"], CLAIMS),
                 "gap": ({"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], parts=("n",))}, [("C1", [])], CLAIMS),
                 "no serves": (self.covered(), ["C1", "C2", ("C3", None), "I1"], CLAIMS)}
        for name, (missions, beliefs, claims) in cases.items():
            with self.subTest(name):
                root = self.tree(missions, beliefs, claims=claims)
                self.assertEqual(quiet(mission_coverage.main, ["--root", str(root)]), 0)
                self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 1)

    def test_a_measure_is_read_from_the_last_row_and_a_missing_one_is_named(self):
        import mission_coverage
        log = ("| Date | Source | Recall |\n|---|---|---|\n| d1 | holdout-v2 | 0.5 |\n| d2 | other | 0.1 |\n"
               "| d3 | holdout-v2 | 0.7 |\n")
        read = 'what = "recall"\nsource = "LOG.md"\nrow = "holdout-v2"\ncolumn = 3\ngate = "g"'
        missions = {"M1-x": mission("M1", ["C1", "C2", "C3"], ["I1"], measure=read),
                    "M2-y": mission("M2", [], measure=None),
                    "M3-z": mission("M3", [], measure=read.replace("holdout-v2", "holdout-v9"))}
        root = self.tree(missions, ["C1", "C2", "C3", "I1"])
        (root / "LOG.md").write_text(log, encoding="utf-8")
        r = mission_coverage.analyse(root)
        self.assertEqual(r["measures"], ["M1: 0.7 = recall (bound: g)"])
        self.assertIn("M2: no [measure], and no `none` that says why", r["unknown"])
        self.assertIn("M3: the measure cannot be read: no row with 'holdout-v9' in LOG.md", r["unknown"])

    def test_the_repository_maps_every_promise_and_names_only_documented_controls(self):
        import mission_coverage
        r = mission_coverage.analyse(ROOT)
        self.assertGreaterEqual(len(r["missions"]), 1, "a population test must fail on an empty population")
        self.assertEqual(r["unknown"], [])
        self.assertEqual(r["gaps"], [], "every part of a mission rests on a belief that can fail")
        self.assertEqual(r["orphans"], [], "a documented control must serve a mission")
        self.assertEqual(r["claims"], [], "every promise of README.md and PRIVACY.md maps to a mission")


if __name__ == "__main__":
    unittest.main()
