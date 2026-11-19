"""scripts/mission_coverage.py joins mission/*.toml, beliefs/*.toml and docs/THREAT-MODEL.md. Each
finding class is checked on a small tree of its own, so a check that finds nothing fails here."""
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


def belief(name, control):
    return f'belief = "{name}"\ncontrol = "{control}"\nstatement = "s"\nrunner = ["t"]\n[proof]\nfile = "f"\n'


def quiet(fn, argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(argv)


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+; the other CI Pythons run the script")
class MissionCoverageTests(unittest.TestCase):
    def tree(self, missions, beliefs):
        root = Path(tempfile.mkdtemp(prefix="maisecrets-mission-"))
        self.addCleanup(shutil.rmtree, root, True)
        for d in ("docs", "mission", "beliefs"):
            (root / d).mkdir()
        (root / "docs" / "THREAT-MODEL.md").write_text(THREAT_MODEL, encoding="utf-8")
        for name, text in missions.items():
            (root / "mission" / f"{name}.toml").write_text(text, encoding="utf-8")
        for i, control in enumerate(beliefs):
            (root / "beliefs" / f"b{i}.toml").write_text(belief(f"b{i}", control), encoding="utf-8")
        return root

    def mission(self, mid, controls, invariants=()):
        return (f'mission = "{mid}"\npromise = "p"\ncontrols = {list(controls)!r}\n'
                f'invariants = {list(invariants)!r}\n').replace("'", '"')

    def test_a_covered_tree_has_no_finding_and_passes_strict(self):
        import mission_coverage
        root = self.tree({"M1-x": self.mission("M1", ["C1", "C2", "C3"], ["I1"])},
                         ["C1", "C1", "C2", "C2", "C3", "C3", "I1"])
        r = mission_coverage.analyse(root)
        for key in ("gaps", "thin", "no_invariant", "orphans", "unknown", "undocumented_belief_controls"):
            self.assertEqual(r[key], [], key)
        self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 0)

    def test_each_finding_class_is_named(self):
        import mission_coverage
        root = self.tree({"M1-x": self.mission("M1", ["C1", "C2", "C9"]), "M7-y": self.mission("M2", [])},
                         ["C1", "C2", "C2", "operations"])
        r = mission_coverage.analyse(root)
        self.assertIn("M1: C9 has no belief", r["gaps"])
        self.assertIn("M1: C1 has one belief", r["thin"])
        self.assertEqual(r["no_invariant"], ["M1", "M2"])
        self.assertEqual(r["orphans"], ["C3 serves no mission", "I1 serves no mission"])
        self.assertIn("M1: C9 is not in docs/THREAT-MODEL.md", r["unknown"])
        self.assertIn("M7-y.toml: the file name does not start with M2-", r["unknown"])
        self.assertEqual(r["undocumented_belief_controls"], ["operations"])

    def test_strict_fails_on_a_gap_and_the_report_alone_does_not(self):
        import mission_coverage
        root = self.tree({"M1-x": self.mission("M1", ["C1", "C2", "C3"], ["I1"])}, ["C1", "C2", "I1"])
        self.assertEqual(quiet(mission_coverage.main, ["--root", str(root)]), 0)
        self.assertEqual(quiet(mission_coverage.main, ["--strict", "--root", str(root)]), 1)

    def test_the_repository_missions_name_only_documented_controls(self):
        import mission_coverage
        r = mission_coverage.analyse(ROOT)
        self.assertGreaterEqual(len(r["missions"]), 1, "a population test must fail on an empty population")
        self.assertEqual(r["unknown"], [])
        self.assertEqual(r["orphans"], [], "a documented control must serve a mission, or be named here")


if __name__ == "__main__":
    unittest.main()
