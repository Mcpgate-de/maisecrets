"""scripts/mission_touch.py names the mission parts a change touches. Each case is a small git repository of its own:
a change inside the guarded lines of a proof is named, a change beside them is only counted, so a script that names
every belief of a changed file, or none, fails here."""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib  # noqa: F401
except ImportError:     # Python < 3.11: the script needs tomllib, like mission_coverage.py
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT / "scripts"))

MISSION = '''mission = "M1"
[[part]]
id = "M1.1"
says = "A value never reaches the model."
[[part]]
id = "M1.2"
says = "Another part."
'''
CODE = ("def check(v):\n    if v.startswith('k'):\n        return True\n    return False\n\n\n"
        "def other():\n    return 1\n")
TESTS = ("class T:\n    def test_check(self):\n        assert check('k1')\n\n"
         "    def test_other(self):\n        assert other() == 1\n")


def belief(find: str) -> str:
    return (f'belief = "b1"\ncontrol = "C1"\nserves = ["M1.1"]\nrunner = ["tests/test_x.py::T::test_check"]\n'
            f"[proof]\nfile = \"maisecrets/x.py\"\nfind = '''{find}'''\nreplace = '''    if True:'''\n")


def git(d: str, *args: str) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   check=True, capture_output=True, env=env)


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+; the other CI Pythons run the script")
class MissionTouchTests(unittest.TestCase):
    def repo(self, d: str) -> Path:
        root = Path(d)
        for path, text in (("mission/M1-x.toml", MISSION), ("beliefs/b1.toml", belief("    if v.startswith('k'):")),
                           ("maisecrets/x.py", CODE), ("tests/test_x.py", TESTS)):
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        subprocess.run(["git", "init", "-q", "-b", "next", d], check=True, capture_output=True)
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "base")
        return root

    def run_on(self, root: Path, *args: str) -> str:
        import mission_touch
        old, mission_touch.ROOT = mission_touch.ROOT, root
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(0, mission_touch.main(list(args) or ["next"]))
            return buf.getvalue()
        finally:
            mission_touch.ROOT = old

    def edit(self, root: Path, path: str, old: str, new: str) -> None:
        text = (root / path).read_text(encoding="utf-8")
        self.assertIn(old, text)
        (root / path).write_text(text.replace(old, new), encoding="utf-8")

    def test_a_change_inside_the_guarded_lines_names_the_belief_and_its_part(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.repo(d)
            self.edit(root, "maisecrets/x.py", "v.startswith('k')", "v.startswith('key')")
            out = self.run_on(root)
            self.assertIn("1 mission parts touched", out)
            self.assertIn("M1.1  A value never reaches the model.", out)
            self.assertIn("guarded code changed: b1 (maisecrets/x.py:2-2)", out)
            self.assertNotIn("M1.2", out)

    def test_a_change_beside_the_guarded_lines_is_only_counted(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.repo(d)
            self.edit(root, "maisecrets/x.py", "return 1", "return 2")
            out = self.run_on(root)
            self.assertIn("0 mission parts touched", out)
            self.assertIn("guarded lines did not change: M1.1 1", out)

    def test_a_line_added_inside_the_guarded_block_counts(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.repo(d)
            (root / "beliefs/b1.toml").write_text(belief("    if v.startswith('k'):\n        return True"),
                                                  encoding="utf-8")
            git(d, "commit", "-q", "-am", "two guarded lines")
            self.edit(root, "maisecrets/x.py", "    if v.startswith('k'):\n",
                      "    if v.startswith('k'):\n        v = v.strip()\n")
            self.assertIn("guarded code changed: b1", self.run_on(root))

    def test_only_the_belief_test_function_counts_not_its_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.repo(d)
            self.edit(root, "tests/test_x.py", "assert other() == 1", "assert other() >= 1")
            out = self.run_on(root)
            self.assertIn("0 mission parts touched", out)
            self.edit(root, "tests/test_x.py", "assert check('k1')", "assert check('k2')")
            self.assertIn("test changed: b1 (tests/test_x.py::test_check)", self.run_on(root))

    def test_the_beliefs_of_the_merge_base_are_read_so_a_reworded_proof_still_counts(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.repo(d)
            self.edit(root, "maisecrets/x.py", "v.startswith('k')", "v.startswith('key')")
            (root / "beliefs/b1.toml").write_text(belief("    if v.startswith('key'):"), encoding="utf-8")
            git(d, "checkout", "-q", "-b", "feat")
            git(d, "commit", "-q", "-am", "the code and its proof change together")
            self.assertIn("guarded code changed: b1", self.run_on(root, "next", "HEAD"))

    def test_new_code_that_no_belief_guards_is_named(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.repo(d)
            (root / "maisecrets/y.py").write_text("z = 1\n", encoding="utf-8")
            self.assertIn("Changed code that no belief guards: maisecrets/y.py", self.run_on(root))


if __name__ == "__main__":
    unittest.main()
