"""scripts/replay_can_fail.py mutates a file, runs the owning tests and puts the file back. A file with CRLF line ends
(the Windows launcher hooks/run.cmd) must come back byte for byte: read as text and written back, it came back with
LF ends after a replay in the work tree."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import tomllib  # noqa: F401
except ImportError:     # Python < 3.11: the replay needs tomllib
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT / "scripts"))

LAUNCHER = b"@echo off\r\nrem a launcher\r\necho deny\r\nexit /b 0\r\n"
TEST = '''import unittest
from pathlib import Path


class T(unittest.TestCase):
    def test_deny(self):
        self.assertIn("deny", (Path(__file__).resolve().parent.parent / "launch.cmd").read_text())
'''


@unittest.skipIf(tomllib is None, "tomllib is Python 3.11+, like the replay")
class ByteRestoreTests(unittest.TestCase):
    def test_a_crlf_file_comes_back_byte_for_byte_after_a_replay(self):
        import replay_can_fail as R
        root = Path(tempfile.mkdtemp(prefix="maisecrets-replay-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts" / "_run_tests_json.py", root / "scripts" / "_run_tests_json.py")
        (root / "tests").mkdir()
        (root / "tests" / "test_launch.py").write_text(TEST, encoding="utf-8")
        (root / "launch.cmd").write_bytes(LAUNCHER)
        # the second anchor holds a line end of the file: counted on text that read_text made, it is not there; the
        # third is written with LF, as every anchor of beliefs/*.toml, and the file holds CRLF (a Windows checkout)
        for find, replace in (("echo deny", "echo allow"), ("echo deny\r\nexit", "echo allow\r\nexit"),
                              ("echo deny\nexit", "echo allow\nexit")):
            with self.subTest(find=find):
                belief = {"belief": "b", "control": "C13", "runner": ["tests/test_launch.py::T::test_deny"],
                          "proof": {"file": "launch.cmd", "find": find, "replace": replace}}
                ok, why = R.replay(belief, root)
                self.assertTrue(ok, why)
                self.assertIsNone(R._baseline(belief, root), "the parallel replay counts the anchor the same way")
                self.assertEqual((root / "launch.cmd").read_bytes(), LAUNCHER, "the CRLF line ends came back")


    def test_a_multi_line_anchor_with_lf_counts_once_in_a_crlf_file_and_the_mutation_keeps_its_line_ends(self):
        import replay_can_fail as R
        text = "def f(v):\r\n    if v:\r\n        return 1\r\n    return 0\r\n"
        find, replace = "    if v:\n        return 1", "    if False:\n        return 1"
        self.assertEqual(R.anchor_count(text, find), 1)
        self.assertEqual(R.anchor_count(text.replace("\r\n", "\n"), find), 1, "an LF file as before")
        mutated = text.replace(R.in_line_ends_of(text, find), R.in_line_ends_of(text, replace), 1)
        self.assertEqual(mutated, "def f(v):\r\n    if False:\r\n        return 1\r\n    return 0\r\n")


if __name__ == "__main__":
    unittest.main()
