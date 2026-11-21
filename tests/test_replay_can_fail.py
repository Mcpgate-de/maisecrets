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
        belief = {"belief": "b", "control": "C13", "runner": ["tests/test_launch.py::T::test_deny"],
                  "proof": {"file": "launch.cmd", "find": "echo deny", "replace": "echo allow"}}
        ok, why = R.replay(belief, root)
        self.assertTrue(ok, why)
        self.assertEqual((root / "launch.cmd").read_bytes(), LAUNCHER, "the CRLF line ends came back")


if __name__ == "__main__":
    unittest.main()
