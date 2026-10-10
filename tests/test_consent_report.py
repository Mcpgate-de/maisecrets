"""`maisecrets consent-report ssh` reads synthetic transcripts and reports counts per reason, with no host and no
command in its output; the masked windows go only into a new file of the person's own (#15)."""
import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401

from maisecrets import consent_report  # noqa: E402


def _session(folder: Path, name: str, commands: list[str]) -> None:
    rows = [json.dumps({"message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": c}}]}})
            for c in commands]
    (folder / f"{name}.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")


class ConsentReportTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="maisecrets-report-"))
        project = self.home / "projects" / "p1"
        project.mkdir(parents=True)
        _session(project, "s1", ["ssh web1 uptime", "ssh web1 sudo reboot", "ssh web1 sudo reboot",
                                 'grep -n "ssh web7" notes.md', "S=ssh; $S web9 reboot", "ls -la"])
        _session(project, "s2", ["scp f web2:/tmp/", "git commit -m 'fix the ssh docs'"])
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        patcher = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_report(self, *args) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = consent_report.run(["ssh", *args])
        return code, out.getvalue()

    def test_the_counts_follow_the_check_and_name_no_host(self):
        code, text = self.run_report("--json")
        self.assertEqual(code, 0)
        result = json.loads(text)
        self.assertEqual((result["sessions"], result["commands"]), (2, 7), "the premise: ls -la names no ssh word")
        self.assertEqual(result["kinds"], {"read": 1, "write": 3, "none": 2, "unknown": 1})
        self.assertEqual(result["write_hosts"], 2, "a write asks once per host and session: web1 once, web2 once")
        self.assertEqual([q["kind"] for q in result["questions"]], ["unknown"])
        code, text = self.run_report()
        for host in ("web1", "web2", "web7", "web9", "reboot", "notes.md"):
            self.assertNotIn(host, text)

    def test_the_windows_go_into_a_new_file_of_the_persons_own(self):
        target = self.home / "windows.jsonl"
        code, text = self.run_report("--excerpts", str(target))
        self.assertEqual(code, 0)
        self.assertNotIn("web9", text)
        lines = target.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn("web9", json.loads(lines[0])["excerpt"])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        code, text = self.run_report("--excerpts", str(target))
        self.assertEqual(code, 1, "an existing file is not replaced")

    def test_a_wrong_argument_shows_the_usage(self):
        for args in (["--last", "x"], ["--nope"]):
            with self.subTest(args):
                self.assertEqual(self.run_report(*args)[0], 2)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(consent_report.run([]), 2)


if __name__ == "__main__":
    unittest.main()
