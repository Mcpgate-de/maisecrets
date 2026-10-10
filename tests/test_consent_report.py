"""`maisecrets consent-report ssh` reads synthetic transcripts and reports counts per reason, with no host and no
command in its output; the masked windows go only into a new file of the person's own (#15)."""
import contextlib
import io
import json
import os
import random
import shutil
import stat
import string
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

    def test_a_reason_that_held_a_value_names_none(self):
        # codex and Opus, review of #15: the sshfs reason quoted its option, and an -o value came back in repr quotes
        _session(self.home / "projects" / "p1", "s3", ["sshfs -o 'ssh_command=ssh -J jump1' web1:/ /mnt",
                                                         "ssh -o \"Bogus'x=hidden-host.internal\" web1 uptime",
                                                         "./acme-billing-prod ssh web1 touch x"])
        code, text = self.run_report("--json")
        result = json.loads(text)
        self.assertEqual((result["sessions"], result["kinds"]["unknown"]), (3, 4), "the premise: all three were read")
        for args in ((), ("--json",)):
            code, text = self.run_report(*args)
            self.assertEqual(code, 0)
            for leak in ("jump1", "ssh_command", "hidden-host", "Bogus", "acme", "billing"):
                self.assertNotIn(leak, text)

    def test_a_quoted_part_of_a_reason_is_removed(self):
        # the second layer behind the reasons of the check: a future reason that quotes a value in either quote
        self.assertEqual(consent_report._reason("the option \"x=hidden\" and 'y' end"), "the option '…' and '…' end")
        self.assertEqual(consent_report._reason("'ssh' as an argument of acme-billing-prod, which can start it"),
                         "'…' as an argument of …, which can start it")
        # Opus, review round 3: a host as the program word, also one that the check's own source names
        for program in ("root@web1:~#", "deploy@db1", "web1", "host"):
            with self.subTest(program):
                self.assertEqual(consent_report._reason(f"'ssh' as an argument of {program}, which can start it"),
                                 "'…' as an argument of …, which can start it")
        self.assertEqual(consent_report._reason("'ssh' started by tmux"), "'…' started by tmux")
        for why in ("'ssh' in a line that runs a command word it builds at run time", "'ssh' in a gh command that runs "
                    "a program", "a command over 8192 characters that names ssh"):
            with self.subTest(why):
                self.assertEqual(consent_report._reason(why), why.replace("'ssh'", "'…'"), "the reason stays")

    def test_a_record_of_another_shape_is_skipped(self):
        folder = self.home / "projects" / "p1"
        (folder / "odd.jsonl").write_text('["Bash", 1]\n{"message": "Bash"}\n'
                                          '{"message": {"content": [{"type": "tool_use", "name": "Bash", '
                                          '"input": ["ssh web1"]}]}}\n\xff\n', encoding="utf-8", errors="replace")
        if hasattr(os, "symlink"):
            try:
                os.symlink(folder / "gone.jsonl", folder / "dangling.jsonl")
            except OSError:
                pass                         # Windows without the right to make a link
        code, text = self.run_report("--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["commands"], 7, "the odd records add nothing")

    def test_a_detected_value_is_masked_in_a_window(self):
        token = "glp" + "at-" + "".join(random.choices(string.ascii_letters + string.digits, k=20))
        _session(self.home / "projects" / "p1", "s4", [f"S=ssh; $S web9 'curl -H \"PRIVATE-TOKEN: {token}\" x'"])
        target = self.home / "masked.jsonl"
        self.assertEqual(self.run_report("--excerpts", str(target))[0], 0)
        windows = target.read_text(encoding="utf-8")
        self.assertEqual(windows.count("<value>"), 1, "the premise: the detectors find the token")
        self.assertNotIn(token, windows)

    def test_a_wrong_argument_shows_the_usage(self):
        for args in (["--last", "x"], ["--last", "0"], ["--nope"]):
            with self.subTest(args):
                self.assertEqual(self.run_report(*args)[0], 2)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(consent_report.run([]), 2)


if __name__ == "__main__":
    unittest.main()
