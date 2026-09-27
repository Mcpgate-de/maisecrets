"""The secret-hygiene skill: its output goes to a cloud model, so no value may appear in it.

Each test builds a throwaway git repository with a generated token, runs the scripts the way
the skill tells the model to, and searches every byte of output for the token."""
from __future__ import annotations

import importlib.util
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "secret-hygiene"
SCRIPTS = SKILL / "scripts"
HAS_GIT = shutil.which("git") is not None


def _token() -> str:
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _run(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONUTF8="1")
    return subprocess.run([sys.executable, str(script), *args], cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", env=env, timeout=120)


class SkillFileTests(unittest.TestCase):
    def test_the_skill_has_front_matter_the_loaders_accept(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        head = text.split("---\n", 2)[1]
        fields = dict(line.split(": ", 1) for line in head.strip().splitlines())
        self.assertEqual(fields["name"], SKILL.name, "the folder name must match the skill name")
        self.assertTrue(fields["description"] and "\n" not in fields["description"])
        self.assertLessEqual(len(fields["description"]), 1024)
        for rel in ("scripts/scan_secrets.py", "scripts/redact_copy.py", "references/rotation.md"):
            self.assertIn(rel, text, rel)
            self.assertTrue((SKILL / rel).is_file(), rel)


@unittest.skipUnless(HAS_GIT, "git is needed for the history scan")
class SkillScriptTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-skill-"))
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.token = _token()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@example.org")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / ".env").write_text(f"GITHUB_TOKEN={self.token}\n", encoding="utf-8")
        (self.repo / "app.py").write_text("print(1)\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "one")
        (self.repo / ".env").unlink()
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "two")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_a_value_only_in_the_history_is_found_and_never_printed(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Working tree: 0 finding(s)", r.stdout)
        self.assertIn("Git history: 1 finding(s)", r.stdout)
        self.assertIn("only in history", r.stdout)
        self.assertIn(".env:1", r.stdout)
        for part in (self.token, self.token[4:], self.token[-12:]):
            self.assertNotIn(part, r.stdout + r.stderr)

    def test_a_clean_tree_exits_zero(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_same_value_carries_one_id_in_the_tree_and_the_history(self):
        (self.repo / "log.txt").write_text(f"token {self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        ids = {line.split()[0] for line in r.stdout.splitlines() if line.startswith("  S")}
        self.assertEqual(ids, {"S1"}, r.stdout)
        self.assertIn("still in tree", r.stdout)
        self.assertNotIn(self.token, r.stdout)

    def test_the_redacted_copy_holds_no_value_and_the_original_is_kept(self):
        src = self.repo / "log.txt"
        src.write_text(f"mail anna.schmidt@firma-xyz.de\nkey {self.token}\nagain {self.token}\n", encoding="utf-8")
        before = src.read_bytes()
        r = _run(SCRIPTS / "redact_copy.py", "log.txt", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        copy = (self.repo / "log.redacted.txt").read_text(encoding="utf-8")
        self.assertNotIn(self.token, copy + r.stdout + r.stderr)
        self.assertNotIn("anna.schmidt", copy + r.stdout)
        self.assertEqual(copy.count("⟦SECRET_1⟧"), 2, "the same value gets the same tag")
        self.assertEqual(src.read_bytes(), before)
        again = _run(SCRIPTS / "redact_copy.py", "log.txt", cwd=self.repo)
        self.assertEqual(again.returncode, 2, "an existing copy is not overwritten without --force")
        same = _run(SCRIPTS / "redact_copy.py", "log.txt", "--out", "log.txt", cwd=self.repo)
        self.assertEqual(same.returncode, 2, "the original is never the output")
        self.assertEqual(src.read_bytes(), before)


@unittest.skipUnless(HAS_GIT, "git is needed for the history scan")
class SkillZipTests(unittest.TestCase):
    def test_the_standalone_zip_has_one_skill_root_and_runs_without_the_plugin(self):
        spec = importlib.util.spec_from_file_location("build_skill_zip", ROOT / "scripts" / "build_skill_zip.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        work = Path(tempfile.mkdtemp(prefix="maisecrets-skillzip-"))
        try:
            out = mod.build(work / "secret-hygiene.zip")
            with zipfile.ZipFile(out) as z:
                names = z.namelist()
                self.assertEqual({n.split("/", 1)[0] for n in names}, {"secret-hygiene"})
                self.assertIn("secret-hygiene/SKILL.md", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/detect.py", names)
                self.assertIn("secret-hygiene/scripts/maisecrets/rules/gitleaks.toml", names)
                self.assertFalse([n for n in names if "vault" in n or "hooks" in n or "__pycache__" in n], names)
                z.extractall(work / "x")
            repo = work / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            token = _token()
            (repo / "config.ini").write_text(f"token = {token}\n", encoding="utf-8")
            r = _run(work / "x" / "secret-hygiene" / "scripts" / "scan_secrets.py", ".", cwd=repo)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("config.ini:1", r.stdout)
            self.assertNotIn(token, r.stdout + r.stderr)
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
