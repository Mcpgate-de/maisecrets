"""The secret-hygiene skill: its output goes to a cloud model, so no value may appear in it.

Each test builds a throwaway git repository with a generated token, runs the scripts the way
the skill tells the model to, and searches every byte of output for the token."""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "secret-hygiene"
SCRIPTS = SKILL / "scripts"
HAS_GIT = shutil.which("git") is not None


def _token() -> str:
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def _clean_env() -> dict:
    """The environment without GIT_*: inside a git hook, GIT_INDEX_FILE, GIT_DIR and the author
    variables point at the repository being committed, and a test repository would inherit them
    (the author of a test commit became the committer of the real one; 2026-09-27)."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=_clean_env())


def _run(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(_clean_env(), PYTHONUTF8="1")
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
        for rel in ("scripts/scan_secrets.py", "scripts/redact_copy.py", "scripts/audit_transcripts.py",
                    "references/rotation.md"):
            self.assertIn(rel, text, rel)
            self.assertTrue((SKILL / rel).is_file(), rel)


class SkillListingTests(unittest.TestCase):
    def test_the_chatgpt_listing_names_the_skill_and_its_icons_exist(self):
        """ChatGPT shows a skill's name and icon from agents/openai.yaml; without it the upload
        showed the folder name and a generic icon (2026-09-27)."""
        text = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        fields = {}
        for line in text.splitlines()[1:]:
            key, _sep, val = line.strip().partition(": ")
            fields[key] = val.strip('"')
        self.assertIn("maisecrets", fields["display_name"])
        self.assertLessEqual(len(fields["short_description"]), 64)
        for key in ("icon_small", "icon_large"):
            self.assertTrue((SKILL / fields[key]).is_file(), fields[key])
        self.assertRegex(fields["brand_color"], r"^#[0-9A-Fa-f]{6}$")


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

    def test_a_history_finding_says_when_who_and_whether_it_was_pushed(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        row = next(line for line in r.stdout.splitlines() if "commit " in line and line.startswith("  S"))
        self.assertRegex(row, r"commit [0-9a-f]{7,} \d{4}-\d{2}-\d{2} by t")
        self.assertIn("no remote", row)
        self.assertIn("github-pat", row, "a keyword match on a provider token is named by the provider")
        self.assertIn("shape", row)

    def test_a_pushed_commit_is_marked_pushed_and_a_new_one_local_only(self):
        remote = self.dir / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True, env=_clean_env())
        _git(self.repo, "remote", "add", "origin", str(remote))
        _git(self.repo, "push", "-q", "origin", "HEAD:refs/heads/main")
        _git(self.repo, "fetch", "-q", "origin")
        (self.repo / "later.cfg").write_text(f"token = {_token()}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "three")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        rows = [line for line in r.stdout.splitlines() if "commit " in line and line.startswith("  S")]
        self.assertTrue(any("pushed" in row and ".env:1" in row for row in rows), r.stdout)
        self.assertTrue(any("local only" in row and "later.cfg:1" in row for row in rows), r.stdout)

    def test_a_cut_history_scan_says_so_and_does_not_exit_clean(self):
        clean = self.dir / "clean"
        clean.mkdir()
        _git(clean, "init", "-q")
        _git(clean, "config", "user.email", "t@example.org")
        _git(clean, "config", "user.name", "t")
        for i in range(3):
            (clean / "f.txt").write_text(f"{i}\n", encoding="utf-8")
            _git(clean, "add", ".")
            _git(clean, "commit", "-qm", str(i))
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", "--max-commits", "1", cwd=clean)
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("stopped after 1 of 3 commits", r.stdout)

    def test_a_large_file_is_scanned_whole_and_a_limit_is_named(self):
        big = self.repo / "dump.sql"
        big.write_text("INSERT INTO t VALUES (1);\n" * 90_000 + f"token = {self.token}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "dump")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertIn("dump.sql:90001", r.stdout, "no default size limit: the value at the end is found")
        self.assertNotIn("NOT scanned", r.stdout)
        cut = _run(SCRIPTS / "scan_secrets.py", ".", "--history", "--max-mb", "1", cwd=self.repo)
        self.assertIn("NOT scanned, larger than 1 MB", cut.stdout)
        self.assertIn("dump.sql in commit", cut.stdout)

    def test_a_folder_without_git_still_reports_its_files(self):
        plain = self.dir / "plain"
        plain.mkdir()
        (plain / "a.env").write_text(f"GITHUB_TOKEN={self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "scan_secrets.py", str(plain), "--history", cwd=self.dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("a.env:1", r.stdout)
        self.assertIn("not a git repository", r.stdout)
        self.assertNotIn(self.token, r.stdout)

    def test_the_full_report_can_go_to_a_file_and_the_model_sees_the_summary(self):
        out = self.dir / "report.txt"
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", "--out", str(out), cwd=self.repo)
        self.assertNotIn(".env:1", r.stdout)
        self.assertIn("Summary:", r.stdout)
        self.assertIn(".env:1", out.read_text(encoding="utf-8"))
        self.assertNotIn(self.token, out.read_text(encoding="utf-8"))

    def test_an_added_line_that_starts_with_plus_plus_is_content_not_a_path(self):
        (self.repo / "notes.txt").write_text(f"++ token={self.token}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "notes")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertNotIn(self.token, r.stdout + r.stderr)
        self.assertNotIn(self.token[4:], r.stdout)
        history = [line for line in r.stdout.splitlines() if " commit " in line]
        self.assertTrue(any(line.endswith("notes.txt:1") for line in history), r.stdout)

    def test_an_author_name_that_looks_like_a_secret_is_not_printed(self):
        _git(self.repo, "config", "user.name", self.token)
        (self.repo / "b.cfg").write_text(f"token = {_token()}\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "b")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        self.assertNotIn(self.token, r.stdout)
        self.assertIn("an author name that looks like a secret", r.stdout)

    def test_redact_never_writes_over_the_original_even_with_force(self):
        src = self.repo / "log.txt"
        src.write_text(f"key {self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "redact_copy.py", "log.txt", "--out", "log.txt", "--force", cwd=self.repo)
        self.assertEqual(r.returncode, 2)
        self.assertIn(self.token, src.read_text(encoding="utf-8"))

    def test_a_clean_tree_exits_zero(self):
        r = _run(SCRIPTS / "scan_secrets.py", ".", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_same_value_carries_one_id_in_the_tree_and_the_history(self):
        (self.repo / "log.txt").write_text(f"token {self.token}\n", encoding="utf-8")
        r = _run(SCRIPTS / "scan_secrets.py", ".", "--history", cwd=self.repo)
        ids = {line.split()[0] for line in r.stdout.splitlines() if line.startswith("  S")}
        self.assertEqual(ids, {"S1"}, r.stdout)
        self.assertIn("value also at", r.stdout)
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
        self.assertIn("NOT replaced: names", r.stdout)
        self.assertIn("inside a git repository", r.stdout)
        self.assertEqual(src.read_bytes(), before)
        again = _run(SCRIPTS / "redact_copy.py", "log.txt", cwd=self.repo)
        self.assertEqual(again.returncode, 2, "an existing copy is not overwritten without --force")
        same = _run(SCRIPTS / "redact_copy.py", "log.txt", "--out", "log.txt", cwd=self.repo)
        self.assertEqual(same.returncode, 2, "the original is never the output")
        self.assertEqual(src.read_bytes(), before)


class RedactSameValueTests(unittest.TestCase):
    def test_an_iban_with_and_without_spaces_gets_one_tag(self):
        work = Path(tempfile.mkdtemp(prefix="maisecrets-redact-"))
        try:
            text = "IBAN DE89 3704 0044 0532 0130 00 and DE89370400440532013000\n"
            (work / "t.txt").write_text(text, encoding="utf-8")
            r = _run(SCRIPTS / "redact_copy.py", "t.txt", cwd=work)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            copy = (work / "t.redacted.txt").read_text(encoding="utf-8")
            self.assertEqual(copy.count("⟦IBAN_1⟧"), 2, copy)
            self.assertNotIn("0532", copy)
        finally:
            shutil.rmtree(work, ignore_errors=True)


@unittest.skipUnless(HAS_GIT, "git is needed for the history scan")
class SkillZipTests(unittest.TestCase):
    def test_the_standalone_zip_has_one_skill_root_and_runs_without_the_plugin(self):
        spec = importlib.util.spec_from_file_location("build_skill_zip", ROOT / "scripts" / "build_skill_zip.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        work = Path(tempfile.mkdtemp(prefix="maisecrets-skillzip-"))
        try:
            flat = mod.build(work / "flat.zip", flat=True)
            with zipfile.ZipFile(flat) as z:
                names = z.namelist()
                self.assertIn("name: maisecrets-secret-hygiene\n", z.read("SKILL.md").decode(),
                              "the standalone ChatGPT skill carries the brand in its name")
                self.assertIn("SKILL.md", names, "the ChatGPT upload reads SKILL.md at the zip root")
                self.assertIn("scripts/", names, "directory entries are written")
                self.assertIn("scripts/maisecrets/detect.py", names)
            out = mod.build(work / "secret-hygiene.zip")
            with zipfile.ZipFile(out) as z:
                names = z.namelist()
                self.assertEqual({n.split("/", 1)[0] for n in names}, {"secret-hygiene"})
                self.assertIn("secret-hygiene/", names)
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


class TranscriptAuditTests(unittest.TestCase):
    """The audit reads agent transcripts, which hold everything a session saw. It must name what
    reached the provider without printing it, and scrub only after a yes."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-audit-"))
        self.claude = self.dir / "claude"
        self.codex = self.dir / "codex"
        self.token, self.other = _token(), _token()
        proj = self.claude / "projects" / "-Users-x-repo"
        proj.mkdir(parents=True)
        rows = [
            {"type": "user", "timestamp": "2026-09-20T10:00:00Z", "message": {"content": f"use {self.token} please"}},
            {"type": "user", "timestamp": "2026-09-21T10:00:00Z",
             "message": {"content": [{"type": "tool_result", "content": f"GITHUB_TOKEN={self.token}"}]}},
            {"type": "attachment", "timestamp": "2026-09-21T10:00:01Z", "attachment": {"type": "hook_success",
                                                                                      "content": self.other}},
        ]
        self.session = proj / "abcdef12-0000.jsonl"
        self.session.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(self.session, (old, old))
        (self.codex / "sessions" / "2026").mkdir(parents=True)
        (self.codex / "sessions" / "2026" / "rollout-x.jsonl").write_text(json.dumps(
            {"type": "response_item", "timestamp": "2026-09-22T09:00:00Z",
             "payload": {"type": "function_call_output", "output": f"token={self.token}"}}) + "\n", encoding="utf-8")
        self.env = dict(_clean_env(), PYTHONUTF8="1", CLAUDE_CONFIG_DIR=str(self.claude), CODEX_HOME=str(self.codex))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def audit(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "audit_transcripts.py"), *args], capture_output=True,
                              text=True, encoding="utf-8", env=self.env, timeout=120)

    def test_the_report_names_what_reached_the_provider_and_no_value(self):
        r = self.audit()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Reached the AI provider: 1 distinct value(s). Only in local records: 1.", r.stdout)
        row = next(line for line in r.stdout.splitlines() if line.startswith("  S1"))
        self.assertIn("to Anthropic/OpenAI", row)
        self.assertIn("in 2 session(s)", row)
        self.assertIn("prompt", row)
        self.assertIn("tool result", row)
        self.assertIn("2026-09-20..2026-09-22", row)
        for part in (self.token, self.token[4:], self.other, self.other[4:]):
            self.assertNotIn(part, r.stdout + r.stderr)

    def test_scrub_asks_first_then_keeps_every_line_valid_json(self):
        dry = self.audit("--scrub", "--claude")
        self.assertIn("Nothing was changed", dry.stdout)
        self.assertIn(self.token, self.session.read_text(encoding="utf-8"))
        done = self.audit("--scrub", "--yes", "--claude")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        text = self.session.read_text(encoding="utf-8")
        self.assertNotIn(self.token, text)
        self.assertIn("⟦SCRUBBED_S", text)
        for line in text.splitlines():
            json.loads(line)
        self.assertIn("provider keeps what it received", done.stdout)
        self.assertNotIn(self.token, done.stdout)

    def test_scrub_keeps_other_lines_byte_for_byte_and_the_file_mode(self):
        extra = (b'{"type":"system","n":1.0e5}\r\n' + b'not json at all \xff\xfe\n'
                 + ("half line token=" + self.token + "\n").encode())
        with open(self.session, "ab") as fh:
            fh.write(extra)
        os.chmod(self.session, 0o600)
        old = time.time() - 3600
        os.utime(self.session, (old, old))
        report = self.audit("--claude")
        self.assertNotIn(self.token, report.stdout)
        done = self.audit("--scrub", "--yes", "--claude")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        raw = self.session.read_bytes()
        self.assertIn(b'{"type":"system","n":1.0e5}\r\n', raw, "an unchanged line stays byte for byte")
        self.assertIn(b"not json at all \xff\xfe\n", raw)
        self.assertNotIn(self.token.encode(), raw, "a line that is not JSON is cleaned as text")
        if os.name != "nt":   # Windows has no Unix mode bits (windows-latest, 2026-09-27)
            self.assertEqual(self.session.stat().st_mode & 0o777, 0o600)

    def test_a_running_session_is_not_scrubbed(self):
        os.utime(self.session, None)
        self.audit("--scrub", "--yes", "--claude")
        self.assertIn(self.token, self.session.read_text(encoding="utf-8"))
