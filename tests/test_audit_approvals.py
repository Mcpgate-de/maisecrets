"""audit_approvals.py: the approvals and settings that Claude Code and Codex keep outside the repository (#56).

Each test builds a temp home for both clients (HOME, CLAUDE_CONFIG_DIR, CODEX_HOME), puts a token that is made at
run time into one file, runs the script as the skill tells the model to, and searches every byte of the output and
the report for the token."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
SCRIPT = ROOT / "skills" / "secret-hygiene" / "scripts" / "audit_approvals.py"


def _token() -> str:
    return "gh" + "p_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


class ApprovalAuditTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-approvals-"))
        self.home = self.dir / "home"
        self.claude = self.dir / "claude-config"
        self.codex = self.dir / "codex-home"
        for d in (self.home, self.claude, self.codex):
            d.mkdir()
        self.token = _token()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "CLAUDE_", "CODEX_"))}
        self.env.update(PYTHONUTF8="1", HOME=str(self.home), USERPROFILE=str(self.home),
                        CLAUDE_CONFIG_DIR=str(self.claude), CODEX_HOME=str(self.codex))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    # -- helpers --------------------------------------------------------------------------------------------
    def write_json(self, path: Path, doc) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return path

    def audit(self, *args, env=None):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,
                              encoding="utf-8", env=env or self.env, timeout=120)

    def assert_found_not_shown(self, r, file: Path, place: str, fix: str = "remove this approval entry"):
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        rows = [line for line in r.stdout.splitlines() if line.startswith("  S1 ")]
        self.assertEqual(len(rows), 1, r.stdout)
        self.assertIn(str(file), rows[0])
        self.assertIn(place, rows[0])
        self.assertIn("github-pat", rows[0])
        self.assertIn("len 40", rows[0])
        self.assertIn(fix, r.stdout)
        self.assertIn("references/rotation.md", r.stdout)
        for part in (self.token, self.token[4:], self.token[10:30]):
            self.assertNotIn(part, r.stdout + r.stderr)

    # -- (a) a user-level Claude Code permission rule ----------------------------------------------------------
    def test_a_user_level_claude_permission_rule_is_found_and_not_shown(self):
        f = self.write_json(self.claude / "settings.json", {"permissions": {"allow": [
            "Bash(ls:*)", "Read", f"Bash(gh auth login --with-token {self.token})"]}})
        self.assert_found_not_shown(self.audit(), f, "permissions.allow[2]")

    def test_the_user_level_local_settings_are_read_too(self):
        f = self.write_json(self.claude / "settings.local.json", {"permissions": {"ask": [
            f"Bash(export GH_TOKEN={self.token})"]}})
        self.assert_found_not_shown(self.audit(), f, "permissions.ask[0]")

    def test_a_value_in_a_setting_gets_the_setting_fix(self):
        f = self.write_json(self.claude / "settings.json", {"env": {"GH_TOKEN": self.token}})
        self.assert_found_not_shown(self.audit(), f, "env.GH_TOKEN", fix="take the value out of this setting")

    # -- (b) a project allowedTools entry in the client config --------------------------------------------------
    def test_a_project_allowed_tools_entry_in_the_client_config_is_found_and_not_shown(self):
        project = self.dir / "work" / "repo"
        f = self.write_json(self.claude / ".claude.json", {
            "oauthAccount": {"emailAddress": "someone@example.test"},
            "projects": {str(project): {"allowedTools": ["Read", f"Bash(gh auth login --with-token {self.token})"]}}})
        self.assert_found_not_shown(self.audit(), f, ".allowedTools[1]")

    def test_without_claude_config_dir_the_client_config_is_in_the_home(self):
        env = dict(self.env)
        del env["CLAUDE_CONFIG_DIR"]
        f = self.write_json(self.home / ".claude.json", {"projects": {"/p": {"allowedTools": [
            f"Bash(gh auth login --with-token {self.token})"]}}})
        self.assert_found_not_shown(self.audit(env=env), f, ".allowedTools[0]")

    def test_the_settings_of_each_project_in_the_client_config_are_read(self):
        project = self.dir / "work" / "repo"
        self.write_json(self.claude / ".claude.json", {"projects": {str(project): {"allowedTools": []}}})
        f = self.write_json(project / ".claude" / "settings.local.json", {"permissions": {"allow": [
            f"Bash(gh auth login --with-token {self.token})"]}})
        self.assert_found_not_shown(self.audit(), f, "permissions.allow[0]")

    # -- (c) a Codex prefix_rule -----------------------------------------------------------------------------------
    def test_a_codex_prefix_rule_is_found_and_not_shown(self):
        f = self.codex / "rules" / "default.rules"
        f.parent.mkdir()
        # the form Codex appends (codex-rs/execpolicy/src/amend.rs blocking_append_allow_prefix_rule)
        f.write_text('prefix_rule(pattern=["ls"], decision="allow")\n'
                     f'prefix_rule(pattern=["gh", "auth", "login", "--with-token", "{self.token}"], '
                     'decision="allow")\n', encoding="utf-8")
        self.assert_found_not_shown(self.audit(), f, "rules/default.rules line 2", fix="remove this prefix_rule")

    def test_a_value_in_the_codex_config_names_its_table_and_key(self):
        f = self.codex / "config.toml"
        f.write_text('model = "x"\n\n[mcp_servers.gh.env]\n'
                     f'GITHUB_TOKEN = "{self.token}"\n', encoding="utf-8")
        self.assert_found_not_shown(self.audit(), f, "line 4 (mcp_servers.gh.env.GITHUB_TOKEN)",
                                    fix="take the value out of this setting")

    def test_the_rules_of_a_codex_project_are_read(self):
        project = self.dir / "work" / "repo"
        (self.codex / "config.toml").write_text(f'[projects."{project.as_posix()}"]\ntrust_level = "trusted"\n',
                                                encoding="utf-8")
        f = project / ".codex" / "rules" / "team.rules"
        f.parent.mkdir(parents=True)
        f.write_text(f'prefix_rule(pattern=["gh", "auth", "--with-token", "{self.token}"])\n', encoding="utf-8")
        self.assert_found_not_shown(self.audit(), f, "rules/team.rules line 1", fix="remove this prefix_rule")

    # -- the guard -------------------------------------------------------------------------------------------------
    def test_a_value_in_a_project_path_is_withheld_too(self):
        """The place of an allowedTools entry names its project; a value in that path would be printed with it."""
        f = self.write_json(self.claude / ".claude.json", {"projects": {f"/srv/{self.token}": {"allowedTools": [
            f"Bash(gh auth login --with-token {self.token})"]}}})
        r = self.audit()
        self.assert_found_not_shown(r, f, "[withheld]")

    def test_the_report_file_holds_no_value_and_stdout_only_the_summary(self):
        f = self.write_json(self.claude / "settings.json", {"permissions": {"allow": [
            f"Bash(gh auth login --with-token {self.token})"]}})
        out = self.dir / "report.txt"
        r = self.audit("--out", str(out))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        report = out.read_text(encoding="utf-8")
        self.assertIn(str(f), report)
        self.assertIn("permissions.allow[0]", report)
        self.assertNotIn("permissions.allow[0]", r.stdout, "the rows go to the file")
        self.assertIn("Findings: 1 distinct value(s)", r.stdout)
        for part in (self.token, self.token[4:]):
            self.assertNotIn(part, report + r.stdout + r.stderr)

    # -- clean config, the files list, exit codes, no write ----------------------------------------------------
    def test_a_clean_config_has_no_finding_and_exits_zero(self):
        self.write_json(self.claude / "settings.json", {"permissions": {"allow": [
            "Bash(npm run test:*)", "Bash(git log:*)", "WebFetch(domain:docs.example.test)"]},
            "env": {"DEBUG": "1"}, "model": "opus"})
        self.write_json(self.claude / ".claude.json", {"projects": {"/p": {"allowedTools": ["Bash(make:*)"]}}})
        (self.codex / "rules").mkdir()
        (self.codex / "rules" / "default.rules").write_text(
            'prefix_rule(pattern=["git", "status"], decision="allow")\n', encoding="utf-8")
        (self.codex / "config.toml").write_text('model = "x"\napproval_policy = "on-request"\n', encoding="utf-8")
        r = self.audit()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Findings: 0 distinct value(s)", r.stdout)
        self.assertNotIn("  S1 ", r.stdout)

    def test_the_report_names_the_files_read_and_the_files_absent(self):
        self.write_json(self.claude / "settings.json", {})
        r = self.audit()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        read = r.stdout.split("Files read:")[1].split("Files that do not exist:")[0]
        absent = r.stdout.split("Files that do not exist:")[1]
        self.assertIn(str(self.claude / "settings.json"), read)
        self.assertIn(str(self.claude / "settings.local.json"), absent)
        self.assertIn(str(self.claude / ".claude.json"), absent)
        self.assertIn(str(self.codex / "config.toml"), absent)
        self.assertIn(str(self.codex / "rules" / "*.rules"), absent)

    def test_claude_config_dir_and_codex_home_are_honoured_and_the_defaults_are_not_read(self):
        """A token in the default folders of the home is not read when the variables point elsewhere, and is read
        when they are not set."""
        self.write_json(self.home / ".claude" / "settings.json", {"permissions": {"allow": [
            f"Bash(gh auth login --with-token {self.token})"]}})
        rules = self.home / ".codex" / "rules" / "default.rules"
        rules.parent.mkdir(parents=True)
        rules.write_text(f'prefix_rule(pattern=["gh", "{self.token}"])\n', encoding="utf-8")
        r = self.audit()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(str(self.home / ".claude"), r.stdout)
        self.assertNotIn(str(self.home / ".codex"), r.stdout)
        env = {k: v for k, v in self.env.items() if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
        r = self.audit(env=env)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(str(self.home / ".claude" / "settings.json"), r.stdout)
        self.assertIn(str(rules), r.stdout)
        self.assertNotIn(self.token, r.stdout + r.stderr)

    def test_a_file_that_cannot_be_read_exits_two(self):
        (self.claude / "settings.json").mkdir()      # a folder in place of the file: unreadable also as root
        r = self.audit()
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("could NOT be read", r.stdout)

    def test_findings_win_over_an_unreadable_file(self):
        (self.claude / "settings.json").mkdir()
        self.write_json(self.claude / "settings.local.json", {"permissions": {"allow": [
            f"Bash(gh auth login --with-token {self.token})"]}})
        self.assertEqual(self.audit().returncode, 1)

    def test_no_file_is_changed(self):
        f = self.write_json(self.claude / "settings.json", {"permissions": {"allow": [
            f"Bash(gh auth login --with-token {self.token})"]}})
        before = (f.read_bytes(), f.stat().st_mtime_ns)
        self.audit()
        self.assertEqual((f.read_bytes(), f.stat().st_mtime_ns), before)
        self.assertEqual(sorted(p.name for p in self.claude.iterdir()), ["settings.json"])


if __name__ == "__main__":
    unittest.main()
