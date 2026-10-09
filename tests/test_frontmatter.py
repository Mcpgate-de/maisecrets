"""scripts/lint_plugin.py passes on the plugin, and each of its checks refuses a broken copy.

The directory check refused commands/report.md with FRONTMATTER_YAML_INVALID: an unquoted
`argument-hint: [last | …] [--create]` starts a YAML list and the text after `]` breaks the line.
Neither a test nor `claude plugin validate --strict` caught it (2026-09-28). The linter runs in
the pre-commit hook, in the CI lint job and before every release; these tests keep it honest.
"""
from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("lint_plugin", ROOT / "scripts" / "lint_plugin.py")
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)


class PluginLintTests(unittest.TestCase):
    def test_the_plugin_passes_every_check(self):
        errors, _parsed = lint.check_frontmatter()
        self.assertEqual(errors + lint.check_json() + lint.check_hook_paths() + lint.check_cli_commands(), [])
        self.assertGreaterEqual(len(lint.component_files()), 9)

    def test_every_frontmatter_parses_as_yaml_with_text_values(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed; the strict line check still ran (CI installs PyYAML)")
        for path in lint.component_files():
            with self.subTest(path.relative_to(ROOT).as_posix()):
                self.assertEqual(lint.yaml_problems(lint.frontmatter(path)), [])

    def test_the_line_check_refuses_the_shapes_that_break_yaml(self):
        for block in ("argument-hint: [last | bug <text>] [--create]\n", "argument-hint: [n]\n",
                      "description: a: b\n", "description: x\ndescription: y\n", 'description: "open\n',
                      "description: text # comment\n", "description:\n", "  indented: x\n"):
            with self.subTest(block):
                self.assertNotEqual(lint.line_problems(block), [])
        good = ('description: Plain text, with a comma - and a dash.\n'
                'argument-hint: "[last | bug <text>] [--create]"\n'
                'allowed-tools: Bash(bash "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" report)\n')
        self.assertEqual(lint.line_problems(good), [])

    def test_a_boolean_key_must_be_a_boolean_and_no_other_key_may_be_one(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")
        self.assertEqual(lint.yaml_problems("disable-model-invocation: true\n"), [])
        self.assertNotEqual(lint.yaml_problems('disable-model-invocation: "true"\n'), [])
        self.assertNotEqual(lint.yaml_problems("description: true\n"), [])


class PluginLintCatchesBreaksTests(unittest.TestCase):
    """Each check on a copy of the plugin with one break in it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="maisecrets-lint-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for d in ("commands", "skills", "hooks", ".claude-plugin", ".codex-plugin", "maisecrets"):
            if (ROOT / d).is_dir():
                shutil.copytree(ROOT / d, self.root / d, ignore=shutil.ignore_patterns("__pycache__"))

    def edit(self, rel: str, old: str, new: str) -> None:
        p = self.root / rel
        text = p.read_text(encoding="utf-8")
        self.assertIn(old, text, rel)
        p.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_the_break_of_0_5_4_is_caught(self):
        self.edit("commands/report.md", 'argument-hint: "[last | bug <text> | feature <text> | incident [code/cause]]"',
                  "argument-hint: [last | bug <text> | feature <text> | incident [code/cause]]")
        errors, _ = lint.check_frontmatter(self.root)
        self.assertTrue(any("commands/report.md" in e and "argument-hint" in e for e in errors), errors)

    def test_a_missing_description_is_caught(self):
        self.edit("commands/list.md", "description:", "summary:")
        errors, _ = lint.check_frontmatter(self.root)
        self.assertIn("commands/list.md: the key description is missing", errors)

    def test_broken_json_is_caught(self):
        self.edit(".claude-plugin/plugin.json", "{", "{,")
        errors = lint.check_json(self.root)
        self.assertTrue(any(e.startswith(".claude-plugin/plugin.json: not valid JSON") for e in errors), errors)

    def test_a_hook_that_names_a_missing_file_is_caught(self):
        (self.root / "hooks" / "run.cmd").unlink()
        self.assertTrue(any("hooks/run.cmd, which does not exist" in e for e in lint.check_hook_paths(self.root)))

    def test_a_command_name_the_dispatcher_does_not_know_is_caught(self):
        self.edit("commands/audit.md", "run.sh\" audit --args-stdin", "run.sh\" audits --args-stdin")
        self.assertTrue(any("run.sh audits is neither handled" in e for e in lint.check_cli_commands(self.root)))


if __name__ == "__main__":
    unittest.main()
