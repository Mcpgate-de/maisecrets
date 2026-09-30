"""Every slash command names a bash form and a PowerShell form.

The ChatGPT desktop client on Windows ran `/maisecrets:status` in PowerShell, which has no bash (2026-09-30).
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CommandFormTests(unittest.TestCase):
    def test_every_command_has_a_powershell_form(self):
        for f in sorted((ROOT / "commands").glob("*.md")):
            s = f.read_text(encoding="utf-8")
            if "!`bash" in s:
                continue   # send.md: Claude Code expands !` itself, before the model sees the text
            with self.subTest(command=f.name):
                sub = re.search(r'hooks/run\.sh" (\w+)', s).group(1)
                self.assertIn(f'& "${{CLAUDE_PLUGIN_ROOT}}/hooks/run.cmd" {sub}', s)
                self.assertIn(f'PowerShell(& "${{CLAUDE_PLUGIN_ROOT}}/hooks/run.cmd" {sub}', s)
                if "--args-stdin" in s:
                    # a single-quoted here-string, so PowerShell expands nothing in the arguments
                    self.assertRegex(s, r"@'\n\$ARGUMENTS\n'@ \| & ")


if __name__ == "__main__":
    unittest.main()
