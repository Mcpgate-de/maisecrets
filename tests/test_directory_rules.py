"""The rules of the Claude plugin directory that a hook command must keep (pre-submission checklist).

The directory refused the 0.5.15 update: "Spell the program by name (node server.js, ${CLAUDE_PLUGIN_ROOT}/bin/x)
instead of computing it", for every hook (2026-09-30). The PowerShell part of each hook called `& $r`, a program
held in a variable. A hook command names each program it runs by its full path from ${CLAUDE_PLUGIN_ROOT}, or as a
plain command word, and runs no package launcher.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCHERS = re.compile(r"(?<![\w-])(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run|uv\s+run)(?![\w-])")


def commands() -> list[tuple[str, str, str]]:
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    out = []
    for event, entries in hooks.items():
        for entry in entries:
            for h in entry.get("hooks", []):
                for key in ("command", "commandWindows"):
                    if h.get(key):
                        out.append((event, key, h[key]))
    return out


class HookCommandTests(unittest.TestCase):
    def test_every_program_is_named_not_computed(self):
        for event, key, cmd in commands():
            with self.subTest(event=event, key=key):
                # a call operator or an exec of a variable computes the program
                self.assertNotRegex(cmd, r"&\s*\$", "PowerShell calls a program held in a variable")
                self.assertNotRegex(cmd, r"(?m)(?:^|[;&|{]\s*)\$[\w:]+\s+(?!=)",
                                    "a shell runs a program held in a variable (an assignment $x = … is none)")
                for call in re.findall(r"&\s*(\"[^\"]*\"|'[^']*'|\S+)", cmd):
                    with self.subTest(call=call):
                        self.assertTrue(call.strip("\"'").startswith("${CLAUDE_PLUGIN_ROOT}/"), call)

    def test_every_path_starts_at_the_plugin_root(self):
        for event, key, cmd in commands():
            with self.subTest(event=event, key=key):
                for path in re.findall(r"[\"']([^\"']*/hooks/[^\"']*)[\"']", cmd):
                    self.assertTrue(path.startswith("${CLAUDE_PLUGIN_ROOT}/"), path)

    def test_no_package_launcher(self):
        for event, key, cmd in commands():
            with self.subTest(event=event, key=key):
                self.assertIsNone(LAUNCHERS.search(cmd))


if __name__ == "__main__":
    unittest.main()
