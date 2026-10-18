"""The boundary of the detection core: what the rest of maisecrets may use of detect.py, and what a plain scan imports.

The core is the modules the standalone skill ships (scripts/build_skill_zip.py) plus personal.py: detect, checksums,
normalise, regions, registry, rulespec, rule_filter. The plugin called private names of detect.py from hooks, the
value check and the rules of your own; a refactor of the core then broke a caller it could not see. These tests hold
the line: a module outside the core uses detect only by its public names (the facade at the end of detect.py), and a
plain detect.scan() imports no module of the plugin beyond the ones it imports today. That list may only get shorter.

Run: python3 -m unittest tests.test_detection_boundary -v
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

CORE = frozenset({"detect", "checksums", "normalise", "regions", "registry", "rulespec", "rule_filter", "personal"})
# the modules of the plugin that a plain scan still imports (measured 2026-10-18 on next c4c1c456). Each is a later
# step: the config read for the regions (vault, through active_regions), the rules of your own and the allow list
# (user_rules), the probes for a term list or an import (term_files, value_files), and the placeholder form that
# vault imports. Remove a name when the scan no longer imports it; never add one.
NOT_YET_OUT = frozenset({"placeholder", "term_files", "user_rules", "value_files", "vault"})


def private_uses(source: str) -> list[tuple[int, str]]:
    """(line, name) of every private name of detect that a module uses: detect._x, or `from .detect import _x`."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "detect" \
                and node.attr.startswith("_"):
            out.append((node.lineno, node.attr))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[-1] == "detect":
            out += [(node.lineno, a.name) for a in node.names if a.name.startswith("_")]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("detect._"):
            out.append((node.lineno, node.value))   # a string annotation: "detect._Lazy"
    return out


def outside_the_core() -> list[Path]:
    return sorted([p for p in (ROOT / "maisecrets").glob("*.py") if p.stem not in CORE]
                  + list((ROOT / "hooks").glob("*.py")))


class DetectionBoundaryTests(unittest.TestCase):
    def test_the_checker_sees_each_form_of_a_private_use_and_passes_a_public_one(self):
        # the vocabulary of the checker, pinned: a checker that sees nothing passes every module
        self.assertEqual(private_uses("from . import detect\nx = detect._ranked(1)\n"), [(2, "_ranked")])
        self.assertEqual(private_uses("from .detect import _LazyRx\n"), [(1, "_LazyRx")])
        self.assertEqual(private_uses("from maisecrets.detect import Match, _word_set\n"), [(1, "_word_set")])
        self.assertEqual(private_uses('def f() -> "detect._Lazy":\n    pass\n'), [(1, "detect._Lazy")])
        self.assertEqual(private_uses("from .detect import LazyRx as _LazyRx\nx = detect.findings('a')\n"), [])

    def test_no_module_outside_the_core_uses_a_private_name_of_detect(self):
        files = outside_the_core()
        self.assertIn(ROOT / "maisecrets" / "hooks.py", files, "the population holds the plugin")
        self.assertIn(ROOT / "hooks" / "dispatch.py", files)
        self.assertGreater(len(files), 20)
        found = [f"{p.relative_to(ROOT)}:{line}: {name}" for p in files
                 for line, name in private_uses(p.read_text(encoding="utf-8"))]
        self.assertEqual(found, [], "use a public name of detect.py (its facade), or add one there")

    def test_every_core_module_exists(self):
        for name in sorted(CORE | NOT_YET_OUT):
            with self.subTest(name):
                self.assertTrue((ROOT / "maisecrets" / f"{name}.py").is_file(), "a renamed module: update the list")

    def test_a_plain_scan_imports_no_new_module_of_the_plugin(self):
        home = Path(tempfile.mkdtemp(prefix="detect-boundary-", dir=_isolate.HOME))
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from maisecrets import detect\n"
            "text = 'pass' + 'word: hunter2x9\\nmail me at someone@example.org, +49 30 1234567\\n'\n"
            "for ch in ('prompt', 'tool'):\n"
            "    assert detect.scan(text, channel=ch), ch\n"
            "    detect.findings(text, channel=ch)\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('maisecrets.'))))\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_", "CLAUDE", "CODEX"))}
        env["MAISECRETS_HOME"] = str(home)
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        loaded = {m.split(".", 1)[1] for m in json.loads(r.stdout)}
        self.assertTrue({"detect", "personal", "registry"} <= loaded, loaded)
        beyond = loaded - CORE
        self.assertFalse(beyond - NOT_YET_OUT, f"a plain scan now imports {sorted(beyond - NOT_YET_OUT)}")
        self.assertFalse(NOT_YET_OUT - beyond, f"no longer imported: remove {sorted(NOT_YET_OUT - beyond)} "
                                               "from NOT_YET_OUT")


if __name__ == "__main__":
    unittest.main()
