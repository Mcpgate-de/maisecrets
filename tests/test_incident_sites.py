"""Every failure site has its incident code, and every code has a site (docs/DIAGNOSTICS.md, section 4), both ways.

A raise of RuntimeError in the plugin's code either carries a code (vault.CodedError) or is named here with the
outcome site it reaches; every code literal at a recording call is a known code; every known code is recorded
somewhere. A new raise or a new code without its other half turns this red.

Run: python3 -m unittest tests.test_incident_sites -v
"""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from maisecrets import incidents  # noqa: E402

# the raises that carry no code, by (file, function), and the outcome site each one reaches
UNCODED = {
    ("vault.py", "delete"): "a keychain delete: store.expire in the sweep; forget, repair and wipe are CLI",
    ("vault.py", "wipe"): "the CLI's wipe only, which prints its own error",
    ("vault.py", "repair"): "the CLI's repair only, which prints its own error",
}
RECORDING_CALLS = {"note", "queue", "write_marker", "write_marker_bounded", "_marker", "CodedError"}
RUNTIME_FILES = sorted((ROOT / "maisecrets").glob("*.py")) + sorted((ROOT / "hooks").glob("*.py"))
SHELL_FILES = [ROOT / "hooks" / "run.sh", ROOT / "hooks" / "run.cmd"]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _functions(tree: ast.AST):
    """(function name, node) for each node, by the innermost enclosing def."""
    out = []

    def walk(node, fn):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, child.name)
            else:
                out.append((fn, child))
                walk(child, fn)
    walk(tree, "<module>")
    return out


class SiteRegistryTests(unittest.TestCase):
    def test_every_runtime_error_raise_has_a_code_or_a_named_outcome(self):
        seen = set()
        for path in sorted((ROOT / "maisecrets").glob("*.py")):
            for fn, node in _functions(ast.parse(path.read_text(encoding="utf-8"))):
                if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
                    continue
                kind = _name(node.exc.func)
                where = f"{path.name}:{node.lineno} in {fn}"
                if kind == "RuntimeError":
                    self.assertIn((path.name, fn), UNCODED, f"{where}: a RuntimeError with no incident code")
                    seen.add((path.name, fn))
                elif kind == "CodedError":
                    code = node.exc.args[1] if len(node.exc.args) > 1 else None
                    if isinstance(code, ast.Constant):
                        self.assertIn(code.value, incidents.CODES, where)
                    else:   # the timeout: a closed map from the store's display name
                        self.assertIn("_TIMEOUT_CODES", ast.unparse(code), where)
        self.assertEqual(seen, set(UNCODED), "a named raise that no longer exists")

    def test_the_timeout_map_and_the_lock_timeout_carry_known_codes(self):
        from maisecrets import vault
        self.assertTrue(set(vault._TIMEOUT_CODES.values()) <= incidents.CODES)
        self.assertIn(vault.LockTimeout.incident_code, incidents.CODES)

    def test_every_code_literal_at_a_recording_call_is_known(self):
        for path in RUNTIME_FILES:
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call) and _name(node.func) in RECORDING_CALLS:
                    args = node.args[1:2] if _name(node.func) == "CodedError" else node.args[:1]
                    for a in args:
                        if isinstance(a, ast.Constant) and isinstance(a.value, str):
                            with self.subTest(f"{path.name}:{node.lineno}"):
                                self.assertIn(a.value, incidents.CODES)
                                if _name(node.func) in ("write_marker", "write_marker_bounded", "_marker"):
                                    self.assertIn(a.value, incidents.MARKER_CODES)

    def test_every_code_has_a_site(self):
        texts = "\n".join(p.read_text(encoding="utf-8") for p in RUNTIME_FILES + SHELL_FILES
                          if p.name != "incidents.py")
        own = (ROOT / "maisecrets" / "incidents.py").read_text(encoding="utf-8")
        for code in sorted(incidents.CODES):
            with self.subTest(code):
                event = re.match(r"\Ahook\.(user-prompt|pre-tool|post-tool|post-tool-failure)\.(\w+)\Z", code)
                if event:
                    # one site per kind, for every event: the unexpected code in code_of, the watchdog's marker
                    template = {"unexpected": ('f"hook.{event}.unexpected"', own),
                                "watchdog": ('f"hook.{event}.watchdog"', texts)}[event.group(2)]
                    self.assertIn(template[0], template[1])
                    continue
                self.assertRegex(texts, r"(?:[\"']|incident-marker\.)" + re.escape(code) + r"(?:[\"']|\b)")


if __name__ == "__main__":
    unittest.main()
