"""The sync scripts read upstream rules as data: the evaluator knows the forms the regexes are built
from and refuses everything else, so no upstream code runs (scripts/_static_python.py)."""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import _static_python as sp  # noqa: E402


def module(src: str, calls=None) -> dict:
    env: dict = {}
    sp.bind(ast.parse(src).body, env, calls)
    return env


class StaticPythonTests(unittest.TestCase):
    def test_the_forms_the_upstream_rules_use_are_read(self):
        env = module(
            "D = ('api_?key', 'secret')\n"
            "R = r'|'.join(D)\n"
            "R = r'({d}){s}'.format(d=R, s=r'\\w*')\n"
            "N = '[0-9]'\n"
            "F = rf'\\b{N}{N}\\b'\n"
            "X = re.compile(r'{r}:'.format(r=R), flags=re.IGNORECASE | re.M)\n"
            "G = {X: 4}\n"
            "P = [Pattern('weak', F, 0.3)]\n",
            {"Pattern": lambda name, regex, score: (name, regex, score)})
        self.assertEqual(env["R"], r"(api_?key|secret)\w*")
        self.assertEqual(env["F"], r"\b[0-9][0-9]\b")
        self.assertEqual(env["X"], sp.Rx(r"(api_?key|secret)\w*:", int(re.IGNORECASE | re.M)))
        self.assertEqual(env["G"], {env["X"]: 4})
        self.assertEqual(env["P"], [("weak", r"\b[0-9][0-9]\b", 0.3)])

    def test_code_is_never_run_and_its_name_stays_unbound(self):
        probes = {
            "A": "__import__('os').system('true')",
            "B": "open('/etc/passwd').read()",
            "C": "(lambda: 1)()",
            "D": "''.__class__",
            "E": "'{0.__class__.__mro__}'.format('x')",
            "F": "'{0[0]}'.format('x')",
            "G": "re.sub('a', 'b', 'a')",
            "H": "[x for x in 'ab']",
            "I": "'a' * 3",
            "J": "Pattern('n', 'r', 1)",          # a call the caller did not name
        }
        env = module("\n".join(f"{k} = {v}" for k, v in probes.items()) + "\nOK = 'still read'\n")
        self.assertEqual(env, {"OK": "still read"})

    def test_a_doubling_string_stops_at_the_limit(self):
        src = "S = 'xxxxxxxxxx'\n" + "S = S + S\n" * 20
        env = module(src)
        self.assertNotIn("S", env, "2**20 * 10 characters passed the limit")
        self.assertEqual(module("S = 'ab'\nS = S + S\n")["S"], "abab")

    def test_no_sync_script_executes_or_imports_upstream_code(self):
        for name in ("sync_detect_secrets.py", "sync_presidio.py", "sync_gitleaks.py"):
            with self.subTest(name):
                tree = ast.parse((ROOT / "scripts" / name).read_text(encoding="utf-8"))
                calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
                self.assertFalse(calls & {"exec", "eval", "compile", "__import__"}, calls)
                attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
                self.assertFalse(attrs & {"import_module", "walk_packages", "run", "Popen", "system"}, attrs)
                imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
                imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
                self.assertFalse(imported & {"presidio_analyzer", "detect_secrets", "importlib", "pkgutil",
                                             "subprocess"}, imported)


if __name__ == "__main__":
    unittest.main()
