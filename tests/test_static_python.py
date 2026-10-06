"""The sync scripts read upstream rules as data: the evaluator knows the forms the regexes are built
from and refuses everything else, so no upstream code runs (scripts/_static_python.py)."""
from __future__ import annotations

import ast
import io
import re
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import _static_python as sp  # noqa: E402
import sync_presidio  # noqa: E402

PKG = sync_presidio.PACKAGE
GOOD = (
    "from presidio_analyzer import Pattern, PatternRecognizer\n"
    "class GoodRecognizer(PatternRecognizer):\n"
    "    N = '[0-9]'\n"
    "    PATTERNS = [Pattern('weak', rf'\\b{N}{N}\\b', 0.3)]\n"
    "    CONTEXT = ['number']\n"
    "    def __init__(self, supported_language: str = 'de', supported_entity: str = 'GOOD'):\n"
    "        pass\n")


def wheel(files: dict[str, str]) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{PKG}/__init__.py", "")
        for name, text in files.items():
            z.writestr(f"{PKG}/{name}", text)
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


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

    def test_a_value_built_large_from_short_source_is_refused(self):
        env = module(
            "W = '{0:>400000000}'.format('a')\n"                 # a width
            "R = '{0!r}'.format('a')\n"                          # a conversion
            "L = 'x' + 'xxxxxxxxxx'\n" + "L = L + L\n" * 12 +   # 40960 characters, below the limit
            "J = ''.join([L, L, L, L, L, L])\n"                  # 245760: above it
            "F = '{0}{0}{0}{0}{0}{0}'.format(L)\n"
            "A = ['x']\n" + "A = [A, A]\n" * 20)               # 2**20 leaves, len stays 2
        for name in ("W", "R", "J", "F"):
            self.assertNotIn(name, env)
        self.assertEqual(len(env["L"]), 45056)
        self.assertNotIn("A", env, "a list that holds itself twice grows without its len")

    def test_join_and_format_refuse_before_they_build_the_value(self):
        # refused after the build, a 400 MB value would already be in memory: the check runs first
        env = {"L": "x" * 40_000, "M": ["a"] * 10}
        for src, why in (("L.join(M)", "join too long"), ("'{0}{0}{0}{0}{0}{0}'.format(L)", "format too long"),
                         ("'{}{}{}{}{}{}'.format(L, L, L, L, L, L)", "format too long")):
            with self.subTest(src):
                with self.assertRaises(sp.Unknown) as ctx:
                    sp.evaluate(ast.parse(src, mode="eval").body, env)
                self.assertEqual(str(ctx.exception), why)

    def test_presidio_reads_a_recognizer_and_its_alias_base(self):
        alias = GOOD.replace("class GoodRecognizer(PatternRecognizer)", "PR = PatternRecognizer\n"
                             "class AliasRecognizer(PR)").replace("'GOOD'", "'ALIAS'")
        out = sync_presidio.recognizers(wheel({"good.py": GOOD, "alias.py": alias}))
        self.assertEqual([(r["class"], r["entity"], r["language"]) for r in out],
                         [("AliasRecognizer", "ALIAS", "de"), ("GoodRecognizer", "GOOD", "de")])
        self.assertEqual(out[1]["patterns"], [{"name": "weak", "score": 0.3, "regex": r"\b[0-9][0-9]\b"}])

    def test_presidio_refuses_a_class_it_cannot_take_whole(self):
        cases = {
            "qualified base": GOOD.replace("(PatternRecognizer)", "(presidio_analyzer.PatternRecognizer)"),
            "two bases": GOOD.replace("(PatternRecognizer)", "(Mixin, PatternRecognizer)"),
            "computed default": GOOD.replace("supported_language: str = 'de'", "supported_language: str = LANG"),
            "patterns built in code": GOOD.replace("PATTERNS = [", "PATTERNS = make([").replace("0.3)]", "0.3)])"),
        }
        for label, text in cases.items():
            with self.subTest(label):
                with self.assertRaises(sync_presidio.Refused):
                    sync_presidio.recognizers(wheel({"x.py": text}))
        with self.assertRaises(sync_presidio.Refused):
            sync_presidio.recognizers(wheel({"a.py": GOOD, "b.py": GOOD}))

    def test_no_sync_script_executes_or_imports_upstream_code(self):
        for name in ("sync_detect_secrets.py", "sync_presidio.py", "sync_gitleaks.py", "_static_python.py"):
            with self.subTest(name):
                tree = ast.parse((ROOT / "scripts" / name).read_text(encoding="utf-8"))
                calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
                self.assertFalse(calls & {"exec", "eval", "compile", "__import__", "getattr", "setattr"}, calls)
                attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
                self.assertFalse(attrs & {"import_module", "walk_packages", "run", "Popen", "system"}, attrs)
                imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
                imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
                self.assertFalse(imported & {"presidio_analyzer", "detect_secrets", "importlib", "pkgutil",
                                             "subprocess", "runpy", "builtins", "marshal", "pickle"}, imported)


if __name__ == "__main__":
    unittest.main()
