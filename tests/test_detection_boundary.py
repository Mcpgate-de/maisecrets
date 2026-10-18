"""The boundary of the detection core: what the rest of maisecrets may use of detect.py, and what a plain scan imports.

The core is the modules the standalone skill ships (scripts/build_skill_zip.py) plus personal.py: __init__, detect,
checksums, normalise, regions, registry, rulespec, rule_filter. The plugin called private names of detect.py from
hooks, the value check and the rules of your own, so a change inside the core could break a caller it does not know.
These tests hold the line: a module outside the core uses detect only by its public names (the facade at the end of
detect.py), in the forms that private_uses() names, and a plain detect.scan() or findings() imports no module of the
plugin beyond the ones it imports today. That list may only get shorter.

Run: python3 -m unittest tests.test_detection_boundary -v
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import io
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

CORE = frozenset({"__init__", "detect", "checksums", "normalise", "regions", "registry", "rulespec", "rule_filter",
                  "personal"})
# the modules of the plugin that a plain scan still imports. Each is a later step: the config read for the regions
# (home, through active_regions), the rules of your own and the allow list (user_rules), and the probes for a term
# list or an import (term_files, value_files). Remove a name when the scan no longer imports it; never add one. The
# one exception so far: home.py took the file and config helpers out of vault.py (2026-10-18), and with it vault and
# placeholder left the scan.
NOT_YET_OUT = frozenset({"home", "term_files", "user_rules", "value_files"})
# a scan never imports the store or the placeholder form, also with a term list and an import of values in place
NEVER = frozenset({"vault", "placeholder", "rehydration", "vault_refs", "hooks", "settings"})


def private_uses(source: str) -> list[tuple[int, str]]:
    """(line, name) of every private name of detect that a module uses in one of these forms. A module expression is
    a name bound to detect (`detect`; `import maisecrets.detect as d`; `from . import detect as d`; `d = <module
    expression>` or `d: T = <module expression>`, also chained) or `maisecrets.detect`. A use is an attribute
    `<module expression>._x`, a literal `getattr(<module expression>, "_x")`, `from .detect import _x`, or a string
    that starts with `detect._` or `maisecrets.detect._` (an annotation). Other forms, such as a name built at run time
    (`getattr(d, name)`) or a binding through a function call, are out of its reach: the test guards against an
    ordinary use, not against one that hides."""
    tree = ast.parse(source)
    names = {"detect"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.asname for a in node.names if a.asname and a.name.split(".")[-1] == "detect"}
        elif isinstance(node, ast.ImportFrom):
            names |= {a.asname or a.name for a in node.names if a.name == "detect"}

    def is_module(e) -> bool:
        return (isinstance(e, ast.Name) and e.id in names) or (
            isinstance(e, ast.Attribute) and e.attr == "detect" and isinstance(e.value, ast.Name)
            and e.value.id == "maisecrets")

    for _ in range(3):   # d = detect, then e = d
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and is_module(node.value):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names |= {t.id for t in targets if isinstance(t, ast.Name)}
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and is_module(node.value):
            out.append((node.lineno, node.attr))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" \
                and len(node.args) >= 2 and is_module(node.args[0]) and isinstance(node.args[1], ast.Constant) \
                and str(node.args[1].value).startswith("_"):
            out.append((node.lineno, node.args[1].value))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[-1] == "detect":
            out += [(node.lineno, a.name) for a in node.names if a.name.startswith("_")]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith(
                ("detect._", "maisecrets.detect._")):
            out.append((node.lineno, node.value))   # a string such as an annotation: "detect._Lazy"
    return sorted(set(out))


def outside_the_core() -> list[Path]:
    return sorted([p for p in (ROOT / "maisecrets").rglob("*.py") if not (p.parent.name == "maisecrets"
                                                                          and p.stem in CORE)]
                  + list((ROOT / "hooks").rglob("*.py")))


class DetectionBoundaryTests(unittest.TestCase):
    def test_the_checker_sees_each_form_of_a_private_use_and_passes_a_public_one(self):
        # the vocabulary of the checker, pinned: a checker that sees nothing passes every module
        self.assertEqual(private_uses("from . import detect\nx = detect._ranked(1)\n"), [(2, "_ranked")])
        self.assertEqual(private_uses("from .detect import _LazyRx\n"), [(1, "_LazyRx")])
        self.assertEqual(private_uses("from maisecrets.detect import Match, _word_set\n"), [(1, "_word_set")])
        self.assertEqual(private_uses('def f() -> "detect._Lazy":\n    pass\n'), [(1, "detect._Lazy")])
        self.assertEqual(private_uses("import maisecrets.detect as d\nd._scan('x')\n"), [(2, "_scan")])
        self.assertEqual(private_uses("from . import detect as d\nd._ranked(1)\n"), [(2, "_ranked")])
        self.assertEqual(private_uses("from . import detect\nd = detect\ne = d\ne._lower('x')\n"), [(4, "_lower")])
        self.assertEqual(private_uses("import maisecrets.detect\nmaisecrets.detect._RULES\n"), [(2, "_RULES")])
        self.assertEqual(private_uses("from . import detect\ngetattr(detect, '_word_set')()\n"), [(2, "_word_set")])
        self.assertEqual(private_uses("from .detect import LazyRx as _LazyRx\nx = detect.findings('a')\n"), [])
        self.assertEqual(private_uses("from . import vault as v\nv._index\n"), [], "another module's private name")
        self.assertEqual(private_uses("from . import detect\nd: object = detect\nd._word_set()\n"), [(3, "_word_set")])
        self.assertEqual(private_uses("import maisecrets.detect\nd = maisecrets.detect\nd._word_set()\n"),
                         [(3, "_word_set")])
        self.assertEqual(private_uses("import maisecrets.detect\ngetattr(maisecrets.detect, '_word_set')()\n"),
                         [(2, "_word_set")])
        self.assertEqual(private_uses('def f(x: "maisecrets.detect._Lazy"):\n    pass\n'),
                         [(1, "maisecrets.detect._Lazy")])
        self.assertEqual(private_uses("from . import other\nother.detect._x\nd = other.detect\nd._y\n"), [],
                         "the detect of another object is not this module")

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
        self.assert_imports("scan")

    def test_findings_import_no_new_module_of_the_plugin(self):
        self.assert_imports("findings")

    def test_a_scan_with_a_term_list_and_an_import_imports_no_store(self):
        home = Path(tempfile.mkdtemp(prefix="detect-boundary-", dir=_isolate.HOME))
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_", "CLAUDE", "CODEX"))}
        env["MAISECRETS_HOME"] = str(home)
        name, other = "Annabell " + "Quarzfeld", "Ottilie " + "Brennwald"
        line = json.dumps({"value": other, "type": "NAME"}) + "\n"
        setup = (f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                 "from maisecrets import terms, values\n"
                 f"assert terms.add_typed({name!r})[0]\n"
                 f"assert values.import_bytes({line.encode()!r}, 'probe').new\n")
        r = subprocess.run([sys.executable, "-I", "-c", setup], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        code = (f"import json, sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                "from maisecrets import detect\n"
                f"kinds = [m.kind for m in detect.scan({name + ' and ' + other + ' met.'!r}, channel='tool')]\n"
                "print(json.dumps([kinds, sorted(m for m in sys.modules if m.startswith('maisecrets.'))]))\n")
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        kinds, mods = json.loads(r.stdout)
        self.assertTrue(any(k.startswith("term:") for k in kinds) and any(k.startswith("import:") for k in kinds),
                        f"the premise: both sources ran ({kinds})")
        loaded = {m.split(".", 1)[1] for m in mods}
        self.assertTrue({"terms", "values"} <= loaded, loaded)
        self.assertFalse(loaded & NEVER, f"a scan imports {sorted(loaded & NEVER)}")

    def assert_imports(self, call: str):
        """Each call in a process of its own: a module that only findings() imports must not count for scan()."""
        home = Path(tempfile.mkdtemp(prefix="detect-boundary-", dir=_isolate.HOME))
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from maisecrets import detect\n"
            "text = 'pass' + 'word: hunter2x9\\nmail me at someone@example.org, +49 30 1234567\\n'\n"
            "for ch in ('prompt', 'tool'):\n"
            f"    assert detect.{call}(text, channel=ch), ch\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('maisecrets.'))))\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS_", "CLAUDE", "CODEX"))}
        env["MAISECRETS_HOME"] = str(home)
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        loaded = {m.split(".", 1)[1] for m in json.loads(r.stdout)}
        self.assertTrue({"detect", "personal", "registry"} <= loaded, loaded)
        beyond = loaded - CORE
        self.assertFalse(loaded & NEVER, f"{call}() imports {sorted(loaded & NEVER)}")
        self.assertFalse(beyond - NOT_YET_OUT, f"{call}() now imports {sorted(beyond - NOT_YET_OUT)}")
        self.assertFalse(NOT_YET_OUT - beyond, f"no longer imported: remove {sorted(NOT_YET_OUT - beyond)} "
                                               "from NOT_YET_OUT")


class GivenRegionsTests(unittest.TestCase):
    """A caller gives the regions of the scans (detect.use_regions); the detector then reads no config for them. The
    plugin gives its config reader in hooks.main, so a hook gets the regions of today."""

    def setUp(self):
        from maisecrets import detect, home, regions
        self.detect, self.home, self.regions = detect, home, regions
        self.addCleanup(detect.reset_rules)
        self.addCleanup(detect.use_regions, None)

    def ids(self, region: str) -> set:
        self.detect.use_regions(self.regions.resolve({"regions": [region]}))
        return {r.id for r in self.detect.rules()}

    def test_given_regions_decide_the_rules_and_no_config_is_read(self):
        with mock.patch.object(self.home, "load_config", side_effect=AssertionError("the detector read the config")):
            us, de = self.ids("us"), self.ids("de")
            self.assertNotEqual(us, de, "the premise: the two regions load different rules")
            given = self.regions.resolve({"regions": ["us"]})
            self.detect.use_regions(given)
            self.assertIs(self.detect.active_regions(), given)
            self.detect.scan("call +1 202 555 0143 today", channel="tool")
            self.assertEqual(self.detect._pii_regions_cached(), ("generic", "us"))

    def test_a_given_reader_is_asked_at_each_use_not_when_it_is_given(self):
        asked = []

        def reader():
            asked.append(1)
            return self.regions.resolve({"regions": ["de"]})
        self.detect.use_regions(reader)
        self.assertEqual(asked, [])
        self.assertEqual(self.detect.active_regions().regions, ("generic", "de"))
        self.assertEqual(len(asked), 1)

    def test_without_given_regions_the_config_of_this_computer_decides(self):
        self.detect.use_regions(None)
        with mock.patch.object(self.home, "load_config", return_value={"regions": ["us"]}):
            self.assertEqual(self.detect.active_regions().regions, ("generic", "us"))
        with mock.patch.object(self.home, "load_config", side_effect=RuntimeError("broken")):
            self.assertEqual(self.detect.active_regions().regions, ("generic", "de"), "a bad config counts as none")

    def test_the_hook_entry_gives_the_config_reader(self):
        from maisecrets import hooks
        with mock.patch.object(self.detect, "use_regions") as given, \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps({
                    "hook_event_name": "PreToolUse", "session_id": "regions", "tool_name": "Grep",
                    "tool_input": {"pattern": "x", "path": "."}}))), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            hooks.main(["dispatch.py", "pre-tool"])
        given.assert_called_once_with(self.home.regions_from_config)

    def test_given_regions_need_no_home_module(self):
        code = (f"import json, sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                "from maisecrets import detect, regions\n"
                "detect.use_regions(regions.resolve({'regions': ['us']}))\n"
                "a = detect.active_regions()\n"
                "print(json.dumps([list(a.regions), 'maisecrets.home' in sys.modules]))\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [["generic", "us"], False])


if __name__ == "__main__":
    unittest.main()
