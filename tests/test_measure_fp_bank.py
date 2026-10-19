"""scripts/measure_fp_bank.py: each tree is pinned to a full commit, a tree that is not at its commit is refused, the
result holds counts and no text of the tree, and compare fails only when the acted hits rose.

Run: python3 -m unittest tests.test_measure_fp_bank -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("measure_fp_bank", ROOT / "scripts" / "measure_fp_bank.py")
fb = importlib.util.module_from_spec(_spec)
sys.modules["measure_fp_bank"] = fb
_spec.loader.exec_module(fb)

PROBE = "fpbankprobe-word-in-the-tree"
IP = ".".join(["52", "14", "7", "9"])  # a public address the ip rule acts on, built here so the file holds none


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(cwd), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


class PinTests(unittest.TestCase):
    def test_each_tree_has_a_unique_name_and_a_full_commit(self):
        names = [t[1] for t in fb.TREES]
        self.assertEqual(len(names), 4)
        self.assertEqual(len(set(names)), len(names))
        for commit, name, url, sub in fb.TREES:
            self.assertRegex(commit, r"^[0-9a-f]{40}$", name)
            self.assertTrue(url.startswith("https://github.com/") and url.endswith(".git"), name)
            self.assertFalse(sub.startswith("/") or ".." in sub, name)


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp(prefix="fpbank-test-"))
        self.addCleanup(shutil.rmtree, self.cache, True)
        d = self.cache / "tiny"
        (d / "src").mkdir(parents=True)
        (d / "src" / "notes.md").write_text(f"{PROBE}\nthe host is {IP} today\n")
        (d / "src" / "skip.bin").write_text(PROBE)
        (d / "outside.md").write_text(f"{PROBE} {IP}\n")
        git(d, "init", "-q")
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "tiny")
        self.commit = git(d, "rev-parse", "HEAD")

    def run_bank(self, commit):
        with mock.patch.object(fb, "TREES", ((commit, "tiny", "https://github.com/x/tiny.git", "src"),)):
            return fb.measure(self.cache, detect)

    def test_a_tree_at_its_commit_is_counted_in_its_subdirectory_only(self):
        result = self.run_bank(self.commit)
        tree = result["trees"]["tiny"]
        self.assertEqual(tree["commit"], self.commit)
        self.assertEqual(tree["files"], 1, "src/notes.md only: no .bin, and outside.md is not in src")
        self.assertRegex(result["maisecrets"], r"^[0-9a-f]{40}$")
        for key, (hits, acted) in tree["rules"].items():
            self.assertRegex(key, r"^(tests|other)\|[A-Z_]+\|[\w.-]+$")
            self.assertLessEqual(acted, hits)
        self.assertEqual(tree["rules"], {"other|IP|ip": [1, 1]}, "one address, in src only")

    def test_the_result_holds_no_text_of_the_tree(self):
        text = json.dumps(self.run_bank(self.commit))
        for part in (PROBE, IP, "notes.md"):
            self.assertNotIn(part, text)

    def test_a_tree_not_at_its_commit_is_refused(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_bank("0" * 40)
        self.assertIn("run fetch first", str(cm.exception))


def bank(commit="c" * 40, **rules):
    return {"maisecrets": "m" * 40, "trees": {"t": {"commit": commit, "files": 1, "chars": 1,
                                                       "rules": {k.replace("__", "|"): v for k, v in rules.items()}}}}


class CompareTests(unittest.TestCase):
    def compare(self, before, after):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fb.compare(before, after)
        return code, out.getvalue()

    def test_more_acted_hits_fail_and_name_the_rule(self):
        code, out = self.compare(bank(other__EMAIL__email=[3, 2]), bank(other__EMAIL__email=[4, 3]))
        self.assertEqual(code, 1)
        self.assertIn("other|EMAIL|email", out)
        self.assertIn("+1", out)

    def test_fewer_or_equal_acted_hits_pass(self):
        self.assertEqual(self.compare(bank(other__IP__ip=[5, 5]), bank(other__IP__ip=[5, 4]))[0], 0)
        self.assertEqual(self.compare(bank(other__IP__ip=[5, 5]), bank(other__IP__ip=[9, 5]))[0], 0,
                         "a hit the test-code rule drops is not a false alarm a user sees")

    def test_a_new_rule_counts_and_a_moved_commit_is_not_compared(self):
        self.assertEqual(self.compare(bank(), bank(tests__SECRET__jwt=[1, 1]))[0], 1)
        code, out = self.compare(bank(other__IP__ip=[1, 1]), bank("d" * 40, other__IP__ip=[9, 9]))
        self.assertEqual(code, 0)
        self.assertIn("not comparable", out)

    def test_the_totals_split_test_code_from_the_rest(self):
        tree = bank(other__IP__ip=[5, 4], tests__IP__ip=[3, 1])["trees"]["t"]
        self.assertEqual(fb.totals(tree), (8, 5, 4))


class FalseAlarmScriptTests(unittest.TestCase):
    def test_the_script_prints_the_same_table_as_before_the_split(self):
        d = Path(tempfile.mkdtemp(prefix="fpbank-mfa-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "a.md").write_text(f"the host is {IP} today\n")
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_false_alarms.py"), str(d)],
                             capture_output=True, text=True, check=True).stdout
        self.assertTrue(out.startswith("1 files, 0.0 MB\nwhere  type"), out)
        self.assertTrue(re.search(r"^other\s+IP\s+ip\s+1\s+1$", out, re.M), out)


if __name__ == "__main__":
    unittest.main()
