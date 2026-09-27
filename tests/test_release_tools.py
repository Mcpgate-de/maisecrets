"""The release tooling: subjects to versions, reverts, and the GitHub wait under network errors."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseClassificationTests(unittest.TestCase):
    def setUp(self):
        self.r = _load("release")

    def test_types_bump_the_0x_scale_and_docs_release_nothing(self):
        r = self.r
        self.assertEqual(r.bump_for([("a", "feat(x): y", "")]), "minor")
        self.assertEqual(r.bump_for([("a", "fix(x): y", "")]), "patch")
        self.assertIsNone(r.bump_for([("a", "docs: y", ""), ("b", "ci(x): z", ""), ("c", "test: t", "")]))
        self.assertIsNone(r.bump_for([("a", "Merge branch x", "")]), "a merge subject releases nothing")
        self.assertEqual(r.next_version("0.3.24", "minor"), "0.3.25", "0.x: a feature bumps the last number")
        self.assertEqual(r.next_version("0.3.24", "major"), "0.4.0", "0.x: a break bumps the middle number")
        self.assertEqual(r.next_version("1.2.3", "minor"), "1.3.0")

    def test_any_revert_is_a_patch_under_reverts_and_passes_the_format_check(self):
        r = self.r
        for subject in ('Revert "feat(x): y"', 'Revert "refactor(hooks): y"', 'Revert "Merge branch x"'):
            with self.subTest(subject):
                typ, text, breaking = r.classify(subject, "")
                self.assertEqual((typ, breaking), ("revert", False))
                self.assertTrue(text.startswith("revert: "))
                self.assertEqual(r.bump_for([("a", subject, "")]), "patch")
        typ, text, _b = r.classify('Revert "Revert "feat(x): y""', "")
        self.assertEqual(typ, "revert")
        self.assertTrue(text.startswith("re-apply: "))
        self.assertIn("Reverts", r.render_notes("0.3.99", [("abc1234", 'Revert "feat(x): y"', "")]))


class GitHubWaitTests(unittest.TestCase):
    def test_network_errors_are_waited_out_and_green_checks_end_the_wait(self):
        w = _load("wait_for_github_checks")
        answers = [urllib.error.URLError("dns"), TimeoutError(), {"check_runs": [
            {"name": "tests (ubuntu-latest)", "status": "completed", "conclusion": "success"},
            {"name": "tests (windows-latest)", "status": "completed", "conclusion": "skipped"}]}]

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=30):
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return _Resp(json.dumps(a).encode())
        with mock.patch.object(w.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(w, "_main_moved", lambda sha: False), \
                mock.patch.object(w.time, "sleep", lambda s: None), \
                mock.patch.object(sys, "stdout", io.StringIO()) as out:
            rc = w.main(["wait", "deadbeef"])
        self.assertEqual(rc, 0)
        self.assertIn("unreachable", out.getvalue())
        self.assertIn("green", out.getvalue())

    def test_a_failed_check_ends_the_wait_red_and_a_moved_main_steps_aside(self):
        w = _load("wait_for_github_checks")

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        red = {"check_runs": [{"name": "tests (windows-latest)", "status": "completed", "conclusion": "failure"}]}
        with mock.patch.object(w.urllib.request, "urlopen", lambda req, timeout=30: _Resp(json.dumps(red).encode())), \
                mock.patch.object(w, "_main_moved", lambda sha: False), \
                mock.patch.object(w.time, "sleep", lambda s: None), \
                mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(w.main(["wait", "deadbeef"]), 1)
        with mock.patch.object(w, "_main_moved", lambda sha: True), mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(w.main(["wait", "deadbeef"]), 0)


if __name__ == "__main__":
    unittest.main()
