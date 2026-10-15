"""scripts/github_matrix.py: the Windows and macOS matrix for a merge request, and the reuse of a
green run for a release. Fakes only: no network, no push, no real remote.
"""
from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir


def _load():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("_gm_github_matrix", ROOT / "scripts" / "github_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


G = _load()
TREE = "1" * 40
WF = ".github/workflows/ci.yml"


def _run(tree=TREE, event="push", conclusion="success", path=WF, rid=1, head_sha="2" * 40):
    return {"id": rid, "event": event, "status": "completed", "conclusion": conclusion, "path": path,
            "head_sha": head_sha, "html_url": f"https://github.invalid/runs/{rid}",
            "jobs_url": f"https://api.github.invalid/runs/{rid}/jobs", "head_commit": {"tree_id": tree}}


def _jobs(*conclusions):
    return [{"status": "completed", "conclusion": c} for c in conclusions]


def _git(cwd, *args, env=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


class BranchNameTests(unittest.TestCase):
    def test_one_branch_per_commit(self):
        self.assertEqual(G.branch_name(42, "abcdef0123456789" * 2 + "abcdef01"), "ci-mr/42-abcdef012345")
        self.assertNotEqual(G.branch_name(42, "a" * 40), G.branch_name(42, "b" * 40))

    def test_refuses_what_is_no_iid_or_sha(self):
        for iid, sha in (("4x", "a" * 40), ("", "a" * 40), (7, "a" * 11), (7, "A" * 40), (7, "../main" + "a" * 12)):
            with self.subTest(iid=iid, sha=sha), self.assertRaises(ValueError):
                G.branch_name(iid, sha)


class CleanupTests(unittest.TestCase):
    NOW = 100 * 86400.0

    def test_older_commits_of_the_same_mr_and_old_branches_go(self):
        refs = {"ci-mr/7-aaaaaaaaaaaa": self.NOW - 60,       # this MR, an older commit
                "ci-mr/7-bbbbbbbbbbbb": self.NOW,            # the branch just pushed
                "ci-mr/70-cccccccccccc": self.NOW - 60,      # another MR whose iid starts with 7
                "ci-mr/8-dddddddddddd": self.NOW - 15 * 86400,   # another MR, older than 14 days
                "ci-mr/9-eeeeeeeeeeee": self.NOW - 13 * 86400,   # another MR, younger
                "main": 0}
        self.assertEqual(G.branches_to_delete(refs, 7, "ci-mr/7-bbbbbbbbbbbb", self.NOW),
                         ["ci-mr/7-aaaaaaaaaaaa", "ci-mr/8-dddddddddddd"])

    def test_the_kept_branch_is_never_deleted_even_when_old(self):
        self.assertEqual(G.branches_to_delete({"ci-mr/7-aaaaaaaaaaaa": 0}, 7, "ci-mr/7-aaaaaaaaaaaa", self.NOW), [])


class ReusableRunTests(unittest.TestCase):
    def _find(self, runs, jobs=None):
        asked = []

        def jobs_of(run):
            asked.append(run["id"])
            return (jobs or {}).get(run["id"], _jobs("success", "success"))
        return G.reusable_run(TREE, runs, jobs_of), asked

    def test_a_green_push_run_on_the_same_tree_is_reused(self):
        run, _a = self._find([_run(tree="3" * 40, rid=1), _run(rid=2), _run(rid=3)])
        self.assertEqual(run["id"], 2)

    def test_a_tree_that_differs_in_one_character_is_not_reused(self):
        run, asked = self._find([_run(tree="1" * 39 + "2"), _run(tree="1" * 39), _run(tree=None)])
        self.assertIsNone(run)
        self.assertEqual(asked, [])

    def test_a_pull_request_run_tested_another_tree_and_does_not_count(self):
        run, asked = self._find([_run(event="pull_request")])
        self.assertIsNone(run)
        self.assertEqual(asked, [])

    def test_skipped_failed_or_missing_jobs_do_not_count(self):
        # the release commit's run concludes success with every job skipped
        for jobs in (_jobs("skipped", "skipped"), _jobs("success", "failure"), _jobs("success", "cancelled"), []):
            with self.subTest(jobs=jobs):
                run, _a = self._find([_run(rid=5)], {5: jobs})
                self.assertIsNone(run)

    def test_a_red_run_or_another_workflow_does_not_count(self):
        run, _a = self._find([_run(conclusion="failure"), _run(path=".github/workflows/other.yml")])
        self.assertIsNone(run)

    def test_a_short_or_odd_tree_is_refused(self):
        for tree in ("", "1" * 12, "1" * 40 + "\n", "G" * 40):
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                G.reusable_run(tree, [], lambda r: [])

    def test_two_commits_with_the_same_tree_match_and_a_changed_file_does_not(self):
        # real git: the release candidate is another commit (a merge) with the tree of the merge request run
        with tempfile.TemporaryDirectory() as d:
            # a git hook runs this suite with GIT_INDEX_FILE and GIT_DIR set: without them removed, the
            # throw-away repository's `git add` staged its file in the real repository (2026-10-15)
            clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env = dict(clean, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull)
            _git(d, "init", "-q", env=env)
            Path(d, "a.txt").write_text("one\n")
            _git(d, "add", "a.txt", env=env)
            _git(d, "commit", "-q", "-m", "x", env=env)
            first = _git(d, "rev-parse", "HEAD", env=env)
            twin = _git(d, "commit-tree", f"{first}^{{tree}}", "-p", first, "-m", "same files", env=env)
            Path(d, "a.txt").write_text("two\n")
            _git(d, "commit", "-q", "-am", "y", env=env)
            changed = _git(d, "rev-parse", "HEAD", env=env)
            cwd = os.getcwd()
            os.chdir(d)
            try:
                with mock.patch.dict(os.environ, env, clear=True):
                    trees = {name: G.tree_of(sha) for name, sha in
                             (("first", first), ("twin", twin), ("changed", changed))}
            finally:
                os.chdir(cwd)
        self.assertNotEqual(first, twin)
        runs = [_run(tree=trees["first"], head_sha=first)]
        self.assertIsNotNone(G.reusable_run(trees["twin"], runs, lambda r: _jobs("success")))
        self.assertIsNone(G.reusable_run(trees["changed"], runs, lambda r: _jobs("success")))


class ReuseCommandTests(unittest.TestCase):
    def _reuse(self, answers):
        urls = []

        def fake_get(url, tries=3):
            urls.append(url)
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return a
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(G, "_get", fake_get), mock.patch.object(G, "tree_of", lambda sha: TREE), \
                redirect_stdout(out), redirect_stderr(err):
            rc = G.cmd_reuse("4" * 40)
        return rc, out.getvalue(), err.getvalue(), urls

    def test_the_ci_repository_then_the_mirror_and_stdout_is_the_run_url(self):
        rc, out, err, urls = self._reuse([{"workflow_runs": [_run(tree="3" * 40)]},
                                          {"workflow_runs": [_run(rid=9)]}, {"jobs": _jobs("success")}])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "https://github.invalid/runs/9\n")
        self.assertIn("same tree 111111111111", err)
        self.assertTrue(urls[0].startswith(f"https://api.github.com/repos/{G.CI_REPO}/actions/runs?event=push"))
        self.assertTrue(urls[1].startswith(f"https://api.github.com/repos/{G.MIRROR_REPO}/actions/runs?"))

    def test_no_run_or_no_answer_is_no_reuse(self):
        rc, out, _e, _u = self._reuse([{"workflow_runs": []}, {"workflow_runs": []}])
        self.assertEqual((rc, out), (1, ""))
        rc, out, err, _u = self._reuse([RuntimeError("github api: 403")])
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("no reuse", err)


REPORT = textwrap.dedent("""\
    test_ok (tests.test_a.A.test_ok) ... ok
    test_bad (tests.test_a.A.test_bad) ... FAIL

    ======================================================================
    ERROR: test_b (unittest.loader._FailedTest.test_b)
    ----------------------------------------------------------------------
    ImportError: Failed to import test module: test_b
    Traceback (most recent call last):
      File "x.py", line 1, in <module>
    ModuleNotFoundError: No module named 'winreg2'


    ======================================================================
    FAIL: test_bad (tests.test_a.A.test_bad) (case='C:\\\\x')
    ----------------------------------------------------------------------
    Traceback (most recent call last):
      File "tests/test_a.py", line 9, in test_bad
        self.assertEqual(1, 2)
    AssertionError: 1 != 2

    ----------------------------------------------------------------------
    Ran 2 tests in 0.010s

    FAILED (failures=1, errors=1)
    """)


class UnittestReportTests(unittest.TestCase):
    def test_each_failure_with_the_last_line_of_its_traceback(self):
        self.assertEqual(G.unittest_failures(REPORT), [
            ("test_b (unittest.loader._FailedTest.test_b)", "ModuleNotFoundError: No module named 'winreg2'"),
            ("test_bad (tests.test_a.A.test_bad) (case='C:\\\\x')", "AssertionError: 1 != 2")])

    def test_annotations_escape_and_stay_within_the_limit(self):
        lines = G.annotations([("t (m.C.t) (k=1, v=a:b)", "50% done\nnext")], 1)
        self.assertEqual(lines, ["::error title=t (m.C.t) (k=1%2C v=a%3Ab)::50%25 done%0Anext"])
        many = [(f"t{i}", "r") for i in range(14)]
        lines = G.annotations(many, 1)
        self.assertEqual(len(lines), G.MAX_ANNOTATIONS)
        self.assertEqual(lines[-1], "::error title=5 more failing tests::" + "%0A".join(f"t{i}" for i in range(9, 14)))
        self.assertEqual(len(G.annotations(many[:10], 1)), 10)

    def test_a_crash_without_a_failure_line_is_named_too(self):
        self.assertIn("exited 3 without a FAIL or ERROR line", G.annotations([], 3)[0])

    def test_the_wrapper_keeps_the_exit_code_and_annotates_a_real_failure(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "tests").mkdir()
            Path(d, "tests", "test_x.py").write_text(textwrap.dedent("""\
                import unittest
                class T(unittest.TestCase):
                    def test_good(self):
                        pass
                    def test_bad(self):
                        self.assertEqual("a", "b")
                """))
            p = subprocess.run([sys.executable, str(ROOT / "scripts" / "github_matrix.py"), "unit"], cwd=d,
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 1, p.stdout)
            self.assertIn("test_good (test_x.T", p.stdout)
            self.assertRegex(p.stdout, r"::error title=test_bad \(test_x\.T[^:]*::AssertionError: 'a' != 'b'")


class SharedWaitTests(unittest.TestCase):
    def test_the_wait_returns_the_newest_run_per_name_for_the_report(self):
        w = G.wait_for_github_checks
        answer = {"check_runs": [{"id": 1, "name": "win", "status": "completed", "conclusion": "cancelled"},
                                 {"id": 2, "name": "win", "status": "completed", "conclusion": "failure"},
                                 {"id": 3, "name": "mac", "status": "completed", "conclusion": "success"}]}

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        import json
        body = json.dumps(answer).encode()
        with mock.patch.object(w.urllib.request, "urlopen", lambda req, timeout=30: _Resp(body)), \
                redirect_stdout(io.StringIO()):
            rc, runs = w.wait("cafe1234beef", "o/r", 1, poll=60)
        self.assertEqual(rc, 1)
        self.assertEqual(sorted(r["id"] for r in runs), [2, 3])


if __name__ == "__main__":
    unittest.main()
