"""The scope of a merge request into next (scripts/mr_scope.py and the rules of .gitlab-ci.yml): measurement results
and the format-watch snapshot alone run baseline_only, .gitlab-ci.yml alone runs ci_only and the smoke jobs, and every
other path runs every test job. A path that no class knows is code; a path set that the rules let past the suites
but that is not of the guard's class turns the guard red.

Run: python3 -m unittest tests.test_mr_scope -v
"""
from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import mr_scope as S  # noqa: E402

CI = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
RUN = "tests.test_mr_scope"

RESULT = "bench/results/2026-11-19-v3-0.9.18/measured.json"
SNAPSHOT = "docs/format-watch.txt"
CODE = "maisecrets/hooks.py"
DOC = "docs/USING.md"
STANDARDS = "docs/REPO-STANDARDS.md"


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True).stdout
    return [n for n in out.split("\0") if n]


def listed(anchor: str, indent: str) -> list[str]:
    """The quoted patterns of a YAML list that starts after `anchor`."""
    rest = CI[CI.index(anchor) + len(anchor):].splitlines()[1:]
    out = []
    for line in rest:
        if not line.startswith(indent + "- "):
            break
        out.append(line[len(indent) + 2:].strip().strip("'"))
    return out


class ClassifyTests(unittest.TestCase):
    def test_measurement_results_and_the_snapshot_are_results(self):
        for paths in ([RESULT], ["bench/HOLDOUT-LOG.md", "docs/coverage.json"], [SNAPSHOT, "docs/format-watch-fp.txt"],
                      [RESULT, SNAPSHOT], ["bench/results/2026-11-04-json-0.8.19/summary.json"],
                      ["bench/results/2026-10-19-v0.6.39.md"]):
            with self.subTest(paths=paths):
                self.assertEqual(S.classify(paths), "results")

    def test_the_ci_file_alone_or_with_the_standards_is_ci(self):
        self.assertEqual(S.classify([".gitlab-ci.yml"]), "ci")
        self.assertEqual(S.classify([".gitlab-ci.yml", STANDARDS]), "ci")

    def test_every_other_path_set_is_code(self):
        for paths in ([], [STANDARDS], [DOC], [CODE], [RESULT, CODE], [RESULT, ".gitlab-ci.yml"],
                      [".gitlab-ci.yml", DOC], [SNAPSHOT, STANDARDS], ["bench/run.py"], ["bench/results"],
                      ["docs/coverage.json.bak"], ["docs/format-watch.txt/x"], ["new-top-level-file"],
                      ["bench/results/../maisecrets/core.py"], ["bench/results/./x"], ["/bench/results/x"],
                      ["bench/results//x"], ["bench\\results\\x"], [".gitlab-ci.yml", ".gitlab-ci.yml.bak"]):
            with self.subTest(paths=paths):
                self.assertEqual(S.classify(paths), "code")


class CheckTests(unittest.TestCase):
    """The guard of a light job: exit 0 for its own class only, on the diff BASE..HEAD of a real repository."""

    def test_the_guard_passes_its_class_and_refuses_the_others(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):
                return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                       "-c", "commit.gpgsign=false", *args], cwd=tmp, capture_output=True,
                                      text=True, check=True).stdout.strip()

            def check(cls, base):
                return subprocess.run([sys.executable, str(ROOT / "scripts" / "mr_scope.py"), "check", cls, base],
                                      cwd=tmp, capture_output=True, text=True)

            git("init", "-q")
            for rel in (RESULT, CODE, ".gitlab-ci.yml"):
                (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / rel).write_text("a\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            base = git("rev-parse", "HEAD")
            self.assertEqual(check("results", base).returncode, 1, "no change is no class")
            (Path(tmp) / RESULT).write_text("b\n", encoding="utf-8")
            git("commit", "-q", "-am", "result")
            self.assertEqual(check("results", base).returncode, 0)
            self.assertEqual(check("ci", base).returncode, 1)
            (Path(tmp) / ".gitlab-ci.yml").write_text("b\n", encoding="utf-8")
            git("commit", "-q", "-am", "ci")
            done = check("results", base)
            self.assertEqual(done.returncode, 1, "a mix of two classes")
            self.assertIn(".gitlab-ci.yml", done.stdout)
            self.assertEqual(check("ci", base).returncode, 1)
            self.assertEqual(check("ci", git("rev-parse", "HEAD~1")).returncode, 0)


class GlobTests(unittest.TestCase):
    def test_the_matcher_follows_gitlab(self):
        # File.fnmatch? with FNM_PATHNAME | FNM_DOTMATCH | FNM_EXTGLOB
        self.assertTrue(S.glob_match("docs/**/*", "docs/a.md"))
        self.assertTrue(S.glob_match("docs/**/*", "docs/a/b.md"))
        self.assertFalse(S.glob_match("docs/*", "docs/a/b.md"))
        self.assertTrue(S.glob_match("*", ".gitignore"))
        self.assertTrue(S.glob_match("{a,b[!x]*}", "by"))
        self.assertFalse(S.glob_match("{a,b[!x]*}", "bx"))
        self.assertFalse(S.glob_match("[!.-]*", "-x"))
        self.assertFalse(S.glob_match("?", "/"))

    def test_the_ci_file_holds_the_generated_patterns(self):
        self.assertEqual(listed(".code_paths: &code_paths", "  "), S.code_globs(),
                         "regenerate: python3 scripts/mr_scope.py globs")
        job = CI[CI.index("\nwindows_macos:"):]
        bench = [line.strip()[2:].strip("'") for line in job[:job.index("\n  variables:")].splitlines()
                 if line.strip().startswith("- 'bench/")]
        # without the third: a folder named like a light file names no file of the tree
        self.assertEqual(bench, [g for g in S.code_globs() if g.startswith("bench/")][:2])

    def test_the_patterns_match_exactly_the_paths_outside_the_light_files(self):
        odd = ["bench/resultsX/a", "bench/result", "bench/Hx", "bench/HOLDOUT-LOG.md.bak", "docs/coverage.jsonx",
               "docs/c", "docs/format-watch", "docs/sub/x", ".gitlab-ci.yml/x", "bench", "docs", ".gitlab-ci.ym",
               ".gitlab-ci.yml2", "x", "b", "benchx/y", "docs2/y", "bench/results", "docs/coverage.json/a",
               "bench/HOLDOUT-LOG.md/a", "docs/REPO-STANDARDS.mdx", "docs/format-watch-fp.txt.orig"]
        globs = S.code_globs()
        paths = tracked() + odd
        self.assertGreater(len(paths), 1000, "the premise: the tree")
        for p in paths:
            light = S.is_result(p) or p in S.CI_FILES
            self.assertEqual(any(S.glob_match(g, p) for g in globs), not light, p)


def _if(expr: str, env: dict) -> bool:
    """The forms of GitLab rules:if that the test jobs use: ||, &&, parentheses, ==, !=, =~, !~, a bare variable."""
    def regex(m: re.Match) -> str:
        return str(bool(re.search(m[3].replace("\\/", "/"), env.get(m[1], ""))) == (m[2] == "=~"))

    def compare(m: re.Match) -> str:
        return str((env.get(m[1], "") == m[3]) == (m[2] == "=="))

    out = re.sub(r"\$(\w+)\s*(=~|!~)\s*/((?:[^/\\]|\\.)*)/", regex, expr)
    out = re.sub(r'\$(\w+)\s*(==|!=)\s*"([^"]*)"', compare, out)
    out = re.sub(r"\$(\w+)", lambda m: str(bool(env.get(m[1]))), out)
    out = out.replace("&&", " and ").replace("||", " or ")
    if not re.fullmatch(r"[\s()]*(?:(?:True|False|and|or)[\s()]*)+", out):
        raise AssertionError(f"the test does not know this rule: {expr}")
    return bool(eval(out))  # noqa: S307 - only True, False, and, or and parentheses are left


class RuleTests(unittest.TestCase):
    """The test jobs that a pipeline creates, from the rules of .gitlab-ci.yml as GitLab reads them."""

    @classmethod
    def setUpClass(cls):
        try:
            import yaml
        except ImportError:
            raise unittest.SkipTest("PyYAML is not installed (CI installs PyYAML)")
        cls.doc = yaml.safe_load(CI)

    def _get(self, name: str, key: str):
        job = self.doc[name]
        if key in job:
            return job[key]
        parent = job.get("extends")
        return self._get(parent, key) if parent else None

    def jobs(self, env: dict, paths: list[str]) -> set[str]:
        out = set()
        for name, job in self.doc.items():
            if not isinstance(job, dict) or name.startswith(".") or self._get(name, "stage") != "test":
                continue
            for rule in self._get(name, "rules") or []:
                if "if" in rule and not _if(rule["if"], env):
                    continue
                if "changes" in rule:
                    globs = rule["changes"]["paths"] if isinstance(rule["changes"], dict) else rule["changes"]
                    if not any(S.glob_match(g, p) for g in globs for p in paths):
                        continue
                if rule.get("when", "on_success") != "never":
                    out.add(name)
                break
        return out

    def mr(self, paths: list[str], target="next", source="feat/x", labels="") -> set[str]:
        return self.jobs({"CI_PIPELINE_SOURCE": "merge_request_event", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": target,
                          "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": source, "CI_MERGE_REQUEST_LABELS": labels}, paths)

    SUITES = {"unit", "unit_python39"}
    LONG = SUITES | {"beliefs_can_fail_replay", "harness_claude", "harness_codex", "windows_macos"}
    SMOKE = {"ci_only", "smoke_unit_python39", "smoke_harness_claude", "smoke_harness_codex"}

    def test_results_and_the_snapshot_run_baseline_only(self):
        for paths in ([RESULT], [SNAPSHOT], ["bench/HOLDOUT-LOG.md", "docs/coverage.json", RESULT]):
            with self.subTest(paths=paths):
                self.assertEqual(self.mr(paths), {"baseline_only"})

    def test_the_ci_file_runs_ci_only_and_the_smoke_jobs(self):
        self.assertEqual(self.mr([".gitlab-ci.yml"]), self.SMOKE)
        self.assertEqual(self.mr([".gitlab-ci.yml", STANDARDS]), self.SMOKE)

    def test_documentation_alone_runs_the_suites_as_before(self):
        for paths in ([DOC], [STANDARDS], [STANDARDS, RESULT]):
            with self.subTest(paths=paths):
                self.assertEqual(self.mr(paths), self.SUITES)

    def test_code_runs_every_test_job(self):
        self.assertEqual(self.mr([CODE]), self.LONG)
        self.assertEqual(self.mr([CODE, ".gitlab-ci.yml"]), self.LONG)
        self.assertEqual(self.mr(["bench/run.py", RESULT]), self.SUITES | {"windows_macos"})
        # a change of the CI file beside documentation: the suites read both; the harnesses get their smoke
        self.assertEqual(self.mr([DOC, ".gitlab-ci.yml"]), self.SUITES | {"smoke_harness_claude",
                                                                         "smoke_harness_codex"})

    def test_no_path_set_skips_the_suites_without_a_guard_of_another_class(self):
        reps = [RESULT, SNAPSHOT, ".gitlab-ci.yml", STANDARDS, DOC, CODE, "bench/run.py", "new-top-level-file",
                ".github/workflows/ci.yml", "docs/coverage-rules.txt", "bench/HOLDOUT-LOG.md.bak"]
        sets = [[a] for a in reps] + [[a, b] for i, a in enumerate(reps) for b in reps[i + 1:]]
        sets += [[p] for p in tracked()[::7]]
        guard = {"baseline_only": "results", "ci_only": "ci"}
        for paths in sets:
            got, cls = self.mr(paths), S.classify(paths)
            with self.subTest(paths=paths, cls=cls, jobs=sorted(got)):
                if self.SUITES <= got:
                    continue
                self.assertFalse(got & self.SUITES, "both suites or neither")
                guards = {guard[j] for j in got if j in guard}
                self.assertEqual(len(guards), 1, "the suites are off, so exactly one guard runs")
                if cls == "code":
                    # the guard turns red: a mix of two classes
                    self.assertNotIn(cls, guards)
                    self.assertGreater(len(paths), 1, "a single path of code always runs the suites")
                else:
                    self.assertEqual(guards, {cls})

    def test_main_tags_schedules_and_the_release_merge_request_stay_as_they_were(self):
        main = {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "main"}
        self.assertEqual(self.jobs(main, [CODE]), self.LONG - {"windows_macos"})
        self.assertEqual(self.jobs(main, [RESULT]), self.LONG - {"windows_macos"})
        self.assertEqual(self.jobs({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_TAG": "v1.2.3"}, [CODE]), set())
        self.assertEqual(self.jobs({"CI_PIPELINE_SOURCE": "schedule"}, [CODE]), set())
        self.assertEqual(self.mr([CODE, RESULT, ".gitlab-ci.yml"], target="main", source="next"), {"windows_macos"})
        # a hotfix into main: every job, the CI file included
        self.assertEqual(self.mr([".gitlab-ci.yml"], target="main", source="fix/x"), self.LONG)
        self.assertEqual(self.mr([RESULT], target="main", source="fix/x"), self.SUITES | {"windows_macos"})

    def test_a_baseline_branch_runs_baseline_only_as_before(self):
        self.assertEqual(self.mr([RESULT], source="chore/baseline-0.9.19"), {"baseline_only"})
        self.assertEqual(self.mr([CODE], source="chore/baseline-0.9.19"), {"baseline_only"})
        self.assertEqual(self.mr([".gitlab-ci.yml"], source="chore/baseline-0.9.19"), {"baseline_only"})


class ReaderTests(unittest.TestCase):
    """The light jobs run the modules that read the files of their class, found here with grep: a reader of a file
    names it, a reader of the whole tree runs git ls-files, and a test of a script that reads the file names it."""

    TOKENS = {"results": r'bench/results|"bench"\s*/\s*"results"|HOLDOUT-LOG|coverage\.json|format-watch',
              "ci": r"\.gitlab-ci\.yml|REPO-STANDARDS"}

    def test_every_reader_runs_in_its_light_job(self):
        for cls, tokens in self.TOKENS.items():
            scripts = sorted(p.stem for p in (ROOT / "scripts").glob("*.py")
                             if p.stem != "mr_scope" and re.search(tokens, p.read_text(encoding="utf-8")))
            self.assertTrue(scripts, cls)
            pattern = re.compile("|".join([tokens, "ls-files"] + [rf"\b{s}\b" for s in scripts]))
            readers = {f"tests.{p.stem}" for p in (ROOT / "tests").glob("test_*.py")
                       if pattern.search(p.read_text(encoding="utf-8"))}
            self.assertGreater(len(readers), 3, cls)
            with self.subTest(cls=cls):
                self.assertLessEqual(readers, set(S.TESTS[cls]), "add them to TESTS in scripts/mr_scope.py")
                self.assertIn(RUN, S.TESTS[cls])

    def test_every_listed_module_exists(self):
        for cls, mods in S.TESTS.items():
            for mod in mods:
                self.assertTrue((ROOT / (mod.replace(".", "/") + ".py")).is_file(), mod)


if __name__ == "__main__":
    unittest.main()
