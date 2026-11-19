"""The scope of a merge request into next (scripts/mr_scope.py and the rules of .gitlab-ci.yml): measurement results
and the format-watch snapshot alone run baseline_only, and every other path, .gitlab-ci.yml included, runs every test
job. A path set that the rules let past the suites but that is not of the class results turns the guard red, and so
does a symlink, a submodule, an unknown file type or a binary that is no gzip.

Run: python3 -m unittest tests.test_mr_scope -v
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
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
GZ = b"\x1f\x8b\x08\x00"


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

    def test_every_other_path_set_is_code(self):
        for paths in ([], [".gitlab-ci.yml"], [".gitlab-ci.yml", "docs/REPO-STANDARDS.md"], [DOC], [CODE],
                      [RESULT, CODE], [RESULT, ".gitlab-ci.yml"], ["bench/run.py"], ["bench/results"],
                      ["docs/coverage.json.bak"], ["docs/format-watch.txt/x"], ["new-top-level-file"],
                      ["bench/results/../maisecrets/core.py"], ["bench/results/./x"], ["/bench/results/x"],
                      ["bench/results//x"], ["bench\\results\\x"]):
            with self.subTest(paths=paths):
                self.assertEqual(S.classify(paths), "code")


class RefusedTests(unittest.TestCase):
    """The guard reads more than the names: the mode, the file type and whether git sees a binary."""

    def test_the_entries_of_a_baseline_pass(self):
        run = "bench/results/2026-11-19-v3-0.9.18/"
        ok = [S.Entry(run + "measured.json.gz", "100644", True, GZ), S.Entry(run + "a.json.log", "100644", False),
              S.Entry(run + "summary.json", "100644", False), S.Entry(run + "cases.jsonl", "100644", False),
              S.Entry(run + "README.md", "100644", False), S.Entry(run + "trees.txt", "100644", False),
              S.Entry(run + "SHA256SUMS", "100644", False), S.Entry("bench/HOLDOUT-LOG.md", "100644", False),
              S.Entry("docs/coverage.json", "100644", False), S.Entry(SNAPSHOT, "100644", False),
              S.Entry("bench/results/2026-01-01-v3-0.0.1/old.csv", "000000", False)]
        self.assertEqual(S.refused(ok), [])

    def test_a_symlink_a_submodule_an_unknown_type_and_a_binary_are_refused(self):
        run = "bench/results/2026-11-19-v3-0.9.18/"
        bad = [S.Entry(run + "link.json", "120000", False), S.Entry(run + "sub", "160000", False),
               S.Entry(run + "run.json", "100755", False), S.Entry(run + "tool.py", "100644", False),
               S.Entry(run + "table.csv", "100644", False), S.Entry(run + "x.json", "100644", True, b"MZ\0\0"),
               S.Entry(run + "fake.json.gz", "100644", True, b"PK\x03\x04"),
               S.Entry("docs/coverage.json", "100644", True, b"\0\0"), S.Entry(CODE, "100644", False),
               S.Entry(".gitlab-ci.yml", "100644", False)]
        got = S.refused(bad)
        self.assertEqual(len(got), len(bad), got)

class CheckTests(unittest.TestCase):
    """The guard of baseline_only on the diff BASE..HEAD of a real repository: modes and binaries from git."""

    def test_the_guard_passes_results_and_refuses_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args, check=True):
                return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                       "-c", "core.symlinks=true", *args], cwd=tmp, capture_output=True,
                                      text=True, check=check).stdout.strip()

            def commit(msg):
                # plumbing: a commit hook of the machine has no say in a test repository
                git("add", "-A")
                parent = ["-p", git("rev-parse", "HEAD")] if git("rev-parse", "--verify", "-q", "HEAD^{commit}",
                                                                 check=False) else []
                git("update-ref", "HEAD", git("commit-tree", git("write-tree"), *parent, "-m", msg))

            def check(base):
                return subprocess.run([sys.executable, str(ROOT / "scripts" / "mr_scope.py"), "check", base],
                                      cwd=tmp, capture_output=True, text=True)

            def write(rel, data: bytes):
                (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / rel).write_bytes(data)

            git("init", "-q")
            write(RESULT, b"a\n")
            write(CODE, b"a\n")
            commit("base")
            base = git("rev-parse", "HEAD")
            self.assertEqual(check(base).returncode, 1, "no change is no class")
            write(RESULT, b"b\n")
            write("bench/results/2026-11-19-v3-0.9.18/measured.json.gz", GZ + b"\0\0data")
            commit("result")
            done = check(base)
            self.assertEqual(done.returncode, 0, done.stdout)
            step = git("rev-parse", "HEAD")
            for rel, data, why in (("bench/results/2026-11-19-v3-0.9.18/x.json", b"MZ\0\0\0", "binary"),
                                   (".gitlab-ci.yml", b"b\n", "no measurement result")):
                write(rel, data)
                commit(rel)
                done = check(base)
                self.assertEqual(done.returncode, 1, rel)
                self.assertIn(why, done.stdout)
                git("rm", "-q", rel)
                commit("undo")
            # a symlink, by its mode in the index: no file system needs to make one
            blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=tmp, input="../../maisecrets",
                                  capture_output=True, text=True, check=True).stdout.strip()
            git("update-index", "--add", "--cacheinfo", f"120000,{blob},bench/results/2026-11-19-v3-0.9.18/l.json")
            git("update-ref", "HEAD", git("commit-tree", git("write-tree"), "-p", step, "-m", "link"))
            done = check(base)
            self.assertEqual(done.returncode, 1)
            self.assertIn("mode 120000", done.stdout)


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
               "docs/c", "docs/format-watch", "docs/sub/x", ".gitlab-ci.yml", "bench", "docs", "x", "b", "benchx/y",
               "docs2/y", "bench/results", "docs/coverage.json/a", "bench/HOLDOUT-LOG.md/a", "docs/REPO-STANDARDS.md",
               "docs/format-watch-fp.txt.orig"]
        globs = S.code_globs()
        paths = tracked() + odd
        self.assertGreater(len(paths), 1000, "the premise: the tree")
        for p in paths:
            self.assertEqual(any(S.glob_match(g, p) for g in globs), not S.is_result(p), p)


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

    def test_results_and_the_snapshot_run_baseline_only(self):
        for paths in ([RESULT], [SNAPSHOT], ["bench/HOLDOUT-LOG.md", "docs/coverage.json", RESULT]):
            with self.subTest(paths=paths):
                self.assertEqual(self.mr(paths), {"baseline_only"})

    def test_the_ci_file_runs_every_test_job(self):
        # it holds the commands of every gate and the pinned versions the harnesses test
        self.assertEqual(self.mr([".gitlab-ci.yml"]), self.LONG)
        self.assertEqual(self.mr([".gitlab-ci.yml", RESULT]), self.LONG)

    def test_documentation_alone_runs_the_suites_as_before(self):
        for paths in ([DOC], ["docs/REPO-STANDARDS.md"], ["docs/REPO-STANDARDS.md", RESULT]):
            with self.subTest(paths=paths):
                self.assertEqual(self.mr(paths), self.SUITES)

    def test_code_runs_every_test_job(self):
        self.assertEqual(self.mr([CODE]), self.LONG)
        self.assertEqual(self.mr(["bench/run.py", RESULT]), self.SUITES | {"windows_macos"})

    def test_no_path_set_skips_the_suites_without_the_guard(self):
        reps = [RESULT, SNAPSHOT, ".gitlab-ci.yml", "docs/REPO-STANDARDS.md", DOC, CODE, "bench/run.py",
                "new-top-level-file", ".github/workflows/ci.yml", "docs/coverage-rules.txt", "bench/HOLDOUT-LOG.md.bak"]
        sets = [[a] for a in reps] + [[a, b] for i, a in enumerate(reps) for b in reps[i + 1:]]
        sets += [[p] for p in tracked()[::7]]
        for paths in sets:
            got, cls = self.mr(paths), S.classify(paths)
            with self.subTest(paths=paths, cls=cls, jobs=sorted(got)):
                if cls == "code":
                    self.assertLessEqual(self.SUITES, got)
                    self.assertNotIn("baseline_only", got)
                else:
                    self.assertEqual(got, {"baseline_only"})

    def test_main_tags_schedules_and_the_release_merge_request_stay_as_they_were(self):
        main = {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "main"}
        self.assertEqual(self.jobs(main, [CODE]), self.LONG - {"windows_macos"})
        self.assertEqual(self.jobs(main, [RESULT]), self.LONG - {"windows_macos"})
        self.assertEqual(self.jobs({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_TAG": "v1.2.3"}, [CODE]), set())
        self.assertEqual(self.jobs({"CI_PIPELINE_SOURCE": "schedule"}, [CODE]), set())
        self.assertEqual(self.mr([CODE, RESULT, ".gitlab-ci.yml"], target="main", source="next"), {"windows_macos"})
        # a hotfix into main: every job
        self.assertEqual(self.mr([".gitlab-ci.yml"], target="main", source="fix/x"), self.LONG)
        self.assertEqual(self.mr([RESULT], target="main", source="fix/x"), self.SUITES | {"windows_macos"})

    def test_a_baseline_branch_runs_baseline_only_as_before(self):
        for paths in ([RESULT], [CODE], [".gitlab-ci.yml"]):
            with self.subTest(paths=paths):
                self.assertEqual(self.mr(paths, source="chore/baseline-0.9.19"), {"baseline_only"})

    def test_the_guard_uses_the_target_tip_in_a_merged_results_pipeline(self):
        job = CI[CI.index("\nbaseline_only:"):CI.index("\nunit:")]
        self.assertIn('BASE="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-$CI_MERGE_REQUEST_DIFF_BASE_SHA}"', job)
        self.assertLess(job.index('git fetch --quiet origin "$BASE"'), job.index('git cat-file -e "$BASE^{commit}"'))
        self.assertLess(job.index('git cat-file -e "$BASE^{commit}"'), job.index('mr_scope.py check "$BASE"'))


class ReaderTests(unittest.TestCase):
    """baseline_only runs the modules that read the result files, found here with grep: a reader of a file names it,
    a reader of the whole tree runs git ls-files, and a test of a script that reads the file names it."""

    TOKENS = r'bench/results|"bench"\s*/\s*"results"|HOLDOUT-LOG|coverage\.json|format-watch'

    def test_every_reader_runs_in_baseline_only(self):
        scripts = sorted(p.stem for p in (ROOT / "scripts").glob("*.py")
                         if p.stem != "mr_scope" and re.search(self.TOKENS, p.read_text(encoding="utf-8")))
        self.assertTrue(scripts)
        pattern = re.compile("|".join([self.TOKENS, "ls-files"] + [rf"\b{s}\b" for s in scripts]))
        readers = {f"tests.{p.stem}" for p in (ROOT / "tests").glob("test_*.py")
                   if pattern.search(p.read_text(encoding="utf-8"))}
        self.assertGreater(len(readers), 3)
        self.assertLessEqual(readers, set(S.TESTS), "add them to TESTS in scripts/mr_scope.py")
        self.assertIn(RUN, S.TESTS)

    def test_every_listed_module_exists(self):
        for mod in S.TESTS:
            self.assertTrue((ROOT / (mod.replace(".", "/") + ".py")).is_file(), mod)


if __name__ == "__main__":
    unittest.main()
