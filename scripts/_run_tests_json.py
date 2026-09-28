#!/usr/bin/env python3
"""Run unittest ids and write each test's outcome as JSON: {id: "pass"|"fail"|"skip"|"broken"}.

The replay needs the outcome per test, not one exit code: an invariant belief demands that
each of its tests goes red under at least one mutation. Parsing `unittest -v` text differs
between Python versions (3.9 prints the class, 3.11 the method) and breaks on a docstring;
a result object does not.

    python3 scripts/_run_tests_json.py OUT.json tests.test_x.Class.test_y ...
"""
from __future__ import annotations

import json
import os
import sys
import unittest


class _Recorder(unittest.TextTestResult):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.outcomes: dict[str, str] = {}

    def _set(self, test, outcome: str) -> None:
        tid = test.id()
        # a subTest failure marks the whole test red; a later pass must not undo it
        if self.outcomes.get(tid) in ("fail", "skip") and outcome == "pass":
            return
        self.outcomes[tid] = outcome

    def addSuccess(self, test):
        super().addSuccess(test)
        self._set(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._set(test, "fail")

    def addError(self, test, err):
        super().addError(test, err)
        if not isinstance(test, unittest.TestCase):
            # a class or module fixture failed; it arrives as a _ErrorHolder named after the fixture.
            # In setUpClass or setUpModule no test of it ran, so none was red on its own evidence. In
            # tearDownClass the tests ran and the fixture's check is evidence too: c5's class finds a
            # value-serving child still alive there under its mutation.
            self.outcomes[test.id()] = "broken" if str(test).startswith(("setUpClass", "setUpModule")) else "fail"
            return
        self._set(test, "fail")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._set(test, "skip")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._set(test, "fail")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._set(test, "pass")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._set(test, "skip" if issubclass(err[0], unittest.SkipTest) else "fail")


def main(argv: list[str]) -> int:
    out, ids = argv[0], argv[1:]
    # `python -m unittest` puts the working directory first on sys.path; a script gets its own dir
    sys.path.insert(0, os.getcwd())
    suite = unittest.defaultTestLoader.loadTestsFromNames(ids)
    runner = unittest.TextTestRunner(resultclass=_Recorder, verbosity=1, stream=sys.stderr)
    result = runner.run(suite)
    outcomes = dict(result.outcomes)
    for tid in ids:
        # a test that never reported (an import error, a class-level error) did not run: "broken",
        # which the replay refuses as evidence, never "fail" (review, 2026-09-28: an import error under
        # a mutation counted as a kill of every owning test)
        if tid not in outcomes and not any(k.startswith(tid + ".") for k in outcomes):
            outcomes[tid] = "broken"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(outcomes, fh)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
