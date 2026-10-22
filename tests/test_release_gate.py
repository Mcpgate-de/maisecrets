"""scripts/release_gate.py: the diff since the last release decides what to measure, and a span the candidate masks
worse than the release stops the gate (2026-10-22: 0.7.6 shipped a phone number it lost, found only after release)."""
from __future__ import annotations

import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import release_gate as gate  # noqa: E402


def result(outcomes: dict, sha: str = "abc") -> dict:
    return {"cases_sha256": sha, "per_case": outcomes}


class ReleaseGateTests(unittest.TestCase):
    def test_the_diff_decides_whether_to_measure(self):
        kind = gate.classify(["maisecrets/detection/personal.py", "docs/BENCHMARKS.md"])
        self.assertTrue(kind["retest"])
        self.assertFalse(kind["live"])
        kind = gate.classify(["maisecrets/hooks.py", "claude-mod/maisecrets-mod.mjs", "tests/test_x.py"])
        self.assertFalse(kind["retest"])
        self.assertTrue(kind["live"])
        kind = gate.classify(["docs/BENCHMARK-V3.md", "bench/run.py", ".gitlab-ci.yml", ".claude-plugin/plugin.json"])
        self.assertEqual((False, False), (kind["retest"], kind["live"]))

    def test_a_span_masked_worse_stops_the_gate(self):
        base = result({"a": ["full", "missed", "fp"], "b": ["partial"]})
        better = result({"a": ["full", "full", "fp"], "b": ["full"]})
        worse = result({"a": ["missed", "full"], "b": ["partial", "fp", "fp"]})
        self.assertEqual(0, gate.compare(base, better)["worse"])
        r = gate.compare(base, worse)
        self.assertEqual(1, r["worse"])
        self.assertEqual([1, 2], r["fp"])
        self.assertFalse(gate.compare(base, result({}, sha="other"))["comparable"])
        kind = gate.classify(["maisecrets/detection/core.py"])
        self.assertTrue(gate.report(kind, {"x": gate.compare(base, worse)}, None)[1])
        self.assertFalse(gate.report(kind, {"x": gate.compare(base, better)}, None)[1])

    def test_holdout_recall_may_not_fall(self):
        kind = gate.classify(["maisecrets/detection/core.py"])
        self.assertTrue(gate.report(kind, {}, (0.63, 0.61))[1])
        self.assertFalse(gate.report(kind, {}, (0.63, 0.63))[1])

    def test_the_run_is_compared_with_the_gzip_results_of_the_release(self):
        with tempfile.TemporaryDirectory() as d:
            base, run = Path(d) / "base", Path(d) / "run"
            base.mkdir()
            run.mkdir()
            with gzip.open(base / "nemotron-dev-maisecrets-full.json.gz", "wt", encoding="utf-8") as f:
                json.dump(result({"a": ["full"]}), f)
            (run / "nemotron-dev-maisecrets-full.json").write_text(json.dumps(result({"a": ["missed"]})))
            (run / "gretel-dev-maisecrets-full.json").write_text(json.dumps(result({"a": ["full"]})))
            out = gate.compare_dirs(base, run)
            self.assertEqual(1, out["nemotron-dev-maisecrets-full"]["worse"])
            self.assertFalse(out["gretel-dev-maisecrets-full"]["comparable"])


if __name__ == "__main__":
    unittest.main()
