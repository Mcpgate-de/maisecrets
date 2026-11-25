"""bench/ner/load.py, the load test of #105: a dry run against the fake name service of the harness writes the run,
the summary and one row per result, and the verdict follows the limit of 1 %. Synthetic values only."""
from __future__ import annotations

import _isolate  # noqa: F401  (first: the temp home)
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.ner import load  # noqa: E402

ROW_KEYS = {"session", "t_s", "shape", "chars", "total", "pieces", "requests", "checked_pct", "state", "reason", "rest",
            "refused", "ner_ms", "wall_ms"}
SUMMARY_KEYS = {"results", "with_rest", "rest_pct", "limit_pct", "verdict", "wall_p50_ms", "wall_p95_ms", "states",
                "reasons", "refusals", "requests", "pieces"}


def row(state: str, reason: str = "", refused: dict | None = None, wall: float = 100.0) -> dict:
    return {"session": 0, "rest": state != "ok", "state": state, "reason": reason, "refused": refused or {},
            "wall_ms": wall, "requests": 2, "pieces": 2, "chars": 30000, "checked_pct": 50.0}


class NerLoadTests(unittest.TestCase):
    def test_a_dry_run_checks_long_results_in_pieces_and_passes(self):
        with tempfile.TemporaryDirectory() as out, contextlib.redirect_stdout(io.StringIO()) as said:
            rc = load.main(["--dry-run", "--duration", "3", "--sessions", "2", "--out", out])
            data = json.loads((Path(out) / "load.json").read_text(encoding="utf-8"))
            readme = (Path(out) / "README.md").read_text(encoding="utf-8")
        self.assertEqual(rc, 0, said.getvalue())
        s, rows = data["summary"], data["rows"]
        self.assertTrue(SUMMARY_KEYS <= set(s), set(s))
        self.assertGreater(s["results"], 0)
        self.assertEqual((s["with_rest"], s["rest_pct"], s["verdict"]), (0, 0.0, "PASS"))
        self.assertEqual(s["states"], {"ok": s["results"]})
        self.assertEqual({r["session"] for r in rows}, {0, 1})
        for r in rows:
            self.assertTrue(ROW_KEYS <= set(r), set(r))
            self.assertTrue(load.MIN_CHARS <= r["chars"] <= load.MAX_CHARS)
            self.assertGreaterEqual(r["pieces"], 2)          # every result is longer than one piece of 20,000
            self.assertEqual(r["requests"], r["pieces"])
            self.assertEqual(r["checked_pct"], 100.0)
        self.assertEqual({r["shape"] for r in rows} - {"bash", "mcp"}, set())
        self.assertTrue(data["meta"]["takes_pieces"])
        self.assertIn("PASS", readme)
        self.assertIn("PASS:", said.getvalue())

    def test_a_system_without_a_load_average_runs_too(self):
        # Windows has no os.getloadavg: the dry run failed there with AttributeError (CI, 2026-11-25)
        from unittest import mock
        with mock.patch.object(os, "getloadavg", side_effect=AttributeError("no load average"), create=True):
            self.assertIsNone(load.load_now())
            self.assertFalse(load.quiet_host(), "no load average: the host is never taken as quiet")
            with tempfile.TemporaryDirectory() as out, contextlib.redirect_stdout(io.StringIO()):
                rc = load.main(["--dry-run", "--duration", "2", "--sessions", "1", "--out", out])
                data = json.loads((Path(out) / "load.json").read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertGreater(data["summary"]["results"], 0)
        self.assertIsNone(data["meta"]["load_max"])

    def test_more_than_one_percent_with_a_rest_fails(self):
        meta = {"sessions": 1}
        rows = [row("ok")] * 98 + [row("partial", "busy", {"busy": 1}), row("unavailable", "rate_limited",
                                                                             {"rate_limited": 1})]
        s = load.summarize(rows, meta)
        self.assertEqual((s["with_rest"], s["rest_pct"], s["verdict"]), (2, 2.0, "FAIL"))
        self.assertEqual(s["reasons"], {"busy": 1, "rate_limited": 1})
        self.assertEqual(s["refusals"], {"busy": 1, "rate_limited": 1})
        self.assertEqual(load.summarize(rows[:99] + [row("ok")], meta)["verdict"], "PASS")    # 1 of 100: at the limit
        self.assertEqual(load.summarize([], meta)["verdict"], "FAIL")                         # no result proves nothing

    def test_the_own_home_is_refused_without_reading_it(self):
        with tempfile.TemporaryDirectory() as out, contextlib.redirect_stderr(io.StringIO()) as said:
            rc = load.main(["--home", os.path.join(os.path.expanduser("~"), ".maisecrets"), "--out", out])
        self.assertEqual(rc, 2)
        self.assertIn("own maisecrets home", said.getvalue())


if __name__ == "__main__":
    unittest.main()
