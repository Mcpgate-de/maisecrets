#!/usr/bin/env python3
"""The release gate: before a release, answer whether the candidate needs to be measured again, and measure it.

    python3 scripts/release_gate.py CANDIDATE OUT [--baseline DIR] [--holdout CASES] [--dry-run]

CANDIDATE is a clean checkout of the commit to release (the head of `next`); OUT a new directory for the run. The gate
compares the candidate with the last release tag:

- **detection changed** (maisecrets/detection/**): Benchmark V3 for maisecrets on the candidate (bench/run_all_v3.sh,
  about 40 minutes), compared span by span with the last release's results in bench/results/ (--baseline, default
  the newest `*-v3-<last version>`). Any span the candidate masks worse than the release stops the gate; the change
  of false positives per source goes into the report. With --holdout, Holdout V2 runs on the candidate too and its
  recall may not fall below the last row of bench/HOLDOUT-LOG.md.
- **hooks changed** (the hooks, the mod, the settings and the rest of the runtime): the gate names the checks that only
  a client shows: the harness (python3 harness/run.py) and a live test between two sessions with --plugin-dir.
- **nothing at run time** (docs, bench, CI, tests): no measurement is needed.

The gate exits 1 when the candidate masks any span worse, 0 otherwise, and prints a report for the release merge
request. Counts only, never a value. It runs locally: the datasets are too large for CI (docs/REPO-STANDARDS.md)."""
from __future__ import annotations

import collections
import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTION = ("maisecrets/detection/",)
RUNTIME = ("maisecrets/", "hooks/", "claude-mod/", "commands/", "skills/", ".claude-plugin/")
RANK = {"missed": 0, "partial": 1, "full": 2}


def classify(changed: list) -> dict:
    """What the changed paths since the last release ask for: detection, hooks (the rest of the run time), or none."""
    detection = sorted(p for p in changed if p.startswith(DETECTION))
    hooks = sorted(p for p in changed if p.startswith(RUNTIME) and not p.startswith(DETECTION)
                   and not p.endswith(("plugin.json", "marketplace.json")))
    return {"detection": detection, "hooks": hooks, "retest": bool(detection), "live": bool(hooks)}


def _load(path: Path) -> dict:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def compare(base: dict, cand: dict) -> dict:
    """Span by span, two result files of bench/run.py on the same cases: the changes of outcome, the spans made worse,
    and the false positives before and after."""
    if base.get("cases_sha256") != cand.get("cases_sha256"):
        return {"comparable": False}
    moves, worse, fp_base, fp_cand = collections.Counter(), 0, 0, 0
    for cid, oc in cand["per_case"].items():
        ob = base["per_case"].get(cid, [])
        fp_base += ob.count("fp")
        fp_cand += oc.count("fp")
        for x, y in zip([o for o in ob if o != "fp"], [o for o in oc if o != "fp"]):
            if x != y:
                moves[f"{x}->{y}"] += 1
                worse += RANK[y] < RANK[x]
    return {"comparable": True, "moves": dict(moves), "worse": worse, "fp": [fp_base, fp_cand]}


def compare_dirs(baseline: Path, run: Path) -> dict:
    """Each maisecrets result of the run against the file of the same name in the baseline (plain or gzip)."""
    out = {}
    for f in sorted(run.glob("*-maisecrets*.json")):
        b = baseline / (f.name + ".gz")
        b = b if b.exists() else baseline / f.name
        out[f.name.replace(".json", "")] = compare(_load(b), _load(f)) if b.exists() else {"comparable": False}
    return out


def _git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def last_release(candidate: Path) -> str:
    """The highest release tag: a release tag sits on main, so `git describe` from next would find an older one."""
    return _git("tag", "--list", "v[0-9]*", "--sort=-v:refname", cwd=candidate).splitlines()[0]


def default_baseline(version: str) -> Path | None:
    hits = sorted(ROOT.glob(f"bench/results/*-v3-{version.lstrip('v')}"))
    return hits[-1] if hits else None


def last_holdout_recall() -> float | None:
    rows = [r for r in (ROOT / "bench" / "HOLDOUT-LOG.md").read_text(encoding="utf-8").splitlines()
            if "holdout-v2" in r and r.startswith("|")]
    return float(rows[-1].split("|")[5]) if rows else None


def report(kind: dict, results: dict, holdout: tuple | None) -> tuple:
    lines = ["## Release gate", ""]
    if not kind["retest"] and not kind["live"]:
        lines.append("Nothing at run time changed since the last release: no measurement needed.")
    if kind["live"]:
        lines.append("Hooks or other runtime files changed (" + ", ".join(kind["hooks"][:8]) + "): run the harness "
                     "and a live test between two sessions with --plugin-dir before the release.")
    failed = False
    if kind["retest"]:
        lines += ["", "Detection changed (" + ", ".join(kind["detection"][:8]) + "): Benchmark V3 against the last "
                  "release, span by span:", "", "| Result | Spans worse | Changes | False positives |",
                  "|---|---:|---|---|"]
        for name, r in results.items():
            if not r.get("comparable"):
                lines.append(f"| {name} | – | not comparable (other cases or no baseline) | – |")
                continue
            failed |= r["worse"] > 0
            lines.append(f"| {name} | {r['worse']} | {r['moves'] or 'none'} | {r['fp'][0]} → {r['fp'][1]} |")
    if holdout:
        before, after = holdout
        failed |= before is not None and after is not None and after < before
        lines += ["", f"Holdout V2 recall: {before} → {after}"]
    lines += ["", "**Gate: " + ("stopped, a span got worse" if failed else "passed") + "**"]
    return "\n".join(lines), failed


def main(argv: list) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--holdout", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="classify the changes only")
    a = ap.parse_args(argv)
    cand = a.candidate.resolve()
    if _git("status", "--porcelain", "--untracked-files=all", cwd=cand):
        raise SystemExit("the candidate checkout has changes: measure a commit")
    tag = last_release(cand)
    kind = classify(_git("diff", "--name-only", f"{tag}..HEAD", cwd=cand).splitlines())
    head = _git("rev-parse", "--short=8", "HEAD", cwd=cand)
    print(f"last release {tag}, candidate {head}: retest {'needed' if kind['retest'] else 'not needed'}, "
          f"live test {'needed' if kind['live'] else 'not needed'}")
    if a.dry_run or not kind["retest"]:
        text, failed = report(kind, {}, None)
        print(text)
        return 0
    baseline = a.baseline or default_baseline(tag)
    if baseline is None:
        raise SystemExit(f"no results of {tag} in bench/results/: run Benchmark V3 on the release first")
    a.out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    subprocess.run(["bash", str(ROOT / "bench" / "run_all_v3.sh"), str(a.out), str(cand)], cwd=ROOT, env=env,
                   check=True)
    results = compare_dirs(baseline, a.out)
    holdout = None
    if a.holdout:
        out = a.out / "holdout-v2.json"
        subprocess.run([env.get("BENCH_PYTHON", sys.executable), "bench/run.py", "--scanner", "maisecrets",
                        "--maisecrets", str(cand), "--source", "holdout-v2", "--holdout", str(a.holdout),
                        "--release-candidate", "--out", str(out)], cwd=ROOT, check=True)
        m = json.loads(out.read_text(encoding="utf-8"))["metrics"].get("all", {})
        holdout = (last_holdout_recall(), m.get("recall_strict"))
    text, failed = report(kind, results, holdout)
    (a.out / "release-gate.md").write_text(text + "\n", encoding="utf-8")
    print(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
