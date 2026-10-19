"""The false-alarm bank: four public trees on fixed commits, measured with scripts/measure_false_alarms.py. A fixed
instrument for a detector change: run it before and after, and compare.

    python3 scripts/measure_fp_bank.py fetch <cache>                  clone each tree at its commit (once)
    python3 scripts/measure_fp_bank.py measure <cache> [--json <out>]  count the hits per tree and rule
    python3 scripts/measure_fp_bank.py compare <before.json> <after.json>

The trees hold no real secrets that we know of; what the detector finds there is a false alarm or a test value of
the project. The output holds no value and no line: per tree and rule, the hits and the hits a Read would act on
(`acted`, after the test-code rule). `compare` prints each rule whose acted count changed and exits 1 when the total
of acted hits rose, so a change that adds false alarms shows up as a failure. It is a measurement, not a CI gate:
the fetch needs the network. The clones are only read, never run.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_false_alarms as mfa  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# (commit, name, repository, the subdirectory to measure or ""). The commit comes first, before any word that the
# detector reads as a label. A new commit here is a new baseline: measure both commits on the same detector first.
TREES = (
    ("ebf955df7a89ed0c7968f79faec1de49f61ed7cb", "cpython-Lib", "https://github.com/python/cpython.git", "Lib"),
    ("5e141933554a0b74e7341841f318be21e895339c", "detect-secrets", "https://github.com/Yelp/detect-secrets.git", ""),
    ("e8c6fe2467818e2054c179ce000dc223300c4778", "ferret-scan", "https://github.com/awslabs/ferret-scan.git", ""),
    ("01dbd7710de79e21bef851aaa8b6cbfb4b1188ad", "Preserve", "https://github.com/thirtysix/Preserve.git", ""),
)


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


def fetch(cache: Path) -> None:
    """A shallow clone of each tree at its commit, with only its subdirectory checked out. A clone that is already at
    the commit is kept."""
    cache.mkdir(parents=True, exist_ok=True)
    for commit, name, url, sub in TREES:
        d = cache / name
        if (d / ".git").is_dir() and git(d, "rev-parse", "HEAD") == commit:
            print(f"{name}: at {commit[:8]}")
            continue
        d.mkdir(exist_ok=True)
        git(d, "init", "-q")
        if not git(d, "remote"):
            git(d, "remote", "add", "origin", url)
        if sub:
            git(d, "sparse-checkout", "set", sub)
        git(d, "fetch", "-q", "--depth", "1", "origin", commit)
        git(d, "checkout", "-q", "--detach", "FETCH_HEAD")
        if git(d, "rev-parse", "HEAD") != commit:
            raise SystemExit(f"{name}: HEAD is not {commit}")
        print(f"{name}: fetched {commit[:8]}")


def measure(cache: Path, detect) -> dict:
    """Per tree: its commit, the files and characters read, and per rule key `where|type|rule` the [hits, acted]."""
    out = {"maisecrets": git(ROOT, "rev-parse", "HEAD"), "trees": {}}
    for commit, name, _url, sub in TREES:
        d = cache / name
        if not (d / ".git").is_dir() or git(d, "rev-parse", "HEAD") != commit:
            raise SystemExit(f"{name}: not at {commit[:8]} in {cache}; run fetch first")
        r = mfa.measure(d / sub if sub else d, detect)
        out["trees"][name] = {
            "commit": commit, "files": r["files"], "chars": r["size"],
            "rules": {"|".join(k): [r["raw"][k], r["acted"][k]] for k in sorted(r["raw"])},
        }
    return out


def totals(tree: dict) -> tuple[int, int, int]:
    """hits, acted, and acted outside test code."""
    rules = tree["rules"]
    return (sum(h for h, _ in rules.values()), sum(a for _, a in rules.values()),
            sum(a for k, (_, a) in rules.items() if k.startswith("other|")))


def report(result: dict) -> None:
    print(f"maisecrets {result['maisecrets'][:8]}")
    print(f"{'tree':16} {'commit':8} {'files':>6} {'MB':>6} {'hits':>6} {'acted':>6} {'acted, not tests':>17}")
    for name, t in result["trees"].items():
        hits, acted, other = totals(t)
        print(f"{name:16} {t['commit'][:8]} {t['files']:6} {t['chars'] / 1e6:6.1f} {hits:6} {acted:6} {other:17}")


def compare(before: dict, after: dict) -> int:
    """Each rule whose acted count changed, per tree; 1 when the total of acted hits rose."""
    rose = 0
    for name in sorted(set(before["trees"]) | set(after["trees"])):
        b, a = before["trees"].get(name), after["trees"].get(name)
        if b is None or a is None or b["commit"] != a["commit"]:
            print(f"{name}: not comparable (tree or commit differs)")
            continue
        for key in sorted(set(b["rules"]) | set(a["rules"])):
            x, y = b["rules"].get(key, [0, 0])[1], a["rules"].get(key, [0, 0])[1]
            if x != y:
                print(f"{name:16} {key:60} {x:6} -> {y:6}")
        rose += totals(a)[1] - totals(b)[1]
    print(f"acted hits, all trees: {'+' if rose >= 0 else ''}{rose}")
    return 1 if rose > 0 else 0


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("fetch", "measure", "compare"):
        print(__doc__.strip())
        return 2
    if argv[0] == "fetch":
        fetch(Path(argv[1]))
        return 0
    if argv[0] == "compare":
        return compare(json.loads(Path(argv[1]).read_text()), json.loads(Path(argv[2]).read_text()))
    result = measure(Path(argv[1]), mfa.load_detect())
    report(result)
    if "--json" in argv:
        Path(argv[argv.index("--json") + 1]).write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
