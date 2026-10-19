"""The false-alarm bank: four public trees on fixed commits, measured with scripts/measure_false_alarms.py. A fixed
instrument for a detector change: run it before and after, and compare.

    python3 scripts/measure_fp_bank.py fetch <cache>                  clone each tree at its commit (once)
    python3 scripts/measure_fp_bank.py measure <cache> [--json <out>]  count the hits per tree and rule
    python3 scripts/measure_fp_bank.py compare <before.json> <after.json>

The trees hold no real secrets that we know of; what the detector finds there is a false alarm or a test value of
the project. The output holds no value and no line: per tree and rule, the hits and the hits a Read would act on
(`acted`, after the test-code rule). `compare` prints each rule whose acted count changed. It exits 2 when a tree is
missing on one side or at another commit, 1 when the total of acted hits rose, else 0, so a change that adds false
alarms shows up as a failure. It is a measurement, not a CI gate: the fetch needs the network. The clones are only
read: fetch makes each one new, and measure counts only a clean clone at its commit.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
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
    # core.fsmonitor names a command in the repository config; a clone of ours never sets it, and we never run one
    return subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def at_commit(d: Path, commit: str, sub: str) -> bool:
    """A clean clone at the commit: HEAD is the commit, the subdirectory exists, and no file is changed, deleted or
    added. A tree that is only partly there would give lower counts that look like an improvement."""
    if not (d / ".git").is_dir() or not (d / sub if sub else d).is_dir():
        return False
    return git(d, "rev-parse", "HEAD") == commit and git(d, "status", "--porcelain", "--untracked-files=all") == ""


def fetch(cache: Path) -> None:
    """A shallow clone of each tree at its commit, with only its subdirectory checked out. Each clone is made in a new
    directory and moved into place when it is complete, so no git command runs in a repository that this script did
    not make. A clean clone at the commit is kept; any other directory with the name stops the fetch and stays as it
    is."""
    cache.mkdir(parents=True, exist_ok=True)
    for commit, name, url, sub in TREES:
        d = cache / name
        if d.exists():
            if at_commit(d, commit, sub):
                print(f"{name}: at {commit[:8]}")
                continue
            raise SystemExit(f"{name}: {d} is not a clean clone at {commit[:8]}; remove it and fetch again")
        new = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=cache))
        try:
            git(new, "init", "-q")
            git(new, "remote", "add", "origin", url)
            if sub:
                git(new, "sparse-checkout", "set", sub)
            git(new, "fetch", "-q", "--depth", "1", "origin", commit)
            git(new, "checkout", "-q", "--detach", "FETCH_HEAD")
            if not at_commit(new, commit, sub):
                raise SystemExit(f"{name}: the new clone is not a clean tree at {commit[:8]}")
            new.rename(d)
        finally:
            shutil.rmtree(new, ignore_errors=True)
        print(f"{name}: fetched {commit[:8]}")


def measure(cache: Path, detect) -> dict:
    """Per tree: its commit, the files and characters read, and per rule key `where|type|rule` the [hits, acted]."""
    out = {"maisecrets": git(ROOT, "rev-parse", "HEAD"), "trees": {}}
    for commit, name, _url, sub in TREES:
        d = cache / name
        if not at_commit(d, commit, sub):
            raise SystemExit(f"{name}: no clean clone at {commit[:8]} in {cache}; run fetch first")
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
    """Each rule whose acted count changed, per tree. 2 when a tree is missing on one side or at another commit (the
    two runs do not measure the same input), else 1 when the total of acted hits rose, else 0."""
    rose = 0
    apart = []
    for name in sorted(set(before["trees"]) | set(after["trees"])):
        b, a = before["trees"].get(name), after["trees"].get(name)
        if b is None or a is None or b["commit"] != a["commit"]:
            apart.append(name)
            print(f"{name}: not comparable (missing on one side, or at another commit)")
            continue
        for key in sorted(set(b["rules"]) | set(a["rules"])):
            x, y = b["rules"].get(key, [0, 0])[1], a["rules"].get(key, [0, 0])[1]
            if x != y:
                print(f"{name:16} {key:60} {x:6} -> {y:6}")
        rose += totals(a)[1] - totals(b)[1]
    print(f"acted hits, compared trees: {'+' if rose >= 0 else ''}{rose}")
    if apart:
        return 2
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
