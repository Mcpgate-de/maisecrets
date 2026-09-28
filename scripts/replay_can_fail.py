#!/usr/bin/env python3
"""Replay every belief's proof: mutate the guarded code, run the owning tests, demand RED.

`beliefs/*.toml` names, per documented control, the tests that own it and one mutation
(file, find, replace) that removes the control. A test that stays green under that mutation
proves nothing about the control (docs/TESTING.md said "every control has a test that goes
red without it"; before this script that sentence was prose). Borrowed from the ai-gateway's
beliefs layer, cut to what a repository this size needs: no provenance vocabulary, no shards.

    python3 scripts/replay_can_fail.py             # every belief
    python3 scripts/replay_can_fail.py --belief X  # one
    python3 scripts/replay_can_fail.py --list

Each belief: the owning tests run once unmutated and must pass (a red baseline is not
evidence about the mutation), then the file is mutated, the tests run again and must fail,
and the file is restored on every exit, signals included. Serial by design: it owns the
working tree for the length of one replay; never run it inside the test suite.
"""
from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import tomllib
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BELIEFS = ROOT / "beliefs"


def load() -> list[dict]:
    out = []
    for path in sorted(BELIEFS.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        data["_path"] = path
        out.append(data)
    return out


def unittest_id(test_id: str) -> str:
    """tests/test_gates.py::Class::method -> tests.test_gates.Class.method"""
    file, _, rest = test_id.partition("::")
    module = file[:-3].replace("/", ".") if file.endswith(".py") else file.replace("/", ".")
    return module + ("." + rest.replace("::", ".") if rest else "")


def run_tests(ids: list[str]) -> tuple[int, dict[str, str]]:
    """Run the owning tests once; return the exit code and each test's outcome.

    Each run gets a fresh bytecode cache. A mutation of the same length written in the same
    second as the green run's compile left a .pyc that Python took for current (size and mtime
    match), so the tests ran the unmutated code and stayed green (2026-09-27)."""
    import json
    import os
    import tempfile
    with tempfile.TemporaryDirectory(prefix="maisecrets-pyc-") as cache:
        report = os.path.join(cache, "outcomes.json")
        cmd = [sys.executable, str(ROOT / "scripts" / "_run_tests_json.py"), report] + [unittest_id(t) for t in ids]
        env = dict(os.environ, PYTHONPYCACHEPREFIX=cache)
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600, env=env)
        try:
            with open(report, encoding="utf-8") as fh:
                outcomes = json.load(fh)
        except (OSError, ValueError):
            # the runner itself died (the mutation broke an import); every test counts as red
            outcomes = {unittest_id(t): "fail" for t in ids}
    # a skipped owning test is no evidence either way: without git in the CI image the skill's
    # tests were skipped, the replay read the skip as green and failed C17 for the wrong reason,
    # and read it as "green before the mutation" too (2026-09-27)
    if "skip" in outcomes.values():
        return SKIPPED, outcomes
    return (1 if "fail" in outcomes.values() or r.returncode else 0), outcomes


SKIPPED = -1


@contextmanager
def restored_on_any_exit(target: Path, original: str):
    """Put the file back on every exit: a SIGTERM from a cancelled CI job would otherwise
    leave the mutation in the tree, indistinguishable from an edit."""
    previous = {}

    def restore_and_die(signum, _frame):
        target.write_text(original, encoding="utf-8")
        signal.signal(signum, previous.get(signum, signal.SIG_DFL))
        raise SystemExit(128 + signum)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            previous[sig] = signal.signal(sig, restore_and_die)
        except (ValueError, OSError):
            pass
    try:
        yield
    finally:
        target.write_text(original, encoding="utf-8")
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def proofs_of(belief: dict) -> list[dict]:
    """`[proof]` (a mechanism belief: one guard, one mutation) or `[[proof]]` (an invariant
    belief: one goal, a mutation per path to it)."""
    proof = belief["proof"]
    return proof if isinstance(proof, list) else [proof]


def is_invariant(belief: dict) -> bool:
    return belief.get("kind") == "invariant"


def _check_mutation(target: Path, mutated: str) -> str | None:
    # a mutation that breaks the syntax turns every test red for the wrong reason
    if target.suffix == ".py":
        try:
            compile(mutated, str(target), "exec")
        except SyntaxError as exc:
            return f"the mutation does not compile ({exc.msg}, line {exc.lineno}); a red proves nothing"
    if target.suffix == ".json":
        import json
        try:
            json.loads(mutated)
        except ValueError as exc:
            return f"the mutation is not valid JSON ({exc}); a red proves nothing"
    return None


def _replay_one(belief: dict, proof: dict) -> tuple[bool, str, set[str]]:
    """Apply one mutation, run the owning tests, restore. Returns (red, why, the red test ids)."""
    target = ROOT / proof["file"]
    original = target.read_text(encoding="utf-8")
    n = original.count(proof["find"])
    if n != 1:
        return False, f"anchor occurs {n} times in {proof['file']} (must be exactly once)", set()
    with restored_on_any_exit(target, original):
        mutated = original.replace(proof["find"], proof["replace"], 1)
        target.write_text(mutated, encoding="utf-8")
        bad = _check_mutation(target, mutated)
        if bad:
            return False, bad, set()
        rc, outcomes = run_tests(belief["runner"])
    if target.read_text(encoding="utf-8") != original:
        return False, "the file was not restored", set()
    if rc == SKIPPED:
        return False, "an owning test was skipped under the mutation; a skip is no evidence", set()
    red = {tid for tid, o in outcomes.items() if o == "fail"}
    if rc == 0:
        return False, "the owning tests stayed GREEN under the mutation: they do not carry this belief", red
    return True, "red", red


def replay(belief: dict) -> tuple[bool, str]:
    proofs = proofs_of(belief)
    for proof in proofs:
        target = ROOT / proof["file"]
        n = target.read_text(encoding="utf-8").count(proof["find"])
        if n != 1:
            return False, f"anchor occurs {n} times in {proof['file']} (must be exactly once)"
    first, _ = run_tests(belief["runner"])
    if first == SKIPPED:
        return False, "an owning test was skipped here (a missing tool?); a skip is no evidence"
    if first != 0:
        return False, "the owning tests are red before the mutation; no evidence"
    killed: set[str] = set()
    for i, proof in enumerate(proofs, 1):
        ok, why, red = _replay_one(belief, proof)
        killed |= red
        if not ok:
            label = proof.get("path", f"mutation {i}")
            return False, (f"{label} ({proof['file']}): {why}" if len(proofs) > 1 else why)
    if is_invariant(belief):
        # a test that no mutation turns red proves nothing about the goal; it is ballast that
        # reads like coverage
        idle = [t for t in belief["runner"]
                if not any(k == unittest_id(t) or k.startswith(unittest_id(t) + ".") for k in killed)]
        if idle:
            return False, "no mutation turns these owning tests red: " + ", ".join(idle)
        return True, f"red under each of {len(proofs)} mutations, every owning test killed, green restored"
    return True, "red under the mutation, green restored"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--belief")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)
    beliefs = load()
    if args.belief:
        beliefs = [b for b in beliefs if b["belief"] == args.belief]
        if not beliefs:
            print(f"no belief named {args.belief}")
            return 2
    if args.list:
        for b in beliefs:
            files = ", ".join(sorted({p["file"] for p in proofs_of(b)}))
            print(f"{b['belief']:<55} {b['control']:<12} {files}")
        return 0
    if not beliefs:
        print("no beliefs found; nothing was proven")
        return 1
    failures = 0
    for b in beliefs:
        ok, why = replay(b)
        failures += not ok
        print(f"[{'OK ' if ok else 'FAIL'}] {b['belief']}: {why}")
    print(f"{len(beliefs) - failures} of {len(beliefs)} beliefs proven; failures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
