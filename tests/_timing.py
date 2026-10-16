"""Time checks that hold on a loaded machine.

A fixed bound on the time of a call (1.0 s of wall time, 3.0 s of CPU) failed in pipelines and on loaded machines
with no change to the code (2026-10-16). The claim of such a test is about how the time grows: a scan that grows with
the square of its text, or a wait per key. So a check here measures CPU time, not wall time (other processes slow the
clock, not the call), takes the fastest of a few calls of the small case (other processes only ever add to it), and
compares two sizes: 8 times the input is 8 times the time when the call is linear and 64 times when it is quadratic.
A generous absolute bound stays, and it only catches a hang.

The slack holds several steps of the CPU clock of Windows (about 15.6 ms each).
"""
from __future__ import annotations

import time

SLACK = 0.05


def cpu_best(fn, *args, runs: int = 3) -> float:
    """The least CPU time of `runs` calls of fn(*args)."""
    best = None
    for _ in range(runs):
        t = time.process_time()
        fn(*args)
        took = time.process_time() - t
        best = took if best is None else min(best, took)
    return best


def assert_linear(case, run, make, n: int, *, hang: float = 10.0, slack: float = SLACK) -> tuple:
    """run(make(n // 8)), the fastest of three, then run(make(n)), the faster of two: at most 16 times plus the slack
    (linear is 8 times, quadratic 64 times), and below `hang` seconds. The inputs are made before the clock starts, and
    one call of run(make(64)) before the first measurement compiles what a first call compiles. One call of the large
    input once took 17 times its usual time (a first allocation of that size): so two. Returns (small, big)."""
    run(make(64))
    small_input, big_input = make(n // 8), make(n)
    small = cpu_best(run, small_input)
    big = cpu_best(run, big_input, runs=2)
    case.assertLess(big, 16 * small + slack, f"{small * 1000:.1f} ms, then {big * 1000:.1f} ms for 8 times the input")
    case.assertLess(big, hang)
    return small, big
