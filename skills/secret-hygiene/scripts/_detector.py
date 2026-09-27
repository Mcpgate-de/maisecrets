"""Find the maisecrets detector for the skill scripts.

Two layouts: inside the maisecrets plugin the package sits three levels up (plugin root);
in the standalone skill zip a copy sits next to this file. The copy wins when both exist.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load():
    if sys.version_info < (3, 11):
        raise SystemExit("secret-hygiene needs Python 3.11 or newer (tomllib).")
    for base in (HERE, *HERE.parents[:3]):
        if (base / "maisecrets" / "detect.py").is_file():
            if str(base) not in sys.path:
                sys.path.insert(0, str(base))
            from maisecrets import detect  # noqa: E402
            return detect
    raise SystemExit("secret-hygiene: the maisecrets detector was not found next to the skill or in the plugin.")


def line_starts(text: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def line_of(starts: list[int], offset: int) -> int:
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1
