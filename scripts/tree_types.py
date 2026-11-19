#!/usr/bin/env python3
"""No symlink, no submodule and no binary in the tree (docs/REPO-STANDARDS.md, "Layout and hygiene"), from the git
index: CI job tree_types, in every pipeline but a schedule.

A tracked entry must be a regular file (mode 100644 or 100755). A binary file (a NUL byte in its first 8000 bytes, the
test git uses) is allowed only where the tree holds data, never code: a gzip result in bench/results and a PNG icon in
assets/ or skills/<skill>/assets/, each with the magic bytes of its type.

    python3 scripts/tree_types.py      # exit 1 and the refused entries
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODES = ("100644", "100755")
BINARY_OK = ((re.compile(r"bench/results/.+\.gz"), b"\x1f\x8b"),
             (re.compile(r"(?:skills/[^/]+/)?assets/[^/]+\.png"), b"\x89PNG\r\n\x1a\n"))


def problems(entries: list[tuple[str, str, bytes]]) -> list[str]:
    """`entries`: (mode, path, first bytes of the file; empty for a mode that is no file)."""
    out = []
    for mode, path, head in entries:
        if mode not in MODES:
            kind = {"120000": "a symlink", "160000": "a submodule"}.get(mode, f"mode {mode}")
            out.append(f"{path}: {kind}")
        elif b"\0" in head[:8000]:
            if not any(rx.fullmatch(path) and head.startswith(magic) for rx, magic in BINARY_OK):
                out.append(f"{path}: a binary file")
    return out


def tracked(root: Path = ROOT) -> list[tuple[str, str, bytes]]:
    out = []
    raw = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=root, capture_output=True, check=True).stdout
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, name = rec.partition(b"\t")
        mode, path = meta.split(b" ")[0].decode(), name.decode("utf-8", "replace")
        head = b""
        if mode in MODES:
            with open(root / path, "rb") as f:
                head = f.read(8000)
        out.append((mode, path, head))
    return out


def main() -> int:
    entries = tracked()
    bad = problems(entries)
    for line in bad:
        print(f"tree_types: {line}")
    if bad:
        print("No symlink, no submodule, no binary outside bench/results/*.gz and the PNG icons "
              "(docs/REPO-STANDARDS.md).")
        return 1
    print(f"tree_types: {len(entries)} tracked files, all regular, no other binary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
