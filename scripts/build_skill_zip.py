#!/usr/bin/env python3
"""Build the standalone skill zip for a skill upload (ChatGPT "Skills", claude.ai "Upload").

The upload wants one skill root at the top of the zip. Inside the plugin the skill scripts
import the detector from the plugin root; the standalone zip carries a copy of the detector
and its rules next to the scripts instead, with the rule licenses. Nothing else is copied:
no vault, no hooks, no config.

    python3 scripts/build_skill_zip.py [--out dist/secret-hygiene.zip]
"""
from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "secret-hygiene"
DETECTOR = ("maisecrets/__init__.py", "maisecrets/detect.py")


def members() -> list[tuple[Path, str]]:
    out = []
    for path in sorted(SKILL.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            out.append((path, f"secret-hygiene/{path.relative_to(SKILL).as_posix()}"))
    for rel in DETECTOR:
        out.append((ROOT / rel, f"secret-hygiene/scripts/{rel}"))
    for path in sorted((ROOT / "maisecrets" / "rules").iterdir()):
        if path.is_file():
            out.append((path, f"secret-hygiene/scripts/maisecrets/rules/{path.name}"))
    out.append((ROOT / "LICENSE", "secret-hygiene/LICENSE"))
    out.append((ROOT / "NOTICE", "secret-hygiene/NOTICE"))
    return out


def build(out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in members():
            z.write(src, arc)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "secret-hygiene.zip"))
    args = ap.parse_args(argv)
    out = build(Path(args.out))
    print(f"wrote {out} ({len(members())} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
