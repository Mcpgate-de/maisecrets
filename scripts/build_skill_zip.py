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
DETECTOR = ("maisecrets/__init__.py", "maisecrets/detect.py", "maisecrets/regions.py")
OPENAI_NAME = "maisecrets-secret-hygiene"


def members() -> list[tuple[Path, str]]:
    out = []
    for path in sorted(SKILL.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            out.append((path, f"secret-hygiene/{path.relative_to(SKILL).as_posix()}"))
    for rel in DETECTOR:
        out.append((ROOT / rel, f"secret-hygiene/scripts/{rel}"))
    rules = ROOT / "maisecrets" / "rules"
    for path in sorted(rules.rglob("*")):
        if path.is_file():
            out.append((path, f"secret-hygiene/scripts/maisecrets/rules/{path.relative_to(rules).as_posix()}"))
    out.append((ROOT / "LICENSE", "secret-hygiene/LICENSE"))
    out.append((ROOT / "NOTICE", "secret-hygiene/NOTICE"))
    return out


def build(out: Path, flat: bool = False) -> Path:
    """flat=True puts SKILL.md at the zip root, the layout the ChatGPT skill upload reads as "one
    skill root"; it refused a single top folder with "must contain one skill root or one
    directory of skill roots" (2026-09-27). Directory entries are written too: some readers find
    folders only through them."""
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [(src, arc.split("/", 1)[1] if flat else arc) for src, arc in members()]
    dirs = sorted({"/".join(arc.split("/")[:i]) + "/" for _src, arc in rows for i in range(1, arc.count("/") + 1)})
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for d in dirs:
            z.writestr(zipfile.ZipInfo(d), "")
        for src, arc in rows:
            if flat and arc == "SKILL.md":
                # ChatGPT skills share one namespace and the skill stands alone there: it carries
                # the brand. In the plugin Claude Code shows it as maisecrets:secret-hygiene.
                text = src.read_text(encoding="utf-8")
                z.writestr(arc, text.replace("\nname: secret-hygiene\n", f"\nname: {OPENAI_NAME}\n", 1))
                continue
            z.write(src, arc)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "secret-hygiene.zip"))
    ap.add_argument("--flat", action="store_true", help="SKILL.md at the zip root (ChatGPT skill upload)")
    args = ap.parse_args(argv)
    out = build(Path(args.out), flat=args.flat)
    print(f"wrote {out} ({len(members())} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
