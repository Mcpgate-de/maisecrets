#!/usr/bin/env python3
"""Write a copy of a file with every secret and every personal-data value replaced.

A value becomes ⟦TYPE_n⟧; the same value gets the same tag, so a log stays readable. The
original is never changed and never printed. The script prints only the output path and the
count per type, because its output goes to a cloud model.

    python3 redact_copy.py INPUT [--out OUTPUT] [--secrets-only] [--force]

Exit code: 0 written, 2 error.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _detector  # noqa: E402


def redact(detect, text: str, secrets_only: bool) -> tuple[str, Counter]:
    tags: dict[str, str] = {}
    per_type: Counter = Counter()
    out, last = [], 0
    for m in sorted(detect.scan(text), key=lambda m: m.start):
        keep = secrets_only and m.type != "SECRET"
        if keep:
            continue
        if m.value not in tags:
            per_type[m.type] += 1
            tags[m.value] = f"⟦{m.type}_{per_type[m.type]}⟧"
        out.append(text[last:m.start])
        out.append(tags[m.value])
        last = m.end
    out.append(text[last:])
    return "".join(out), per_type


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Write a redacted copy; never print the content.")
    ap.add_argument("input")
    ap.add_argument("--out")
    ap.add_argument("--secrets-only", action="store_true", help="keep personal data, replace only secrets")
    ap.add_argument("--force", action="store_true", help="overwrite an existing output file")
    args = ap.parse_args(argv)
    src = Path(args.input)
    if not src.is_file():
        print(f"secret-hygiene: {src} is not a file")
        return 2
    dst = Path(args.out) if args.out else src.with_name(f"{src.stem}.redacted{src.suffix}")
    if dst.resolve() == src.resolve():
        print("secret-hygiene: the output must be a new file; the original is never changed")
        return 2
    if dst.exists() and not args.force:
        print(f"secret-hygiene: {dst} exists; pass --force to overwrite it")
        return 2
    detect = _detector.load()
    text = src.read_bytes().decode("utf-8", errors="replace")
    clean, per_type = redact(detect, text, args.secrets_only)
    dst.write_text(clean, encoding="utf-8")
    counts = ", ".join(f"{n} {t}" for t, n in sorted(per_type.items())) or "nothing"
    print(f"Wrote {dst}. Replaced: {counts}. The original is unchanged; do not open it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
