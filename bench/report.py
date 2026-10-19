#!/usr/bin/env python3
"""Write the Markdown tables of Benchmark V1 from result files of bench/run.py.

    python3 bench/report.py RESULT.json [RESULT.json ...] > report.md

One table per source and split and per family: a scanner gets a row in a family table only when its scope claims
that family, so a PII scanner is not listed under secrets and a secret scanner not under personal data. A rate is "-"
where a group has fewer than 30 spans (bench/score.py, MIN_RATE)."""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path


def _f(x, digits=3):
    return "-" if x is None else f"{x:.{digits}f}" if isinstance(x, float) else str(x)


def claims(scope, family: str) -> bool:
    return any(s == family + "." or s.startswith(family + ".") or s == family for s in scope)


def main(argv) -> int:
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in argv]
    groups = collections.defaultdict(list)
    for r in runs:
        groups[(r["source"], r["split"])].append(r)
    out = []
    for (source, split), rs in sorted(groups.items()):
        n = rs[0]["cases"]
        out.append(f"## {source}, split {split} ({n} cases)\n")
        for fam in ("secret", "pii"):
            rows = [r for r in rs if claims(r["scanner"].get("scope", []), fam) and r["metrics"].get(fam)]
            if not rows:
                continue
            out.append(f"### {fam}\n")
            out.append("| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | "
                       "Char recall | FP | Precision (all findings) | F1 | Too wide | FP / 1000 negative | "
                       "Median ms |")
            out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
            for r in sorted(rows, key=lambda r: r["scanner"]["scanner"]):
                m, a, s = r["metrics"][fam], r["metrics"]["all"], r["scanner"]
                ver = s.get("version") or ""
                if s.get("commit"):
                    ver += f" ({s['commit'][:8]})"
                out.append(f"| {s['scanner']} | {ver} | {m.get('spans', 0)} | {m.get('full', 0)} | "
                           f"{m.get('partial', 0)} | {m.get('missed', 0)} | {_f(m.get('recall_strict'))} | "
                           f"{_f(m.get('recall_lenient'))} | {_f(m.get('char_recall'))} | {m.get('fp', 0)} | "
                           f"{_f(a.get('precision'))} | {_f(a.get('f1'))} | {a.get('too_wide', 0)} | "
                           f"{_f(a.get('fp_per_1000_negative'), 1)} | {_f(r['timing'].get('median_ms'), 2)} |")
            out.append("")
            classes = sorted({k for r in rows for k in r["metrics"] if k.startswith(fam + ".")})
            if classes:
                out.append("| Class | " + " | ".join(r["scanner"]["scanner"] for r in rows) + " |")
                out.append("|---|" + "---|" * len(rows))
                for c in classes:
                    cells = []
                    for r in rows:
                        m = r["metrics"].get(c, {})
                        cells.append(f"{m.get('full', 0)} / {m.get('partial', 0)} / {m.get('missed', 0)}"
                                     if m else "-")
                    out.append(f"| {c} | " + " | ".join(cells) + " |")
                out.append("\nCells: full / partial / missed spans.\n")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
