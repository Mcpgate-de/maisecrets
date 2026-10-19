"""The scoring of Benchmark V1 (docs/BENCHMARK-V1.md, "When a span counts as found" and "Metrics").

A finding is (start, end, cls). Only a span whose core the findings cover whole counts as found ("full"); a span that
they cover in part is "partial" and counts as missed in the strict recall."""
from __future__ import annotations

import collections

from bench.cases import family, in_scope

MIN_RATE = 30   # a class with fewer spans reports counts and no rate


def _covered(intervals, lo: int, hi: int) -> int:
    """The number of characters of [lo, hi) inside the union of the intervals."""
    n, pos = 0, lo
    for s, e in sorted(intervals):
        s, e = max(s, pos), min(e, hi)
        if e > s:
            n += e - s
            pos = e
    return n


def _label_start(text: str, start: int) -> int:
    """Where the label of a span starts: the start of its line. Masking the label is no over-masking."""
    return text.rfind("\n", 0, start) + 1


def score_case(case: dict, findings, scope) -> dict:
    """The outcome of each span in scope, and the count of false positives and too wide findings of one case."""
    spans = [s for s in case["spans"] if in_scope(s["class"], scope) and not s.get("neutral")]
    removed = [s for s in case["spans"] if not in_scope(s["class"], scope) or s.get("neutral")]
    found = [(int(s), int(e), c) for s, e, c in findings if int(e) > int(s)]
    cover = [(s, e) for s, e, _ in found]
    outcomes = []
    for sp in spans:
        lo, hi = sp.get("core") or (sp["start"], sp["end"])
        got = _covered(cover, lo, hi)
        full = got == hi - lo or any(_covered(cover, a, b) == b - a for a, b in sp.get("alt", ()))
        right_family = full and any(s < sp["end"] and e > sp["start"] and family(c) == family(sp["class"])
                                    for s, e, c in found)
        outcomes.append({"class": sp["class"], "outcome": "full" if full else "partial" if got else "missed",
                         "chars": hi - lo, "covered": hi - lo if full else got, "family_right": right_family})
    allowed = [(_label_start(case["text"], s["start"]), s["end"]) for s in case["spans"]]
    fp, on_target, too_wide, fp_family = 0, 0, 0, collections.Counter()
    for s, e, c in found:
        hits = [sp for sp in spans if s < sp["end"] and e > sp["start"]]
        if hits:
            on_target += 1
            extra = (e - s) - _covered(allowed, s, e)
            if extra > max(8, max(sp["end"] - sp["start"] for sp in hits)):
                too_wide += 1
        elif not any(s < sp["end"] and e > sp["start"] for sp in removed):
            fp += 1
            fp_family[family(c)] += 1
    return {"spans": outcomes, "fp": fp, "fp_family": dict(fp_family), "on_target": on_target,
            "too_wide": too_wide, "negative": not removed and not spans, "bytes": len(case["text"].encode("utf-8")),
            "lines": case["text"].count("\n") + 1}


def _rate(num: float, den: float):
    return round(num / den, 4) if den else None


def aggregate(results, group=lambda case, span: span["class"]) -> dict:
    """Metrics per group of spans (default: per class), per family and in total. results: (case, score) pairs."""
    rows = collections.defaultdict(collections.Counter)
    total = collections.Counter()
    for case, sc in results:
        for sp in sc["spans"]:
            for key in (group(case, sp), family(sp["class"]), "all"):
                r = rows[key]
                r["spans"] += 1
                r[sp["outcome"]] += 1
                r["chars"] += sp["chars"]
                r["covered"] += sp["covered"]
                r["family_right"] += sp["family_right"]
        for fam, n in sc["fp_family"].items():
            rows[fam]["fp"] += n
        rows["all"]["fp"] += sc["fp"]
        total["on_target"] += sc["on_target"]
        total["fp"] += sc["fp"]
        total["too_wide"] += sc["too_wide"]
        total["cases"] += 1
        total["negative"] += sc["negative"]
        total["fp_negative"] += sc["fp"] if sc["negative"] else 0
        total["bytes"] += sc["bytes"]
        total["lines"] += sc["lines"]
    out = {}
    for key, r in sorted(rows.items()):
        m = dict(r)
        if r["spans"] >= MIN_RATE:
            m["recall_strict"] = _rate(r["full"], r["spans"])
            m["recall_lenient"] = _rate(r["full"] + r["partial"], r["spans"])
            m["char_recall"] = _rate(r["covered"], r["chars"])
        else:
            m["too_few"] = bool(r["spans"])
        out[key] = m
    a = out.setdefault("all", {})
    findings = total["on_target"] + total["fp"]
    p = _rate(total["on_target"], findings)
    r = a.get("recall_strict")
    a.update({"findings": findings, "fp": total["fp"], "precision": p, "too_wide": total["too_wide"],
              "f1": round(2 * p * r / (p + r), 4) if p and r else None,
              "cases": total["cases"], "negative_cases": total["negative"],
              "fp_per_1000_negative": _rate(total["fp_negative"] * 1000, total["negative"]),
              "fp_per_mb": _rate(total["fp"] * 2 ** 20, total["bytes"]),
              "fp_per_10000_lines": _rate(total["fp"] * 10000, total["lines"])})
    return out
