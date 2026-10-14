"""Measure maisecrets on Samsung CredData, line by line. docs/BENCHMARKS.md has the method, the pinned data and the
results of each release.

    python3 scripts/measure_creddata.py <CredData checkout> [--maisecrets DIR] [--baseline DIR]
        [--exclude-repo 2ba83c6a] [--regions de|us] [--locale de_DE] [--channel prompt|tool] [--split none|half]
        [--workers N] [--out result.json]

Each labelled line of CredData's meta files is scanned alone, without its file path, the way a prompt or a tool
result reaches the hook. A row counts as caught when its labelled value no longer appears after every match is
masked. The method is the one of Cloakroom's bench/credata.py, so numbers compare across tools.

--maisecrets is the checkout to measure (default: this one). --baseline is a second checkout, for example the last
release; then the script also prints the rows each one catches that the other does not, by repository half.
A release before 0.6.17 has one channel; --channel tool measures it as the prompt channel.

The script prints counts and class names only, never a value or a line, and the JSON holds row ids (file path and
CredData id), labels and rule ids, never a value. The store is a fresh temp directory, never ~/.maisecrets.
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import hashlib
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_VECTORS = "2ba83c6a"   # 3,427 of CredData's 3,822 "Key" rows: cipher test vectors (Key = <hex>)

_detect = None
_channel = "prompt"


def load_items(cd: str) -> list:
    """The labelled single-line rows with a value of 4 or more characters, in a fixed order."""
    rows = []
    for f in sorted(glob.glob(os.path.join(cd, "meta", "*.csv"))):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if (r["GroundTruth"] not in ("T", "F") or r["LineStart"] != r["LineEnd"]
                        or r["ValueStart"] in ("", "-1")):
                    continue
                rows.append(r)
    cache: dict = {}
    items = []
    for r in rows:
        path = os.path.join(cd, r["FilePath"])
        if path not in cache:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    cache[path] = fh.read().splitlines()
            except OSError:
                cache[path] = None
        lines = cache[path]
        n = int(r["LineStart"]) - 1
        line = lines[n] if lines and 0 <= n < len(lines) else None
        if line is None:
            continue
        a = int(r["ValueStart"])
        b = int(r["ValueEnd"]) if r["ValueEnd"] not in ("", "-1") else len(line)
        value = line[a:b]
        if len(value) < 4:
            continue
        items.append((r["GroundTruth"], r["Category"], line, value, a, b, r["FilePath"], r["Id"]))
    return items


def _init(ms_dir: str, channel: str) -> None:
    global _detect, _channel
    sys.path.insert(0, ms_dir)
    from maisecrets import detect
    detect.rules()
    _detect = detect
    _channel = channel if "channel" in inspect.signature(detect.scan).parameters else ""


def _work(line: str):
    ms = _detect.scan(line, channel=_channel) if _channel else _detect.scan(line)
    ms = sorted(ms, key=lambda m: -m.start)
    out = line
    for i, m in enumerate(ms):
        out = out[:m.start] + f"[{m.type}_{i}]" + out[m.end:]
    return line, out, [(m.kind, m.start, m.end) for m in ms]


def scan_rows(ms_dir: str, channel: str, items: list, workers: int) -> list:
    uniq = sorted({it[2] for it in items})
    with Pool(workers, initializer=_init, initargs=(ms_dir, channel)) as pool:
        res = {line: (out, ms) for line, out, ms in pool.imap_unordered(_work, uniq, chunksize=50)}
    rows = []
    for gt, cat, line, value, a, b, fp, rid in items:
        out, ms = res[line]
        rows.append({"id": fp + "#" + rid, "gt": gt, "cat": cat, "hit": value not in out,
                     "rules": sorted({k for k, s, e in ms if s < b and a < e})})
    return rows


def repo_of(row_id: str) -> str:
    parts = row_id.split("#")[0].split("/")
    return parts[1] if len(parts) > 1 else parts[0]


def half_of(repo: str) -> str:
    """The fixed split by repository: D (where the rules of 0.6.16 and 0.6.17 were found) or V (where they were
    counted), by the first 8 hex digits of sha256(repository id)."""
    return "D" if int(hashlib.sha256(repo.encode()).hexdigest()[:8], 16) % 2 == 0 else "V"


def counts(rows) -> dict:
    c = collections.Counter({"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for r in rows:
        c[{("T", True): "tp", ("T", False): "fn", ("F", True): "fp", ("F", False): "tn"}[(r["gt"], r["hit"])]] += 1
    p = c["tp"] / max(1, c["tp"] + c["fp"])
    rc = c["tp"] / max(1, c["tp"] + c["fn"])
    return {**c, "P": round(p, 4), "R": round(rc, 4), "F1": round(2 * p * rc / max(1e-9, p + rc), 4)}


# ---------------------------------------------------------------- the classes of the rows still missed
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
LABEL_RE = re.compile(
    r"([A-Za-z_$@][A-Za-z0-9_.\-]{0,60})[\"'\]]?\s*(=>|:=|==|=|:|\(|,)?\s*[\"'`]?\s*"
    r"(?:(?:[Bb]earer|[Bb]asic|[Tt]oken|[Dd]igest)\s+)?$")
WRAP_RE = re.compile(r"(?:(?:Some|Ok|String::from|str|bytes|SecretString::new|Secret::new|SecretStr|SecretBytes"
                     r"|Optional\.of|Box::new|Sensitive|new\s+String)\s*\(\s*)+([\"'`]?)\s*$")
SQL_PW_RE = re.compile(r"(?i)\bidentified\s+(?:with\s+\w+\s+)?by\s*(?:password\s*)?['\"]?\s*$")
PS_SECURE_RE = re.compile(r"(?i)ConvertTo-SecureString\s+(?:-String\s+)?['\"]?\s*$")
CLASSES = ("identifier (UUID, bucket name, id)", "labelled value, not a word", "value without a label",
           "password of letters only")


def _has_label(before: str) -> bool:
    t = before[-160:]
    if SQL_PW_RE.search(t) or PS_SECURE_RE.search(t):
        return True
    m = LABEL_RE.search(WRAP_RE.sub(r"\1", t))
    return bool(m and re.sub(r"[.\-]+", "_", m.group(1).lstrip("$@-")).strip("_"))


def miss_class(cat: str, line: str, value: str, a: int) -> str:
    v = value.strip("'\"")
    if UUID.fullmatch(v) or "UUID" in cat or "Bucket" in cat or cat.endswith(" ID") or ":ID" in cat:
        return CLASSES[0]
    parts = [p for p in re.split(r"[_.-]+", v) if p]
    if "Password" in cat and parts and all(p.isalpha() for p in parts):
        return CLASSES[3]
    if not _has_label(line[:a]):
        return CLASSES[2]
    return CLASSES[1]


def misses(items: list, rows: list, keep) -> dict:
    t, f = collections.Counter(), collections.Counter()
    for it, r in zip(items, rows):
        if r["hit"] or not keep(r):
            continue
        gt, cat, line, value, a = it[:5]
        (t if gt == "T" else f)[miss_class(cat, line, value, a)] += 1
    return {k: {"missed_T": t[k], "same_class_F": f[k]} for k in CLASSES}


def delta(base: list, new: list, keep) -> dict:
    out = {h: collections.Counter({"gain_T": 0, "gain_F": 0, "lost_T": 0, "lost_F": 0}) for h in "DV"}
    for b, n in zip(base, new):
        if not keep(n):
            continue
        h = half_of(repo_of(n["id"]))
        if n["hit"] and not b["hit"]:
            out[h]["gain_" + n["gt"]] += 1
        elif b["hit"] and not n["hit"]:
            out[h]["lost_" + n["gt"]] += 1
    return {h: dict(c) for h, c in out.items()}


def line(name: str, c: dict) -> str:
    return (f"{name:28s} TP {c['tp']:5d}  FN {c['fn']:5d}  FP {c['fp']:5d}  TN {c['tn']:5d}  "
            f"P {c['P']:.3f}  R {c['R']:.3f}  F1 {c['F1']:.3f}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("creddata", help="CredData checkout with meta/ and the downloaded data/")
    ap.add_argument("--maisecrets", default=str(ROOT), help="maisecrets checkout to measure (default: this one)")
    ap.add_argument("--baseline", help="a second maisecrets checkout to compare with, such as the last release")
    ap.add_argument("--exclude-repo", default=TEST_VECTORS, help="repository id to leave out ('' keeps every row)")
    ap.add_argument("--regions", default="de", help="the regions setting, such as de or us (default de)")
    ap.add_argument("--locale", default="de_DE", help="the system setting maisecrets sees (default de_DE)")
    ap.add_argument("--channel", default="prompt", choices=("prompt", "tool"))
    ap.add_argument("--split", default="none", choices=("none", "half"))
    ap.add_argument("--workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)))
    ap.add_argument("--out", help="write counts and per-row results (no values) to this JSON file")
    a = ap.parse_args(argv)

    if not os.path.isdir(os.path.join(a.creddata, "meta")):
        ap.error(f"{a.creddata} has no meta/ directory: give the CredData checkout")
    home = tempfile.mkdtemp(prefix="maisecrets-creddata-")
    try:
        with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"backend": "jsonfile", "allow_plaintext_store": True,
                       "regions": [x for x in a.regions.split(",") if x]}, fh)
        os.environ["MAISECRETS_HOME"] = home
        os.environ["MAISECRETS_LOCALE"] = a.locale
        return measure(a, ap)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def measure(a, ap) -> int:
    items = load_items(a.creddata)
    if not items:
        ap.error("no labelled rows found: did download_data.py run? (data/ must exist)")
    rows = scan_rows(a.maisecrets, a.channel, items, a.workers)

    def keep(r):
        return not a.exclude_repo or repo_of(r["id"]) != a.exclude_repo

    kept = [r for r in rows if keep(r)]
    result = {"settings": {"channel": a.channel, "regions": a.regions, "locale": a.locale,
                           "exclude_repo": a.exclude_repo, "rows": len(kept)},
              "summary": counts(kept), "misses": misses(items, rows, keep)}
    scope = f"without {a.exclude_repo}" if a.exclude_repo else "all rows"
    print(f"CredData line method, {scope}, channel {a.channel}, regions {a.regions}, locale {a.locale}: "
          f"{len(kept)} rows")
    print(line("maisecrets", result["summary"]))
    if a.split == "half":
        result["halves"] = {h: counts([r for r in kept if half_of(repo_of(r["id"])) == h]) for h in "DV"}
        for h in "DV":
            print(line(f"  half {h}", result["halves"][h]))

    if a.baseline:
        base = scan_rows(a.baseline, a.channel, items, a.workers)
        result["baseline"] = counts([r for r in base if keep(r)])
        result["delta"] = delta(base, rows, keep)
        print(line("baseline", result["baseline"]))
        for h in "DV":
            d = result["delta"][h]
            print(f"  half {h}: caught only by maisecrets +{d['gain_T']} credentials / +{d['gain_F']} false alarms;"
                  f" caught only by the baseline {d['lost_T']} / {d['lost_F']}")

    total = sum(v["missed_T"] for v in result["misses"].values())
    print(f"credentials still missed: {total}")
    for k, v in result["misses"].items():
        prec = v["missed_T"] / max(1, v["missed_T"] + v["same_class_F"])
        print(f"  {k:36s} {v['missed_T']:5d} ({v['missed_T'] / max(1, total):5.1%})   same-class non-secrets "
              f"{v['same_class_F']:5d}   precision of a rule that took the class {prec:.2f}")

    if a.out:
        result["rows"] = rows
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
