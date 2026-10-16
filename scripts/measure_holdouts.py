"""Measure maisecrets on Cloakroom's holdout sets v2 to v7: the planted values it leaks, per set and half, the false
alarms on the clean samples, and the leaked values per class. docs/BENCHMARKS.md, "Cloakroom holdout sets", holds the
results.

    python3 scripts/measure_holdouts.py fetch [--data DIR]
    python3 scripts/measure_holdouts.py run --maisecrets DIR [--baseline DIR] [--data DIR | --bench DIR]
        [--regions "us,uk,in;de"] [--locale de_DE] [--out result.json]

fetch downloads `bench/holdout_v2.jsonl` to `bench/holdout_v7.jsonl` of Cloakroom (Apache-2.0) at the pinned commit
into the data directory (default ~/.cache/maisecrets-datasets/cloakroom, never inside the repository) and checks the
sha256 of each file. --bench reads the same files from a Cloakroom checkout instead; the sha256 check is the same.

run scans each sample with detect.scan(text, channel="tool") of the checkout under --maisecrets (and of --baseline),
once per regions setting, each in a new process with a fresh temp home and no variable of a client or of maisecrets;
it refuses to run when a machine policy is installed or the scan reports other regions. A planted value counts as
leaked when it still appears in the text after every match is replaced by a placeholder such as `[EMAIL_3]`, as in
the scratch script of the first numbers (a value of one to three characters can also appear inside a placeholder).
A clean sample (no planted value) counts as a false alarm when a match changes its text. Each sample falls into half
D or half C by the first 8 hex digits of sha256 of "<set>/<id>" (even: D); the rules of 0.6.21 were written from the
values of half D.

The class of a planted value comes from its shape alone (`value_class`, written for this measurement); the classes
are the rows of the class table in docs/BENCHMARKS.md.

The script prints counts only, never a value or a text, and --out writes counts and per-value flags (set, sample id,
index, half, class, leaked), never a value. The downloaded data is read as data; nothing in it is run.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = Path.home() / ".cache" / "maisecrets-datasets" / "cloakroom"
USER_AGENT = "maisecrets-measure (+https://github.com/Mcpgate-de/maisecrets)"
_HOME_VAR = "MAISECRETS" + "_HOME"

# ------------------------------------------------------------------------------------------------- pinned source
SOURCE = {
    "title": "Cloakroom benchmark holdout sets",
    "licence": "Apache-2.0",
    "url": "https://github.com/shanjeevrajendran/cloakroom",
    "commit": "cc3c88d76aa5e4e5b6b3c223270b2f2a96fa39a9",
    "raw": "https://raw.githubusercontent.com/shanjeevrajendran/cloakroom/{commit}/bench/{name}",
    "files": {
        "holdout_v2.jsonl": "c8ca4af9f44927e9fe4949c1c50a38297823b14362df29fcca40f708c32ae48c",
        "holdout_v3.jsonl": "c7e660de1a4d5d4fdf9d944fb229c6bc5176a89727071d372aa3182104be12d5",
        "holdout_v4.jsonl": "4ee291bff6664d5b9a874b8f6463ff0da7a48a2f714404c75d794b8130b6ec08",
        "holdout_v5.jsonl": "d8d16f36f8b91c99fadfcbf62dee9c8ceb879709c28238f791b25df90d229711",
        "holdout_v6.jsonl": "4a31e8b449efbe8d5ac1e8d95bce3e0c4a25cab6de1eedd062ac6f7293327d06",
        "holdout_v7.jsonl": "fa85b5864f8a32a76e6d281d8b6bbbc8b5929392df62e10633e9714c96907e6f",
    },
}
SETS = tuple(f"holdout_v{n}" for n in range(2, 8))


class DataError(Exception):
    """A missing or changed data file. The message names the file, never a value."""


# ------------------------------------------------------------------------------------------------------- split
def half(set_name: str, sample_id) -> str:
    """D or C: the first 8 hex digits of sha256("<set>/<id>"), even is D. The posted numbers use this split."""
    return "D" if int(hashlib.sha256(f"{set_name}/{sample_id}".encode()).hexdigest()[:8], 16) % 2 == 0 else "C"


# ------------------------------------------------------------------------------------------------------- class
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|januar|februar|märz|mai|juni|juli|okt|dez)[a-zä]*\.?"


def _luhn(digits: str) -> bool:
    total = 0
    for i, c in enumerate(reversed(digits)):
        n = int(c) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _card(s: str, digits: str) -> bool:
    """A card number: digits, spaces and dashes only, Luhn-valid, not a fictional 555-01xx number."""
    return (not re.search(r"555[\s.-]?01\d\d", s) and _luhn(digits) and re.fullmatch(r"[\d\s-]+", s) is not None)


def value_shape(v: str) -> str:
    """The shape of a planted value, from the value alone (a name is one capitalised word, or two to five, without a
    digit)."""
    s = v.strip()
    if re.fullmatch(r"[\w.+%-]+@[\w-]+(\.[\w-]+)+", s):
        return "email"
    if re.fullmatch(r"[\w.+%-]+(?:%40|\s?\[at\]\s?|\s?\(at\)\s?| at )[\w-]+(?:\.| dot | ?\[dot\] ?)[\w.-]+", s, re.I):
        return "email-obfuscated"
    if (re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d+|:\d+)?", s)
            or re.fullmatch(r"[0-9a-fA-F:]{6,}::?[0-9a-fA-F:]*", s) and s.count(":") >= 2):
        return "ip"
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", s):
        return "mac"
    if re.search(r"SHA256:|MD5:", s) or re.fullmatch(r"(?:[0-9a-f]{2}:){15}[0-9a-f]{2}", s):
        return "key-fingerprint"
    if re.match(r"(?:[A-Za-z]:\\|/|~/|\\\\)", s):
        return "path"
    if re.fullmatch(r"\+?[\d\s().-]{7,20}", s) and len(re.sub(r"\D", "", s)) >= 7 and re.search(r"[\s().+-]", s):
        dd = re.sub(r"\D", "", s)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s) or re.fullmatch(r"\d{1,2}[./-]\d{1,2}[./-]\d{2,4}", s):
            return "date"
        if re.fullmatch(r"\d{3}-\d{2}-\d{4}", s):
            return "national-id"
        if 13 <= len(dd) <= 19 and _card(s, dd):
            return "card"
        return "phone"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}", s) or (
            re.search(_MONTH, s, re.I) and re.search(r"\d", s) and len(s) < 25):
        return "date"
    if (re.fullmatch(r"\d{1,6}[A-Za-z]?\s+[\w .'-]+|[\w .'-]+(?:straße|strasse|str\.|weg|gasse|platz|allee)\s*\d+\w?"
                     r"(?:,.*)?", s, re.I) and re.search(r"[A-Za-z]{3}", s)):
        return "address"
    if re.search(r",\s*\d{4,5}\b|\b\d{5}\s+[A-ZÄÖÜ][a-zäöü]+", s) and re.search(r"[A-Za-z]{3}", s) and " " in s:
        return "address"
    if re.fullmatch(r"(?:[A-ZÄÖÜÉÁ][\w'’.-]+|(?:van|von|de|da|del|der|al|bin|ibn|la|le|di|du|mc)\b)"
                    r"(?:[ -](?:[A-ZÄÖÜÉÁ][\w'’.-]+|(?:van|von|de|da|del|der|al|bin|ibn|la|le|di|du)\b)){1,4}", s) \
            and not re.search(r"\d", s):
        return "name"
    if re.fullmatch(r"[A-ZÄÖÜ][\w'’-]+", s) and not re.search(r"\d", s):
        return "name-single"
    if re.search(r"-----BEGIN", s):
        return "private-key"
    if re.search(r"://[^:@\s]+:[^@\s]+@", s):
        return "url-credential"
    if re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9 ]{10,30}", s):
        return "iban"
    if re.fullmatch(r"[\d\s-]{6,}", s):
        return "number-id"
    if re.fullmatch(r"[A-Z0-9]{1,4}[-\s]?\d[\dA-Z\s-]{4,}", s) and re.search(r"\d{3}", s):
        return "alnum-id"
    if re.fullmatch(r"[a-z][a-z0-9._-]{1,31}", s):
        return "username"
    if len(s) >= 16 and re.fullmatch(r"[\w./+=:-]+", s):
        return "token-like"
    if len(s) >= 6 and " " not in s:
        return "password-like"
    return "other"


CLASS_OF_SHAPE = {
    "name": "names", "name-single": "names", "username": "user names", "path": "user names",
    "address": "addresses", "date": "birth dates", "number-id": "ID numbers", "alnum-id": "ID numbers",
    "national-id": "ID numbers", "card": "ID numbers", "iban": "ID numbers", "phone": "phone numbers",
    "token-like": "tokens and passwords", "password-like": "tokens and passwords",
    "url-credential": "tokens and passwords", "private-key": "tokens and passwords",
    "key-fingerprint": "tokens and passwords", "email": "e-mail addresses", "email-obfuscated": "e-mail addresses",
    "ip": "other", "mac": "other", "other": "other",
}
CLASSES = ("names", "user names", "addresses", "birth dates", "ID numbers", "phone numbers", "tokens and passwords",
           "e-mail addresses", "other")


def value_class(v: str) -> str:
    return CLASS_OF_SHAPE[value_shape(v)]


# ------------------------------------------------------------------------------------------------------- data
def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_data_dir(data: Path) -> Path:
    data = data.expanduser().resolve()
    if data == ROOT or ROOT in data.parents:
        raise DataError(f"{data} is inside the repository; the data stays outside it")
    return data


def fetch(data: Path) -> None:
    data.mkdir(parents=True, exist_ok=True)
    for name, want in SOURCE["files"].items():
        dest = data / name
        if dest.is_file() and sha256_of(dest) == want:
            continue
        req = urllib.request.Request(SOURCE["raw"].format(commit=SOURCE["commit"], name=name),
                                     headers={"User-Agent": USER_AGENT})
        tmp = dest.with_name(dest.name + ".part")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as fh:
                shutil.copyfileobj(resp, fh, 1 << 20)
            tmp.replace(dest)
        finally:
            if tmp.exists():
                tmp.unlink()
    verify(data)


def verify(bench: Path) -> None:
    for name, want in SOURCE["files"].items():
        path = bench / name
        if not path.is_file():
            raise DataError(f"{path} is missing: run `fetch` first, or name a Cloakroom checkout's bench with --bench")
        if sha256_of(path) != want:
            raise DataError(f"{name} does not match its pinned sha256 (Cloakroom commit {SOURCE['commit'][:10]})")


def load(bench: Path) -> list:
    """The samples: (set, id, text, planted values), in file order."""
    out = []
    for s in SETS:
        with open(bench / f"{s}.jsonl", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    it = json.loads(line)
                    out.append((s, it["id"], it["text"], list(it["planted"])))
    return out


# ------------------------------------------------------------------------------------------------------- scan
def _scan_child(ms_dir: str, bench: str) -> int:
    """In a new process: scan every sample with the checkout under ms_dir, print flags as JSON (no value)."""
    sys.path.insert(0, ms_dir)
    import inspect
    from maisecrets import detect
    has_channel = "channel" in inspect.signature(detect.scan).parameters
    regions = list(detect.active_regions().regions) if hasattr(detect, "active_regions") else None
    try:
        from maisecrets import vault
        import platform
        policy = vault.POLICY_PATHS.get(platform.system())
        policy = bool(policy is not None and policy.exists())
    except (ImportError, AttributeError):
        policy = False
    values, negatives = [], []
    for s, sid, text, planted in load(Path(bench)):
        found = detect.scan(text, channel="tool") if has_channel else detect.scan(text)
        masked = text
        for i, m in enumerate(sorted(found, key=lambda m: -m.start)):
            masked = masked[:m.start] + f"[{m.type}_{i}]" + masked[m.end:]
        if not planted:
            negatives.append([s, sid, masked != text])
            continue
        for idx, v in enumerate(planted):
            values.append([s, sid, idx, v in masked])
    json.dump({"values": values, "negatives": negatives, "regions": regions, "policy": policy,
               "channel": "tool" if has_channel else "none (scan() of this release has no channel)"}, sys.stdout)
    return 0


def scan_tree(ms_dir: str, bench: Path, regions: list, locale: str) -> dict:
    ms_dir, bench = os.path.abspath(ms_dir), Path(bench).resolve()
    home = tempfile.mkdtemp(prefix="maisecrets-holdouts-")
    try:
        with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": regions}, fh)
        # no variable of a client or of maisecrets reaches the scan: only the temp home and the locale
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS", "CLAUDE", "CODEX"))}
        env[_HOME_VAR] = home
        env["MAISECRETS_LOCALE"] = locale
        r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "_scan", ms_dir, str(bench)],
                           env=env, capture_output=True, text=True, cwd=home)
        if r.returncode != 0:
            # the child's traceback could quote a sample: name the failure only
            raise DataError(f"the scan with {ms_dir} failed (exit {r.returncode})")
        res = json.loads(r.stdout)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if res.get("policy"):
        raise DataError("a machine policy of maisecrets is installed on this computer; it changes the rules, so the "
                        "counts would not be comparable. Measure on a computer without it")
    ran = [r for r in res.get("regions") or () if r != "generic"]   # the generic rules run in every setting
    if res.get("regions") is not None and sorted(ran) != sorted(regions):
        raise DataError(f"the scan ran with the regions {','.join(ran)}, not {','.join(regions)}")
    return res


# ------------------------------------------------------------------------------------------------------- report
def tables(samples: list, runs: dict) -> dict:
    """Counts per set and half, and per class, for each run ('baseline', 'maisecrets')."""
    cls = {}
    for s, sid, _t, planted in samples:
        for idx, v in enumerate(planted):
            cls[(s, sid, idx)] = value_class(v)
    out = {"sets": {}, "classes": {}}
    for name, res in runs.items():
        per = collections.Counter()
        by_class = collections.Counter()
        for s, sid, idx, leaked in res["values"]:
            h = half(s, sid)
            per[(s, "values", h)] += 1
            per[(s, "leaked", h)] += int(leaked)
            if leaked:
                by_class[(cls[(s, sid, idx)], h)] += 1
        for s, _sid, hit in res["negatives"]:
            per[(s, "clean", "")] += 1
            per[(s, "false_alarms", "")] += int(hit)
        out["sets"][name] = {f"{s}|{k}|{h}": n for (s, k, h), n in per.items()}
        out["classes"][name] = {f"{c}|{h}": n for (c, h), n in by_class.items()}
    total = collections.Counter(cls.values())
    out["class_values"] = {c: total[c] for c in CLASSES}
    return out


def _group(t: dict, run: str, sets: tuple, key: str, h: str) -> int:
    return sum(t["sets"][run].get(f"{s}|{key}|{h}", 0) for s in sets)


def report(regions: str, t: dict, runs: tuple, names: dict, channels: dict | None = None) -> None:
    arrow = " → ".join(names[r] for r in runs)
    chans = set((channels or {}).values()) or {"tool"}
    channel = "tool channel" if chans == {"tool"} else "channel " + "; ".join(
        f"{names[r]}: {channels[r]}" for r in runs)
    print(f"\nRegions {regions}, {channel}. Leaked and false alarms: {arrow}.\n")
    print(f"| Set | Values, D | Leaked D, {arrow} | Values, C | Leaked C, {arrow} | Clean samples | "
          f"False alarms, {arrow} |")
    print("|---|---|---|---|---|---|---|")
    rows = [(s.replace("holdout_", ""), (s,)) for s in SETS] + [("v2 to v6", SETS[:-1]), ("v2 to v7", SETS)]
    first = runs[0]
    for label, sets in rows:
        def col(key, h):
            return " → ".join(str(_group(t, r, sets, key, h)) for r in runs)
        print(f"| {label} | {_group(t, first, sets, 'values', 'D')} | {col('leaked', 'D')} | "
              f"{_group(t, first, sets, 'values', 'C')} | {col('leaked', 'C')} | "
              f"{_group(t, first, sets, 'clean', '')} | {col('false_alarms', '')} |")
    print(f"\nBy class, values leaked in half D / half C, regions {regions}:\n")
    print("| Class | Values | " + " | ".join(names[r] for r in runs) + " |")
    print("|---|---|" + "---|" * len(runs))
    for c in CLASSES:
        cells = " | ".join(f"{t['classes'][r].get(c + '|D', 0)} / {t['classes'][r].get(c + '|C', 0)}" for r in runs)
        print(f"| {c} | {t['class_values'][c]} | {cells} |")


def _label(ms_dir: str) -> str:
    """The checkout's version (maisecrets/VERSION or the plugin manifest), else its directory name."""
    p = Path(ms_dir)
    for f in (p / "VERSION", p / "maisecrets" / "VERSION"):
        if f.is_file():
            return f.read_text(encoding="utf-8").strip()
    man = p / ".claude-plugin" / "plugin.json"
    if man.is_file():
        try:
            return json.loads(man.read_text(encoding="utf-8")).get("version") or p.name
        except ValueError:
            pass
    return p.name


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")    # the arrows of the tables, also into a file on Windows
    if argv[:1] == ["_scan"]:
        return _scan_child(argv[1], argv[2])
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--data", type=Path, default=DEFAULT_DATA, help="the data directory, outside the repository")
    r = sub.add_parser("run")
    r.add_argument("--maisecrets", default=str(ROOT), help="maisecrets checkout to measure (default: this one)")
    r.add_argument("--baseline", help="a second checkout, shown before the first (for example the release before)")
    r.add_argument("--data", type=Path, default=DEFAULT_DATA, help="the data directory of `fetch`")
    r.add_argument("--bench", type=Path, help="the bench directory of a Cloakroom checkout, instead of --data")
    r.add_argument("--regions", default="us,uk,in;de", help="regions settings, separated by ';' (default: two runs)")
    r.add_argument("--locale", default="de_DE", help="the system locale (default de_DE)")
    r.add_argument("--out", help="write counts and per-value flags (no values) to this JSON file")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "fetch":
            data = check_data_dir(a.data)
            fetch(data)
            print(f"cloakroom {SOURCE['commit'][:10]}: {len(SOURCE['files'])} files fetched and verified",
                  file=sys.stderr)
            return 0
        bench = a.bench.expanduser().resolve() if a.bench else check_data_dir(a.data)
        verify(bench)
        samples = load(bench)
        trees = {"maisecrets": os.path.abspath(a.maisecrets)}
        if a.baseline:
            trees = {"baseline": os.path.abspath(a.baseline), **trees}
        names = {k: _label(v) for k, v in trees.items()}
        if len(set(names.values())) < len(names):
            names = {k: f"{v} ({k})" for k, v in names.items()}
        classes = {(s, sid, idx): value_class(v) for s, sid, _t, p in samples for idx, v in enumerate(p)}
        n_values = sum(len(p) for *_x, p in samples)
        n_clean = sum(1 for *_x, p in samples if not p)
        print(f"Cloakroom {SOURCE['commit'][:10]}, holdout v2 to v7: {n_values} planted values in "
              f"{len(samples) - n_clean} samples, {n_clean} clean samples; locale {a.locale}")
        result = {"settings": {"commit": SOURCE["commit"], "locale": a.locale, "python": sys.version.split()[0],
                               "trees": names}, "regions": {}}
        for regs in [x for x in a.regions.split(";") if x.strip()]:
            regions = [x.strip() for x in regs.split(",") if x.strip()]
            runs = {k: scan_tree(v, bench, regions, a.locale) for k, v in trees.items()}
            t = tables(samples, runs)
            label = " ".join(regions)
            report(label, t, tuple(trees), names, {k: v.get("channel", "tool") for k, v in runs.items()})
            result["regions"][label] = {
                "counts": t,
                "values": {k: [[s, sid, idx, half(s, sid), classes[(s, sid, idx)], leaked]
                               for s, sid, idx, leaked in v["values"]] for k, v in runs.items()},
            }
    except DataError as exc:
        print(f"measure_holdouts: {exc}", file=sys.stderr)
        return 2
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
