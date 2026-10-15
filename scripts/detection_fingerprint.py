"""Write every hit of the detector on fixed inputs to one file, so a refactor of the rules can show it changed nothing.

    python3 scripts/detection_fingerprint.py --out FILE [--creddata DIR] [--regions none,de,us,all]
        [--channels prompt,tool] [--samples FILE] [--no-tests] [--workers N]

For each input text, each channel and each region set the file holds one JSON line with the full hit list of
`detect.scan()`: rule id, placeholder type, start, end, and three flags per hit (`is_fixture` with no path,
`is_fixture` under a test path, `is_public_test_value`). The lines are sorted, so two runs on the same code give
the same bytes: compare them with `cmp`. A first line names the rules that `rules()` loads for each region set (a
count and a digest of the ids in their order).

The inputs:
- CredData (`--creddata`): every unique line of the labelled rows, read with the loader of
  `scripts/measure_creddata.py`. A line is named by its first row id (file path and CredData id).
- `tests/fp_corpus.py`: `NO_HIT` and `HIT`, with the `§` marks removed as the test does.
- `tests/fp_corpus_pii.py`, if the tree has it: `PII_NO_HIT` and `POSITIVE`.
- The token lists of the tests (`TOKENS` in `tests/test_rules_from_the_catalogs.py` and
  `tests/test_rules_from_other_detectors.py`), drawn with the seeds the tests use, in the forms the tests use.
- `--samples FILE`: a JSON list of `[corpus, id, text]`, for a check of the script itself.

The file holds ids, rule ids and offsets, never a value or a line. Each region set runs with its own fresh temp
store home and the test locale (`de_DE`), never ~/.maisecrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from multiprocessing import get_context
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
CHANNELS = ("prompt", "tool")
# every country code that maisecrets/regions.py names a language for: a superset of the regions of the regional
# and the Presidio rules. Fixed here, so a change in how a rule finds its region shows up as a changed hit
ALL_REGIONS = ("at", "au", "be", "br", "ca", "ch", "cz", "de", "dk", "es", "fi", "fr", "ie", "in", "it", "kr", "li",
               "lu", "ng", "nl", "no", "nz", "ph", "pl", "pt", "se", "sg", "th", "tr", "uk", "us", "za")
REGION_SETS = {"none": (), "de": ("de",), "us": ("us",), "all": ALL_REGIONS, "de+own": ("de",)}
# the set "de+own" adds rules of your own (a *.prefixes and a *.json file in rules.d) and an allow list that switches a
# built-in rule off and allows one exact value, so the rules of your own and the allow list are in the fingerprint too
OWN_PREFIXES = "acme-deploy-token  acme_dpl_[A-Za-z0-9]{24}\n"
OWN_JSON = {"rules": [{"id": "ticket-secret", "regex": "TKT-SECRET-[0-9a-f]{16}", "keywords": ["tkt-secret"]},
                      {"id": "staff-number", "type": "SECRET", "regex": "\\bSTAFF-[0-9]{7}\\b"}]}
OWN_ALLOW_RULE = "jwt"
TEST_PATH = "tests/test_fingerprint_probe.py"
_HOME_VAR = "MAISECRETS" + "_HOME"
_CLIENT_PREFIXES = ("CODEX_", "CLAUDE_CODE_", "CLAUDE_PLUGIN_OPTION_")
_CLIENT_NAMES = ("CLAUDECODE", "MAISECRETS_KEY_FILE", "MAISECRETS_DEBUG_LOG", "MAISECRETS_TEST_HOME_OWNED")

_detect = None


# ------------------------------------------------------------------------------------------------- inputs --
def creddata_items(cd: str) -> list:
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_creddata as mc
    first: dict = {}
    for it in mc.load_items(cd):
        first.setdefault(it[2], it[6] + "#" + it[7])
    return [("creddata", rid, line) for line, rid in first.items()]


def corpus_items() -> list:
    sys.path.insert(0, str(TESTS))
    import fp_corpus
    out = [("fp_corpus:NO_HIT", f"{i:04d} {name}", text.replace("§", ""))
           for i, (name, text) in enumerate(fp_corpus.NO_HIT)]
    out += [("fp_corpus:HIT", f"{i:04d} {name}", text.replace("§", ""))
            for i, (name, text, _) in enumerate(fp_corpus.HIT)]
    if (TESTS / "fp_corpus_pii.py").exists():
        import fp_corpus_pii
        out += [("fp_corpus_pii:PII_NO_HIT", f"{i:04d} {name}", text)
                for i, (name, text) in enumerate(fp_corpus_pii.PII_NO_HIT)]
        out += [("fp_corpus_pii:POSITIVE", f"{i:04d} {name}", text)
                for i, (name, text, _) in enumerate(fp_corpus_pii.POSITIVE)]
    return out


_OWN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def _own_token(r, n: int = 24) -> str:
    return "acme_dpl_" + "".join(r.choice(_OWN_ALPHABET) for _ in range(n))


def own_items() -> list:
    """Texts for the rules of your own of the set "de+own", drawn from a fixed seed. The first token is the value the
    allow list of that set names."""
    import random
    r = random.Random("own rules")
    out = []
    for n in range(10):
        tok, ticket, staff = _own_token(r), "TKT-SECRET-" + "".join(r.choice("0123456789abcdef") for _ in range(16)), \
            "STAFF-" + "".join(r.choice("0123456789") for _ in range(7))
        forms = (tok, f"deploy with {tok} today", f"ticket {ticket} and staff {staff}", f"mail {staff}@example.org",
                 f"export TOKEN={tok}\n", _own_token(r, 12))
        out += [("own", f"{n:02d} {k}", text) for k, text in enumerate(forms)]
    return out


def _allowed_value() -> str:
    import random
    return _own_token(random.Random("own rules"))


def token_items() -> list:
    """The tokens and look-alikes of the token tests, drawn with the tests' seeds (random.Random(rule id), 20 draws),
    in the three forms the tests scan. The test modules import tests/_isolate.py, which gives this process a temp
    home; each region set below still gets its own."""
    import random
    sys.path.insert(0, str(TESTS))
    out = []
    for mod_name in ("test_rules_from_the_catalogs", "test_rules_from_other_detectors"):
        mod = __import__(mod_name)
        for rule_id, gen in sorted(mod.TOKENS.items()):
            r = random.Random(rule_id)
            for n in range(20):
                tok, miss = gen(r)
                forms = (tok, f"export TOKEN_VALUE={tok}\n", f"here it is: {tok} thanks", miss)
                for k, text in enumerate(forms):
                    out.append((f"tokens:{mod_name}", f"{rule_id} {n:02d} {k}", text))
    return out


# ----------------------------------------------------------------------------------------------- the scan --
def _init(home: str) -> None:
    global _detect
    for k in list(os.environ):
        if k.startswith(_CLIENT_PREFIXES) or k in _CLIENT_NAMES:
            del os.environ[k]
    os.environ[_HOME_VAR] = home
    os.environ["MAISECRETS_LOCALE"] = "de_DE"
    sys.path.insert(0, str(ROOT))
    from maisecrets import detect
    detect.rules()
    _detect = detect


def _hits(text: str, channel: str) -> list:
    d = _detect
    out = []
    for m in d.scan(text, channel=channel):
        out.append([m.kind, m.type, m.start, m.end, int(d.is_fixture(m, text)), int(d.is_fixture(m, text, TEST_PATH)),
                    int(d.is_public_test_value(m.value, m.type))])
    return out


def _work(item):
    corpus, rid, text, channels = item
    return corpus, rid, {ch: _hits(text, ch) for ch in channels}


def _rule_info(_=None):
    d = _detect
    ids = [r.id for r in d.rules()]
    active = d.active_regions()
    return {"rules": len(ids), "ids_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest(),
            "regions": list(active.regions), "languages": list(active.languages)}


def _home_for(name: str) -> str:
    home = tempfile.mkdtemp(prefix="maisecrets-fingerprint-")
    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"backend": "jsonfile", "allow_plaintext_store": True, "regions": list(REGION_SETS[name])}, fh)
    if name.endswith("+own"):
        own = os.path.join(home, "rules.d")
        os.makedirs(own)
        with open(os.path.join(own, "acme.prefixes"), "w", encoding="utf-8") as fh:
            fh.write(OWN_PREFIXES)
        with open(os.path.join(own, "team.json"), "w", encoding="utf-8") as fh:
            json.dump(OWN_JSON, fh)
        with open(os.path.join(home, "allow.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"rule: {OWN_ALLOW_RULE}\n{_allowed_value()}\n")
    return home


def run(items: list, region_sets: list, channels: tuple, workers: int) -> tuple:
    """(header, lines, hits): the rule info per region set, one sorted JSON line per input, channel and region set,
    and the number of hits in them."""
    header, lines, hits = {}, [], 0
    ctx = get_context("spawn")    # the same start on every platform; a fork would copy this process' imports
    for name in region_sets:
        home = _home_for(name)
        try:
            with ctx.Pool(max(1, workers), initializer=_init, initargs=(home,)) as pool:
                header[name] = pool.apply(_rule_info)
                work = [(c, i, t, channels) for c, i, t in items]
                for corpus, rid, res in pool.imap(_work, work, chunksize=50):
                    for ch in channels:
                        hits += len(res[ch])
                        lines.append(json.dumps([name, corpus, rid, ch, res[ch]], ensure_ascii=False,
                                                separators=(",", ":")))
        finally:
            shutil.rmtree(home, ignore_errors=True)
    lines.sort()
    return header, lines, hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--creddata", help="a CredData checkout (meta/ and data/)")
    ap.add_argument("--regions", default="none,de,us,all,de+own", help="region sets: " + ",".join(REGION_SETS))
    ap.add_argument("--channels", default=",".join(CHANNELS))
    ap.add_argument("--samples", help="a JSON list of [corpus, id, text] instead of the built-in inputs")
    ap.add_argument("--no-tests", action="store_true", help="leave out the corpora and token lists of tests/")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    region_sets = [x for x in a.regions.split(",") if x]
    bad = [x for x in region_sets if x not in REGION_SETS]
    channels = tuple(x for x in a.channels.split(",") if x)
    if bad or not region_sets or not channels or set(channels) - set(CHANNELS):
        ap.error(f"unknown region set or channel: {bad or channels}")
    items: list = []
    if a.samples:
        items += [tuple(x) for x in json.loads(Path(a.samples).read_text(encoding="utf-8"))]
    else:
        if a.creddata:
            items += creddata_items(a.creddata)
        if not a.no_tests:
            items += corpus_items() + token_items() + own_items()
    keys = [(c, i) for c, i, _ in items]
    if len(set(keys)) != len(keys):
        raise SystemExit("two inputs have the same corpus and id")
    header, lines, hits = run(items, region_sets, channels, a.workers)
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"inputs": len(items), "rules": header}, sort_keys=True) + "\n")
        for ln in lines:
            fh.write(ln + "\n")
    print(f"{len(items)} inputs, {len(lines)} lines, {hits} hits -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
