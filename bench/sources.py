"""The sources of Benchmark V1 (docs/BENCHMARK-V1.md, "Sources"). Each source gives cases in the format of
bench/cases.py; a public source reads its pinned files from the data directory and copies nothing into the
repository.

    bank                          bench/bank/ (this repository)
    nemotron gretel mendeley piilo  the labelled PII datasets of scripts/measure_datasets.py, with its label cleaning
    catalogs                      the rule examples of six secret catalogs (scripts/measure_catalog_coverage.py)"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

from bench import cases

ROOT = Path(__file__).resolve().parent.parent
BANK = ROOT / "bench" / "bank"
DATASETS = ("nemotron", "gretel", "mendeley", "piilo")
SOURCES = ("bank",) + DATASETS + ("catalogs",)

# the types of scripts/measure_datasets.py to the classes of the benchmark; SECRET by the dataset's own label
TYPE_CLASS = {"EMAIL": "pii.email", "PHONE": "pii.phone", "IP": "pii.ip", "IBAN": "pii.iban", "CARD": "pii.card",
              "US_SSN": "pii.national_id", "ABA_ROUTING_NUMBER": "pii.bank_account",
              "US_BANK_NUMBER": "pii.bank_account", "NAME": "pii.name", "ADDRESS": "pii.address",
              "BIRTH_DATE": "pii.birth_date", "ID_NUMBER": "pii.national_id", "USERNAME": "pii.username"}
SECRET_LABEL = {"password": "secret.password"}
REGION_OF_LANG = {"en": "us", "de": "de", "fr": "fr", "es": "es", "it": "it", "nl": "nl", "sv": "se"}


def _measure_datasets():
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_datasets
    return measure_datasets


def dataset_cases(name: str, data: Path, stats: collections.Counter, limit: int = 0):
    """The cases of one labelled PII dataset. A label the cleaning marks oos or uncertain becomes a neutral span (a
    finding on it is neither a hit nor a false alarm); a label error is left out."""
    md = _measure_datasets()
    counts: dict = {}
    n = 0
    for sample in md.load(name, data, stats):
        record = str(sample["id"])
        spans = []
        for g in md.clean(name, sample, counts):
            if g["gold"] == "neg":
                continue
            if g["type"] == md.OUT_OF_SCOPE:
                cls = "pii.other"
            elif g["type"] == "SECRET":
                cls = SECRET_LABEL.get(g["label"], "secret.generic")
            else:
                cls = TYPE_CLASS[g["type"]]
            sp = {"start": g["start"], "end": g["end"], "class": cls, "label": g["label"]}
            if g["gold"] != "pos":
                sp["neutral"] = True
            spans.append(sp)
        lang = sample.get("lang", "en")
        yield {"id": f"{name}/{record}", "text": sample["text"], "channel": "tool", "context": "doc", "path": None,
               "spans": spans, "split": cases.split_of(name, record), "tags": sample.get("tags", []),
               "region": REGION_OF_LANG.get(lang, lang), "lang": lang,
               "source": {"name": name, **{k: md.SOURCES[name].get(k) for k in ("url", "revision", "licence")
                                            if k in md.SOURCES[name]}, "record": record}}
        n += 1
        if limit and n >= limit:
            return


def catalog_cases(catalogs: Path, max_examples: int = 6):
    """Each example of a secret catalog twice: the secret alone and after `token = `, as
    scripts/measure_catalog_coverage.py probes it. The expected span is the catalog's secret."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import measure_catalog_coverage as mcc
    for cat in mcc.CATALOGS:
        root = Path(catalogs) / cat
        if not root.is_dir():
            continue
        commit = mcc.commit_of(root)
        for r in mcc.load_catalog(cat, root):
            rule = r["rule"]
            for i, ex in enumerate(r["pos"][:max_examples]):
                yield from _catalog_forms(cat, commit, rule, i, ex["secret"])


def _catalog_forms(cat: str, commit: str, rule: str, i: int, secret: str):
    if secret:
        for form, body in (("bare", secret), ("label", "token = " + secret)):
            start = body.index(secret)
            cls = "secret.webhook" if secret.startswith("http") else "secret.token"
            record = f"{cat}/{rule}/{i}/{form}"
            yield {"id": f"catalogs/{record}", "text": body, "channel": "tool", "context": "prose",
                   "spans": [{"start": start, "end": start + len(secret), "class": cls}],
                   "split": cases.split_of("catalogs", f"{cat}/{rule}"), "tags": [f"catalog:{cat}", f"form:{form}"],
                   "source": {"name": cat, "commit": commit, "record": f"{rule}/{i}"}}


def load(name: str, data: Path | None = None, catalogs: Path | None = None, limit: int = 0,
         stats: collections.Counter | None = None):
    stats = stats if stats is not None else collections.Counter()
    if name == "bank":
        return iter(cases.load_bank(BANK))
    if name in DATASETS:
        md = _measure_datasets()
        return dataset_cases(name, Path(data or md.DEFAULT_DATA), stats, limit)
    if name == "catalogs":
        if catalogs is None:
            raise SystemExit("the catalogs source needs --catalogs DIR (one clone per catalog)")
        return catalog_cases(catalogs)
    raise SystemExit(f"no source {name}; known: {', '.join(SOURCES)}")
