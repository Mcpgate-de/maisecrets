# Benchmark V1: the specification

This file defines how maisecrets and other scanners are measured on the same input. It is the contract for
`bench/` (the runner, the adapters and the data of our own) and for every number that a release or a comparison
reports. `docs/BENCHMARKS.md` keeps the results of the older scripts; their sources become sources of this runner
one by one (section "Sources").

The aim is a measurement that a reader outside the project can repeat and trust, not a measurement on which
maisecrets looks good. Three rules follow from that aim:

1. Each number names its source, its commit or version, its split and its command.
2. A scanner is scored only on the classes it claims to find (section "Scope"). There is no total ranking.
3. The frozen holdout is not used to write rules (section "Splits").

## Terms

- **Case.** One input text with the sensitive spans it holds, its channel and its metadata.
- **Span.** A range `[start, end)` of characters in the text of a case that a scanner must hide.
- **Finding.** A range that a scanner reports, with the class the scanner gives it.
- **Source.** A set of cases: our own bank, a public dataset or a catalog of rule examples.
- **Adapter.** The code that gives a case to one scanner and turns its output into findings.

## The case format

One case is one JSON object (one line of a `.jsonl` file). Fields:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Stable and unique in its source, for example `bank/webhook/teams-0003` |
| `text` | string | yes | The input, after the loader removed the markers (below) |
| `channel` | `prompt` or `tool` | yes | Where maisecrets sees the text: a prompt the person types, or the result of a tool |
| `context` | string | yes | The form of the text: `prose`, `shell`, `log`, `json`, `yaml`, `config`, `code`, `stacktrace`, `doc`, `url` |
| `path` | string or null | no | The file path the text came from, when a tool read a file |
| `spans` | list | yes | The expected spans; an empty list makes the case a negative case |
| `spans[].start`, `spans[].end` | int | yes | Offsets into `text` |
| `spans[].class` | string | yes | The class of the span (section "Classes") |
| `spans[].alt` | list of `[start, end]` | no | Other ranges that also count as full masking, for example the value without its quotes |
| `spans[].core` | `[start, end]` | no | The part that must be hidden in all cases. Default: the whole span |
| `spans[].neutral` | bool | no | A label the source marks as out of scope or uncertain: a finding on it is neither a hit nor a false positive |
| `source` | object | yes | `name`, `url`, `commit` or `version`, `license`, `record` (the id in the source) |
| `tags` | list of string | no | Free tags, for example `provider:microsoft`, `form:bare`, `form:after-label` |
| `difficulty` | `easy`, `medium`, `hard` | no | The author's estimate |
| `region` | string | no | The region or language of the value, for example `de`, `us`, `intl` |
| `split` | `dev`, `val`, `holdout` | yes | Section "Splits" |

### How a case of our own bank is written

A case file of our bank cannot hold a real-looking secret: `scripts/scan_tree.py` and the pre-commit check scan the
whole tree. The text of a case therefore carries two kinds of marks, and the loader (`bench/cases.py`) removes them:

- `§` splits a value, as in `tests/fp_corpus.py`. The loader deletes every `§`.
- `«` and `»` enclose an expected span. The loader deletes them and records the offsets. The classes of the spans
  are in `spans` in the same order as the marks.

The public bank is not written by hand. `bench/bank/make_bank.py` renders it from templates: a slot `{kind|class}` in
a template is a random value of that kind (with the checksum its type needs: IBAN, Luhn, the German tax id) and an
expected span of that class; a slot `{kind}` is a value that is no span (a git commit id in a hard negative). The seed
is fixed, so the files are the same on each run, and `make_bank.py --check` fails when a file differs from its
templates. Each template gives three cases.

A loader test checks that each case has as many mark pairs as spans and that no `«`, `»` or `§` is left in the text.

## Classes

A class is a dotted name. The first part is the family; the benchmark reports each family and each class.

| Family | Classes | Examples |
|---|---|---|
| `secret` | `secret.token` (a provider token with a fixed form), `secret.webhook` (a URL that is the credential), `secret.url_credential` (user and password in a URL), `secret.password` (a value after a password label), `secret.private_key`, `secret.connection_string`, `secret.generic` (a value after a key or token label, no fixed form) | `ghp_…`, a Teams webhook, `postgres://u:p@h/db` |
| `pii` | `pii.email`, `pii.phone`, `pii.iban`, `pii.card`, `pii.bank_account`, `pii.national_id` (with `region`), `pii.tax_id`, `pii.name`, `pii.address`, `pii.birth_date`, `pii.username`, `pii.ip`; `pii.other` for a neutral label of a dataset | |

A source maps its own labels to these classes in its loader. A label that maps to no class is left out and counted
("labels left out" in the report).

## Scope of a scanner

Each adapter declares the classes its scanner claims (`scope`, a list of class prefixes such as `secret.` or
`pii.email`). For a run of scanner S:

- An expected span outside the scope of S is removed from the case. It is no false negative of S.
- A finding of S that overlaps a removed span is ignored. It is no false positive of S.
- A finding of S that overlaps no expected span is a false positive, whatever class S gives it.

So a PII scanner is not scored on AWS keys, and a secret scanner is not scored on names. A table compares two
scanners only on the classes that both claim.

## When a span counts as found

The question for a person is "did the secret leave the computer?". The masking is what counts, not the class name
that a scanner gives. For each expected span, let `covered` be the number of its `core` characters inside the union of
all findings of the case.

| Outcome | Condition |
|---|---|
| **full** | every `core` character is covered, or one `alt` range is covered whole |
| **partial** | at least one, but not every, `core` character is covered |
| **missed** | no character is covered |

Only **full** is a true positive. A Teams webhook of which a scanner masks 17 of 204 characters is **partial**: it
counts as a false negative in the strict recall, and the report shows it in its own column.

Over-masking: for each finding that overlaps an expected span, `extra` is the number of its characters outside every
expected span and outside the label of the span (the text from the start of the line or the last separator to the
span). A finding with `extra` above `max(8, len(span))` is **too wide**. A too-wide finding still masks the span, so
it is no false negative; the report counts it, because it hides text the model needs.

Class accuracy: a full span whose covering finding has a class in the same family counts as "family right". The
report gives this rate; it does not change precision or recall.

## Metrics

Per scanner, source, split and class (and per family and region where the data allow it):

| Metric | Definition |
|---|---|
| spans | expected spans in scope |
| full / partial / missed | the outcomes above |
| recall, strict | full / spans |
| recall, lenient | (full + partial) / spans |
| character recall | covered core characters / all core characters |
| findings | findings that overlap an expected span, plus false positives |
| FP | findings that overlap no expected span and no removed span |
| precision | (findings − FP) / findings |
| F1 | 2 P R / (P + R), with the strict recall |
| too wide | findings that are too wide |
| FP per 1,000 negative cases | FP in negative cases × 1,000 / negative cases |
| FP per MB | for a source of whole files (the false-alarm bank): FP × 2²⁰ / bytes scanned |
| time | wall time per case (median and p95), throughput in KB/s, and the cold start (process start to the first finding) |

A source with fewer than 30 spans in a class reports the counts and no rate for that class ("too few").

## Splits

| Split | What it is for | Where it lives |
|---|---|---|
| `dev` | Writing and debugging rules. Every case is public and may be read. | `bench/bank/dev/` (25 templates), and the public sources |
| `val` | Checking a rule change before a merge. The cases are public, but a rule is not written from a single val case. | `bench/bank/val/` (11 templates) |
| `holdout` | The honest number for a release. Nobody writes a rule from it. | Outside this repository: a private directory given with `--holdout DIR`; 20 templates of their own (other forms and contexts than the bank), 80 cases, written 2026-10-19 before any rule change this benchmark measures |

For the public sources, the split comes from the id: the first 8 hex digits of `sha256(source + "/" + record)`, as
an integer modulo 10: 0 to 5 is `dev`, 6 to 7 is `val`, 8 to 9 is `holdout`. A new release of a source does not move
an old record to another split.

The holdout rules:

1. The runner prints only totals for the holdout split: no case id, no text and no value.
2. Each holdout run writes one line to `bench/HOLDOUT-LOG.md`: the date, the commit of maisecrets, the scanners and
   the totals. A rule change that names a holdout case in its reason is rejected in review.
3. The private bank has a manifest in the repository (`bench/holdout.manifest`): the number of cases and the sha256 of
   each file. The runner refuses a holdout directory whose files do not match it, so the holdout cannot change without
   a commit that says so.
4. A set that was used for tuning becomes `dev`, and the log says so. The Cloakroom holdouts v2 to v7 are such sets:
   0.6.21 was written from half D (`docs/BENCHMARKS.md`).

## Sources

| Source | Classes | Form | Licence | Status in V1 |
|---|---|---|---|---|
| maisecrets bank (`bench/bank/`) | secret, pii | prompts, tool results, logs, JSON, configs, shell, code, docs; hard negatives | Apache-2.0 (this repository) | new in V1 |
| Rule examples of six secret catalogs (Nosey Parker, Kingfisher, gitleaks, Betterleaks, TruffleHog, GitLab) | `secret.token`, `secret.webhook` | the value bare and after a label | Apache-2.0, MIT; TruffleHog is AGPL-3.0, so its examples are read at run time and never copied | `scripts/measure_catalog_coverage.py`, a source of the runner in V1 |
| Samsung CredData | secret | one line of source code; `ValueStart`/`ValueEnd` give the span | each file under the licence of its project (the dataset filters for licences that allow it) | `scripts/measure_creddata.py`; a source in V1 |
| NVIDIA Nemotron-PII | pii | synthetic documents with spans | CC BY 4.0 | `scripts/measure_datasets.py`; a source in V1 |
| Gretel synthetic_pii_finance_multilingual | pii, some secret | synthetic finance documents, 7 languages | Apache-2.0 | as above |
| Mendeley financial documents (doi 10.17632/tzrjx692jy.1) | pii | synthetic documents | CC BY 4.0 | as above |
| PIILO | pii (names, user names, URLs) | student essays | CC BY 4.0 | as above |
| False-alarm bank (CPython `Lib/`, detect-secrets, ferret-scan, Preserve, fixed commits) | none: every finding is a false alarm or a test value | whole files | PSF, Apache-2.0, Apache-2.0, see the repository | `scripts/measure_fp_bank.py`; FP per MB |
| Cloakroom holdouts v2 to v7 | secret, pii | planted values without offsets | Apache-2.0 | `dev` only (seen before) |

Left out, with the reason:

- SecretBench (NC State): access needs a signed data protection agreement, so a reader cannot repeat a result.
- Loghub: "freely available for research or academic work"; the licence of each log set is not clear enough for a
  public benchmark. Logs in our bank are written by hand instead.
- Data sets on Hugging Face without a licence on the card.

## Adapters

An adapter is a module in `bench/adapters/` with `NAME`, `SCOPE` (the class prefixes it claims), `describe()` (version
or commit, configuration, detectors, locale, network, dependencies; it goes into each result file) and `scan(cases)`
(one list of findings `(start, end, class, rule)` per case, and the timing). Each scanner runs in a process of its own,
started with `python -I`, in the Python of its own virtual environment (an environment variable names it), so the
benchmark needs none of their packages and they need none of each other's.

| Adapter | Version, pinned | Scope | Configuration | Network | Mapping of a finding |
|---|---|---|---|---|---|
| `maisecrets` | the checkout under `--maisecrets` (its commit and the version in its manifest) | secret, pii | `Detector` with regions `generic` plus `--regions` (default `de,us`), no sources, no references, a fixed host; before 0.6.39, `detect.scan` in a temp home | no | a match: its offsets; `SECRET` is family secret, the other placeholder types are pii classes |
| `detect_secrets` | detect-secrets 1.5.0 (PyPI) | secret | `SecretsCollection.scan_file` with the default settings (all plugins, default filters), one file per case | no | a secret value: its first place in its line |
| `secret_scan` | secret-scan 0.4.2, commit 7d8b5c1 | secret | `scan_directory` defaults (named patterns, entropy off), `redact=False` for the offsets | no | a match: line and column |
| `pii_anon` | pii-anon 1.7.0rc1, commit 2171ace, plus numpy (imported but not declared) | pii | `PIIOrchestrator.run` with the README's profile (weighted consensus, `en`, no segmentation); without extras only its regex engine runs | no | an `ensemble_findings` entry: its span; entity type to class by a table |
| `preserve` | preserve-pii 0.6.1, commit 01dbd77 | secret, pii | `Scrubber(PreserveConfig())`, the defaults (no LLM review) | no | a detection: its offsets; the type name to class by its words |

Not yet an adapter:

- Cloakroom (Apache-2.0): its rules-only mode needs no model, but the package was not installed for V1. Its holdout
  sets are a source (dev only), and `docs/BENCHMARKS.md` keeps the numbers that its own file reports.
- ferret-scan (awslabs, Apache-2.0): a Go CLI; an adapter needs a Go toolchain or a release binary.
- Presidio: the PII engine behind several tools; an adapter needs spaCy and a language model download.

## Result files and the report

`bench/run.py` writes one JSON file per scanner, source and split: the `describe()` of the scanner, the commit of the
benchmark, the source and its version, the split, the metrics per class and family, per region and class, per context
and class, the timing, and the outcome per case id (not for the holdout). The files hold no value and no text.
`bench/report.py` writes the Markdown tables; a scanner appears in a family table only when it claims that family.

## Repeat a measurement

Each command runs from the root of a checkout of this repository. The data of the PII datasets and the catalogs come
from their own fetch commands and are pinned by sha256 or commit.

```bash
# the tools to compare, each in its own environment
python3 -m venv /tmp/venv-ds && /tmp/venv-ds/bin/pip install detect-secrets==1.5.0
git clone https://github.com/harshahemanth/secret-scan /tmp/secret-scan && git -C /tmp/secret-scan checkout 7d8b5c1
python3 -m venv /tmp/venv-ss && /tmp/venv-ss/bin/pip install /tmp/secret-scan
git clone https://github.com/subhash-holla/pii-anon /tmp/pii-anon && git -C /tmp/pii-anon checkout 2171ace
python3 -m venv /tmp/venv-pa && /tmp/venv-pa/bin/pip install /tmp/pii-anon numpy
git clone https://github.com/thirtysix/Preserve /tmp/preserve && git -C /tmp/preserve checkout 01dbd77
python3 -m venv /tmp/venv-pr && /tmp/venv-pr/bin/pip install /tmp/preserve
export BENCH_DETECT_SECRETS_PYTHON=/tmp/venv-ds/bin/python BENCH_SECRET_SCAN_PYTHON=/tmp/venv-ss/bin/python
export BENCH_PII_ANON_PYTHON=/tmp/venv-pa/bin/python BENCH_PRESERVE_PYTHON=/tmp/venv-pr/bin/python

# the data: the PII datasets (pinned by sha256) and the six catalogs (see scripts/measure_catalog_coverage.py);
# the catalog source needs PyYAML and Python 3.11 or later (tomllib)
python3 scripts/measure_datasets.py fetch

# the bank is in the repository; check that it matches its templates
python3 bench/bank/make_bank.py --check

# every scanner on every source it can take, and the report; maisecrets of another checkout as the second argument
BENCH_PYTHON=<python 3.11+ with PyYAML> BENCH_CATALOGS=<catalog clones> bench/run_all.sh results/ [<checkout>]

# one run by hand: --every N keeps the cases whose sha256 of the id is a multiple of N (a fixed sample, the same
# for every scanner); run_all.sh uses N=50 on the PII datasets for the comparison and runs maisecrets also in full
python3 bench/run.py --scanner preserve --source nemotron --split all --every 50 --out results/n.json
python3 bench/report.py results/*.json > report.md

# the frozen holdout (maintainer only; the directory is private and must match bench/holdout.manifest)
python3 bench/run.py --scanner maisecrets --source holdout --holdout DIR --out results/holdout-maisecrets.json
```
