# Benchmark V2: a draft, not frozen

Status: **draft** (2026-10-19). V2 keeps everything of `docs/BENCHMARK-V1.md` that is not named here. It is frozen by a
commit that changes the status line above to "frozen" and names the commit of the scoring code; only after that is the
private Holdout V2 written and sealed. A change to a frozen part needs a V3.

## What V2 freezes from V1

- **Sources and their pins:** the four PII datasets (Nemotron-PII, Gretel, Mendeley, PIILO, pinned by sha256 in
  `bench/sources.py`), the six secret catalogs at their commits, and the public bank (`bench/bank/`).
- **The case format, the classes and the scope of each scanner** (`bench/cases.py`, V1 "Classes" and "Scope of a
  scanner").
- **Scoring** (`bench/score.py`): a span is `full`, `partial` or `missed`; precision counts a finding as right when it
  lies on sensitive text; `too wide`; a rate is "-" under 30 spans. The commit of `bench/score.py` is named at the
  freeze.
- **The split rule:** `sha256(source + "/" + record)`, the first 8 hex digits modulo 10: 0 to 5 `dev`, 6 to 7 `val`,
  8 to 9 `holdout`.

## What V2 adds

### Separate results by split

A rule round reads cases only from `dev`. It decides on `val` and on the false-alarm bank. A result on `all` may be
reported, but never next to a holdout number as if it were one. `bench/run.py --split all` writes the case ids of every
split; a run for analysis uses `--split dev`.

### Reproducible scanner configurations

Each scanner runs with the configuration its result file names (`scanner.configuration`) and nothing tuned per source:
maisecrets with regions `generic,de,us`, sources and references off; the other scanners in their own environments from
`bench/requirements/` with every distribution pinned. A result whose checkout or package is not the named one is
refused (V1 "Adapters").

### A report per class

`bench/report.py` writes, per source and split, one row per class: spans, full, partial, missed, recall (full), and per
family the false positives and precision. Aggregate F1 is a secondary line. A comparison of two scanners or two
commits is read per class first: a gain in one class and a loss in another must both be visible.

### Limitations that a reader must know

- The public datasets are synthetic and mostly English. Their labels are not always ours: Nemotron labels some policy
  and loan numbers as bank accounts, and documentation example passwords as passwords.
- Names and addresses are most of the missed spans (Nemotron 116,000 names). maisecrets has no named-entity model; its
  recall there is a known limit, not a measurement error.
- maisecrets runs in the tool channel on every case; a typed prompt is a different channel with stricter rules.
- PIILO is small (1,496 spans). A rate under 30 spans is not printed.

## Holdout V2

1. **The templates are written before any case is generated, and not from maisecrets' misses.** Their source is a
   list of real-world formats per class (public format specifications, issuer ranges, documented label words), written
   down and committed first. Nobody who wrote the templates looks at a list of maisecrets misses for them.
2. A seeded generator writes the cases into a private directory. The manifest (`bench/holdout.manifest`: number of
   cases, sha256 of each file) is committed before the first run.
3. The holdout runs only on a release candidate. Each run writes one line to `bench/HOLDOUT-LOG.md`, with totals only.
4. No rule is changed because of a holdout result. A set that was read for tuning becomes `dev`, and the log says so.
5. The V1 holdout (80 cases) gets its last run on the next release candidate and then becomes `val`.

## Open decisions before the freeze

1. **The public holdout split of the rule round of 2026-10-19.** The analyses of that round ran on `--split all` and
   read the cases of the public holdout split too (shapes, context words, table headers of missed spans). By V1 rule 6
   that split is no longer a test. Options: (a) count the public holdout split as `dev` from now on and take the honest
   number only from the private Holdout V2; (b) a new salt for the split rule, which does not help, since every record
   was read. The draft proposes (a).
2. **More sources.** A public set that nobody has read for tuning would give a second independent number besides the
   private holdout. Which set, and who checks that it was not read?
3. **Which foreign scanners** take part in V2 (V1: detect-secrets, secret-scan, pii-anon, preserve) and whether
   Presidio itself runs as a scanner.
