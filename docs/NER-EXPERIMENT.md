# The NER experiment: an optional PERSON layer after the deterministic detector

Status: an experiment on maisecrets 0.7.3. Nothing here is part of the plugin or of `maisecrets.detection`; the code is
in `bench/` (`bench/ner/person_worker.py`, `bench/adapters/maisecrets_ner.py`), which the release tree leaves out.

## The question

The Benchmark V1 snapshot of 0.7.3 (`bench/results/2026-10-21-v0.7.3.md`) leaves 48.7 % of the missed spans of the four
PII datasets in category D, 96 % of them names in running text, and on Privy 0.7.3 masks 312 of 8,121 names whole.
Can a local PERSON model, run after the deterministic detector and only where it found nothing, close a real part of
that gap without giving up the precision of maisecrets?

## The design under test

1. The deterministic detector of the checkout runs first, as in the benchmark (`bench/adapters/maisecrets.py`).
2. Its findings are kept as they are.
3. The model reads the whole text (its context is the same with or without the layer).
4. A PERSON span of the model is kept only when it overlaps no deterministic finding and no PERSON span kept before
   it; it becomes a `pii.name` finding. A deterministic finding is never made smaller, moved or retyped.
5. Without the NER environment the adapter refuses to run; the deterministic adapter is the baseline and stays as it
   was. (In a product, a missing or failing layer would mean the findings of step 1 alone.)

## Fixed before the first measurement (2026-10-21)

This section was committed before any measurement of a candidate on a dataset, and is not changed afterwards.

**Candidates.**

| | A: spaCy small | B: spaCy large | C: GLiNER |
|---|---|---|---|
| Model | `en_core_web_sm` 3.8.0 | `en_core_web_lg` 3.8.0 (Presidio's default) | `urchade/gliner_multi-v2.1` at `443d26d6` |
| Library | spaCy 3.8.16 | spaCy 3.8.16 | gliner 0.2.29, torch 2.14.1, transformers 5.16.1 |
| Licence | MIT (library and model) | MIT | Apache-2.0 (library and model); encoder mDeBERTa-v3-base, MIT |
| Model size | 15 MB | 428 MB | 1.1 GB |
| Environment on disk | 587 MB (with both models) | the same | 928 MB, of it torch 587 MB |
| Languages | English | English | multilingual |
| Python | 3.9 to 3.14 | 3.9 to 3.14 | 3.10 or later |
| CPU only | yes | yes | yes (measured on CPU) |
| Setting | PERSON entities, no threshold | the same | label `person`, threshold 0.5 (the library default) |

A fourth variant, **C-high**, is GLiNER with threshold 0.3: one explicit high-recall setting, not a tuned value.

Left out, with the reason: the PII-specific GLiNER models `nvidia/gliner-PII` and `knowledgator/gliner-pii-*` (their
training data is synthetic PII of the kind of Nemotron and Gretel, so the benchmark could measure their training set;
the NVIDIA licence is not Apache-2.0); `urchade/gliner_multi_pii-v1` (2024, the same concern); Presidio as a whole
(its PERSON comes from `en_core_web_lg`, which is candidate B; its other recognizers are vendored into maisecrets
already); Flair and BERT token classifiers (a transformer of the same cost as C with fewer languages).

**Added later, on the maintainer's request (2026-10-21, after the Nemotron sample of B, C and C-high was seen):**
candidate **D**, DistilBERT, `dslim/distilbert-NER` at `dfa2838a` (Apache-2.0, 250 MB, trained on CoNLL-2003,
English), run with transformers 5.16.1 and torch 2.14.1 in the GLiNER environment: the `token-classification`
pipeline with `aggregation_strategy="simple"`, its `PER` entities, no threshold, the text in pieces of 100 tokens. The
setting was fixed before D's first measurement; nothing else in this section changed. After D's samples (all `dev`):
1,868 of its false positives in the family "rest" end inside a word, 1,348 of them on Gretel, the part that is not
English. `aggregation_strategy="simple"` returns pieces of words. **D2** is D with `aggregation_strategy="first"`, which
keeps whole words: a choice made on `dev`, as the rules allow.

**Data and splits.** The four PII datasets of Benchmark V1 with the case hashes of the 0.7.3 snapshot: the fixed sample
of 1 in 50 for every variant, and each dataset in full for the baseline, A and B (C on the sample only: about 0.1 to
0.5 s per document). The bank and the catalogs are left out (6 and 0 names). No threshold or setting is chosen from a
result; `val` is reported, not used.

**Measures.** Per variant against the baseline of the same run: the `pii.name` class (whole, partial, missed, strict
recall) and the PII family (false positives, precision, F1); the names the layer adds and the false positives it adds;
spans made worse (must be 0); the PERSON spans dropped on a deterministic finding, by its type; names by bucket of
`bench/funnel.py` (running text against record fields) and by language where a dataset has one; the time per
document (cold start, model load, median, 95th percentile), the peak memory of the NER process, the throughput, one
input of 1 MB, and many requests on one loaded model.

**The false positives the layer adds** are sorted by rules fixed here, before reading any: a span that is a gold span
of another class (address, user name, other), a span in a record field (funnel bucket), a span with a digit, `@`, `_`
or `/` (technical identifier), a span with a company word (Inc, LLC, Ltd, Corp, GmbH, AG, Bank, Group, Company,
Partners, Holdings, Technologies, Solutions, Services, University, Hospital, Foundation), a span of one word at the
start of a sentence, a span of role or title words only, and the rest. Then a sample of the rest is read on `dev`
in masked form.

**Privy**, after all of the above and with nothing changed: totals only, the sample for every variant, in full for
A and B and, when the time allows, for C. No Privy case is read, before or after.

## Results

Not measured yet.
