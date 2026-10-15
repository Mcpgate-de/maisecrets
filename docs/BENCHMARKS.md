# Benchmarks

This file is a snapshot. Each table names what was measured, how, the source and the date. The method and its
limits are in their own section. "Repeat this measurement" has the commands.

| Snapshot | |
|---|---|
| Date | 2026-10-14 |
| maisecrets | v0.6.17 (tag `v0.6.17`); earlier releases from their tags; the CredData rows of 0.6.18 to 0.6.21 and the holdout section: 2026-10-15 |
| Data | Samsung CredData, commit `0b1940e171725ad8937311120b191602608a4801` (2026-09-29); four labelled PII datasets, pinned in "Labelled PII datasets" (2026-10-15) |
| Machine | Apple M5, 10 cores, macOS 27.0 |
| Python | 3.14.8 (CredData runs); 3.14.8 and 3.9.6 (timing) |
| Scripts | `scripts/measure_creddata.py`, `scripts/measure_scan_time.py`, `scripts/measure_datasets.py`, `tests/test_fp_corpus.py` |

## CredData, results per release

CredData line method, without repository `2ba83c6a` (23,667 rows: 10,106 credentials, 13,561 non-secrets),
`--locale de_DE`. Source: `scripts/measure_creddata.py`, 2026-10-14; 0.6.18 to 0.6.21 on 2026-10-15, each from a worktree
of its tag (0.6.21: the merge request branch). A release before 0.6.17 has one channel.

| Release | Channel | TP | FN | FP | P | R | F1 | F1, `--regions us` |
|---|---|---|---|---|---|---|---|---|
| 0.6.14 | one | 4,822 | 5,284 | 427 | 0.919 | 0.477 | 0.628 | 0.607 |
| 0.6.15 | one | 4,882 | 5,224 | 429 | 0.919 | 0.483 | 0.633 | 0.612 |
| 0.6.16 | one | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.17 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.17 | tool | 5,838 | 4,268 | 443 | 0.929 | 0.578 | 0.713 | 0.690 |
| 0.6.18 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.18 | tool | 5,854 | 4,252 | 445 | 0.929 | 0.579 | 0.714 | 0.691 |
| 0.6.19 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.19 | tool | 5,854 | 4,252 | 445 | 0.929 | 0.579 | 0.714 | 0.691 |
| 0.6.20 | prompt | 5,337 | 4,769 | 441 | 0.924 | 0.528 | 0.672 | 0.650 |
| 0.6.20 | tool | 5,854 | 4,252 | 445 | 0.929 | 0.579 | 0.714 | 0.691 |
| 0.6.21 | prompt | 5,345 | 4,761 | 441 | 0.924 | 0.529 | 0.673 | 0.650 |
| 0.6.21 | tool | 5,862 | 4,244 | 446 | 0.929 | 0.580 | 0.714 | 0.691 |

This table uses all 29,893 rows (14,471 credentials, 15,422 non-secrets). Source: `scripts/measure_creddata.py
--exclude-repo ""`, 2026-10-14; 0.6.18 to 0.6.21 on 2026-10-15.

| Release | Channel | P | R | F1 | P, R, F1 with `--regions us` |
|---|---|---|---|---|---|
| 0.6.14 | one | 0.953 | 0.613 | 0.746 | 0.900, 0.613, 0.729 |
| 0.6.15 | one | 0.953 | 0.617 | 0.749 | 0.901, 0.617, 0.732 |
| 0.6.16 | one | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.17 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.17 | tool | 0.956 | 0.683 | 0.797 | 0.908, 0.683, 0.780 |
| 0.6.18 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.18 | tool | 0.956 | 0.684 | 0.798 | 0.908, 0.684, 0.781 |
| 0.6.19 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.19 | tool | 0.956 | 0.684 | 0.798 | 0.908, 0.684, 0.781 |
| 0.6.20 | prompt | 0.954 | 0.649 | 0.772 | 0.904, 0.649, 0.755 |
| 0.6.20 | tool | 0.956 | 0.684 | 0.798 | 0.908, 0.684, 0.781 |
| 0.6.21 | prompt | 0.954 | 0.649 | 0.773 | 0.904, 0.649, 0.756 |
| 0.6.21 | tool | 0.956 | 0.685 | 0.798 | 0.908, 0.685, 0.781 |

## CredData, split by repository

0.6.17 tool channel against 0.6.16, without `2ba83c6a`, `--regions de`. The maintainers wrote the rules of 0.6.16
and 0.6.17 on half D. Half V holds the other repositories. Source: `scripts/measure_creddata.py --split half
--baseline <0.6.16>`, 2026-10-14.

| Half | P | R | F1 | Credentials only 0.6.17 catches | False alarms only 0.6.17 raises | Rows only 0.6.16 catches |
|---|---|---|---|---|---|---|
| D | 0.920 | 0.646 | 0.759 | 263 | 2 | 0 |
| V | 0.940 | 0.514 | 0.664 | 247 | 0 | 0 |

## CredData, credentials still missed

0.6.17 tool channel, without `2ba83c6a`, `--regions de`, by class (see "Method and limits"). Source:
`scripts/measure_creddata.py`, 2026-10-14.

| Class | Credentials missed | Share | Same-class non-secrets | Credentials ÷ (credentials + same-class non-secrets) |
|---|---|---|---|---|
| identifier (UUID, bucket name, id) | 2,589 | 60.7 % | 3,728 | 0.41 |
| labelled value, not a word | 1,140 | 26.7 % | 7,536 | 0.13 |
| value without a label | 300 | 7.0 % | 1,011 | 0.23 |
| password of letters only | 239 | 5.6 % | 843 | 0.22 |

## False alarms in developer text

`detect.scan` on each text of `tests/fp_corpus.py`, with each channel, `--locale de_DE`. Source:
`tests/test_fp_corpus.py` (the suite fails on a change), 2026-10-14.

| Set | Size | 0.6.17 prompt channel | 0.6.17 tool channel |
|---|---|---|---|
| `NO_HIT`: code, configuration, docs, logs and prose without a secret | 1,114 texts | 0 texts with a hit | 0 texts with a hit |
| `HIT`: texts with known values | 136 texts | 136 give exactly their values | 136 give exactly their values |

Typed prompts from the maintainers' own sessions, through the hook: 0 new blocks against 0.6.16 over 771 prompts.
Source: the 0.6.17 release measurement, 2026-10-14. The prompts are not published, so this number cannot be
repeated outside the maintainers' machines.

## Coverage against other catalogs

The built-in examples of six other secret catalogs, scanned by maisecrets. Per rule with examples, up to 6
examples, each in two forms: the secret alone ("bare") and after `token = ` ("after a label"). A rule counts as
found when the hits of one channel cover the whole secret of one of its examples. "0.6.19" is the tag `v0.6.19`;
"0.6.20" is the branch of that release. Source: `scripts/measure_catalog_coverage.py`, 2026-10-15; its docstring has
the method. The tables show which forms maisecrets misses, not a ranking between tools: the other tools also verify a
key with its provider, pair a key with its id and use provider logic, and maisecrets uses labels and shapes only.

| Catalog | Commit | Rules | Rules with examples | 0.6.19 bare | 0.6.20 bare | 0.6.19 after a label | 0.6.20 after a label |
|---|---|---|---|---|---|---|---|
| Nosey Parker | `2e6e7f36ce36` | 189 | 189 | 67 (35.4 %) | 78 (41.3 %) | 171 (90.5 %) | 171 (90.5 %) |
| Kingfisher | `82d050530cde` (v1.113.0) | 1,095 | 1,095 | 211 (19.3 %) | 230 (21.0 %) | 994 (90.8 %) | 994 (90.8 %) |
| gitleaks | `b58d3f102cf3` | 225 | 158 | 73 (46.2 %) | 74 (46.8 %) | 153 (96.8 %) | 153 (96.8 %) |
| betterleaks | `c613797a6843` | 467 | 360 | 147 (40.8 %) | 152 (42.2 %) | 346 (96.1 %) | 346 (96.1 %) |
| trufflehog | `27d8ea2876d9` | 943 | 890 | 61 (6.9 %) | 66 (7.4 %) | 838 (94.2 %) | 838 (94.2 %) |
| GitLab secret detection rules | `cae5670b0d83` | 217 | 172 | 91 (52.9 %) | 104 (60.5 %) | 161 (93.6 %) | 161 (93.6 %) |

## Timing

Median time of one scan, 15 runs after one warm-up run; "import + first scan" is the median of 5 new processes,
as each hook call is a new process. Machine as above, load average below 4, round 2 of two rounds (the rounds
differ by up to 7 %). Source: `scripts/measure_scan_time.py --maisecrets <v0.6.17>`, 2026-10-14.

| Input | Python 3.14, prompt | Python 3.14, tool | Python 3.9, prompt | Python 3.9, tool |
|---|---|---|---|---|
| import + first scan | 46 ms | 46 ms | 64 ms | 68 ms |
| typed prompt, 1 KB | 1.8 ms | 1.9 ms | 2.1 ms | 2.2 ms |
| Python code, 70 KB | 121 ms | 122 ms | 135 ms | 135 ms |
| log, 70 KB | 80 ms | 80 ms | 96 ms | 94 ms |
| configuration, 70 KB, 2,092 password labels | 187 ms | 185 ms | 242 ms | 241 ms |

## Cloakroom holdout sets, 2026-10-15

Cloakroom's holdout sets v2 to v7 (`bench/holdout_v*.jsonl` at commit `cc3c88d76a`, 2026-10-14): 1,652 planted values
in 470 samples, and 215 clean samples (200 in v2 to v6, 15 in v7). A value counts as leaked when it still appears
after every match is masked. Tool channel (`detect.scan(text, channel="tool")`), `--locale de_DE`. Source: a script
outside this repository that reads the sets and calls `detect.scan`, 2026-10-15. 0.6.20 is tag `v0.6.20`; 0.6.21 is
the release of these rules.

Each sample falls into half D or half C by the first 8 hex digits of sha256 of `<set>/<id>` (even: D). The rules of
0.6.21 were written from the values of half D that 0.6.18 leaked; half C was counted. Half C is the number to read.
Regions `us`, `uk`, `in`:

| Set | Values, D | Leaked D, 0.6.20 → 0.6.21 | Values, C | Leaked C, 0.6.20 → 0.6.21 | Clean samples | False alarms, 0.6.20 → 0.6.21 |
|---|---|---|---|---|---|---|
| v2 | 92 | 36 → 24 | 127 | 46 → 33 | 40 | 1 → 1 |
| v3 | 208 | 88 → 49 | 112 | 48 → 30 | 40 | 1 → 1 |
| v4 | 154 | 86 → 55 | 174 | 90 → 60 | 40 | 2 → 2 |
| v5 | 178 | 85 → 58 | 216 | 116 → 77 | 40 | 2 → 2 |
| v6 | 157 | 83 → 51 | 157 | 80 → 59 | 40 | 0 → 0 |
| v7 | 33 | 2 → 0 | 44 | 1 → 0 | 15 | 1 → 1 |
| v2 to v6 | 789 | 378 → 237 | 786 | 380 → 259 | 200 | 6 → 6 |
| v2 to v7 | 822 | 380 → 237 | 830 | 381 → 259 | 215 | 7 → 7 |

Regions `de`:

| Set | Values, D | Leaked D, 0.6.20 → 0.6.21 | Values, C | Leaked C, 0.6.20 → 0.6.21 | Clean samples | False alarms, 0.6.20 → 0.6.21 |
|---|---|---|---|---|---|---|
| v2 | 92 | 41 → 30 | 127 | 53 → 39 | 40 | 0 → 0 |
| v3 | 208 | 97 → 58 | 112 | 51 → 36 | 40 | 0 → 0 |
| v4 | 154 | 89 → 59 | 174 | 92 → 62 | 40 | 0 → 0 |
| v5 | 178 | 89 → 62 | 216 | 120 → 84 | 40 | 0 → 0 |
| v6 | 157 | 94 → 67 | 157 | 87 → 69 | 40 | 0 → 0 |
| v7 | 33 | 2 → 0 | 44 | 1 → 0 | 15 | 1 → 1 |
| v2 to v6 | 789 | 410 → 276 | 786 | 403 → 290 | 200 | 0 → 0 |
| v2 to v7 | 822 | 412 → 276 | 830 | 404 → 290 | 215 | 1 → 1 |

By class of the planted value (the shape of the value, sorted by the analysis script; for example a name is two to
five capitalised words without a digit), regions `us`, `uk`, `in`:

| Class | Values | Leaked 0.6.20, D / C | Leaked 0.6.21, D / C |
|---|---|---|---|
| names | 324 | 167 / 154 | 103 / 107 |
| user names | 146 | 66 / 79 | 57 / 68 |
| addresses | 26 | 15 / 11 | 14 / 11 |
| birth dates | 72 | 37 / 35 | 9 / 14 |
| ID numbers | 114 | 18 / 18 | 10 / 8 |
| phone numbers | 207 | 12 / 18 | 0 / 6 |
| tokens and passwords | 334 | 31 / 31 | 24 / 24 |
| e-mail addresses | 286 | 0 / 3 | 0 / 3 |
| other | 143 | 34 / 32 | 20 / 18 |

Each new rule alone on 0.6.20: values it closes, half D / half C, and new hits on the sets of ordinary text. "PII
corpus" is `tests/fp_corpus_pii.py` (367 developer texts in the shape of personal data that are none, ten regions);
"developer texts" are 2,464 texts in the tool channel (`tests/fp_corpus.py` and the review corpora of 0.6.15 and
0.6.16) and "prompts" are 771 typed prompts of the maintainers in the prompt channel.

| Rule | Closed, us uk in: D / C | Closed, de: D / C | New false alarms, holdouts | New hits, PII corpus (tool / prompt) | New hits, developer texts | Newly blocked prompts |
|---|---|---|---|---|---|---|
| `name-after-label` | 42 / 21 | 42 / 21 | 0 | 0 / 0 | 0 | 0 |
| `name-before-email` | 23 / 24 | 23 / 24 | 0 | 0 / 0 | 0 | 0 |
| `birth-date-after-label` | 26 / 21 | 26 / 21 | 0 | 0 / 0 | 0 | 0 |
| `street-address` | 14 / 14 | 4 / 3 | 0 | 0 / 0 | 0 | 0 |
| `id-number-after-label` | 12 / 8 | 14 / 11 | 0 | 0 / 0 | 0 | 0 |
| `csv-personal-column` | 10 / 8 | 15 / 9 | 0 | 0 / 0 | 0 | 0 |
| `user-in-home-path` | 5 / 9 | 5 / 9 | 0 | 0 / 0 | 0 | 0 |
| `user-in-url` | 4 / 2 | 4 / 2 | 0 | 0 / 0 | 0 | 0 |
| `phone-one-digit-groups` | 3 / 10 | 3 / 10 | 0 | 0 / 0 | 0 | 0 |
| `phone-us-national` | 4 / 1 | 0 / 0 | 0 | 0 / 0 | 0 | 0 |
| `twilio-account-sid-labelled` | 3 / 5 | 3 / 5 | 0 | 0 / 0 | 0 | 0 |
| `openai-anthropic-key-relaxed` | 3 / 1 | 3 / 1 | 0 | 0 / 0 | 0 | 0 |
| `slack-token-relaxed` | 1 / 1 | 1 / 1 | 0 | 0 / 0 | 0 | 0 |

The rules of 0.6.20 already hit 8 of the 367 texts of the PII corpus (4 by `phone`, one each by `de-vat-id`,
`email`, `us-bank` and `de-plz`); 0.6.21 adds none. The 44 true hits of the corpus (46 values): 0.6.20 masks 8,
0.6.21 masks 46. Two review rounds (codex gpt-5.6-sol and Opus) wrote about 360 more developer snippets; after the
fixes, 12 of 182 and 0 of 98 still give a hit of a new rule, most of them a person's name or path.

Left out after measuring, each alone on 0.6.20 (the closed values are both halves; prompts are the prompt
channel, the rest the tool channel):

| Rule | Closed, us uk in | New false alarms, v2 to v6 | New hits, PII corpus | New hits, developer texts | Newly blocked prompts |
|---|---|---|---|---|---|
| a user name after a user label (`user:`, `login:`, `requested by`) | 55 | 3 | 4 | 68 | 28 |
| a password after a password word in prose | 5 | 0 | 0 | 80 | 53 |
| a random token after a token word in prose | 11 | 0 | 0 | 17 | 5 |

An AWS key id with any capital and digit was left out on CredData (+105 credentials, +48 false alarms, precision
−0.006, holdout analysis of 2026-10-14); a Twilio Account SID without its name was left out as an id of other uses.

The values 0.6.21 still leaks (regions `us`, `uk`, `in`), by class and by reason. A name or an address without a
label or a postcode needs a model; a user name or a date with no label is ambiguous without context; "left out" are
the values that one of the three rules above would close; the rest is a remaining gap:

| Class | needs a model (no label, no postcode) | ambiguous without context | left out for its false hits | remaining gap |
|---|---|---|---|---|
| names | 210 | 0 | 0 | 0 |
| user names | 0 | 79 | 46 | 0 |
| addresses | 25 | 0 | 0 | 0 |
| birth dates | 0 | 23 | 0 | 0 |
| ID numbers | 0 | 0 | 0 | 18 |
| phone numbers | 0 | 0 | 0 | 6 |
| tokens and passwords | 0 | 0 | 11 | 37 |
| e-mail addresses | 0 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 38 |
| all | 235 | 102 | 57 | 102 |

The rules of 0.6.20 already hit 8 of the 367 texts of the PII corpus (4 by `phone`, one each by `de-vat-id`, `email`,
`us-bank` and `de-plz`); 0.6.21 adds none. The 44 true hits of the corpus (46 values): 0.6.20 masks 8, 0.6.21 masks
46. Two review rounds (codex gpt-5.6-sol and Opus) wrote about 360 more developer snippets; after the fixes, 12 of 182
and 0 of 98 still give a hit of a new rule, most of them a person's name or path. CredData and the time per scan of
0.6.21 are in the release tables above.

Limits of this measurement:

- This is a result on Cloakroom's benchmark, not on an unseen holdout. The analysis of 2026-10-14 sorted all 765
  values that 0.6.18 leaked by class, in both halves, so the classes of half C were seen; the rule texts came from the
  values of half D. The false alarms of both halves were read and the rules changed after them.
- Two rule families come from Cloakroom's code: a name before an e-mail address and the columns of a CSV header
  (Apache-2.0, credited in the commits and in "Credit"); the code here is written anew.
- Cloakroom tuned its own engine on v2 to v5 after their first run; v6 is its set that was never tuned on (their
  `bench/RESULTS.md`).

## Labelled PII datasets, 2026-10-15

Four public datasets with labelled personal data and secrets. "0.6.21" is tag `v0.6.21`; "0.6.20" is tag `v0.6.20`.
Regions by language (`us` for English text), the locale of the language (`en_US` for English). Source:
`scripts/measure_datasets.py run`, 2026-10-15; "Method and limits" and "Repeat this measurement" below have the
details.

| Dataset | Version | Licence and attribution | Samples | Records left out |
|---|---|---|---|---|
| [Gretel synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) | Hugging Face commit `7b844d16738527a04264f50214cb426a4cea0897`, `data/train` and `data/test` | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), Gretel.ai | 41,932 documents in 7 languages | 14,008 below Gretel's `quality_score` 90 |
| [NVIDIA Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) | Hugging Face commit `b70ffaf5ff39e079776134c5bf4381f00a9fd1ed`, `data/test` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), NVIDIA | 100,000 documents (50,000 `us`, 50,000 `intl` locale) | 0 |
| [Synthetic Dataset for PII Detection and Anonymization in Financial Documents](https://doi.org/10.17632/tzrjx692jy.1) (Mendeley Data) | version 1, doi 10.17632/tzrjx692jy.1 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), the authors named at the DOI | 45,030 documents (`Training_Set.xlsx`, `Testing_Set.xlsx`) | 0; 5,003 texts repaired (mojibake) |
| [PIILO](https://www.kaggle.com/datasets/lburleigh/piilo-dataset) (PII Labeling and Obfuscation) | Kaggle dataset version 2 (2024-10-03), `train.json` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), "PIILO © 2024 by The Learning Agency Lab" | 6,807 student essays | 0 |

The script pins the sha256 of each file. No dataset value enters this repository; the tables hold counts. The script
cleans the labels as "Method and limits" says and repairs Mendeley's text in memory; it changes no file.

Per type, one row per channel. "Values" are the labelled values that stay after the cleaning. P counts detections, R
counts values ("Method and limits", "Scoring"). "R, own type" counts a value as found only by a detection of its own
type; "R, covered" only when the detections cover all of it. "R raw" is the recall over the labels before the
cleaning, at their original offsets. A type with no labelled values has a row when it has detections. "F1 0.6.20" is
the same row for tag `v0.6.20`. The types NAME, ADDRESS, BIRTH_DATE, ID_NUMBER and USERNAME (tier "personal") have
rules from 0.6.21, in the tool channel only (`maisecrets/personal.py`); 0.6.20 has none.


### Gretel

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| SECRET | 1,415 | 1,411 | 0 | 0 | 0 | 0 | 0 | 4 |
| EMAIL | 10,657 | 8,556 | 457 | 65 | 1,794: no value of its type 1, reserved domain 1,694, syntax 99 | 224 | 0 | 18 |
| PHONE | 6,857 | 4,563 | 71 | 16 | 2,053: digit count 28, letters 14, no value of its type 29, placeholder 1,982 | 208 | 0 | 17 |
| IP | 2,324 | 2,073 | 0 | 0 | 246: not public 193, syntax 53 | 0 | 0 | 5 |
| IBAN | 1,530 | 1,185 | 7 | 6 | 336: checksum 336 | 0 | 0 | 3 |
| CARD | 1,012 | 501 | 1 | 0 | 508: checksum 508 | 0 | 0 | 3 |
| US_SSN | 1,117 | 774 | 148 | 0 | 343: checksum 343 | 0 | 0 | 0 |
| ABA_ROUTING_NUMBER | 1,178 | 129 | 0 | 0 | 1,046: checksum 1,046 | 0 | 0 | 3 |
| NAME | 78,600 | 77,117 | 0 | 1,327 | 0 | 0 | 0 | 156 |
| ADDRESS | 31,618 | 31,414 | 0 | 160 | 0 | 0 | 0 | 44 |
| BIRTH_DATE | 1,916 | 1,912 | 0 | 1 | 0 | 0 | 0 | 3 |
| ID_NUMBER | 2,284 | 2,273 | 0 | 4 | 0 | 0 | 0 | 7 |
| USERNAME | 729 | 725 | 0 | 0 | 0 | 0 | 0 | 4 |

132,457 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a
false alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SECRET | prompt | 1,411 | 515 | 896 | 95 | 0.844 | 0.365 | 0.510 | 0.364 | 0.364 | 0.365 | 0.510 |
| SECRET | tool | 1,411 | 530 | 881 | 101 | 0.840 | 0.376 | 0.519 | 0.375 | 0.374 | 0.376 | 0.519 |
| EMAIL | prompt | 8,556 | 8,551 | 5 | 56 | 0.994 | 0.999 | 0.996 | 0.999 | 0.994 | 0.809 | 0.996 |
| EMAIL | tool | 8,556 | 8,551 | 5 | 56 | 0.994 | 0.999 | 0.996 | 0.999 | 0.994 | 0.809 | 0.996 |
| PHONE | prompt | 4,563 | 2,567 | 1,996 | 317 | 0.889 | 0.563 | 0.689 | 0.556 | 0.545 | 0.457 | 0.689 |
| PHONE | tool | 4,563 | 2,752 | 1,811 | 332 | 0.891 | 0.603 | 0.719 | 0.596 | 0.577 | 0.485 | 0.689 |
| IP | prompt | 2,073 | 1,929 | 144 | 28 | 0.986 | 0.930 | 0.957 | 0.930 | 0.930 | 0.834 | 0.957 |
| IP | tool | 2,073 | 1,929 | 144 | 28 | 0.986 | 0.930 | 0.957 | 0.930 | 0.930 | 0.834 | 0.957 |
| IBAN | prompt | 1,185 | 1,160 | 25 | 43 | 0.964 | 0.979 | 0.972 | 0.977 | 0.977 | 0.764 | 0.972 |
| IBAN | tool | 1,185 | 1,160 | 25 | 43 | 0.964 | 0.979 | 0.972 | 0.977 | 0.977 | 0.764 | 0.972 |
| CARD | prompt | 501 | 222 | 279 | 10 | 0.951 | 0.443 | 0.605 | 0.389 | 0.443 | 0.227 | 0.605 |
| CARD | tool | 501 | 223 | 278 | 10 | 0.951 | 0.445 | 0.606 | 0.389 | 0.445 | 0.309 | 0.605 |
| US_SSN | prompt | 774 | 460 | 314 | 51 | 0.894 | 0.594 | 0.714 | 0.558 | 0.592 | 0.421 | 0.714 |
| US_SSN | tool | 774 | 475 | 299 | 51 | 0.894 | 0.614 | 0.728 | 0.558 | 0.611 | 0.436 | 0.714 |
| ABA_ROUTING_NUMBER | prompt | 129 | 44 | 85 | 25 | 0.432 | 0.341 | 0.381 | 0.147 | 0.341 | 0.367 | 0.381 |
| ABA_ROUTING_NUMBER | tool | 129 | 45 | 84 | 25 | 0.432 | 0.349 | 0.386 | 0.147 | 0.349 | 0.371 | 0.381 |
| US_BANK_NUMBER | prompt | 0 | 0 | 0 | 3,276 | 0.000 | – | – | – | – | – | – |
| US_BANK_NUMBER | tool | 0 | 0 | 0 | 3,276 | 0.000 | – | – | – | – | – | – |
| NAME | prompt | 77,117 | 232 | 76,885 | 0 | – | 0.003 | – | 0.000 | 0.003 | 0.003 | – |
| NAME | tool | 77,117 | 5,873 | 71,244 | 32 | 0.994 | 0.076 | 0.141 | 0.073 | 0.059 | 0.076 | – |
| ADDRESS | prompt | 31,414 | 167 | 31,247 | 0 | – | 0.005 | – | 0.000 | 0.000 | 0.005 | – |
| ADDRESS | tool | 31,414 | 922 | 30,492 | 105 | 0.883 | 0.029 | 0.057 | 0.025 | 0.020 | 0.029 | – |
| BIRTH_DATE | prompt | 1,912 | 2 | 1,910 | 0 | – | 0.001 | – | 0.000 | 0.001 | 0.001 | – |
| BIRTH_DATE | tool | 1,912 | 1,186 | 726 | 85 | 0.933 | 0.620 | 0.745 | 0.619 | 0.620 | 0.620 | – |
| ID_NUMBER | prompt | 2,273 | 914 | 1,359 | 0 | – | 0.402 | – | 0.000 | 0.294 | 0.402 | – |
| ID_NUMBER | tool | 2,273 | 1,092 | 1,181 | 77 | 0.698 | 0.480 | 0.569 | 0.078 | 0.373 | 0.480 | – |
| USERNAME | prompt | 725 | 55 | 670 | 0 | – | 0.076 | – | 0.000 | 0.076 | 0.076 | – |
| USERNAME | tool | 725 | 57 | 668 | 5 | 0.286 | 0.079 | 0.123 | 0.003 | 0.079 | 0.079 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 15,448 | 3,744 | 3,901 | 0.797 | 0.805 | 0.801 | 0.801 |
| core | region `de` | prompt | 969 | 306 | 61 | 0.941 | 0.760 | 0.841 | 0.841 |
| core | region `es` | prompt | 1,419 | 269 | 52 | 0.965 | 0.841 | 0.898 | 0.898 |
| core | region `fr` | prompt | 1,192 | 303 | 60 | 0.952 | 0.797 | 0.868 | 0.868 |
| core | region `it` | prompt | 1,213 | 268 | 48 | 0.962 | 0.819 | 0.885 | 0.885 |
| core | region `nl` | prompt | 1,239 | 479 | 26 | 0.979 | 0.721 | 0.831 | 0.831 |
| core | region `se` | prompt | 1,197 | 404 | 50 | 0.959 | 0.748 | 0.840 | 0.840 |
| core | region `us` | prompt | 8,219 | 1,715 | 3,604 | 0.693 | 0.827 | 0.754 | 0.754 |
| core | `format:structured` | prompt | 2,288 | 963 | 2,883 | 0.440 | 0.704 | 0.541 | 0.541 |
| core | `format:unstructured` | prompt | 13,160 | 2,781 | 1,018 | 0.928 | 0.826 | 0.874 | 0.874 |
| core | all | tool | 15,665 | 3,527 | 3,922 | 0.798 | 0.816 | 0.807 | 0.801 |
| core | region `de` | tool | 975 | 300 | 61 | 0.941 | 0.765 | 0.844 | 0.842 |
| core | region `es` | tool | 1,421 | 267 | 52 | 0.965 | 0.842 | 0.899 | 0.898 |
| core | region `fr` | tool | 1,192 | 303 | 61 | 0.951 | 0.797 | 0.868 | 0.868 |
| core | region `it` | tool | 1,213 | 268 | 48 | 0.962 | 0.819 | 0.885 | 0.885 |
| core | region `nl` | tool | 1,245 | 473 | 26 | 0.979 | 0.725 | 0.833 | 0.831 |
| core | region `se` | tool | 1,200 | 401 | 50 | 0.959 | 0.750 | 0.842 | 0.840 |
| core | region `us` | tool | 8,419 | 1,515 | 3,624 | 0.697 | 0.848 | 0.765 | 0.755 |
| core | `format:structured` | tool | 2,325 | 926 | 2,902 | 0.441 | 0.715 | 0.546 | 0.543 |
| core | `format:unstructured` | tool | 13,340 | 2,601 | 1,020 | 0.928 | 0.837 | 0.880 | 0.874 |
| personal | all | prompt | 1,370 | 112,071 | 0 | – | 0.012 | – | – |
| personal | region `de` | prompt | 194 | 9,690 | 0 | – | 0.020 | – | – |
| personal | region `es` | prompt | 11 | 9,863 | 0 | – | 0.001 | – | – |
| personal | region `fr` | prompt | 43 | 8,182 | 0 | – | 0.005 | – | – |
| personal | region `it` | prompt | 45 | 9,394 | 0 | – | 0.005 | – | – |
| personal | region `nl` | prompt | 18 | 12,198 | 0 | – | 0.002 | – | – |
| personal | region `se` | prompt | 29 | 11,672 | 0 | – | 0.003 | – | – |
| personal | region `us` | prompt | 1,030 | 51,072 | 0 | – | 0.020 | – | – |
| personal | `format:structured` | prompt | 230 | 20,179 | 0 | – | 0.011 | – | – |
| personal | `format:unstructured` | prompt | 1,140 | 91,892 | 0 | – | 0.012 | – | – |
| personal | all | tool | 9,130 | 104,311 | 304 | 0.962 | 0.081 | 0.148 | – |
| personal | region `de` | tool | 826 | 9,058 | 64 | 0.913 | 0.084 | 0.153 | – |
| personal | region `es` | tool | 555 | 9,319 | 23 | 0.959 | 0.056 | 0.106 | – |
| personal | region `fr` | tool | 635 | 7,590 | 14 | 0.977 | 0.077 | 0.143 | – |
| personal | region `it` | tool | 840 | 8,599 | 43 | 0.949 | 0.089 | 0.163 | – |
| personal | region `nl` | tool | 248 | 11,968 | 12 | 0.950 | 0.020 | 0.040 | – |
| personal | region `se` | tool | 323 | 11,378 | 15 | 0.951 | 0.028 | 0.054 | – |
| personal | region `us` | tool | 5,703 | 46,399 | 133 | 0.972 | 0.110 | 0.197 | – |
| personal | `format:structured` | tool | 1,254 | 19,155 | 154 | 0.868 | 0.061 | 0.115 | – |
| personal | `format:unstructured` | tool | 7,876 | 85,156 | 150 | 0.978 | 0.085 | 0.156 | – |

Detections of a type of no tier on no labelled value, 0.6.21: prompt 1,053 (0.6.20: 1,053), tool 1,048 (0.6.20:
1,053). By type, tool channel: DE_PLZ 274, US_DRIVER_LICENSE 246, US_PASSPORT 191, IT_VAT_CODE 132, SE_PERSONNUMMER
97, US_NPI 40, SE_ORGANISATIONSNUMMER 34, DE_TAX_NUMBER 11, DE_KFZ 6, ES_NIF 6, DE_VAT_ID 5, US_ITIN 3, IT_FISCAL_CODE
2, MEDICAL_LICENSE 1.

### Nemotron-PII

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| SECRET | 11,652 | 11,652 | 0 | 0 | 0 | 0 | 0 | 0 |
| EMAIL | 53,930 | 53,550 | 48 | 0 | 105: reserved domain 92, syntax 13 | 275 | 0 | 0 |
| PHONE | 30,353 | 30,240 | 7 | 0 | 113: digit count 2, no value of its type 1, placeholder 110 | 0 | 0 | 0 |
| IP | 9,217 | 7,971 | 3 | 0 | 1,246: no value of its type 7, not public 955, syntax 284 | 0 | 0 | 0 |
| CARD | 12,867 | 1,527 | 2 | 0 | 11,340: checksum 11,340 | 0 | 0 | 0 |
| US_SSN | 6,062 | 6,035 | 1 | 0 | 27: checksum 25, no value of its type 2 | 0 | 0 | 0 |
| ABA_ROUTING_NUMBER | 8,354 | 843 | 0 | 0 | 7,511: checksum 7,511 | 0 | 0 | 0 |
| US_BANK_NUMBER | 16,693 | 11,660 (6 more are IBANs) | 0 | 0 | 5,027: digit count 9, letters 5,018 | 0 | 0 | 0 |
| NAME | 143,639 | 143,639 | 0 | 0 | 0 | 0 | 0 | 0 |
| ADDRESS | 16,879 | 16,879 | 0 | 0 | 0 | 0 | 0 | 0 |
| BIRTH_DATE | 18,079 | 18,079 | 0 | 0 | 0 | 0 | 0 | 0 |
| ID_NUMBER | 28,807 | 28,807 | 0 | 0 | 0 | 0 | 0 | 0 |
| USERNAME | 15,800 | 15,800 | 0 | 0 | 0 | 0 | 0 | 0 |

478,008 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a
false alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SECRET | prompt | 11,652 | 2,841 | 8,811 | 33 | 0.988 | 0.244 | 0.391 | 0.242 | 0.239 | 0.244 | 0.391 |
| SECRET | tool | 11,652 | 2,852 | 8,800 | 33 | 0.988 | 0.245 | 0.392 | 0.242 | 0.239 | 0.245 | 0.392 |
| EMAIL | prompt | 53,550 | 53,550 | 0 | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.993 | 1.000 |
| EMAIL | tool | 53,550 | 53,550 | 0 | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.993 | 1.000 |
| PHONE | prompt | 30,240 | 7,004 | 23,236 | 19 | 0.997 | 0.232 | 0.376 | 0.229 | 0.230 | 0.231 | 0.376 |
| PHONE | tool | 30,240 | 8,034 | 22,206 | 24 | 0.997 | 0.266 | 0.419 | 0.263 | 0.264 | 0.265 | 0.376 |
| IP | prompt | 7,971 | 7,958 | 13 | 62 | 0.992 | 0.998 | 0.995 | 0.998 | 0.998 | 0.864 | 0.995 |
| IP | tool | 7,971 | 7,958 | 13 | 62 | 0.992 | 0.998 | 0.995 | 0.998 | 0.998 | 0.864 | 0.995 |
| IBAN | prompt | 6 | 5 | 1 | 3 | 0.500 | 0.833 | 0.625 | 0.500 | 0.500 | – | 0.625 |
| IBAN | tool | 6 | 5 | 1 | 3 | 0.500 | 0.833 | 0.625 | 0.500 | 0.500 | – | 0.625 |
| CARD | prompt | 1,527 | 1,458 | 69 | 1 | 0.999 | 0.955 | 0.977 | 0.951 | 0.955 | 0.117 | 0.977 |
| CARD | tool | 1,527 | 1,458 | 69 | 1 | 0.999 | 0.955 | 0.977 | 0.951 | 0.955 | 0.118 | 0.977 |
| US_SSN | prompt | 6,035 | 6,033 | 2 | 424 | 0.934 | 1.000 | 0.966 | 1.000 | 1.000 | 0.995 | 0.966 |
| US_SSN | tool | 6,035 | 6,033 | 2 | 424 | 0.934 | 1.000 | 0.966 | 1.000 | 1.000 | 0.995 | 0.966 |
| ABA_ROUTING_NUMBER | prompt | 843 | 834 | 9 | 3 | 0.996 | 0.989 | 0.993 | 0.989 | 0.989 | 0.973 | 0.993 |
| ABA_ROUTING_NUMBER | tool | 843 | 834 | 9 | 3 | 0.996 | 0.989 | 0.993 | 0.989 | 0.989 | 0.973 | 0.993 |
| US_BANK_NUMBER | prompt | 11,660 | 7,818 | 3,842 | 115 | 0.986 | 0.670 | 0.798 | 0.669 | 0.480 | 0.477 | 0.798 |
| US_BANK_NUMBER | tool | 11,660 | 10,018 | 1,642 | 115 | 0.986 | 0.859 | 0.918 | 0.669 | 0.669 | 0.802 | 0.798 |
| NAME | prompt | 143,639 | 49 | 143,590 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| NAME | tool | 143,639 | 4,509 | 139,130 | 12 | 0.995 | 0.031 | 0.061 | 0.031 | 0.031 | 0.031 | – |
| ADDRESS | prompt | 16,879 | 2 | 16,877 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | tool | 16,879 | 262 | 16,617 | 0 | 1.000 | 0.015 | 0.031 | 0.015 | 0.015 | 0.015 | – |
| BIRTH_DATE | prompt | 18,079 | 0 | 18,079 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| BIRTH_DATE | tool | 18,079 | 5,286 | 12,793 | 1 | 1.000 | 0.292 | 0.453 | 0.292 | 0.292 | 0.292 | – |
| ID_NUMBER | prompt | 28,807 | 4,350 | 24,457 | 0 | – | 0.151 | – | 0.000 | 0.079 | 0.151 | – |
| ID_NUMBER | tool | 28,807 | 4,701 | 24,106 | 14 | 0.962 | 0.163 | 0.279 | 0.012 | 0.091 | 0.163 | – |
| USERNAME | prompt | 15,800 | 43 | 15,757 | 0 | – | 0.003 | – | 0.000 | 0.003 | 0.003 | – |
| USERNAME | tool | 15,800 | 43 | 15,757 | 0 | – | 0.003 | – | 0.000 | 0.003 | 0.003 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 87,501 | 35,983 | 666 | 0.992 | 0.709 | 0.827 | 0.827 |
| core | `format:structured` | prompt | 47,708 | 19,367 | 405 | 0.992 | 0.711 | 0.828 | 0.828 |
| core | `format:unstructured` | prompt | 39,793 | 16,616 | 261 | 0.994 | 0.705 | 0.825 | 0.825 |
| core | `locale:intl` | prompt | 50,723 | 14,656 | 532 | 0.990 | 0.776 | 0.870 | 0.870 |
| core | `locale:us` | prompt | 36,778 | 21,327 | 134 | 0.996 | 0.633 | 0.774 | 0.774 |
| core | all | tool | 90,742 | 32,742 | 671 | 0.993 | 0.735 | 0.844 | 0.827 |
| core | `format:structured` | tool | 49,274 | 17,801 | 410 | 0.992 | 0.735 | 0.844 | 0.828 |
| core | `format:unstructured` | tool | 41,468 | 14,941 | 261 | 0.994 | 0.735 | 0.845 | 0.825 |
| core | `locale:intl` | tool | 52,769 | 12,610 | 533 | 0.990 | 0.807 | 0.889 | 0.870 |
| core | `locale:us` | tool | 37,973 | 20,132 | 138 | 0.996 | 0.653 | 0.789 | 0.774 |
| personal | all | prompt | 4,444 | 218,760 | 0 | – | 0.020 | – | – |
| personal | `format:structured` | prompt | 2,348 | 111,993 | 0 | – | 0.021 | – | – |
| personal | `format:unstructured` | prompt | 2,096 | 106,767 | 0 | – | 0.019 | – | – |
| personal | `locale:intl` | prompt | 1,510 | 108,856 | 0 | – | 0.014 | – | – |
| personal | `locale:us` | prompt | 2,934 | 109,904 | 0 | – | 0.026 | – | – |
| personal | all | tool | 14,801 | 208,403 | 27 | 0.997 | 0.066 | 0.124 | – |
| personal | `format:structured` | tool | 10,553 | 103,788 | 19 | 0.997 | 0.092 | 0.169 | – |
| personal | `format:unstructured` | tool | 4,248 | 104,615 | 8 | 0.995 | 0.039 | 0.075 | – |
| personal | `locale:intl` | tool | 7,240 | 103,126 | 16 | 0.997 | 0.066 | 0.123 | – |
| personal | `locale:us` | tool | 7,561 | 105,277 | 11 | 0.997 | 0.067 | 0.126 | – |

Detections of a type of no tier on no labelled value, 0.6.21: prompt 146 (0.6.20: 146), tool 146 (0.6.20: 146). By
type, tool channel: US_DRIVER_LICENSE 106, US_PASSPORT 20, US_NPI 10, MEDICAL_LICENSE 9, US_ITIN 1.

### Mendeley financial documents

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| EMAIL | 34,637 | 0 | 0 | 0 | 34,637: reserved domain 34,637 | 0 | 0 | 0 |
| PHONE | 45,028 | 45,028 | 0 | 0 | 0 | 0 | 0 | 0 |
| CARD | 42,527 | 39,060 | 39,060 | 0 | 3,467: checksum 3,102, no value of its type 365 | 0 | 0 | 0 |
| US_SSN | 51,283 | 51,283 | 0 | 0 | 0 | 0 | 0 | 0 |
| NAME | 77,200 | 77,200 | 0 | 0 | 0 | 0 | 0 | 0 |
| ADDRESS | 46,264 | 46,264 | 0 | 0 | 0 | 0 | 0 | 0 |

100,461 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a
false alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PHONE | prompt | 45,028 | 42,268 | 2,760 | 0 | 1.000 | 0.939 | 0.968 | 0.911 | 0.911 | 0.939 | 0.968 |
| PHONE | tool | 45,028 | 42,268 | 2,760 | 0 | 1.000 | 0.939 | 0.968 | 0.911 | 0.911 | 0.939 | 0.968 |
| CARD | prompt | 39,060 | 31,687 | 7,373 | 0 | 1.000 | 0.811 | 0.896 | 0.677 | 0.811 | 0.757 | 0.896 |
| CARD | tool | 39,060 | 31,687 | 7,373 | 0 | 1.000 | 0.811 | 0.896 | 0.677 | 0.811 | 0.757 | 0.896 |
| US_SSN | prompt | 51,283 | 51,283 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| US_SSN | tool | 51,283 | 51,283 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| NAME | prompt | 77,200 | 0 | 77,200 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| NAME | tool | 77,200 | 0 | 77,200 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | prompt | 46,264 | 0 | 46,264 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | tool | 46,264 | 0 | 46,264 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 125,238 | 10,133 | 0 | 1.000 | 0.925 | 0.961 | 0.961 |
| core | all | tool | 125,238 | 10,133 | 0 | 1.000 | 0.925 | 0.961 | 0.961 |
| personal | all | prompt | 0 | 123,464 | 0 | – | 0.000 | – | – |
| personal | all | tool | 0 | 123,464 | 0 | – | 0.000 | – | – |

Detections of a type of no tier on no labelled value: 0 in both channels.

### PIILO

Cleaning, labelled values per type:

| Type | Labelled | Kept as a value | Of these trimmed | Merged (labelled twice) | Uncertain, by reason | Negative (label error) | Offset moved | Dropped (offset outside the text) |
|---|---|---|---|---|---|---|---|---|
| EMAIL | 39 | 39 | 0 | 0 | 0 | 0 | 0 | 0 |
| PHONE | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| NAME | 1,365 | 1,365 | 0 | 0 | 0 | 0 | 0 | 0 |
| ADDRESS | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| ID_NUMBER | 78 | 78 | 0 | 0 | 0 | 0 | 0 | 0 |
| USERNAME | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

110 more labels have no type that maisecrets claims (`OUT_OF_SCOPE`); a detection on one is neither a find nor a false
alarm.

Results per type, 0.6.21:

| Type | Channel | Values | TP | FN | FP | P | R | F1 | R, own type | R, covered | R raw | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EMAIL | prompt | 39 | 39 | 0 | 1 | 0.975 | 1.000 | 0.987 | 1.000 | 1.000 | 1.000 | 0.987 |
| EMAIL | tool | 39 | 39 | 0 | 1 | 0.975 | 1.000 | 0.987 | 1.000 | 1.000 | 1.000 | 0.987 |
| PHONE | prompt | 6 | 0 | 6 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| PHONE | tool | 6 | 4 | 2 | 0 | 1.000 | 0.667 | 0.800 | 0.667 | 0.167 | 0.667 | – |
| IP | prompt | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| IP | tool | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| US_BANK_NUMBER | prompt | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| US_BANK_NUMBER | tool | 0 | 0 | 0 | 1 | 0.000 | – | – | – | – | – | – |
| NAME | prompt | 1,365 | 0 | 1,365 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| NAME | tool | 1,365 | 85 | 1,280 | 0 | 1.000 | 0.062 | 0.117 | 0.062 | 0.062 | 0.062 | – |
| ADDRESS | prompt | 2 | 0 | 2 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ADDRESS | tool | 2 | 0 | 2 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| ID_NUMBER | prompt | 78 | 2 | 76 | 0 | – | 0.026 | – | 0.000 | 0.026 | 0.026 | – |
| ID_NUMBER | tool | 78 | 2 | 76 | 0 | – | 0.026 | – | 0.000 | 0.026 | 0.026 | – |
| USERNAME | prompt | 6 | 0 | 6 | 0 | – | 0.000 | – | 0.000 | 0.000 | 0.000 | – |
| USERNAME | tool | 6 | 0 | 6 | 2 | 0.000 | 0.000 | – | 0.000 | 0.000 | 0.000 | – |

Results per tier, region and tag, 0.6.21:

| Tier | Part | Channel | TP | FN | FP | P | R | F1 | F1 0.6.20 |
|---|---|---|---|---|---|---|---|---|---|
| core | all | prompt | 39 | 6 | 3 | 0.929 | 0.867 | 0.897 | 0.897 |
| core | all | tool | 43 | 2 | 3 | 0.935 | 0.956 | 0.945 | 0.897 |
| personal | all | prompt | 2 | 1,449 | 0 | – | 0.001 | – | – |
| personal | all | tool | 87 | 1,364 | 2 | 0.977 | 0.060 | 0.113 | – |

Detections of a type of no tier on no labelled value: 0 in both channels.

### Label to type

A dataset label maps to the maisecrets type below; every other label is `OUT_OF_SCOPE`. The tables are `LABELS` in
`scripts/measure_datasets.py`.

| Type | Gretel | Nemotron-PII | Mendeley | PIILO |
|---|---|---|---|---|
| SECRET | `password`, `api_key` | `password`, `api_key` | – | – |
| EMAIL | `email` | `email` | `email` | `EMAIL` |
| PHONE | `phone_number` | `phone_number`, `fax_number` | `phone` | `PHONE_NUM` |
| IP | `ipv4`, `ipv6` | `ipv4`, `ipv6` | – | – |
| IBAN | `iban` | an `account_number` that is a valid IBAN | – | – |
| CARD | `credit_card_number` | `credit_debit_card` | `credit_card` | – |
| US_SSN | `ssn` | `ssn` | `ssn` | – |
| ABA_ROUTING_NUMBER | `bank_routing_number` | `bank_routing_number` | – | – |
| US_BANK_NUMBER | – | `account_number` | – | – |
| NAME | `name`, `first_name`, `last_name` | `first_name`, `last_name` | `name` | `NAME_STUDENT` |
| ADDRESS | `street_address` | `street_address` | `address` | `STREET_ADDRESS` |
| BIRTH_DATE | `date_of_birth` | `date_of_birth` | – | – |
| ID_NUMBER | `passport_number`, `driver_license_number` | `national_id`, `tax_id`, `medical_record_number`, `health_plan_beneficiary_number`, `certificate_license_number` | – | `ID_NUM` |
| USERNAME | `user_name` | `user_name` | – | `USERNAME` |

## Rule classes, 2026-10-15

What each class of rules adds at the margin: the script switches one class off and scans every input again
(`scripts/measure_rule_classes.py`, regions `de`, `--locale de_DE`). When a class is off, another rule can still
take the span, so a number counts what only that class catches. The classes come from the rule registry
(`maisecrets/registry.py`, `coarse_class`): a token class per source, one class per label rule, a PII class per
type and region. `maisecrets rules list` shows the class of each rule.

Base, all rules on:

| Input | Items | Prompt channel | Tool channel |
|---|---:|---:|---:|
| CredData, T values masked | 14471 | 9396 | 9913 |
| CredData, F lines with a masked F value | 9439 | 324 | 329 |
| Developer texts (`tests/fp_corpus.py`), HIT values masked | 139 | 139 | 139 |
| Developer texts, NO_HIT snippets with a hit | 1114 | 0 | 0 |
| PII corpus (`tests/fp_corpus_pii.py`), POSITIVE values masked | 46 | 6 | 41 |
| PII corpus, PII_NO_HIT samples with a hit | 367 | 7 | 7 |
| Cloakroom holdout v2 to v7, planted values masked | 1652 | 854 | 1086 |
| Cloakroom holdout, clean samples with a hit | 215 | 1 | 1 |

Per class, sorted by the values it alone catches (tool channel, CredData plus holdout plus PII corpus). "Lost" is a
value the base masks and the variant does not; "saved" is an input that has a false hit in the base and none in the
variant. The other corpora are in the tool channel.

| Class | Rules | CredData T values lost, prompt / tool | CredData F lines saved, prompt / tool | Developer texts: HIT values lost / NO_HIT saved | PII corpus: POSITIVE values lost / PII_NO_HIT saved | Holdout v2-v7: values lost / clean samples saved |
|---|---:|---:|---:|---:|---:|---:|
| `label:generic-api-key` | 1 | 3561 / 3563 | 58 / 60 | 0 / 0 | 0 / 0 | 5 / 0 |
| `label:auth-scheme` | 1 | 767 / 766 | 0 / 0 | 0 / 0 | 0 / 0 | 3 / 0 |
| `label:literal` | 4 | 230 / 741 | 7 / 9 | 7 / 0 | 0 / 0 | 3 / 0 |
| `label:keyword` | 16 | 1007 / 588 | 140 / 134 | 64 / 0 | 0 / 0 | 23 / 0 |
| `token:betterleaks` | 416 | 318 / 303 | 18 / 18 | 5 / 0 | 0 / 0 | 64 / 0 |
| `pii:email` | 2 | 9 / 9 | 20 / 20 | 2 / 0 | 0 / 1 | 297 / 0 |
| `token:own-secret` | 21 | 233 / 220 | 3 / 3 | 3 / 0 | 0 / 0 | 10 / 0 |
| `pii:phone` | 3 | 0 / 0 | 0 / 0 | 3 / 0 | 3 / 4 | 177 / 0 |
| `token:detect-secrets` | 1 | 128 / 128 | 7 / 7 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:name` | 2 | 0 / 0 | 0 / 0 | 0 / 0 | 11 / 0 | 100 / 0 |
| `pii:ip` | 5 | 0 / 0 | 15 / 15 | 0 / 0 | 0 / 0 | 61 / 0 |
| `pii:birth_date` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 8 / 0 | 47 / 0 |
| `pii:id_number` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 8 / 0 | 25 / 0 |
| `pii:column` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 3 / 0 | 24 / 0 |
| `pii:iban` | 2 | 2 / 1 | 0 / 0 | 2 / 0 | 0 / 0 | 24 / 0 |
| `pii:username` | 2 | 0 / 0 | 0 / 1 | 0 / 0 | 4 / 0 | 20 / 0 |
| `pii:card` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 18 / 0 |
| `pii:address` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 | 7 / 0 |
| `token:fallback` | 4 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 6 / 0 |
| `pii:de_plz@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 1 | 4 / 0 |
| `label:url-query-secret` | 1 | 1 / 1 | 7 / 7 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_passport@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 | 0 / 0 |
| `token:own-json` | 9 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 |
| `label:auth-scheme-apikey` | 1 | 0 / 0 | 0 / 0 | 2 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_bsnr@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_fuehrerschein@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_health_insurance@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_id_card@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_kfz@de` | 5 | 0 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_lanr@de` | 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_social_security@de` | 3 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_tax_id@de` | 2 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_tax_number@de` | 3 | 0 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 0 / 0 |
| `pii:de_vat_id@de` | 2 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 1 | 0 / 0 |
| `token:prefixes` | 44 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

With a class switched off, the variant also masked values that the base leaves: `label:url-query-secret` off: 3 / 3 recall gained (creddata, prompt / tool); `token:own-secret` off: 1 / 1 recall gained (creddata, prompt / tool). There the class
takes a span, and with the class off a later rule masks the value. The rule order stays as measured; a change of
it is a change of its own.

Inputs: CredData as in "CredData, results per release" (every unique labelled line, 23155 lines;
a T value counts once per line); Cloakroom's holdout sets v2 to v7 as in "Cloakroom holdout sets"; the two test
corpora of this tree. A run takes about 45 seconds with 6 workers: only an input with a hit of the class in the
base can change, so the script scans the variant on those inputs only, and it checks on 2 % of the inputs that the
base with every rule enabled by key equals the plain scan.
## Comparison with other tools

"Theirs" is Cloakroom's
[`bench/RESULTS.md`](https://github.com/shanjeevrajendran/cloakroom/blob/cf4360c8bd/bench/RESULTS.md) at commit
`cf4360c8bd` (2026-10-12); each cell names the version and the date that file gives. Their maisecrets runs equal
`--regions us` here. "Ours" is a script of this repository, 2026-10-14, unless the cell says otherwise. Machines
and inputs differ, so a time gives an order of magnitude, not a ranking.

| Measure | maisecrets | Cloakroom (rules and model) | Source |
|---|---|---|---|
| CredData, all rows, P / R / F1 | 0.6.14: 0.90 / 0.61 / 0.73 | 0.2.0: 0.66 / 0.65 / 0.66 | theirs, 2026-10-12 |
| CredData, all rows, P / R / F1, `--regions us` | 0.6.14: 0.900 / 0.613 / 0.729; 0.6.17 tool: 0.908 / 0.683 / 0.780 | – | ours |
| CredData without `2ba83c6a`, P / R / F1 | 0.6.14: 0.83 / 0.48 / 0.61 | 0.2.2: 0.66 / 0.73 / 0.69 | theirs, 2026-10-12 |
| CredData without `2ba83c6a`, P / R / F1 | 0.6.17 tool: 0.855 / 0.578 / 0.690 (`--regions us`), 0.929 / 0.578 / 0.713 (`--regions de`) | – | ours |
| CredData, non-secret rows masked | 0.6.14: 981 | 0.2.0: 4,750 | theirs, 2026-10-12 |
| CredData recall by category: passwords / tokens / URL credentials / AWS client IDs | 0.6.14: 0.62 / 0.66 / 0.70 / 0.36 | 0.2.0: 0.97 / 0.96 / 1.00 / 0.99 | theirs, 2026-10-12 |
| CredData recall by category: generic keys | 0.6.14: 0.88 | 0.2.0: 0.36 | theirs, 2026-10-12 |
| Holdouts v2–v6 rerun, values leaked: critical of 334 / high of 1,005 / low of 221 | 0.6.14: 78 / 550 / 161 (default regions), 67 / 550 / 161 (us, uk, in) | 0.2.0: 2 / 1 / 1 | theirs, 2026-10-12; sets seen before, their file: "not an honest score" |
| Holdouts v2–v6 rerun, false alarms in 200 clean samples | 0.6.14: 5 (default regions), 6 (us, uk, in) | 0.2.0: 23 | theirs, 2026-10-12; sets seen before |
| Holdout v6, values leaked of 314 / false alarms of 40 | 176 / 5 (version not given) | 3 / 12 | theirs, 2026-10-10 |
| Holdout v7, real vendor key formats: values leaked of 77 / false alarms of 15 | 0.6.14: 13 / 1 | 0 / 3 | theirs, 2026-10-12 |
| Holdout v7, values leaked of 77 | 0.6.15: 3 (Twilio Account SIDs) | – | ours, 2026-10-13, their `holdout_v7` set, reported in [#17](https://github.com/Mcpgate-de/maisecrets/issues/17); no script in this repository |
| Names and street addresses | not detected (README, "Names are not detected") | detected by its model (PII-Tracer) | README; theirs |
| Time per item in their harness, holdout v6 | 0.4 ms (version not given) | 63 ms | theirs, 2026-10-10 |
| Time per item, other machines | – | 62 ms on an Apple M-series CPU; 887 ms on a 2-vCPU Windows server; `cloakroom doctor`, one check on that server: 412 ms | theirs, 2026-10-10 |
| Time per scan, v0.6.17 | 1.8–2.2 ms per 1 KB prompt; 80–242 ms per 70 KB tool result; 46–68 ms import + first scan (Apple M5) | – | ours, "Timing" above |

maisecrets uses rules, checksums and labels and no model; Cloakroom adds a language model to its rules.

## Credit

The line method (each labelled line alone, without its file path) and the split without the test-vector
repository come from the [Cloakroom](https://github.com/shanjeevrajendran/cloakroom) benchmark
([`bench/RESULTS.md`](https://github.com/shanjeevrajendran/cloakroom/blob/cf4360c8bd/bench/RESULTS.md)) and from
the discussion in [Mcpgate-de/maisecrets#17](https://github.com/Mcpgate-de/maisecrets/issues/17).
`scripts/measure_creddata.py` follows its `bench/credata.py`. The holdout sets v2 to v7 are Cloakroom's. The rule families of 0.6.21 for a name before an
e-mail address and for the columns of a CSV header follow Cloakroom's rules (Apache-2.0); the code is written anew.

The method of the labelled PII datasets comes from the bench of the public fork
[danszymkowiak/maisecrets](https://github.com/danszymkowiak/maisecrets) (Apache-2.0, commit `73f36bd`, `bench/` and
`docs/UPSTREAM-DETECTION.md`): the choice of the datasets, the cleaning of the labels before a rule is judged (a
checksum, a placeholder, a reserved domain, a private address, a label error, the rule that no cut drops a group of a
value, the repair of Mendeley's mojibake), the label tables and the Mendeley sheet reader.
`scripts/measure_datasets.py` adapts them; the checks are written again with the standard library.

## Method and limits

- **Rows.** A row is a CredData label with `GroundTruth` T or F, on one line, with a value position and a value of
  4 or more characters.
- **Line method.** Each line is scanned alone, without its file path, the way a prompt or a tool result reaches the
  hook. A row is caught when its labelled value no longer appears after every match is masked.
- **No file path.** In the hook, a file path can change the result (test files, `is_fixture`). CredData lines carry
  no path here, so a rule that uses the path shows no effect in this benchmark.
- **The test-vector repository.** Repository `2ba83c6a` holds 3,427 of CredData's 3,822 "Key" credentials, nearly
  all cipher test vectors (`Key = <hex>`; count from Cloakroom's `bench/RESULTS.md`). The first table leaves it
  out; the second keeps it.
- **Split.** A repository is in half D when the first 8 hex digits of sha256 of its id give an even number, and in
  half V otherwise.
- **Classes of missed rows.** In this order: an identifier (the value is a UUID, or the category names a UUID, a
  bucket or an id); a password of letters only (a "Password" row whose parts between `_`, `.` and `-` are letters);
  a value without a label (no name right before the value, after an optional `=`, `:`, `(` or quote); else a
  labelled value. The
  same-class non-secrets are the non-secret rows of that class that the release leaves alone.
- **Regions.** `--regions` selects the country rules for personal data. With `us`, the US bank-account rule takes
  digit runs; this adds 546 false alarms to every release on the split without `2ba83c6a`. `--locale` sets the
  system setting maisecrets sees (the label languages); for 0.6.17 (tool channel, all rows, `--regions us`),
  `de_DE` and `en_US` give the same numbers.
- **Channel.** From 0.6.17, a typed prompt (`prompt`) and a tool result or a file (`tool`) take different password
  rules. A harness that calls `detect.scan(text)` measures the prompt channel.
- **The store.** Each run uses a new temp store. Values that a session stores and looks for later play no part.
- **Obfuscation.** CredData replaces each credential with a random value of the same shape. The seed is fixed per
  row (`obfuscate_creds.py`, `--noise 0`), so a download at the pinned commit gives the same lines.

- **Labelled PII datasets: the cleaning.** Each labelled value of a type with a check goes through it before it is
  counted. A value that fails is *uncertain*: neither a miss nor a false alarm, and a detection on it counts neither
  way. The checks: CARD Luhn over 13 to 19 digits; IBAN two letters, two digits, 11 to 30 letters or digits and mod
  97; US_SSN no area 000, 666 or 9xx, no group 00, no serial 0000, and not an advertising number such as 123-45-6789;
  ABA_ROUTING_NUMBER the 3-7-1 checksum; PHONE 7 to 15 digits, no letters, not one repeated digit, and a North
  American number with an area code and an exchange that start with 2 to 9 and an area code without a 9 in the middle
  (`(123) 456-7890`, `(800) 123-4567` and `555-555-5555` fail). A number is North American when it starts with `+1`
  or `1`, or, in English text only, when it has the US layout without a leading 0. EMAIL: the address syntax (a full
  stop after the address is trimmed off) and not a reserved domain (example.com, .net, .org, and .test, .example,
  .invalid, .localhost); maisecrets leaves these alone on purpose. It also leaves `.local` and `.internal` alone;
  those count as values here, so they lower R. IP: a public address by Python's `ipaddress` (`is_global`), as
  maisecrets masks public addresses only; the resolver addresses that maisecrets skips count as values. Python 3.9
  and 3.14 differ on a few IPv6 ranges; `--out` names the Python of the run (3.14.8 here). US_BANK_NUMBER: 4 to 17
  digits and no letters. The checks are written in the script; they do not use the measured checkout, so a release
  cannot change its own gold.
- **Label errors.** A PHONE, EMAIL or IP label with no digit or no `@` in it (`[Phone Number]`, a phrase) is
  negative: a detection there is a false alarm.
- **Spans wider than the value.** A span with text around a valid value (a card block with holder, expiry and CVC)
  is trimmed to the value. A cut falls only at a separator, and only when the first group it drops differs in length
  from the last group it keeps (the ` 12` of an expiry after a card number). A fake card or IBAN cut at a group
  boundary passes its checksum by chance (1 in 10, 1 in 97); such a span stays uncertain. PHONE, EMAIL and IP spans are
  never shortened inside a match: a shorter phone number passes the rules as easily as the whole one.
- **Offsets.** A span outside the text is dropped and counted. Where a dataset says what a span holds (Nemotron's own
  copy of the value, Mendeley's value columns), a span that does not hold it moves to the nearest copy within 64
  characters, or else becomes uncertain. Mendeley's texts are UTF-8 read as cp1252; the script repairs them first,
  and then every span holds its value (0 moved).
- **Values labelled twice.** Positive spans of one type that overlap are one value (Gretel labels some values
  twice); the cleaning table counts them under "merged". The raw recall merges them the same way.
- **Account numbers as IBANs.** A Nemotron `account_number` that is no US bank number but a valid IBAN counts as an
  IBAN.
- **Scoring.** A labelled value is found (TP) when a detection of any type overlaps it by one character or more.
  "R, own type" counts a value only when a detection of its own type overlaps it; "R, covered" only when the
  detections together cover every character of it. A detection on no labelled value of any type and on no uncertain
  value is a false alarm (FP) of the detected type. P is the share of a type's detections on a labelled value of
  that type among those detections and its FP; a detection on a value of another type only counts in neither, and
  each detection counts once (two fragments on one value count twice). Unlabelled text counts as clean: an FP can be
  a real value that the dataset left unlabelled (the generated datasets have values outside their labels; PIILO
  labels only a student's own data). A type of no tier (`US_PASSPORT`, `DE_PLZ`, …) has no labelled values; its
  detections on no labelled value are listed under each dataset.
- **Gretel.** Train and test splits; records below Gretel's own `quality_score` 90 are left out, as the fork did. The
  structured formats (CSV, EDI, SWIFT, FIX, BAI, XBRL, FpML, MT940) stay and carry the tag `format:structured`.
- **Regions.** Each language group runs with its own regions setting and locale: English `us`/`en_US`, German
  `de`/`de_DE`, French `fr`, Spanish `es`, Italian `it`, Dutch `nl`, Swedish `se`/`sv_SE`. `--regions` sets one
  regions setting for every text.
- **The store.** Each language group runs in a new temp home. Values that a session stores play no part.

## Repeat this measurement

On Linux or macOS (CredData has file names that Windows does not allow). The download fetches the 337
repositories of the meta files and needs about 1 GB. The scripts are on `main`; each release to measure is a
worktree of its tag.

```bash
git clone https://github.com/Samsung/CredData.git
cd CredData
git checkout 0b1940e171725ad8937311120b191602608a4801
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python download_data.py --data_dir data
cd ..

git clone https://github.com/Mcpgate-de/maisecrets.git
cd maisecrets
git worktree add ../maisecrets-0.6.17 v0.6.17
git worktree add ../maisecrets-0.6.16 v0.6.16
python3 scripts/measure_creddata.py ../CredData --maisecrets ../maisecrets-0.6.17 --channel tool --split half \
    --baseline ../maisecrets-0.6.16
python3 scripts/measure_scan_time.py --maisecrets ../maisecrets-0.6.17 --channel tool
python3 scripts/measure_rule_classes.py --creddata ../CredData --holdout <Cloakroom checkout>/bench --workers 6
```

The download took about 1 hour here. If a clone stops on a network error, run `download_data.py` again; it keeps
the repositories it already has. A fresh download on 2026-10-14 gave the same `data/` tree, file for file, as the
copy behind the tables, and the same output below.

One CredData run takes about 10 seconds on the machine above (8 worker processes). The CredData command prints:

```text
CredData line method, without 2ba83c6a, channel tool, regions de, locale de_DE: 23667 rows
maisecrets                   TP  5838  FN  4268  FP   443  TN 13118  P 0.929  R 0.578  F1 0.713
  half D                     TP  3158  FN  1730  FP   273  TN  8666  P 0.920  R 0.646  F1 0.759
  half V                     TP  2680  FN  2538  FP   170  TN  4452  P 0.940  R 0.514  F1 0.664
baseline                     TP  5328  FN  4778  FP   441  TN 13120  P 0.924  R 0.527  F1 0.671
  half D: caught only by maisecrets +263 credentials / +2 false alarms; caught only by the baseline 0 / 0
  half V: caught only by maisecrets +247 credentials / +0 false alarms; caught only by the baseline 0 / 0
credentials still missed: 4268
  identifier (UUID, bucket name, id)    2589 (60.7%)   same-class non-secrets  3728   precision of a rule that took the class 0.41
  labelled value, not a word            1140 (26.7%)   same-class non-secrets  7536   precision of a rule that took the class 0.13
  value without a label                  300 ( 7.0%)   same-class non-secrets  1011   precision of a rule that took the class 0.23
  password of letters only               239 ( 5.6%)   same-class non-secrets   843   precision of a rule that took the class 0.22
```

Options: `--channel prompt`, `--regions us`, `--exclude-repo ""` (all rows), `--out result.json` (counts and
per-row results with row ids, labels and rule ids; no value).

The catalog coverage needs Python 3.11 or newer (tomllib) and PyYAML. Clone each catalog at its pinned commit into one
directory, under the names below, and run the script; it reads the catalogs as data and prints counts only:

```bash
mkdir catalogs && cd catalogs
for spec in noseyparker=https://github.com/praetorian-inc/noseyparker@2e6e7f36ce36619852532bbe698d8cb7a26d2da7 \
    kingfisher=https://github.com/mongodb/kingfisher@82d050530cdef9af070b8f9a75701c9c27a948c3 \
    gitleaks=https://github.com/gitleaks/gitleaks@b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b \
    betterleaks=https://github.com/betterleaks/betterleaks@c613797a684337a014168063577bb6fa6e3b6296 \
    trufflehog=https://github.com/trufflesecurity/trufflehog@27d8ea2876d990b274996fc97aff0f8d952d364c \
    gitlab=https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules@cae5670b0d83aaea0ff37c085119e82ff394f283
do
  name=${spec%%=*}; rest=${spec#*=}
  git clone -q "${rest%@*}" "$name" && git -C "$name" checkout -q "${rest##*@}"
done
cd ..
python3 maisecrets/scripts/measure_catalog_coverage.py catalogs --maisecrets maisecrets-0.6.20 \
    --baseline maisecrets-0.6.19
```

The labelled PII datasets need about 400 MB of disk outside the repository (default `~/.cache/maisecrets-datasets`).
The fetch reads the Hugging Face parquet files with pyarrow (26.0.0 here) and stores them as gzipped JSON lines; the
run needs the standard library only and works on Python 3.9:

```bash
python3 -m venv ../pyarrow-venv && ../pyarrow-venv/bin/pip install pyarrow
../pyarrow-venv/bin/python -I scripts/measure_datasets.py fetch     # about 1 minute; checks each sha256
git worktree add ../maisecrets-0.6.20 v0.6.20
python3 -I scripts/measure_datasets.py run --maisecrets ../maisecrets-0.6.20 \
    --out ~/.cache/maisecrets-datasets/result-0.6.20.json
git worktree add ../maisecrets-0.6.21 v0.6.21
python3 -I scripts/measure_datasets.py run --maisecrets ../maisecrets-0.6.21 \
    --out ~/.cache/maisecrets-datasets/result-0.6.21.json
```

One run of all four datasets took 6 to 9 minutes here (6 worker processes, load average 8 to 15): Gretel 80 to 95 s,
Nemotron-PII 160 to 220 s, Mendeley 80 to 170 s, PIILO 30 to 50 s. `--only nemotron` runs one dataset, `--channel
tool` one channel, `--limit 2000` a fixed choice of about 2,000 samples per dataset. The script prints the cleaning
counts and, per channel, one line per type and per tier, region and tag; `--out` writes the same counts and, per
sample, its id, the gold spans (offsets, label, type, verdict), the detections (offsets, type, rule id, class) and
whether each span was found. It holds no value.

To judge a rule class: run the release before the change and the change, each with `--out`, and compare the rows of
the rule's type in both channels. TP and FN show the gain; FP shows the cost; "R raw" against R shows how much of a
change falls on values the cleaning set aside.

## Add a new release row

1. Add a worktree of the new release tag, and one of the release before it for `--baseline`.
2. For the first table, run the CredData command four times: `--channel prompt` and `--channel tool`, each with
   `--regions de` and `--regions us`.
3. For the second table, run the same four commands with `--exclude-repo ""`.
4. Run `scripts/measure_scan_time.py` with both channels, on Python 3.9 and on the newest Python, two rounds at a
   load average below 5.
5. Run `scripts/measure_datasets.py run --maisecrets <release> --out <file>` and add a column for the release to
   the tables of "Labelled PII datasets".
6. Add the rows to the tables above. Change the date, the release and the machine in the snapshot table. Keep the
   rows of earlier releases as they are.
7. If the CredData commit or a pinned dataset changes, run every release again and name the new version.
