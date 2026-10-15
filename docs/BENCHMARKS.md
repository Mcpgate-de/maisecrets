# Benchmarks

This file is a snapshot. Each table names what was measured, how, the source and the date. The method and its
limits are in their own section. "Repeat this measurement" has the commands.

| Snapshot | |
|---|---|
| Date | 2026-10-14 |
| maisecrets | v0.6.17 (tag `v0.6.17`); earlier releases from their tags |
| Data | Samsung CredData, commit `0b1940e171725ad8937311120b191602608a4801` (2026-09-29) |
| Machine | Apple M5, 10 cores, macOS 27.0 |
| Python | 3.14.8 (CredData runs); 3.14.8 and 3.9.6 (timing) |
| Scripts | `scripts/measure_creddata.py`, `scripts/measure_scan_time.py`, `tests/test_fp_corpus.py` |

## CredData, results per release

CredData line method, without repository `2ba83c6a` (23,667 rows: 10,106 credentials, 13,561 non-secrets),
`--locale de_DE`. Source: `scripts/measure_creddata.py`, 2026-10-14. A release before 0.6.17 has one channel.

| Release | Channel | TP | FN | FP | P | R | F1 | F1, `--regions us` |
|---|---|---|---|---|---|---|---|---|
| 0.6.14 | one | 4,822 | 5,284 | 427 | 0.919 | 0.477 | 0.628 | 0.607 |
| 0.6.15 | one | 4,882 | 5,224 | 429 | 0.919 | 0.483 | 0.633 | 0.612 |
| 0.6.16 | one | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.17 | prompt | 5,328 | 4,778 | 441 | 0.924 | 0.527 | 0.671 | 0.649 |
| 0.6.17 | tool | 5,838 | 4,268 | 443 | 0.929 | 0.578 | 0.713 | 0.690 |

This table uses all 29,893 rows (14,471 credentials, 15,422 non-secrets). Source: `scripts/measure_creddata.py
--exclude-repo ""`, 2026-10-14.

| Release | Channel | P | R | F1 | P, R, F1 with `--regions us` |
|---|---|---|---|---|---|
| 0.6.14 | one | 0.953 | 0.613 | 0.746 | 0.900, 0.613, 0.729 |
| 0.6.15 | one | 0.953 | 0.617 | 0.749 | 0.901, 0.617, 0.732 |
| 0.6.16 | one | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.17 | prompt | 0.954 | 0.648 | 0.772 | 0.904, 0.648, 0.755 |
| 0.6.17 | tool | 0.956 | 0.683 | 0.797 | 0.908, 0.683, 0.780 |

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
the method.

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
in 1,437 samples and 215 clean samples. A value counts as leaked when it still appears after every match is masked.
Tool channel (`detect.scan(text, channel="tool")`), `--locale de_DE`. Source: a script outside this repository that
reads the sets and calls `detect.scan`, 2026-10-15. 0.6.18 is tag `v0.6.18`; 0.6.21 is this branch.

The rules of 0.6.21 come from the values that 0.6.18 leaked. Each sample falls into half D or half C by the first 8 hex
digits of sha256 of `<set>/<id>` (even: D). The rules were written from the leaks of half D; half C was only counted.
Cloakroom tuned its own engine on v2 to v5 after their first run; v6 was never tuned on (their `bench/RESULTS.md`).

Regions `us`, `uk`, `in` (as on Cloakroom's machine):

| Set | Values | Leaked, 0.6.18 | Leaked, 0.6.21 | Clean samples | False alarms, 0.6.18 | False alarms, 0.6.21 |
|---|---|---|---|---|---|---|
| holdout v2 | 219 | 82 | 57 | 40 | 1 | 1 |
| holdout v3 | 320 | 136 | 82 | 40 | 1 | 1 |
| holdout v4 | 328 | 176 | 115 | 40 | 2 | 2 |
| holdout v5 | 394 | 201 | 135 | 40 | 2 | 2 |
| holdout v6 | 314 | 163 | 110 | 40 | 0 | 0 |
| holdout v7 | 77 | 3 | 0 | 15 | 1 | 1 |
| half D (rules written here) | 822 | 380 | 240 | 107 | 4 | 4 |
| half C (counted only) | 830 | 381 | 259 | 108 | 3 | 3 |
| all | 1,652 | 761 | 499 | 215 | 7 | 7 |

Regions `de`:

| Set | Values | Leaked, 0.6.18 | Leaked, 0.6.21 | Clean samples | False alarms, 0.6.18 | False alarms, 0.6.21 |
|---|---|---|---|---|---|---|
| holdout v2 | 219 | 94 | 69 | 40 | 0 | 0 |
| holdout v3 | 320 | 148 | 97 | 40 | 0 | 0 |
| holdout v4 | 328 | 181 | 121 | 40 | 0 | 0 |
| holdout v5 | 394 | 209 | 146 | 40 | 0 | 0 |
| holdout v6 | 314 | 182 | 136 | 40 | 0 | 0 |
| holdout v7 | 77 | 3 | 0 | 15 | 1 | 1 |
| half D (rules written here) | 822 | 413 | 279 | 107 | 0 | 0 |
| half C (counted only) | 830 | 404 | 290 | 108 | 1 | 1 |
| all | 1,652 | 817 | 569 | 215 | 1 | 1 |

Each new rule alone on 0.6.18: values it closes, half D / half C, and new hits on the four sets of ordinary text.
"PII corpus" is `tests/fp_corpus_pii.py` (367 developer texts in the shape of personal data that are none, tool and
prompt channel, ten regions); "developer texts" are 2,464 texts in the tool channel (`tests/fp_corpus.py` and the
review corpora of 0.6.15 and 0.6.16) and "prompts" are 771 typed prompts of the maintainers in the prompt channel.

| Rule | Closed, us uk in: D / C | Closed, de: D / C | New false alarms, holdouts | New hits, PII corpus | New hits, developer texts | Newly blocked prompts |
|---|---|---|---|---|---|---|
| `name-after-label` | 39 / 21 | 39 / 21 | 0 | 0 | 0 | 0 |
| `name-before-email` | 23 / 24 | 23 / 24 | 0 | 0 | 0 | 0 |
| `birth-date-after-label` | 26 / 21 | 26 / 21 | 0 | 0 | 0 | 0 |
| `street-address` | 14 / 14 | 4 / 3 | 0 | 0 | 0 | 0 |
| `id-number-after-label` | 12 / 8 | 15 / 11 | 0 | 0 | 0 | 0 |
| `csv-personal-column` | 10 / 8 | 15 / 9 | 0 | 0 | 0 | 0 |
| `user-in-home-path` | 5 / 9 | 5 / 9 | 0 | 0 | 0 | 0 |
| `user-in-url` | 4 / 2 | 4 / 2 | 0 | 0 | 0 | 0 |
| `phone-one-digit-groups` | 3 / 10 | 3 / 10 | 0 | 0 | 0 | 0 |
| `phone-us-national` | 4 / 1 | 0 / 0 | 0 | 0 | 0 | 0 |
| `twilio-account-sid-labelled` | 3 / 5 | 3 / 5 | 0 | 0 | 0 | 0 |
| `openai-anthropic-key-relaxed` | 3 / 1 | 3 / 1 | 0 | 0 | 0 | 0 |
| `slack-token-relaxed` | 1 / 1 | 1 / 1 | 0 | 0 | 0 | 0 |

The rules of 0.6.18 already hit 8 of the 367 texts of the PII corpus (4 by `phone`, one each by `de-vat-id`,
`email`, `us-bank` and `de-plz`); 0.6.21 adds none. The 44 true hits of the corpus (46 values): 0.6.18 masks 8,
0.6.21 masks 46.

Left out after measuring (holdout analysis of 2026-10-14): an AWS key id with any capital and digit (CredData +105
credentials, +48 false alarms), a user name after a user label, a password or a token word in prose, and a Twilio
Account SID without its name.

CredData, line method, without `2ba83c6a`, `--locale de_DE`. Source: `scripts/measure_creddata.py`, 2026-10-15.

| Release | Channel | Regions | TP | FP | P | R | F1 |
|---|---|---|---|---|---|---|---|
| 0.6.18 | tool | de | 5,854 | 445 | 0.929 | 0.579 | 0.714 |
| 0.6.21 | tool | de | 5,862 | 446 | 0.929 | 0.580 | 0.714 |
| 0.6.18 | tool | us | 5,854 | 991 | 0.855 | 0.579 | 0.691 |
| 0.6.21 | tool | us | 5,862 | 992 | 0.855 | 0.580 | 0.691 |
| 0.6.18 | prompt | de | 5,328 | 441 | 0.924 | 0.527 | 0.671 |
| 0.6.21 | prompt | de | 5,336 | 441 | 0.924 | 0.528 | 0.672 |
| 0.6.18 | prompt | us | 5,328 | 987 | 0.844 | 0.527 | 0.649 |
| 0.6.21 | prompt | us | 5,336 | 987 | 0.844 | 0.528 | 0.650 |

The 8 new true positives come from `twilio-account-sid-labelled`. The one new false alarm in the tool channel is a
Windows home path in a JSON fixture whose user part is a person's user name; CredData labels the line as no password,
and `user-in-home-path` masks the user name as personal data.

Time per scan, tool channel, Python 3.14.8, `scripts/measure_scan_time.py`, three rounds per release, interleaved, load
average 4.2 to 5.0 (above the bar of 4 of "Timing"; rounds differ by up to 30 %), 2026-10-15:

| Input | 0.6.18, range of rounds | 0.6.21, range of rounds |
|---|---|---|
| import + first scan | 50–68 ms | 57–65 ms |
| typed prompt, 1 KB | 2.0–2.9 ms | 2.2–2.5 ms |
| Python code, 70 KB | 129–167 ms | 153–176 ms |
| log, 70 KB | 92–135 ms | 114–139 ms |
| configuration, 70 KB | 206–257 ms | 243–272 ms |

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

## Add a new release row

1. Add a worktree of the new release tag, and one of the release before it for `--baseline`.
2. For the first table, run the CredData command four times: `--channel prompt` and `--channel tool`, each with
   `--regions de` and `--regions us`.
3. For the second table, run the same four commands with `--exclude-repo ""`.
4. Run `scripts/measure_scan_time.py` with both channels, on Python 3.9 and on the newest Python, two rounds at a
   load average below 5.
5. Add the rows to the tables above. Change the date, the release and the machine in the snapshot table. Keep the
   rows of earlier releases as they are.
6. If the CredData commit changes, run every release again and name the new commit.
