# Holdout log

Each run on the private frozen holdout adds one row here (`bench/run.py --source holdout`). The holdout is not used to
write rules (docs/BENCHMARK-V1.md, "Splits"). A row names the scanner, its version and commit, and the totals; it
holds no case and no value. Many rows between two releases are a warning sign: each run tells a little about the
holdout.

| Date | Scanner | Source | Cases | Recall, strict | Precision | FP |
|---|---|---|---|---|---|---|
| 2026-10-19 | maisecrets 0.6.39 a6846dc35417147451e75bb8920ba3b2d9927b48 | holdout | 80 | 0.8333 | 1.0 | 0 |
| 2026-10-19 | maisecrets 0.6.30 3b29d0593d69906a305d00d92dde50a81a9c2ceb | holdout | 80 | 0.8333 | 1.0 | 0 |
