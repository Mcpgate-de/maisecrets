# Holdout log

Each run on the private frozen holdout adds one row here (`bench/run.py --source holdout`). The holdout is not used to
write rules (docs/BENCHMARK-V1.md, "Splits"). A row names the scanner, its version and commit, and the totals; it
holds no case and no value. Many rows between two releases are a warning sign: each run tells a little about the
holdout.

| Date | Scanner | Source | Cases | Recall, strict | Precision | FP |
|---|---|---|---|---|---|---|
