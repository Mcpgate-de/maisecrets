# Missions

One file per product promise (`M*.toml`). Each file says the promise in plain words, the actors of
`docs/THREAT-MODEL.md` it protects against, the controls (C*) and invariants (I*) that serve it, where the
promise ends, and its parts: one sentence each, with an id (`M1.3`). Each belief (`beliefs/*.toml`) names the
parts it proves in `serves = ["M1.3"]`, one or more; `serves = []` says that it serves no promise. A belief whose
control is a label, not a documented control (`operations`, `detector`), serves only a mission that names the label
in `labels`. A belief without
`serves`, a part id that no mission has, and a belief whose control its mission does not name are findings, so a new
belief counts for no part until its author says which. A part that only a test without a belief covers names that
test in `tests` and still counts as a gap: no mutation proves that the test can fail.

`claims.toml` maps the promises that `README.md` and `PRIVACY.md` make to users onto the missions: a promise
to the mission that keeps it, a limit ("What it does not protect") to the mission whose `ends` names it, a
function to none. Every bullet of the gated sections (three of README.md, and "What it reads", "What it stores,
and where" and "What leaves the machine" of PRIVACY.md) must start with the quote of a claim, so a new or reworded
promise turns the check red until it is mapped; a gated section that is renamed or gone is a finding too.

Each mission names its measured number in `[measure]` (a source file, the row and column that hold it, and the
gate that keeps its bound), or says in `none` why it has none: most promises are kept or broken, not a rate.

M1 to M5 are derived from the controls (bottom-up); M6 comes from README.md and PRIVACY.md (top-down) and
brought control C33 into the threat model.

    python3 scripts/mission_coverage.py            # report
    python3 scripts/mission_coverage.py --strict   # exit 1 on a gap, an orphan, an unknown name or a claim

The beliefs prove that each test can fail; this layer shows which promise each belief serves.
`tests/test_mission_coverage.py` runs the strict check on the repository in CI: a gap, an orphan control, an
unknown name or a claim finding turns it red. A thin part, a mission without an invariant and the measures are
reported only.
