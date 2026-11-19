# Missions

One file per product promise (`M*.toml`). Each file says the promise in plain words, the actors of
`docs/THREAT-MODEL.md` it protects against, the controls (C*) and invariants (I*) that serve it, and
where the promise ends.

The missions are derived from the controls, not the other way round: they name what the existing
controls already promise, so a control that serves no promise, or a promise part with no belief that
can fail, becomes visible.

    python3 scripts/mission_coverage.py            # report
    python3 scripts/mission_coverage.py --strict   # exit 1 on a gap, an orphan or an unknown name

The beliefs (`beliefs/*.toml`) prove that each test can fail; this layer shows which promise each
belief serves. It is a draft (#77) and not a CI gate yet.
