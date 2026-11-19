"""Mission coverage: does every product promise rest on controls that can fail?

mission/M*.toml names one promise each and the controls (C*) and invariants (I*) of
docs/THREAT-MODEL.md that serve it; beliefs/*.toml name the control each belief proves, and
scripts/replay_can_fail.py proves that each belief's test goes red under its mutation. This
script joins the three and reports:

- a control of a mission that has no belief (the promise rests on prose there),
- a control with one belief only (thin; an invariant is one belief by design),
- a mission without an invariant (only per-line proofs, no check over every path),
- a documented control or invariant that no mission names (dead weight, or a missing promise),
- a name in a mission or a belief that the threat model does not document.

Without --strict it only reports and exits 0. With --strict it exits 1 on a gap, an orphan or an
unknown name. Python 3.11+ (tomllib), like replay_can_fail.py.
"""
import argparse
import re
import sys
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROL_ROW = re.compile(r"^\| (C\d+) \|", re.M)
INVARIANT_ITEM = re.compile(r"^- \*\*(I\d+)\*\*", re.M)


def documented(threat_model: str):
    return set(CONTROL_ROW.findall(threat_model)), set(INVARIANT_ITEM.findall(threat_model))


def load(folder: Path):
    return [(p, tomllib.loads(p.read_text(encoding="utf-8"))) for p in sorted(folder.glob("*.toml"))]


def analyse(root: Path):
    controls, invariants = documented((root / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8"))
    missions = load(root / "mission")
    per_control = Counter(b.get("control", "") for _, b in load(root / "beliefs"))
    served = defaultdict(list)
    report = {"missions": [], "gaps": [], "thin": [], "no_invariant": [], "orphans": [], "unknown": [],
              "undocumented_belief_controls": sorted(c for c in per_control
                                                     if c not in controls and c not in invariants)}
    for path, m in missions:
        mid = m["mission"]
        if not path.stem.startswith(mid + "-"):
            report["unknown"].append(f"{path.name}: the file name does not start with {mid}-")
        rows = []
        for name in m.get("controls", []) + m.get("invariants", []):
            served[name].append(mid)
            if name not in controls and name not in invariants:
                report["unknown"].append(f"{mid}: {name} is not in docs/THREAT-MODEL.md")
            n = per_control.get(name, 0)
            rows.append((name, n))
            if n == 0:
                report["gaps"].append(f"{mid}: {name} has no belief")
            elif n == 1 and name.startswith("C"):    # an invariant is one belief with a proof per path
                report["thin"].append(f"{mid}: {name} has one belief")
        if not m.get("invariants"):
            report["no_invariant"].append(mid)
        report["missions"].append((mid, m["promise"], rows))
    for name in sorted(controls | invariants, key=lambda s: (s[0], int(s[1:]))):
        if name not in served:
            report["orphans"].append(f"{name} serves no mission")
    return report


def render(r) -> str:
    out = []
    for mid, promise, rows in r["missions"]:
        out.append(f"{mid}  {sum(n for _, n in rows)} beliefs  {promise}")
        out.append("    " + "  ".join(f"{name}:{n}" for name, n in rows))
    for key, title in (("gaps", "promise parts with no belief"), ("thin", "controls with one belief"),
                       ("no_invariant", "missions without an invariant"),
                       ("orphans", "documented controls in no mission"),
                       ("unknown", "names the threat model does not document"),
                       ("undocumented_belief_controls", "belief control labels that are no documented control")):
        out.append(f"\n{title}: {len(r[key])}")
        out.extend(f"  {line}" for line in r[key])
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--strict", action="store_true", help="exit 1 on a gap, an orphan or an unknown name")
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args(argv)
    r = analyse(args.root)
    print(render(r))
    return 1 if args.strict and (r["gaps"] or r["orphans"] or r["unknown"]) else 0


if __name__ == "__main__":
    sys.exit(main())
