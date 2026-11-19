"""Mission coverage: does every product promise rest on beliefs that can fail?

mission/M*.toml names one promise each, the controls (C*) and invariants (I*) of docs/THREAT-MODEL.md that serve
it, and its parts: one sentence each, with an id (M1.3). Each belief of beliefs/*.toml names the parts it proves in
`serves`, so a new belief counts for no part until its author says which. scripts/replay_can_fail.py proves that each belief's test goes red under its mutation. mission/claims.toml maps the
promises that README.md and PRIVACY.md make to users onto the missions. This script joins them and reports:

- a part with no belief (the sentence rests on prose, or on tests no mutation proves), or with one only (thin),
- a mission without an invariant (only per-line proofs, no check over every path),
- a documented control or invariant that no mission names, and beliefs that no part names,
- a name in a mission or a belief that the threat model does not document, a belief without `serves`, a part id
  in `serves` that no mission has, a part without its id, or a belief whose control its mission does not name,
- a claim whose quote no longer stands in its source, and a bullet of a gated README section that no claim maps,
- each mission's measured number (`[measure]`: a source file, the row that holds it and its column, and the gate
  that keeps its bound), or why it has none (`none`); a measure that cannot be read is a finding.

Without --strict it only reports and exits 0. With --strict it exits 1 on a gap, an orphan control, an unknown name
or a claim finding. Python 3.11+ (tomllib), like replay_can_fail.py.
"""
import argparse
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROL_ROW = re.compile(r"^\| (C\d+) \|", re.M)
INVARIANT_ITEM = re.compile(r"^- \*\*(I\d+)\*\*", re.M)
# the README sections whose every bullet is a promise, a limit or a feature that claims.toml must map
GATED_SECTIONS = ("What it does", "What the Claude Code mod does", "What it does not protect")
KINDS = ("promise", "limit", "feature")


def documented(threat_model: str):
    return set(CONTROL_ROW.findall(threat_model)), set(INVARIANT_ITEM.findall(threat_model))


def flat(text: str) -> str:
    return " ".join(text.split())


def bullets(markdown: str, section: str) -> list[str]:
    """The top-level bullets of one `## section`, each as one line of text without its `- `."""
    m = re.search(rf"^## {re.escape(section)}\n(.*?)(?=^## |\Z)", markdown, re.M | re.S)
    if not m:
        return []
    out: list[str] = []
    for line in m.group(1).splitlines():
        if line.startswith("- "):
            out.append(line[2:])
        elif out and line.startswith("  ") and line.strip():
            out[-1] += " " + line.strip()
    return [flat(b) for b in out]


def check_claims(root: Path, missions: set[str]) -> list[str]:
    path = root / "mission" / "claims.toml"
    if not path.exists():
        return []
    claims = tomllib.loads(path.read_text(encoding="utf-8")).get("claim", [])
    findings: list[str] = []
    texts: dict[str, str] = {}
    for c in claims:
        src, quote, kind = c.get("source", ""), flat(c.get("quote", "")), c.get("kind")
        if src not in texts:
            texts[src] = (root / src).read_text(encoding="utf-8") if (root / src).exists() else ""
        if not quote or quote not in flat(texts[src]):
            findings.append(f"claim not found in {src}: {quote[:70]}")
        if kind not in KINDS:
            findings.append(f"claim kind {kind!r} is not one of {', '.join(KINDS)}: {quote[:50]}")
        elif kind != "feature" and c.get("mission") not in missions:
            findings.append(f"claim names no existing mission ({c.get('mission')}): {quote[:50]}")
    readme = texts.get("README.md") or (root / "README.md").read_text(encoding="utf-8")
    quotes = [flat(c.get("quote", "")) for c in claims if c.get("source") == "README.md"]
    for section in GATED_SECTIONS:
        for b in bullets(readme, section):
            if not any(q and b.startswith(q) for q in quotes):
                findings.append(f"README \"{section}\" bullet no claim maps: {b[:70]}")
    return findings


def read_measure(root: Path, measure: dict) -> tuple[float | None, str]:
    """The newest value of a measure: the last table row of `source` that holds `row`, its `column` (1-based, as the
    cells of a Markdown row split on "|"). (value, "") or (None, why)."""
    path = root / measure.get("source", "")
    if not path.is_file():
        return None, f"source {measure.get('source')} not found"
    lines = path.read_text(encoding="utf-8").splitlines()
    rows = [r for r in lines if r.startswith("|") and measure.get("row", "") in r]
    if not rows:
        return None, f"no row with {measure.get('row')!r} in {measure.get('source')}"
    try:
        return float(rows[-1].split("|")[int(measure["column"])]), ""
    except (KeyError, IndexError, ValueError):
        return None, f"column {measure.get('column')} of the last {measure.get('row')!r} row is no number"


def analyse(root: Path):
    controls, invariants = documented((root / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8"))
    loaded = [tomllib.loads(p.read_text(encoding="utf-8")) for p in sorted((root / "beliefs").glob("*.toml"))]
    beliefs = {b["belief"]: b.get("control", "") for b in loaded}
    serves = {b["belief"]: b.get("serves") for b in loaded}
    missions = [(p, tomllib.loads(p.read_text(encoding="utf-8"))) for p in sorted((root / "mission").glob("M*.toml"))]
    served: set[str] = set()
    parts: dict[str, set[str]] = {}         # part id -> the controls and invariants its mission names
    for _path, m in missions:
        for part in m.get("part", []):
            if part.get("id"):
                parts.setdefault(part["id"], set(m.get("controls", [])) | set(m.get("invariants", [])))
    r = {"missions": [], "gaps": [], "thin": [], "no_invariant": [], "orphans": [], "unknown": [], "claims": [],
         "measures": [],
         "unowned_beliefs": Counter(),
         "undocumented_belief_controls": sorted({c for c in beliefs.values()
                                                 if c not in controls and c not in invariants})}
    for path, m in missions:
        mid = m["mission"]
        if not path.stem.startswith(mid + "-"):
            r["unknown"].append(f"{path.name}: the file name does not start with {mid}-")
        for name in m.get("controls", []) + m.get("invariants", []):
            served.add(name)
            if name not in controls and name not in invariants:
                r["unknown"].append(f"{mid}: {name} is not in docs/THREAT-MODEL.md")
        if not m.get("invariants"):
            r["no_invariant"].append(mid)
        rows = []
        seen_ids: set[str] = set()
        for i, part in enumerate(m.get("part", []), 1):
            pid = part.get("id", "")
            if not re.fullmatch(rf"{re.escape(mid)}\.\d+", pid):
                r["unknown"].append(f"{mid}, part {i}: the id {pid!r} is not {mid}.<number>")
            elif pid in seen_ids:
                r["unknown"].append(f"{pid}: two parts have this id")
            seen_ids.add(pid)
            if "beliefs" in part:
                r["unknown"].append(f"{pid or mid}: a part names no beliefs; each belief names its parts in serves")
            got = {b for b, s in serves.items() if pid and pid in (s or [])}
            rows.append((pid, part["says"], len(got)))
            elsewhere = f" (tested only in {', '.join(part['tests'])}, which no mutation proves)" \
                if part.get("tests") else ""
            if not got:
                r["gaps"].append(f"{pid}: no belief{elsewhere}: {part['says']}")
            elif len(got) == 1:
                r["thin"].append(f"{pid}: one belief: {part['says']}")
        if not m.get("part"):
            r["gaps"].append(f"{mid}: no part names a belief")
        measure = m.get("measure") or {}
        if measure.get("none"):
            r["measures"].append(f"{mid}: none: {measure['none']}")
        elif measure:
            value, why = read_measure(root, measure)
            if value is None:
                r["unknown"].append(f"{mid}: the measure cannot be read: {why}")
            else:
                r["measures"].append(f"{mid}: {value} = {measure.get('what')} (bound: {measure.get('gate')})")
        else:
            r["unknown"].append(f"{mid}: no [measure], and no `none` that says why")
        r["missions"].append((mid, m["promise"], rows))
    for name in sorted(controls | invariants, key=lambda s: (s[0], int(s[1:]))):
        if name not in served:
            r["orphans"].append(f"{name} serves no mission")
    for b, control in beliefs.items():
        s = serves[b]
        if not isinstance(s, list) or not all(isinstance(x, str) for x in s):
            r["unknown"].append(f"{b}: no serves list of part ids (serves = [] when it serves no promise)")
            continue
        if not s:
            r["unowned_beliefs"][control] += 1
        for pid in s:
            if pid not in parts:
                r["unknown"].append(f"{b}: serves {pid}, which no mission has")
            elif (control in controls or control in invariants) and control not in parts[pid]:
                r["unknown"].append(f"{b}: serves {pid}, but {pid.split('.')[0]} does not name its control {control}")
    r["claims"] = check_claims(root, {m["mission"] for _, m in missions})
    return r


def render(r) -> str:
    out = []
    for mid, promise, rows in r["missions"]:
        out.append(f"{mid}  {promise}")
        out.extend(f"    {pid}  {n:4} beliefs  {says}" for pid, says, n in rows)
    unowned = [f"{c or '-'}: {n}" for c, n in sorted(r["unowned_beliefs"].items())]
    sections = (("gaps", "parts with no belief", r["gaps"]), ("thin", "parts with one belief", r["thin"]),
                ("no_invariant", "missions without an invariant", r["no_invariant"]),
                ("orphans", "documented controls in no mission", r["orphans"]),
                ("unowned", "beliefs that serve no promise (serves = []), by control", unowned),
                ("unknown", "unknown names and broken links", r["unknown"]),
                ("claims", "claims of README.md and PRIVACY.md", r["claims"]),
                ("measures", "the measured number of each mission", r["measures"]),
                ("labels", "belief control labels that are no documented control",
                 r["undocumented_belief_controls"]))
    for _key, title, lines in sections:
        out.append(f"\n{title}: {len(lines)}")
        out.extend(f"  {line}" for line in lines)
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 on a gap, an orphan control, an unknown name or a claim finding")
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args(argv)
    r = analyse(args.root)
    print(render(r))
    return 1 if args.strict and (r["gaps"] or r["orphans"] or r["unknown"] or r["claims"]) else 0


if __name__ == "__main__":
    sys.exit(main())
