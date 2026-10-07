#!/usr/bin/env python3
"""Measure where stored secrets go in real agent work: input for secret destinations (Mcpgate-de/maisecrets#13,
maisecrets/destinations.py).

    python3 scripts/measure_binding.py [transcript-dir] [--skip-cwd TEXT]   # default: ~/.claude/projects

It reads the tool calls in Claude Code transcripts that carry a secret: a placeholder ⟦SECRET_cN⟧ (since maisecrets
ran) or a value the maisecrets detector types SECRET (before). Per use it takes the destination the way
maisecrets/destinations.py does (a host from a URL, an ssh host, an MCP server and tool). It prints counts only: no
value, host, path or command; destinations are hashed in memory. `--skip-cwd TEXT` leaves out every transcript that
ran in a directory whose path contains TEXT (the default `maisecrets`: those sessions hold test fixtures).

Measured on 2026-10-07 with this script over the maintainer's transcripts (90 days, sessions on maisecrets itself
left out; a local use such as a file counts as a destination here):
- 1010 uses of 455 secrets; 380 went to one destination, 55 to two, 20 to three or more.
- Pattern breaks (a secret with N uses on D distinct days at one network destination goes to a new one): 1/1 -> 56,
  2/1 -> 18, 3/1 -> 8 (the first after 19 days, 1.9 per 30 days), 3/2 -> 1 (after 112 days), 5/2 -> 0.
  destinations.ESTABLISHED_USES is 3 on one day: stricter would almost never fire, looser counts a token's setup.
- MCP keys, secrets with more than one destination of 56 with an MCP use: server 2, server+tool 5,
  server+tool+action 16, server+tool+resource 5. The key is server and tool; an `action` is the operation inside a
  service, not where the value goes.
"""
from __future__ import annotations

import collections
import datetime as dt
import glob
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ["MAISECRETS_HOME"] = tempfile.mkdtemp(prefix="maisecrets-measure-")   # never the real store
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
sys.path.insert(0, str(ROOT))
from maisecrets import destinations, detect, hooks, ssh_consent  # noqa: E402
from maisecrets.placeholder import find_refs  # noqa: E402

THRESHOLDS = ((1, 1), (2, 1), (3, 1), (3, 2), (5, 2))


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _secrets(text: str, session: str) -> list[str]:
    out = [session + key for key, _a, _b in find_refs(text) if key.startswith("SECRET_")]
    out += ["v:" + _h(m.value) for m in detect.scan(text) if m.type == "SECRET" and not detect.is_fixture(m, text, "")]
    return out


def _destinations(tool: str, inp: dict) -> list[tuple[str, str]]:
    ssh_hosts = []
    if tool == "Bash":
        cmd = str(inp.get("command") or "")
        if ssh_consent._TOKEN_RE.search(cmd):
            ssh_hosts = list(ssh_consent.classify(cmd, hooks._parse_for_consent).hosts)
    return destinations.destinations_of(tool, inp, ssh_hosts)


def main(argv: list[str]) -> int:
    skip = "maisecrets"
    if "--skip-cwd" in argv:
        k = argv.index("--skip-cwd")
        skip = argv[k + 1] if k + 1 < len(argv) else ""
        argv = argv[:k] + argv[k + 2:]
    base = Path(argv[0]).expanduser() if argv else Path.home() / ".claude" / "projects"
    uses = []                       # (time, secret, kind, destination hash)
    mcp = collections.defaultdict(lambda: collections.defaultdict(set))
    for path in glob.glob(str(base / "*" / "*.jsonl")):
        session = Path(path).stem
        records, skipped = [], False
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if '"tool_use"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if skip and skip in (rec.get("cwd") or ""):
                        skipped = True
                        break
                    records.append(rec)
        except OSError:
            continue
        if skipped:
            continue
        for rec in records:
            try:
                when = dt.datetime.fromisoformat((rec.get("timestamp") or "").replace("Z", "+00:00"))
            except ValueError:
                continue
            for b in (rec.get("message") or {}).get("content") or []:
                if not (isinstance(b, dict) and b.get("type") == "tool_use"):
                    continue
                tool = b.get("name") or ""
                inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                text = inp.get("command") if tool == "Bash" else json.dumps(inp, ensure_ascii=False)
                found = _secrets(str(text or ""), session)
                if not found:
                    continue
                dests = _destinations(tool, inp)
                for s in found:
                    for kind, label in dests:
                        uses.append((when, s, kind, _h(label)))
                    if tool.startswith("mcp__"):
                        server, name = (tool.split("__") + ["", ""])[1:3]
                        action = str(inp.get("action") or "")
                        res = str(inp.get("project") or inp.get("url") or inp.get("repo") or inp.get("host") or "")
                        mcp["server"][s].add(_h(server))
                        mcp["server+tool"][s].add(_h(server + name))
                        mcp["server+tool+action"][s].add(_h(server + name + action))
                        mcp["server+tool+resource"][s].add(_h(server + name + res))
    if not uses:
        print("no use of a secret found")
        return 0
    uses.sort()
    per = collections.defaultdict(set)
    for _t, s, _k, d in uses:
        per[s].add(d)
    dist = collections.Counter(min(len(v), 3) for v in per.values())
    print(f"uses: {len(uses)}, secrets: {len(per)}; destinations per secret: 1 = {dist[1]}, 2 = {dist[2]}, "
          f"3+ = {dist[3]}")
    network = [u for u in uses if u[2] == "network"]
    first = network[0][0] if network else None
    span = max(1, (network[-1][0] - first).days) if network else 1
    print("\npattern breaks (network destinations only)")
    for need, days in THRESHOLDS:
        seen: dict = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, set()]))
        breaks = []
        for t, s, _k, d in network:
            known = seen[s]
            established = any(n >= need and len(ds) >= days for n, ds in known.values())
            if d not in known and established:
                breaks.append(t)
            known[d][0] += 1
            known[d][1].add(t.date())
        after = (breaks[0] - first).days if breaks else "-"
        print(f"  {need} uses / {days} day(s): {len(breaks):4} breaks, {len(breaks) * 30 / span:5.1f} per 30 days, "
              f"first after {after} days")
    print("\nMCP destination keys: secrets with more than one destination")
    for g, by_secret in mcp.items():
        print(f"  {g:22} {sum(1 for v in by_secret.values() if len(v) > 1):4} of {len(by_secret)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
