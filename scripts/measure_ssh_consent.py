#!/usr/bin/env python3
"""Measure what ssh consent (#8) would do with the ssh commands an agent really ran: how often it would ask.

    python3 scripts/measure_ssh_consent.py [transcript-dir]      # default: ~/.claude/projects

It reads the Bash calls in Claude Code transcripts, classifies each one that names ssh (maisecrets/ssh_consent.py)
and replays the consents per session: a write asks once per host (or group of hosts), a form the hook cannot read
asks every time. It prints counts and reasons only: no host, no command, no value. A reality check, not a gate.

Measured on 2026-10-07 over the maintainer's transcripts (this script, default directory: 296 sessions with ssh,
4155 calls): write 82.8 %, unknown 12.4 %, none 4.6 %, read 0.2 %; questions per session median 1, 90th percentile
4, at most 150, 863 in all. The sessions that work on maisecrets itself are in that count; their commands name ssh
in test cases. Without them (117 sessions, 3644 calls): questions per session median 2, 90th percentile 10, at most 48.
Real ops commands almost always use sudo or docker on the remote side, so they are writes by design: the consent
per host carries them, not the read list.
"""
from __future__ import annotations

import collections
import glob
import json
import os
import re
import statistics
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ["MAISECRETS_HOME"] = tempfile.mkdtemp(prefix="maisecrets-measure-")   # never the real store
sys.path.insert(0, str(ROOT))
from maisecrets import hooks, ssh_consent  # noqa: E402


def parse(text: str):
    ctxs = hooks._shell_contexts(text)
    return hooks._segments(text, ctxs), ctxs


def commands(path: str) -> list[str]:
    out = []
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            if '"Bash"' not in line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            for block in (rec.get("message") or {}).get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Bash":
                    cmd = (block.get("input") or {}).get("command", "")
                    if isinstance(cmd, str) and ssh_consent._TOKEN_RE.search(cmd):
                        out.append(cmd)
    except OSError:
        pass
    return out


def main(argv: list[str]) -> int:
    base = Path(argv[0]).expanduser() if argv else Path.home() / ".claude" / "projects"
    kinds, why, asks = collections.Counter(), collections.Counter(), []
    total = 0
    for path in glob.glob(str(base / "*" / "*.jsonl")):
        cmds = commands(path)
        if not cmds:
            continue
        granted: set[str] = set()
        n = 0
        for cmd in cmds:
            total += 1
            v = ssh_consent.classify(cmd, parse)
            kinds[v.kind] += 1
            if v.kind in ("write", "unknown", "deny"):
                why[(v.kind, re.sub(r"'[^']*'", "'…'", v.why))] += 1
            if v.kind == "unknown":
                n += 1
            elif v.kind == "write" and not set(v.hosts) <= granted:
                n += 1
                granted |= set(v.hosts)
        asks.append(n)
    if not total:
        print("no ssh command found")
        return 0
    print(f"sessions with ssh: {len(asks)}, calls: {total}")
    for k, n in kinds.most_common():
        print(f"  {k:8} {n:6}  {100 * n / total:5.1f} %")
    asks.sort()
    print(f"questions per session: median {statistics.median(asks)}, 90th percentile {asks[int(0.9 * len(asks))]}, "
          f"at most {asks[-1]}, {sum(asks)} in all")
    for (k, w), n in why.most_common(10):
        print(f"  {n:6}  {k:8} {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
