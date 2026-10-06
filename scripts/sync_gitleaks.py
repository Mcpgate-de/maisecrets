#!/usr/bin/env python3
"""Refresh the vendored gitleaks ruleset to a pinned tag.

Usage: scripts/sync_gitleaks.py v8.30.1
Writes maisecrets/rules/gitleaks.toml, gitleaks.json, LICENSE-gitleaks and GITLEAKS_VERSION.
The rules are consumed as data by maisecrets/detect.py; no gitleaks binary is used.
"""
import re
import sys
import urllib.request
from pathlib import Path

tag = sys.argv[1] if len(sys.argv) > 1 else None
if not tag or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):   # it becomes part of a URL
    print("usage: sync_gitleaks.py vX.Y.Z")
    sys.exit(2)
dst = Path(__file__).resolve().parent.parent / "maisecrets" / "rules"
base = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/"
for src, name in (("config/gitleaks.toml", "gitleaks.toml"), ("LICENSE", "LICENSE-gitleaks")):
    with urllib.request.urlopen(base + src, timeout=30) as r:
        (dst / name).write_bytes(r.read())
(dst / "GITLEAKS_VERSION").write_text(tag + "\n")
# the detector reads the JSON form: tomllib is Python 3.11+, and the stock python3 of macOS is 3.9
import json  # noqa: E402
import tomllib  # noqa: E402
cfg = tomllib.loads((dst / "gitleaks.toml").read_text(encoding="utf-8"))
(dst / "gitleaks.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=0, sort_keys=True) + "\n",
                                   encoding="utf-8")
print("vendored gitleaks", tag)
