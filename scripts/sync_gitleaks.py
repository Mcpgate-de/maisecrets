#!/usr/bin/env python3
"""Refresh the vendored gitleaks ruleset to a pinned tag.

Usage: scripts/sync_gitleaks.py v8.30.1
Writes maisecrets/rules/gitleaks.toml, LICENSE-gitleaks and GITLEAKS_VERSION.
The rules are consumed as data by maisecrets/detect.py; no gitleaks binary is used.
"""
import sys
import urllib.request
from pathlib import Path

tag = sys.argv[1] if len(sys.argv) > 1 else None
if not tag or not tag.startswith("v"):
    print("usage: sync_gitleaks.py vX.Y.Z")
    sys.exit(2)
dst = Path(__file__).resolve().parent.parent / "maisecrets" / "rules"
base = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/"
for src, name in (("config/gitleaks.toml", "gitleaks.toml"), ("LICENSE", "LICENSE-gitleaks")):
    with urllib.request.urlopen(base + src, timeout=30) as r:
        (dst / name).write_bytes(r.read())
(dst / "GITLEAKS_VERSION").write_text(tag + "\n")
print("vendored gitleaks", tag)
