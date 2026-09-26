#!/usr/bin/env python3
"""Claude Code hook entry point: SessionStart. Full sweep of expired vault values, prints nothing."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maisecrets.vault import HOME, Vault  # noqa: E402

try:
    json.load(sys.stdin)
except ValueError:
    pass
HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
Vault().expire(limit=None)
print("{}")
