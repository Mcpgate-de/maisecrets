#!/usr/bin/env python3
"""Single entry point for every hook event; the launcher run.sh picks the interpreter."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maisecrets.hooks import main  # noqa: E402

if len(sys.argv) == 2 and sys.argv[1] == "session-start":
    import json
    from maisecrets.vault import HOME, Vault  # noqa: E402
    try:
        json.load(sys.stdin)
    except ValueError:
        pass
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    Vault().expire(limit=None)
    print("{}")
    sys.exit(0)
sys.exit(main(["hook", sys.argv[1] if len(sys.argv) == 2 else ""]))
