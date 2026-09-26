#!/usr/bin/env python3
"""Claude Code hook entry point: post-tool. Thin wrapper, all logic in maisecrets/hooks.py."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maisecrets.hooks import main  # noqa: E402
sys.exit(main(["hook", "post-tool"]))
