#!/usr/bin/env python3
"""Reads one vault value under a one-time grant. The Bash hook writes
``$(python resolve.py KEY --grant NONCE)`` into the command in place of the placeholder."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maisecrets.cli import cmd_resolve  # noqa: E402

sys.exit(cmd_resolve(sys.argv[1:]))
