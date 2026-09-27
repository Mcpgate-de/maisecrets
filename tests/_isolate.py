"""Every test module imports this first: the vault home is a temp directory this module made.

The modules used `os.environ.setdefault("MAISECRETS_HOME", tmp)`, so a MAISECRETS_HOME set on the
machine won, and the reset helpers then deleted the index, the store and the logs in it (Codex
review of the suite, 2026-09-27). This module makes one temp home per test process, reuses it only
when it made it itself, and refuses a home that is the real ~/.maisecrets.
"""
import os
import tempfile

_MINE = "MAISECRETS_TEST_HOME_OWNED"

if not os.environ.get(_MINE) or os.environ.get(_MINE) != os.environ.get("MAISECRETS_HOME"):
    home = tempfile.mkdtemp(prefix="maisecrets-test-home-")
    os.environ["MAISECRETS_HOME"] = home
    os.environ[_MINE] = home

HOME = os.environ["MAISECRETS_HOME"]
_REAL = os.path.realpath(os.path.expanduser("~/.maisecrets"))
if os.path.realpath(HOME) == _REAL or os.path.realpath(HOME).startswith(_REAL + os.sep):
    raise SystemExit(f"refusing to run tests against the real vault home {HOME}")
