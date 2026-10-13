"""One text writes the vault index at most once (0.6.15).

Each exact-match hit in a tool result admitted its key alone, and each admit re-read and rewrote the whole index, also
when the session held the key already: 5 hits with 6000 stored values took 1.9 s on Python 3.9. The batching is
ported from the work on value imports (commit 90cc506).

Run: python3 -m unittest tests.test_index_writes -v
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets import vault as vault_mod  # noqa: E402

_R = random.Random(6000)


def word() -> str:
    """A value with no shape of its own: only the exact match finds it."""
    return "Probe" + "".join(_R.choice(string.ascii_lowercase) for _ in range(6)) + "Qx" + str(_R.randrange(10 ** 6))


class OneIndexWritePerTextTests(unittest.TestCase):
    def setUp(self):
        for f in ("index.json", "vault.json"):
            Path(_isolate.HOME, f).unlink(missing_ok=True)
        hooks._live_cache.clear()
        self.addCleanup(hooks._live_cache.clear)
        self.v = vault_mod.Vault()
        self.values = [word() for _ in range(5)]
        self.keys = [self.v.put(x, "SECRET", "manual", session="s-old").key for x in self.values]

    def post(self, session: str) -> dict:
        text = "result: " + " and ".join(self.values) + "\n"
        return hooks.post_tool({"tool_name": "Bash", "session_id": session, "prompt_id": "p",
                                "tool_response": {"stdout": text, "stderr": ""}})

    def writes(self, session: str) -> tuple[int, dict]:
        real = vault_mod.Vault._save_index
        n = {"v": 0}

        def counted(v):
            n["v"] += 1
            return real(v)
        with mock.patch.object(vault_mod.Vault, "_save_index", counted):
            out = self.post(session)
        return n["v"], out

    def test_five_hits_in_a_new_session_write_the_index_once_and_admit_each_key(self):
        n, out = self.writes("s-new")
        self.assertEqual(n, 1)
        text = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        for x in self.values:
            self.assertNotIn(x, text)
        index = vault_mod.Vault()._index["entries"]
        for k in self.keys:
            self.assertIn("s-new", index[k]["sessions"], "the session may resolve each key it saw")

    def test_hits_the_session_holds_already_write_nothing(self):
        self.writes("s-again")
        n, out = self.writes("s-again")
        self.assertEqual(n, 0)
        self.assertIn("hookSpecificOutput", out)


if __name__ == "__main__":
    unittest.main()
