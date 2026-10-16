"""Vault references: every lock wait of a hook step ends at the step's deadline (L1, 2026-10-16).

Each lock of the path waited up to its own 6 s, one after the other: the post-tool hook could pass its 16 s watchdog,
which then withheld the output of the tool, and the resolve of a pre-tool call could pass its 7 s watchdog. The lock of
vault references (vault-refs/.lock) and the lock of the store (.lock) are held here by another process, and the lock's
own wait is set to 30 s, so a wait that the deadline does not bound shows as 30 s.

Run: python3 -m unittest tests.test_vault_refs_deadline -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks, vault, vault_refs  # noqa: E402
from maisecrets.vault import HOME, LockTimeout, Vault, load_config  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

OPEN, CLOSE = "⟦", "⟧"
URL = "https://127.0.0.1:9/mcp"
ORIGIN = "https://127.0.0.1:9"
# the same lock call as vault._Lock, per platform; the lock is held until the test kills the child
_HOLD = ("import os, sys, time; fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
         "if os.name == 'nt':\n    import msvcrt; msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)\n"
         "else:\n    import fcntl; fcntl.flock(fd, fcntl.LOCK_EX)\n"
         "print('held', flush=True); time.sleep(120)")


class Base(unittest.TestCase):
    def setUp(self) -> None:
        vault_refs.DIR.mkdir(parents=True, exist_ok=True)
        for f in (vault_refs.NOTES, vault_refs.SENT, vault_refs.ENDPOINTS):
            if f.exists():
                f.unlink()
        self.profile = Path(tempfile.mkdtemp(prefix="vault-refs-deadline-"))
        self.addCleanup(shutil.rmtree, self.profile, True)
        (self.profile / ".claude.json").write_text(json.dumps({"mcpServers": {"srv": {"type": "http", "url": URL}}}))
        p = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.profile)})
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(vault._Lock, "LOCK_DEADLINE", 30.0)     # an unbounded wait would take 30 s
        p.start()
        self.addCleanup(p.stop)

    def hold(self, path: Path) -> None:
        child = subprocess.Popen([sys.executable, "-c", _HOLD, str(path)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.stdout.close)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertEqual(child.stdout.readline().strip(), "held")

    def result_payload(self) -> dict:
        return {"tool_name": "mcp__srv__customers", "mcp_server": {"name": "srv", "source": "user"},
                "session_id": "s1", **CLAUDE, "tool_response": [{"type": "text", "text": f"see {OPEN}EMAIL_1{CLOSE}"}]}


class PostToolTests(Base):
    def test_a_busy_lock_ends_at_the_budget_and_the_output_passes(self):
        self.hold(vault_refs.DIR / ".lock")
        with mock.patch.object(vault_refs, "NOTE_BUDGET", 0.5):
            started = time.monotonic()
            with self.assertRaises(LockTimeout):
                vault_refs.note_result(self.result_payload(), load_config(), Vault(load_config()).backend)
            self.assertLess(time.monotonic() - started, 10.0, "the wait of 30 s was not bounded")
            started = time.monotonic()
            out = hooks._post_tool_guarded(self.result_payload())
            self.assertLess(time.monotonic() - started, 10.0)
        self.assertNotIn("withheld", json.dumps(out), "the output of the tool passes")
        self.assertFalse(vault_refs.NOTES.exists(), "the token stays text")

    def test_a_deadline_from_the_caller_bounds_the_wait(self):
        # the hook gives no deadline and note_result takes NOTE_BUDGET; a caller's deadline counts the same way
        self.hold(vault_refs.DIR / ".lock")
        started = time.monotonic()
        with self.assertRaises(LockTimeout):
            vault_refs.note_result(self.result_payload(), load_config(), None, deadline=time.monotonic() + 0.3)
        self.assertLess(time.monotonic() - started, 10.0)


class ResolveTests(Base):
    def test_forget_and_the_key_wait_until_the_deadline_only(self):
        self.hold(vault_refs.DIR / ".lock")
        started = time.monotonic()
        with self.assertRaises(LockTimeout):
            vault_refs.forget(["EMAIL_1"], ORIGIN, URL, time.monotonic() + 0.3)
        self.assertLess(time.monotonic() - started, 10.0)
        backend = Vault(load_config()).backend
        self.hold(HOME / ".lock")
        started = time.monotonic()
        with self.assertRaises(LockTimeout):
            vault_refs._key(backend, ORIGIN, False, deadline=time.monotonic() + 0.3)
        self.assertLess(time.monotonic() - started, 10.0)

    def test_a_busy_lock_costs_the_answer_of_the_metadata_only_its_cache(self):
        meta = json.dumps({"client_vault_endpoint": ORIGIN + "/vault/resolve"}).encode()
        self.hold(vault_refs.DIR / ".lock")
        with mock.patch.object(vault_refs, "_request", return_value=(200, {"content-type": "application/json"}, meta)):
            started = time.monotonic()
            got = vault_refs.endpoint({}, URL, time.monotonic() + 0.3)
            self.assertLess(time.monotonic() - started, 10.0)
        self.assertEqual(got, ORIGIN + "/vault/resolve")
        self.assertFalse(vault_refs.ENDPOINTS.exists(), "not cached: the next call asks again")

    def test_the_resolve_passes_its_deadline_to_every_wait(self):
        # a note for the key, so the resolve reaches the store for the key of the origin
        vault_refs.NOTES.write_text(json.dumps({vault_refs.profile(): {ORIGIN: {"EMAIL_1": {
            "type": "EMAIL", "seen": {URL: vault_refs._now_iso()}, "display": {URL: ""}, "conflict": [],
            "sessions": {URL: ["s1"]}}}}}))
        self.hold(HOME / ".lock")
        backend = Vault(load_config()).backend
        started = time.monotonic()
        with self.assertRaises(LockTimeout):
            vault_refs.resolve({}, backend, ["EMAIL_1"], "s1", deadline=time.monotonic() + 0.3)
        self.assertLess(time.monotonic() - started, 10.0)


class BoundedLockTests(Base):
    def test_the_lock_keeps_its_own_wait_for_every_other_step(self):
        lock = vault._lock_for(vault_refs.DIR / ".lock")
        with vault_refs._bounded(lock, time.monotonic() + 0.5):
            self.assertEqual(lock.depth, 1)
            with vault_refs._bounded(lock, time.monotonic() - 1):     # held already: a re-entry, no wait
                self.assertEqual(lock.depth, 2)
        self.assertEqual(lock.depth, 0)
        self.assertNotIn("LOCK_DEADLINE", vars(lock))
        self.assertEqual(lock.LOCK_DEADLINE, 30.0)


if __name__ == "__main__":
    unittest.main()
