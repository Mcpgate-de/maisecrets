"""The keychain store against a fake `security` that runs as a real program first on PATH (tests/fake_security.py).

#75: a value never stands on the command line of `security`, where `ps` of any process of the user shows it, at any
length. #76: a keychain that does not answer holds no hook past its own time; the hook fails closed and says why.

The real `security` and the real keychain are never reached: the fake comes first on PATH, before the tripwires of
tests/_isolate.py.

Run: python3 -m unittest tests.test_keychain_process -v
"""
from __future__ import annotations

import base64
import json
import os
import secrets
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

from maisecrets import vault  # noqa: E402
from maisecrets.vault import CodedError, KeychainBackend  # noqa: E402

FAKE = Path(__file__).resolve().parent / "fake_security.py"


def make_fake(where: Path) -> dict:
    """A `security` in its own bin folder, and the environment that puts it first on PATH."""
    bin_dir = where / "bin"
    bin_dir.mkdir(parents=True)
    tool = bin_dir / "security"
    tool.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n', encoding="utf-8")
    tool.chmod(0o755)
    return {"PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""), "FAKE_SECURITY_DIR": str(where)}


def random_text(n: int) -> str:
    """A value with no repeated window, so any 16 characters of it on a command line are found."""
    return secrets.token_urlsafe(n)[:n]


class FakeKeychain(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fake-security-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        env = mock.patch.dict(os.environ, make_fake(self.dir))
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(vault.hook_deadline, None)
        self.backend = KeychainBackend()

    def calls(self) -> list[dict]:
        try:
            lines = (self.dir / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        return [json.loads(ln) for ln in lines]

    def items(self) -> dict:
        try:
            return json.loads((self.dir / "items.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}


class NoValueOnTheCommandLineTests(FakeKeychain):
    """#75: before 0.9.18 a record above 3900 bytes went to `security add-generic-password -w <value>`."""

    def assert_not_on_argv(self, value: str) -> None:
        stored = base64.b64encode(value.encode("utf-8")).decode("ascii")
        argv = "\0".join(a for c in self.calls() for a in c["argv"])
        for text in (value, stored):
            for i in range(0, max(1, len(text) - 16), 8):
                window = text[i:i + 16]
                self.assertFalse(window in argv, "a part of the value stands on the command line of `security`")
        stdin = "".join(c["stdin"] for c in self.calls())
        self.assertIn(stored[:64], stdin, "the value goes through stdin")

    def test_a_short_value_goes_through_stdin(self):
        value = random_text(40)
        self.backend.put("SECRET_c1", value)
        self.assertEqual(self.backend.get("SECRET_c1"), value)
        self.assert_not_on_argv(value)

    def test_a_long_value_goes_through_stdin_in_parts(self):
        for n, key in ((5000, "SECRET_c2"), (40000, "SECRET_c3")):
            with self.subTest(length=n):
                value = random_text(n)
                self.backend.put(key, value, label=f"maisecrets {key} (manual)", comment="a fake comment")
                self.assertEqual(self.backend.get(key), value)
                self.assert_not_on_argv(value)

    def test_a_long_token_pair_of_a_gateway_login(self):
        from maisecrets import sref_client
        origin = "https://gateway.example.test"
        record = {"access": random_text(1800), "refresh": random_text(1800), "client_id": "fake-client",
                  "scope": "refs ner", "expires": 1_800_000_000}
        sref_client._keep(self.backend, origin, record)
        self.assertEqual(sref_client._load(self.backend, origin), record)
        self.assert_not_on_argv(json.dumps(record))

    def test_each_line_fits_the_line_limit_of_security_i(self):
        self.backend.put("SECRET_c4", random_text(30000))
        for c in self.calls():
            for line in c["stdin"].split("\n"):
                self.assertLessEqual(len(line.encode("utf-8")), KeychainBackend.MAX_LINE)

    def test_a_replaced_or_deleted_long_value_leaves_no_part_behind(self):
        long1, long2, short = random_text(9000), random_text(12000), random_text(30)
        self.backend.put("SECRET_c5", long1)
        self.backend.put("SECRET_c5", long2)
        self.assertEqual(self.backend.get("SECRET_c5"), long2)
        head = next(v for k, v in self.items().items() if k.endswith("\0SECRET_c5"))
        gen = head.split(":")[2]
        parts = [k for k in self.items() if ".part" in k]
        self.assertEqual(len(parts), int(head.split(":")[1]) - 1)
        self.assertTrue(all(k.endswith("." + gen) for k in parts), "the parts of long1 are gone")
        self.backend.put("SECRET_c5", short)
        self.assertEqual(self.backend.get("SECRET_c5"), short)
        self.assertEqual(len(self.items()), 1)
        self.backend.put("SECRET_c5", long1)
        self.assertEqual(self.backend.keys(), ["SECRET_c5"])  # the parts are no keys of their own
        self.backend.delete("SECRET_c5")
        self.assertEqual(self.items(), {})
        self.assertIsNone(self.backend.get("SECRET_c5"))

    def test_a_part_of_another_value_reads_as_nothing(self):
        # a put that stopped halfway, or two writers: the head and a part of two values of the same length
        self.backend.put("SECRET_c6", random_text(9000))
        self.backend.put("SECRET_c7", random_text(9000))
        items = self.items()
        mine = next(k for k in items if "SECRET_c6.part1." in k)
        items[mine] = items[next(k for k in items if "SECRET_c7.part1." in k)]
        (self.dir / "items.json").write_text(json.dumps(items), encoding="utf-8")
        self.assertIsNone(self.backend.get("SECRET_c6"))

    def test_a_value_too_long_for_the_stdin_form_is_refused_and_not_put_on_the_command_line(self):
        value = random_text(KeychainBackend.MAX_PARTS * 3700)
        with self.assertRaisesRegex(CodedError, "too long") as cm:
            self.backend.put("SECRET_c7", value)
        self.assertNotIn(value[:16], str(cm.exception))
        self.assertEqual(self.items(), {})
        self.assertFalse([c for c in self.calls() if c["argv"][:1] == ["add-generic-password"]])


class SlowKeychainTests(FakeKeychain):
    """#76: a keychain read waited its own 5 s, also when the hook had less time left."""

    def slow(self, name: str, seconds: float) -> None:
        env = mock.patch.dict(os.environ, {"FAKE_SECURITY_SLEEP": f"{name}:{seconds}"})
        env.start()
        self.addCleanup(env.stop)

    def test_a_read_ends_with_the_hooks_time(self):
        self.backend.put("SECRET_c1", "fake-value-0001")
        self.slow("find-generic-password", 30)
        vault.hook_deadline(vault.STORE_MARGIN + 1.0)
        started = time.monotonic()
        with self.assertRaises(CodedError) as cm:
            self.backend.get("SECRET_c1")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(vault.is_store_timeout(cm.exception))
        self.assertNotIn("fake-value-0001", str(cm.exception))

    def test_a_write_ends_with_the_hooks_time(self):
        self.slow("add-generic-password", 30)
        vault.hook_deadline(vault.STORE_MARGIN + 1.0)
        started = time.monotonic()
        with self.assertRaises(CodedError):
            self.backend.put("SECRET_c1", "fake-value-0002")
        self.assertLess(time.monotonic() - started, 2.5)

    def test_no_call_starts_when_no_time_is_left(self):
        vault.hook_deadline(vault.STORE_MARGIN - 0.5)
        with mock.patch.object(vault.subprocess, "run") as run, self.assertRaises(CodedError) as cm:
            self.backend.get("SECRET_c1")
        run.assert_not_called()
        self.assertTrue(vault.is_store_timeout(cm.exception))

    def test_a_shorter_budget_of_a_caller_counts_inside_its_block(self):
        self.slow("find-generic-password", 30)
        vault.hook_deadline(6.0)
        started = time.monotonic()
        with self.assertRaises(CodedError), vault.store_deadline(time.monotonic() + 0.8):
            self.backend.get("SECRET_c1")
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(vault.store_time_left() > 3, True)   # the block's limit ends with the block

    def test_the_gateway_login_read_of_the_name_service_ends_with_its_deadline(self):
        from maisecrets import sref_client
        origin = "https://gateway.example.test"
        sref_client._keep(self.backend, origin, {"access": "a", "refresh": "r"})
        self.slow("find-generic-password", 30)
        found = {"origin": origin, "token_endpoint": origin + "/token"}
        started = time.monotonic()
        with self.assertRaisesRegex(sref_client.Refused, "did not answer"):
            sref_client._access({}, self.backend, found, time.monotonic() + 0.8)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_the_name_service_of_a_gateway_leaves_the_names_unchecked_as_with_a_slow_service(self):
        from maisecrets import ner_gateway, sref_client
        origin = "https://gateway.example.test"
        sref_client._keep(self.backend, origin, {"access": "a", "refresh": "r", "scope": "ner"})
        self.slow("find-generic-password", 30)
        found = {"origin": origin, "ner": {"scope": "ner", "endpoint": origin + "/ner"}}
        started = time.monotonic()
        with mock.patch.object(ner_gateway, "found_for", return_value=found), \
                mock.patch("maisecrets.vault.make_backend", return_value=self.backend):
            got, why = ner_gateway.detector({}, {"gateway": origin}, lambda *a: "a detector", time.monotonic() + 0.8)
        self.assertIsNone(got)
        self.assertIn("did not answer in time", why)
        self.assertEqual(ner_gateway.LAST["cause"], "slow")
        self.assertLess(time.monotonic() - started, 2.0)


@unittest.skipIf(os.name == "nt", "the fake is a shell script")
class HookFailsClosedTests(unittest.TestCase):
    """The whole hook, as the client starts it: a keychain that does not answer ends in the hook's own answer, which
    names the keychain, before the watchdog."""

    SCRIPT = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets import hooks, vault\n"
              "vault.make_backend = lambda cfg: vault.KeychainBackend()\n"
              "sys.exit(hooks.main(['hook', sys.argv[2]]))\n")

    def test_a_prompt_with_a_value_and_a_keychain_that_waits(self):
        home = Path(tempfile.mkdtemp(prefix="maisecrets-slow-keychain-"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        env.update(make_fake(home / "fake"))
        env.update({"MAISECRETS_HOME": str(home), "MAISECRETS_TEST_HOME_OWNED": str(home),
                    "MAISECRETS_TEST_WATCHDOG": "4", "PYTHONDONTWRITEBYTECODE": "1",
                    "FAKE_SECURITY_SLEEP": "find-generic-password:30"})
        payload = {"session_id": "s1", "hook_event_name": "UserPromptSubmit",
                   "prompt": "deploy with glpat-" + "abcdefghijKLMNOPQRST"}
        started = time.monotonic()
        r = subprocess.run([sys.executable, "-c", self.SCRIPT, str(ROOT), "user-prompt"], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=20)
        took = time.monotonic() - started
        answer = json.loads(r.stdout)
        self.assertEqual(answer.get("decision"), "block", r.stdout)
        self.assertIn("keychain did not answer", answer["reason"])
        self.assertNotIn("took longer", answer["reason"])
        self.assertLess(took, 4 + 2)


if __name__ == "__main__":
    unittest.main()
