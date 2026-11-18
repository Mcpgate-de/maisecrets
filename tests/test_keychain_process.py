"""The keychain store against a fake `security` that runs as a real program first on PATH (tests/fake_security.py).

#75: a value never stands on the command line of `security`, where `ps` of any process of the user shows it, at any
length.

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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

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


if __name__ == "__main__":
    unittest.main()
