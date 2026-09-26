"""Round trip on the native backend of THIS machine (keychain, Credential Locker, encrypted file).

Runs in CI on macOS, Windows and Linux runners. Uses its own vault home so it never
touches a developer's real store (the service name is derived from the home path).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MAISECRETS_HOME", tempfile.mkdtemp(prefix="maisecrets-platform-"))

from maisecrets import vault  # noqa: E402


class PlatformBackendTests(unittest.TestCase):
    def test_native_backend_round_trip(self):
        v = vault.Vault({"backend": "keychain"})   # resolves to the platform default
        name = type(v.backend).__name__
        value = "glpat-" + "PlatformSmoke0123456789ab"
        e = v.put(value, "SECRET", "gitlab-pat")
        self.assertEqual(v.get(e.key, human=True), (value, "ok"), name)
        v._index["entries"][e.key]["expires"] = 0
        v._save_index()
        self.assertEqual(v.get(e.key, human=True), (None, "expired"), name)
        self.assertIsNone(v.backend.get(e.key), name)
        print(f"native backend on {sys.platform}: {name} ok")


if __name__ == "__main__":
    unittest.main()
