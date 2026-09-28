"""Round trip on the native backend of THIS machine (keychain, Credential Locker, encrypted file).

Runs in CI on the macOS and Windows runners of GitHub and on the Linux runner of GitLab. Uses its
own vault home so it never touches a developer's real store (the service name is derived from the
home path).
"""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import vault  # noqa: E402


@unittest.skipUnless(os.environ.get("MAISECRETS_NATIVE_BACKEND_TEST") == "1" or os.environ.get("CI"),
                     "touches the real store of this user; set MAISECRETS_NATIVE_BACKEND_TEST=1")
class PlatformBackendTests(unittest.TestCase):
    def tearDown(self):
        # the fingerprint key is a store item too; without this every run left one behind
        try:
            vault.Vault({"backend": "keychain"}).backend.delete(vault.FP_KEY_ENTRY)
        except Exception:  # noqa: BLE001
            pass

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
        # a value with an umlaut and a quote comes back equal (the keychain printed hex before)
        e2 = v.put("pässwörd'\"" + "Q9z-2026", "SECRET", "manual")
        self.assertEqual(v.get(e2.key, human=True)[0], "pässwörd'\"" + "Q9z-2026", name)
        v.backend.delete(e2.key)
        print(f"native backend on {sys.platform}: {name} ok")


if __name__ == "__main__":
    unittest.main()
