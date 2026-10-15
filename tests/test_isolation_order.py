"""A runner that loads maisecrets before tests/_isolate.py must not reach the real store (TASK-25).

On 2026-10-12 a scratch runner called detect.rules() before the tests imported _isolate: detect imported the vault,
which bound HOME, INDEX, CONFIG and SERVICE to the real ~/.maisecrets, and the suite's resets deleted the real index,
vault file and key there. Two guards: _isolate refuses to start when the vault already names another home, and the
vault refuses to work when a test run owns another home (MAISECRETS_TEST_HOME_OWNED).

Each case runs in a child whose HOME is a temp directory standing in for the user's home: the real home is never in
reach, even when a guard is missing.

Run: python3 -m unittest tests.test_isolation_order -v
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent


class IsolationOrderTests(unittest.TestCase):
    def setUp(self):
        self.fake_user_home = Path(tempfile.mkdtemp(prefix="maisecrets-fake-user-home-"))
        self.addCleanup(shutil.rmtree, self.fake_user_home, True)

    def child(self, code: str) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items()
               if k not in ("MAISECRETS_HOME", "MAISECRETS_TEST_HOME_OWNED", "MAISECRETS_TEST_TMP_OWNED")}
        env["HOME"] = env["USERPROFILE"] = str(self.fake_user_home)
        prelude = f"import sys; sys.path[:0] = [{str(ROOT)!r}, {str(TESTS)!r}]\n"
        return subprocess.run([sys.executable, "-c", prelude + textwrap.dedent(code)], env=env,
                              capture_output=True, text=True, timeout=120)

    def user_store(self) -> list[str]:
        d = self.fake_user_home / ".maisecrets"
        return sorted(p.name for p in d.iterdir()) if d.exists() else []

    def test_the_premise_loading_the_rules_first_binds_the_vault_to_the_user_home(self):
        r = self.child("""
            from maisecrets import detect, vault
            detect.rules()
            print(vault.HOME)
        """)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), str(self.fake_user_home / ".maisecrets"))

    def test_isolate_refuses_to_start_after_the_vault_bound_another_home(self):
        r = self.child("""
            from maisecrets import detect
            detect.rules()
            import _isolate
        """)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("_isolate must be imported first", r.stderr)

    def test_a_store_call_under_a_test_home_marker_fails_loudly_and_touches_nothing(self):
        r = self.child("""
            import os, tempfile
            from maisecrets import detect, vault
            detect.rules()
            mine = tempfile.mkdtemp()
            os.environ["MAISECRETS_HOME"] = os.environ["MAISECRETS_TEST_HOME_OWNED"] = mine
            for call in (vault.load_config, vault.Vault, lambda: vault.make_backend({"backend": "jsonfile"})):
                try:
                    call()
                except vault.WrongHome as e:
                    print("refused:", e)
                else:
                    print("ran")
        """)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("refused:"), 3, r.stdout)
        self.assertNotIn("ran", r.stdout)
        self.assertEqual(self.user_store(), [], "nothing was written into the user's home")

    def test_the_vault_works_when_the_home_is_the_one_the_test_run_owns(self):
        r = self.child("""
            import _isolate
            from pathlib import Path
            import os
            Path(os.environ["MAISECRETS_HOME"], "config.json").write_text(
                '{"backend": "jsonfile", "allow_plaintext_store": true}')
            from maisecrets import vault
            vault.Vault()
            print("ok")
        """)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "ok")
        self.assertEqual(self.user_store(), [])


if __name__ == "__main__":
    unittest.main()
