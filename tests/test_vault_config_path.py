"""Vault references read and write the config file that the client itself uses.

Claude Code 2.1.301 (function `v_`) uses `<config home>/.config.json` when it is a regular file and not empty, or
when it is empty with a write bit set and the global file does not exist; else `<CLAUDE_CONFIG_DIR or home>/
.claude<suffix>.json`. On a machine with both files, the other one is a stale copy: maisecrets must never read a URL
from it or write a header into it. Its lock is `<chosen file>.lock` and its backup lies beside the chosen file.

Run: python3 -m unittest tests.test_vault_config_path -v
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import ssl
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
import test_vault_refs as tvr  # noqa: E402  the Base class only: its tests stay in their own module

from maisecrets import hooks, vault_refs  # noqa: E402
from maisecrets.vault import Vault, load_config  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

STALE_URL = "https://stale.example/mcp"
FRESH_URL = "https://fresh.example/mcp"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _guard_module():
    spec = importlib.util.spec_from_file_location("maisecrets_guard_under_test", tvr.ROOT / "hooks" / "guard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Choice(tvr.Base):
    """Which file is the client config: each clause of the client's condition."""

    def legacy(self, servers: dict | None = None, raw: str | None = None) -> Path:
        path = self.profile / ".config.json"
        path.write_text(raw if raw is not None else json.dumps({"mcpServers": servers or {}}, indent=2))
        return path

    def assertChosen(self, name: str) -> None:
        self.assertEqual(vault_refs.claude_json(), self.profile / name)
        self.assertEqual(Path(_guard_module()._client_config()), self.profile / name, "the guard has the same rule")

    def test_without_config_json_the_global_file_is_used(self):
        self.client_config({"a": {"url": FRESH_URL}})
        self.assertChosen(".claude.json")

    def test_a_non_empty_config_json_wins_over_an_existing_claude_json(self):
        self.client_config({"a": {"url": STALE_URL}})
        self.legacy({"a": {"url": FRESH_URL}})
        self.assertChosen(".config.json")
        self.assertEqual(vault_refs.user_servers(), {"a": FRESH_URL})

    def test_an_empty_writable_config_json_wins_only_when_the_global_file_is_missing(self):
        path = self.legacy(raw="")
        os.chmod(path, 0o600)
        self.assertChosen(".config.json")
        self.client_config({"a": {"url": FRESH_URL}})
        self.assertChosen(".claude.json")

    def test_an_empty_config_json_without_a_write_bit_is_not_used(self):
        path = self.legacy(raw="")
        os.chmod(path, 0o444)
        self.addCleanup(os.chmod, path, 0o600)
        if os.name == "nt":
            self.skipTest("Windows reports the write bits from the read-only attribute only")
        self.assertChosen(".claude.json")

    def test_a_folder_named_config_json_is_not_used(self):
        (self.profile / ".config.json").mkdir()
        self.client_config({"a": {"url": FRESH_URL}})
        self.assertChosen(".claude.json")

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_a_link_is_followed_as_the_client_follows_it(self):
        target = self.profile / "dotfiles.json"
        target.write_text(json.dumps({"mcpServers": {"a": {"url": FRESH_URL}}}))
        (self.profile / ".config.json").symlink_to(target)
        self.client_config({"a": {"url": STALE_URL}})
        self.assertChosen(".config.json")
        (self.profile / ".config.json").unlink()
        (self.profile / ".config.json").symlink_to(self.profile / "missing.json")
        self.assertChosen(".claude.json")

    def test_a_custom_oauth_url_names_another_global_file(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_CUSTOM_OAUTH_URL": "https://login.example"}):
            self.assertChosen(".claude-custom-oauth.json")
            self.legacy({"a": {"url": FRESH_URL}})
            self.assertChosen(".config.json")

    def test_without_claude_config_dir_the_config_home_is_dot_claude(self):
        home = Path(tempfile.mkdtemp(prefix="vault-refs-home-"))
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        env.update(HOME=str(home), USERPROFILE=str(home))
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(vault_refs.claude_json(), home / ".claude.json")
            (home / ".claude").mkdir()
            (home / ".claude" / ".config.json").write_text("{}")
            self.assertEqual(vault_refs.claude_json(), home / ".claude" / ".config.json")
            self.assertEqual(Path(_guard_module()._client_config()), home / ".claude" / ".config.json")

    def test_the_profile_id_does_not_change_with_the_chosen_file(self):
        self.client_config({"a": {"url": FRESH_URL}})
        before = vault_refs.profile()
        self.legacy({"a": {"url": FRESH_URL}})
        self.assertEqual(vault_refs.profile(), before, "the key of an origin stays the same")

    def test_an_empty_claude_config_dir_changes_nothing(self):
        # outside the suite's own guard, with the default home: only the empty value refuses (a check, no write)
        env = {k: v for k, v in os.environ.items() if k != "MAISECRETS_TEST_HOME_OWNED"}
        env["CLAUDE_CONFIG_DIR"] = ""
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(vault_refs, "HOME", vault_refs._DEFAULT_HOME):
            self.assertFalse(vault_refs._may_change_config())
            self.assertEqual(vault_refs.legacy_file(), Path(".config.json"), "relative, as `??` in the client")
            self.assertEqual(Path(_guard_module()._client_config()).name, ".config.json"
                             if (Path.cwd() / ".config.json").is_file() else ".claude.json")
            self.assertEqual(vault_refs.user_servers(), {}, "no server is read from a file the hook cannot know")

    def test_the_config_home_is_normalized_to_nfc_as_the_client_does(self):
        import unicodedata
        nfd = unicodedata.normalize("NFD", str(self.profile / "Pr\u00f6file"))
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": nfd}):
            want = unicodedata.normalize("NFC", nfd)
            self.assertEqual(str(vault_refs.legacy_file()), os.path.join(want, ".config.json"))
            self.assertEqual(str(vault_refs.global_file()), os.path.join(nfd, ".claude.json"), "b() keeps the spelling")
            g, seen, real_stat = _guard_module(), [], os.stat
            with mock.patch.object(g.os, "stat", side_effect=lambda p: seen.append(p) or real_stat(p)):
                g._client_config()
            self.assertEqual(seen, [os.path.join(want, ".config.json")], "the guard looks at the NFC name too")

    def test_an_empty_writable_config_json_beside_a_broken_global_link_is_used(self):
        if os.name == "nt":
            self.skipTest("a symbolic link needs a privilege on Windows")
        path = self.legacy(raw="")
        os.chmod(path, 0o600)
        (self.profile / ".claude.json").symlink_to(self.profile / "missing.json")
        self.assertChosen(".config.json")

    def test_a_global_file_that_is_a_folder_still_counts_as_existing(self):
        path = self.legacy(raw="")
        os.chmod(path, 0o600)
        (self.profile / ".claude.json").mkdir()
        self.assertChosen(".claude.json")

    def test_the_plain_claude_json_stays_guarded_with_a_custom_oauth_url(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_CUSTOM_OAUTH_URL": "https://login.example"}):
            self.assertIn(str(self.profile / ".claude.json"), vault_refs.config_files())
            self.assertTrue(hooks._a_guarded_path(str(self.profile / ".claude.json"), str(self.work)))

    def test_the_account_of_the_install_check_comes_from_the_chosen_file(self):
        from maisecrets import cli
        self.client_config({}, oauthAccount={"organizationUuid": "org-stale", "accountUuid": "acc-stale"})
        self.assertEqual(cli._active_account(), "org-stale_acc-stale")
        self.legacy(raw=json.dumps({"oauthAccount": {"organizationUuid": "org-new", "accountUuid": "acc-new"}}))
        self.assertEqual(cli._active_account(), "org-new_acc-new")
        self.assertEqual(_guard_module()._account(), "org-new_acc-new")

    def test_both_files_are_guarded_from_a_bash_value(self):
        self.client_config({"a": {"url": STALE_URL}})
        self.legacy({"a": {"url": FRESH_URL}})
        files = vault_refs.config_files()
        self.assertEqual(files[0], str(self.profile / ".config.json"))
        self.assertIn(str(self.profile / ".claude.json"), files)
        for name in (".config.json", ".claude.json"):
            self.assertTrue(hooks._a_guarded_path(str(self.profile / name), str(self.work)), name)


class Write(tvr.Base):
    """The header, the lock and the backup go to the chosen file; the stale file keeps its bytes."""

    def setUp(self) -> None:
        super().setUp()
        self.stale = self.client_config({"a": {"type": "http", "url": STALE_URL}})
        self.fresh = self.profile / ".config.json"
        self.fresh.write_text(json.dumps({"numStartups": 9, "mcpServers": {"a": {"type": "http", "url": FRESH_URL}}},
                                         indent=2))
        self.stale_sha = sha(self.stale)

    def tearDown(self) -> None:
        self.assertEqual(sha(self.stale), self.stale_sha, "the stale .claude.json keeps its bytes")
        self.assertFalse((self.profile / ".claude.json.maisecrets-backup").exists())
        self.assertFalse((self.profile / ".claude.json.lock").exists())

    def test_the_header_goes_into_config_json(self):
        self.assertIn("a supports Client-Vault", self.enable())
        header = json.loads(self.fresh.read_text())["mcpServers"]["a"]["headers"]["Client-Vault"]
        self.assertRegex(header, r"\Av=1, kid=:[A-Za-z0-9+/]{43}=:\Z")
        self.assertEqual(json.loads(self.fresh.read_text())["numStartups"], 9)
        self.assertTrue((self.profile / ".config.json.maisecrets-backup").exists())
        self.assertEqual(vault_refs._enabled(), {"https://fresh.example": [("a", FRESH_URL)]})
        self.assertIsNone(self.start(), "a second start finds the header in place")
        self.assertFalse((self.profile / ".config.json.maisecrets-backup").exists())

    def test_the_lock_is_the_one_of_config_json(self):
        taken = []
        real = vault_refs._ConfigLock.__enter__

        def enter(lock):
            taken.append(lock.dir)
            return real(lock)
        with mock.patch.object(vault_refs._ConfigLock, "__enter__", enter):
            self.enable()
        self.assertEqual(taken, [self.profile / ".config.json.lock"])

    def test_a_busy_lock_of_config_json_holds_the_write_and_one_of_claude_json_does_not(self):
        (self.profile / ".claude.json.lock").mkdir()
        try:
            self.assertIn("a supports Client-Vault", self.enable(), "the stale file's lock is no lock of ours")
        finally:
            (self.profile / ".claude.json.lock").rmdir()
        self.config({"client_header": False})
        lock = self.profile / ".config.json.lock"
        lock.mkdir()
        try:
            # a long stale time: under a high load the 10 s of the client passed before the start (local run)
            with mock.patch.object(vault_refs, "LOCK_STALE", 3600), \
                    mock.patch.object(vault_refs._ConfigLock, "__init__",
                                   lambda s, p, wait=0.3: (setattr(s, "dir", p.with_name(p.name + ".lock")),
                                                           setattr(s, "wait", wait))[0]):
                with self.assertRaises(TimeoutError):
                    self.start()
        finally:
            lock.rmdir()
        self.assertIn("Client-Vault", json.loads(self.fresh.read_text())["mcpServers"]["a"]["headers"],
                      "a fresh client lock: nothing was written")

    def test_a_file_that_changed_before_the_lock_is_not_written(self):
        self.fresh.unlink()                     # the global file is chosen now; .config.json appears under the lock
        real = vault_refs._ConfigLock.__enter__

        def enter(lock):
            self.fresh.write_text(json.dumps({"mcpServers": {"a": {"type": "http", "url": FRESH_URL}}}))
            return real(lock)
        vault_refs._remember_key("https://stale.example", "k", ("a", STALE_URL))
        vault_refs._key(Vault().backend, "https://stale.example", create=True)
        with mock.patch.object(vault_refs._ConfigLock, "__enter__", enter):
            self.assertEqual(vault_refs._apply_config(load_config(), Vault().backend)[:2], ([], []))

    def test_an_old_backup_beside_the_unused_global_file_goes(self):
        self.enable()
        old = self.profile / ".claude.json.maisecrets-backup"
        old.write_text("{}")
        self.assertIsNone(self.start())
        self.assertFalse(old.exists())

    def test_status_names_the_file_it_reads(self):
        lines = vault_refs.status_lines(load_config(), Vault().backend, check=False)
        self.assertEqual(lines[0], f"vault references: client config {self.fresh} ({self.stale} is not read)")
        self.assertIn("a (https://fresh.example)", lines[1])

    def test_status_without_a_second_file_names_one(self):
        os.rename(self.stale, self.profile / "moved.json")
        try:
            lines = vault_refs.status_lines(load_config(), Vault().backend, check=False)
            self.assertEqual(lines[0], f"vault references: client config {self.fresh}")
        finally:
            os.rename(self.profile / "moved.json", self.stale)

    @unittest.skipIf(os.name == "nt", "a symbolic link needs a privilege on Windows")
    def test_a_linked_config_json_stays_a_link_and_the_backup_stays_beside_the_link(self):
        target_dir = Path(tempfile.mkdtemp(prefix="vault-refs-dotfiles-"))
        target = target_dir / "config.json"
        os.replace(self.fresh, target)
        self.fresh.symlink_to(target)
        taken = []
        real = vault_refs._ConfigLock.__enter__

        def enter(lock):
            taken.append(lock.dir)
            return real(lock)
        with mock.patch.object(vault_refs._ConfigLock, "__enter__", enter):
            self.assertIsNotNone(self.enable())
        self.assertEqual(taken, [self.profile / ".config.json.lock"], "the lock of the link's name, as the client's")
        self.assertTrue(self.fresh.is_symlink())
        self.assertIn("Client-Vault", json.loads(target.read_text())["mcpServers"]["a"]["headers"])
        self.assertTrue((self.profile / ".config.json.maisecrets-backup").exists())
        self.assertEqual(sorted(p.name for p in target_dir.iterdir()), ["config.json"],
                         "no backup in a dotfiles folder")


@unittest.skipUnless(tvr.HAS_OPENSSL, "the fake server needs the openssl command for its certificate")
class Resolve(tvr.Base):
    """The whole path with the fake server: the note, the trigger and the resolve use the `.config.json` entry."""

    def setUp(self) -> None:
        super().setUp()
        self.srv = tvr.VaultServer(cert=tvr._cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        self.config({"client_vault_cafile": self.srv.cert})
        self.stale = self.client_config({"demo": {"type": "http", "url": STALE_URL}})
        self.fresh = self.profile / ".config.json"
        self.fresh.write_text(json.dumps({"mcpServers": {"demo": {"type": "http", "url": self.srv.url + "/mcp"}}}))
        self.stale_sha = sha(self.stale)
        self.srv.mint("EMAIL_1", tvr.VALUES[0])

    def test_the_first_token_enables_the_config_json_entry_and_its_value_resolves(self):
        payload = {"tool_name": "mcp__demo__customers", "mcp_server": {"name": "demo", "source": "user"},
                   "session_id": "s1", **CLAUDE, "tool_response": [{"type": "text", "text": f"x {tvr.tok('EMAIL_1')}"}]}
        hooks._post_tool_guarded(payload)
        header = json.loads(self.fresh.read_text())["mcpServers"]["demo"].get("headers")
        self.assertTrue(header and header.get("Client-Vault"), "the trigger wrote the header into .config.json")
        self.assertEqual(sha(self.stale), self.stale_sha)
        req = urllib.request.Request(self.srv.url + "/token", data=b"grant_type=authorization_code", headers=header)
        urllib.request.urlopen(req, context=ssl.create_default_context(cafile=self.srv.cert)).read()
        hooks._post_tool_guarded(payload)
        origin = vault_refs.origin_of(self.srv.url)
        self.assertEqual(vault_refs.noted(["EMAIL_1"], "s1"), {"EMAIL_1": [origin]})
        out = self.write(f"mail,{tvr.tok('EMAIL_1')}\n")
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["content"], f"mail,{tvr.VALUES[0]}\n")
        self.assertEqual(sha(self.stale), self.stale_sha)


if __name__ == "__main__":
    unittest.main()
