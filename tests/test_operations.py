"""Operations paths the reviews found untested: a damaged store file, retention, wipe, the
keychain dump parser, the MCP transcript scrub, and the cost of the post-tool pass."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MAISECRETS_HOME", tempfile.mkdtemp(prefix="maisecrets-ops-"))
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
os.environ.pop("XDG_RUNTIME_DIR", None)

from maisecrets import hooks, vault as vmod  # noqa: E402
from maisecrets.vault import HOME, Vault, parse_keychain_dump, wipe_everything  # noqa: E402

tempfile.tempdir = str(HOME)
_TMP = str(HOME)


def _reset() -> None:
    for f in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
        try:
            os.unlink(Path(_TMP, f))
        except FileNotFoundError:
            pass
    shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
    hooks._live_cache.clear()


class StoreIntegrityTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_damaged_store_file_is_never_overwritten(self):
        Vault().put("first-value-0001-xyz", "SECRET", "manual", session="S1")
        store = Path(_TMP, "vault.json")
        store.write_text("{not json", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            Vault().put("second-value-0002-xyz", "SECRET", "manual", session="S1")
        self.assertEqual(store.read_text(encoding="utf-8"), "{not json", "a put must not replace a damaged store")
        self.assertEqual(Vault().get("SECRET_c1", human=True)[0], None, "reads report nothing rather than guess")

    def test_keychain_dump_parser_takes_only_this_services_accounts(self):
        dump = (
            'keychain: "/Users/x/Library/Keychains/login.keychain-db"\nversion: 512\nclass: "genp"\nattributes:\n'
            '    0x00000007 <blob>="maisecrets SECRET_c3 (manual)"\n    "acct"<blob>="SECRET_c3"\n'
            '    "desc"<blob>="maisecrets placeholder"\n    "svce"<blob>="maisecrets"\n    "type"<uint32>=<NULL>\n'
            'keychain: "/Users/x/Library/Keychains/login.keychain-db"\nversion: 512\nclass: "genp"\nattributes:\n'
            '    0x00000007 <blob>="gh:github.com"\n    "acct"<blob>="someone"\n    "svce"<blob>="gh:github.com"\n'
            'keychain: "/Users/x/Library/Keychains/login.keychain-db"\nclass: "genp"\nattributes:\n'
            '    "acct"<blob>="_maisecrets_fpkey"\n    "svce"<blob>="maisecrets"\n'
            'keychain: "/Users/x/Library/Keychains/login.keychain-db"\nclass: "genp"\nattributes:\n'
            '    "acct"<blob>="EMAIL_c1"\n    "svce"<blob>="maisecrets@1a2b3c4d"\n'
        )
        self.assertEqual(parse_keychain_dump(dump, "maisecrets"), ["SECRET_c3", "_maisecrets_fpkey"])
        self.assertEqual(parse_keychain_dump(dump, "maisecrets@1a2b3c4d"), ["EMAIL_c1"])
        self.assertEqual(parse_keychain_dump("", "maisecrets"), [])


class RetentionTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_purged_metadata_is_deleted_after_keep_purged_days(self):
        v = Vault()
        e = v.put("old-value-1234-abcd", "SECRET", "manual", session="S1")
        v._index["entries"][e.key]["expires"] = time.time() - 10
        v._save_index()
        v = Vault()
        v.expire(limit=None)
        self.assertTrue(v._index["entries"][e.key]["purged"])
        self.assertIn(e.fingerprint, v._index["by_fingerprint"])
        v._index["entries"][e.key]["purged_at"] = time.time() - 31 * 86400
        v._save_index()
        v = Vault()
        v.expire(limit=None)
        self.assertNotIn(e.key, v._index["entries"], "metadata is retention too")
        self.assertNotIn(e.fingerprint, v._index["by_fingerprint"])

    def test_audit_log_is_capped_at_audit_max_lines(self):
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "audit_max_lines": 5}')
        try:
            v = Vault()
            e = v.put("audit-value-1234-abcd", "SECRET", "manual", session="S1")
            for i in range(40):
                self.assertEqual(v.record_resolve(e.key, "S1", "Bash", "x" * 120 + str(i)), "ok")
            lines = Path(_TMP, "audit.log").read_text(encoding="utf-8").splitlines()
            self.assertLessEqual(len(lines), 5)
            self.assertTrue(lines[-1].endswith("39"), "the newest lines are the ones kept")
        finally:
            Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def test_session_start_sweeps_pending_prompts_older_than_15_minutes(self):
        import subprocess
        hooks._save_pending("old prompt", "S-old")
        hooks._save_pending("fresh prompt", "S-new")
        old = hooks._pending_path("S-old")
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(ROOT)}
        Path(_TMP, ".shortcut").write_text("kept\n")
        subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                       input="{}", capture_output=True, text=True, env=env, timeout=60)
        self.assertFalse(old.exists())
        self.assertTrue(hooks._pending_path("S-new").exists())

    def test_wipe_everything_removes_values_metadata_and_logs_and_reports_problems(self):
        v = Vault()
        e = v.put("wipe-value-1234-abcd", "SECRET", "manual", session="S1")
        v.record_resolve(e.key, "S1", "Bash", "echo")
        hooks._save_pending("p", "S1")
        n, problems = wipe_everything(hooks.load_config(), None)
        self.assertGreaterEqual(n, 1)
        self.assertEqual(problems, [])
        for name in ("index.json", "audit.log"):
            self.assertFalse(Path(_TMP, name).exists(), name)
        self.assertEqual(list(Path(_TMP, "pending").iterdir()), [])
        self.assertIsNone(vmod.make_backend(hooks.load_config()).get(e.key))
        self.assertTrue(Path(_TMP, "config.json").exists(), "the config stays")


class McpScrubTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_mcp_pre_tool_hands_the_exact_values_to_the_transcript_scrub(self):
        from unittest import mock
        e = Vault().put("mcp-value-with quote\" and, comma", "SECRET", "manual", session="S1")
        with mock.patch.object(hooks, "_scrub_transcript_later") as later:
            out = hooks.pre_tool({"tool_name": "mcp__x__y", "session_id": "S1", "prompt_id": "p",
                                  "transcript_path": "/tmp/t.jsonl", "tool_input": {"q": "use " + e.ref}})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["q"], "use mcp-value-with quote\" and, comma")
        later.assert_called_once()
        path, values, refs = later.call_args[0]
        self.assertEqual(path, "/tmp/t.jsonl")
        self.assertEqual(values, ["mcp-value-with quote\" and, comma"])
        self.assertEqual(refs, [e.ref])


class CostTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_post_tool_over_a_megabyte_with_25_resolved_keys_stays_far_below_the_watchdog(self):
        v = Vault()
        keys = []
        for i in range(25):
            e = v.put(f"resolved-value-{i:02d}-QzT9xW", "SECRET", "manual", session="S1")
            self.assertEqual(v.record_resolve(e.key, "S1", "mcp__x__y", "{}"), "ok")
            keys.append(e)
        filler = ("lorem ipsum dolor sit amet " * 40 + "\n") * 950
        text = filler + " ".join(f"token {e.key}=resolved-value-{i:02d}-QzT9xW" for i, e in enumerate(keys))
        self.assertGreater(len(text), 1_000_000)
        started = time.time()
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
                               "tool_response": {"stdout": text}})
        took = time.time() - started
        self.assertLess(took, 5.0, f"post-tool took {took:.1f}s on 1 MB; the watchdog fires at 16 s")
        redacted = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertNotIn("QzT9xW", redacted)


if __name__ == "__main__":
    unittest.main()


class ReadRetryTests(unittest.TestCase):
    def test_a_reader_waits_out_a_replace_in_progress_and_gives_up_last(self):
        from unittest import mock
        from maisecrets import vault
        calls = {"n": 0}

        def flaky(self, encoding=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise PermissionError(13, "Permission denied")
            return '{"ok": 1}'
        with mock.patch.object(Path, "read_text", flaky), mock.patch.object(vault.time, "sleep"):
            self.assertEqual(vault.read_text_retry(Path("index.json")), '{"ok": 1}')
        self.assertEqual(calls["n"], 3)
        with mock.patch.object(Path, "read_text", side_effect=PermissionError(13, "x")), \
                mock.patch.object(vault.time, "sleep"):
            with self.assertRaises(PermissionError):
                vault.read_text_retry(Path("index.json"), attempts=3)

