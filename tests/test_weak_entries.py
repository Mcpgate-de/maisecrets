"""A word that only a label rule found is replaced where it was found and never hunted in other texts.

`DB_PASSWORD=postgres` stored `postgres`. Every later text of every session held the word as a whole token, so
`docker ps` showed `⟦SECRET_c1⟧:16`, and the prompt "please add a postgres service" was blocked, for a day (review,
2026-09-29). A random value after a label is still hunted: it is a secret wherever it shows up again.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import INDEX, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
WORD = "postgres"
RANDOM = "Kx7Qp2" + "Zr9Lm4Wn"


class WeakEntryTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)

    def bash(self, stdout: str, session: str = "s1") -> dict:
        hooks._live_cache.clear()
        return hooks.post_tool({"tool_name": "Bash", "session_id": session, **CLAUDE, "tool_input": {"command": "x"},
                                "tool_response": {"stdout": stdout, "stderr": "", "interrupted": False,
                                                  "isImage": False}})

    def prompt(self, text: str, session: str = "s2") -> dict:
        hooks._live_cache.clear()
        return hooks.user_prompt({"prompt": text, "session_id": session, **CLAUDE})

    def test_a_word_is_replaced_where_it_was_found_and_nowhere_else(self):
        out = self.bash("DB_PASS" + f"WORD={WORD}\n")
        self.assertNotIn(WORD, json.dumps(out), "the result that held the label is redacted")
        entries = json.loads(INDEX.read_text())["entries"]
        self.assertEqual([m["weak"] for m in entries.values()], [True])
        # later texts: the word alone is no secret
        self.assertEqual(self.bash(f"1a2b3c4d5e6f   {WORD}:16   app-{WORD}-1\n"), {})
        self.assertEqual(self.bash(f"image: {WORD}:16\n", session="s9"), {})
        self.assertNotEqual(self.prompt(f"please add a {WORD} service to the compose file").get("decision"), "block")

    def test_a_random_value_is_still_hunted_everywhere(self):
        out = self.bash("DB_PASS" + f"WORD={RANDOM}\n")
        self.assertNotIn(RANDOM, json.dumps(out))
        self.assertEqual([m["weak"] for m in json.loads(INDEX.read_text())["entries"].values()], [False])
        self.assertNotIn(RANDOM, json.dumps(self.bash(f"export X={RANDOM}\n")))
        self.assertEqual(self.prompt(f"the value is {RANDOM}").get("decision"), "block")

    def test_the_placeholder_of_a_word_still_resolves_and_the_mark_survives_a_use(self):
        e = Vault().put(WORD, "SECRET", "ds-keyword-equal-signs", session="s1")
        self.assertTrue(e.weak)
        self.assertEqual(Vault().get(e.key, "s1"), (WORD, "ok"))       # a use rewrites the index record
        self.assertTrue(json.loads(INDEX.read_text())["entries"][e.key]["weak"])
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                              "tool_input": {"command": f"psql -U {e.ref}"}})
        self.assertIn("updatedInput", out.get("hookSpecificOutput", {}), out)
        # a value this session resolved is hunted as a substring; a word is not: postgresql stays readable
        Vault().record_resolve(e.key, "s1", "Bash", "psql")
        self.assertEqual(self.bash("connected to postgresql 16 as the admin role\n"), {})

    def test_a_word_from_put_or_a_shape_rule_is_not_weak(self):
        self.assertFalse(Vault().put("Sommerwiese", "SECRET", "manual", session="s1").weak)
        self.assertFalse(Vault().put("glpat-" + "Q7w8E9r0T1y2U3i4O5p6", "SECRET", "gitlab-pat", session="s1").weak)
        self.assertFalse(Vault().put("Sommer2026!", "SECRET", "ds-keyword-colon", session="s1").weak)

    def test_an_entry_of_an_older_version_is_marked_at_the_next_start(self):
        v = Vault()
        word = v.put(WORD, "SECRET", "ds-keyword-colon", session="s1")
        rnd = v.put(RANDOM, "SECRET", "ds-keyword-colon", session="s1")
        idx = json.loads(INDEX.read_text())
        for key in (word.key, rnd.key):
            del idx["entries"][key]["weak"]                               # as 0.5.14 wrote them
        INDEX.write_text(json.dumps(idx))
        self.assertEqual(Vault().mark_weak_entries(), 1)
        entries = json.loads(INDEX.read_text())["entries"]
        self.assertEqual((entries[word.key]["weak"], entries[rnd.key]["weak"]), (True, False))
        self.assertEqual(Vault().live_fingerprints(), {rnd.fingerprint: rnd.key})
        self.assertEqual(Vault().mark_weak_entries(), 0, "a marked entry is not read again")


if __name__ == "__main__":
    unittest.main()
