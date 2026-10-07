"""Codex runs a plugin hook only while the trust the person gave it still matches the hook.

Codex keeps `trusted_hash` per hook in config.toml and compares it with a hash of the hook as it is now
(codex-rs hooks/src/engine/discovery.rs, hook_hash). A different hash makes the hook "Modified", and a modified
hook does not run, with no message, until the person trusts it again; the ChatGPT app has no screen for that. The
hash covers the command text of the platform (commandWindows on Windows), the timeout and the matcher. The
recomputation below matched the hashes in two real config.toml files (macOS and Windows, 2026-09-30).

So a change to a command in hooks/hooks.json switches maisecrets off for every Codex user. If the change is
meant, update the hashes here and say in the CHANGELOG that Codex users must trust the hooks again.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = {"SessionStart": "session_start", "UserPromptSubmit": "user_prompt_submit", "PreToolUse": "pre_tool_use",
          "PostToolUse": "post_tool_use"}
# events Codex does not have: it skips them and loads the others (PostToolUseFailure, measured with codex-cli 0.159.2:
# harness/codex.py passed with it in hooks.json), so they carry no trust
NOT_IN_CODEX = {"PostToolUseFailure"}

# the hashes Codex stored when people trusted the hooks of 0.5.16 to 0.5.23 (posix) and 0.5.15 to 0.5.23 (windows)
TRUSTED = {
    "posix": {
        "session_start": "sha256:192782bd8413e5789b44fe8980e1170ce3bc76606dd1163ad8db243154c22447",
        "user_prompt_submit": "sha256:db3cb30fdc83870f43e5452b1abca1ddd76833eb0637c3ee44ee3cea6baf0626",
        "pre_tool_use": "sha256:6b1daad7c27b49db322e7fadcf59993a29e8c38ba6a691e300616719b73ba6e6",
        "post_tool_use": "sha256:da89673d4eba379ff9959005f328f139f446bc5ce2af4b1aada695bae906bc3d",
    },
    "windows": {
        "session_start": "sha256:5c887c5fb89ef7438e8c3b8b8aa61ad7f6a58d474d59e0aacfba6d01e16229e7",
        "user_prompt_submit": "sha256:0ce6f3cc3c1893e7ef41d95931a6fbad9ef960afdef7f8647a71316ed02e689e",
        "pre_tool_use": "sha256:0faee6bbf9d8d04cc2a426b28bded5badcda126dddfe189c0c9f8e97a38b22ad",
        "post_tool_use": "sha256:752908c82411d878240a3044702b5508118d7e9cb29028632a18ed8693031505",
    },
}


def codex_hashes(platform: str) -> dict:
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    out = {}
    for event, groups in hooks.items():
        if event in NOT_IN_CODEX:
            continue
        for g in groups:
            h = g["hooks"][0]
            command = (h.get("commandWindows") or h["command"]) if platform == "windows" else h["command"]
            identity = {"event_name": EVENTS[event],
                        "hooks": [{"type": "command", "command": command, "timeout": h.get("timeout", 600),
                                   "async": False}]}
            if g.get("matcher") is not None:
                identity["matcher"] = g["matcher"]
            blob = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            out[EVENTS[event]] = "sha256:" + hashlib.sha256(blob).hexdigest()
    return out


class CodexTrustTests(unittest.TestCase):
    def test_the_hook_commands_keep_the_trust_codex_users_gave(self):
        for platform, want in TRUSTED.items():
            with self.subTest(platform):
                self.assertEqual(codex_hashes(platform), want,
                                 "a hook command changed: every Codex user's maisecrets hooks stop running until "
                                 "they trust them again (see the docstring)")


if __name__ == "__main__":
    unittest.main()
