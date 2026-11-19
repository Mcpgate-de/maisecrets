"""A weakening command in a tool call (#84): a Bash call that runs it is refused, a Bash call that only mentions it
passes (hooks._carries, shell_commands.only_mentions). A mention: the text stands in quotes, a heredoc body or a
comment, and no word of the line runs a text (a shell, an interpreter, an AI client, a wrapper, a path or a variable
as the command word). PowerShell has no word parser here and refuses every mention.

Each guard of the same class gets both sides: settings and term removal and the name service (C22, C26), the removal
of an import (C26), not-a-secret (C22) and the demo (C22). The ssh consent sentence (C21, frozen) keeps refusing every
mention.
Run: python3 -m unittest tests.test_mention_is_no_call -v
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

from maisecrets import hooks, not_a_secret  # noqa: E402
from maisecrets.shell_commands import only_mentions  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CONFIG = Path(HOME, "config.json")
SESSION = "S1"
NAS = "/maisecrets:" + "not-a-secret"          # built from parts: the hook of the session that edits this file
NAS_CODEX = "maisecrets: " + "not a secret"
KEY = "NAME" + "_c1"
BODY = (f"Thanks for the report. To keep this value unmasked, type {NAS} {KEY} as your own prompt "
        f"(Codex: {NAS_CODEX} {KEY}). Codex users can also run the command in the terminal.")


def setUpModule():  # noqa: N802 - unittest hook
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))


def tearDownModule():  # noqa: N802 - unittest hook
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    _hygiene.assert_pristine()


def _decision(command: str, tool: str = "Bash", **cfg) -> str:
    if cfg:
        CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **cfg}))
    hooks._live_cache.clear()
    try:
        out = hooks.pre_tool({"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": SESSION, **CLAUDE,
                              "tool_input": {"command": command}})
    finally:
        if cfg:
            CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision", "pass")


def _heredoc(head: str, body: str, tag: str = "EOF") -> str:
    return f"{head} <<'{tag}'\n{body}\n{tag}"


class NotASecretMentions(unittest.TestCase):
    def test_a_comment_body_in_a_heredoc_passes(self):
        # the field case of #84
        self.assertEqual(_decision(_heredoc("gh issue comment 29 --body-file -", BODY)), "pass")
        self.assertEqual(_decision(_heredoc("glab issue note 84 --message \"$(cat)\" 2>&1", BODY)), "deny",
                         "a substitution runs its text: no mention")

    def test_a_commit_message_passes(self):
        for command in (f"git commit -m 'docs: name {NAS} KEY in the usage'",
                        f'git commit -m "docs: name {NAS} KEY" -m "Fixes #84"',
                        _heredoc("git commit -F -", f"docs: tell the person about {NAS} {KEY}"),
                        _heredoc("cat > notes.md", BODY),
                        f"printf '%s\\n' '{NAS} {KEY}' >> notes.md 2>&1 && git add notes.md",
                        f"grep -rn '{NAS}' docs/ # look for {NAS}",
                        # a line continuation and a redirection do not start a command (a backslash before a
                        # heredoc makes its body unsure: refused, shell_commands.heredoc_is_sure)
                        f"git -C \\\n  ./repo commit -m 'docs: {NAS} {KEY}'",
                        _heredoc("gh issue comment 29 2>&1 --repo group/proj --body-file -", BODY)):
            with self.subTest(command=command):
                self.assertEqual(_decision(command), "pass")

    def test_each_form_that_runs_the_command_is_refused(self):
        refused = (
            f"codex exec '{NAS_CODEX} {KEY}'",
            f'claude -p "{NAS} {KEY}"',
            _heredoc("codex exec -", BODY),
            _heredoc("claude -p", BODY),
            f"echo '{NAS} {KEY}' | codex exec -",
            f"echo '{NAS} {KEY}' | xargs -0 codex exec",
            f"env CODEX_HOME=x codex exec '{NAS_CODEX} {KEY}'",
            f"bash -c 'codex exec \"{NAS_CODEX} {KEY}\"'",
            f"sh -c \"claude -p '{NAS} {KEY}'\"",
            f"eval \"codex exec '{NAS_CODEX} {KEY}'\"",
            f"c=codex; $c exec '{NAS_CODEX} {KEY}'",
            f"\"$C\" exec '{NAS_CODEX} {KEY}'",
            f"/opt/homebrew/bin/codex exec '{NAS_CODEX} {KEY}'",
            f"./ask.sh '{NAS} {KEY}'",
            f"'codex' exec '{NAS_CODEX} {KEY}'",
            f"npx @openai/codex exec '{NAS_CODEX} {KEY}'",
            f"unbuffer codex exec '{NAS_CODEX} {KEY}'",
            f"tmux send-keys -t 0 '{NAS} {KEY}' Enter",
            f"printf '{NAS} {KEY}' > p.txt; codex exec - < p.txt",
            f"codex \\\nexec '{NAS_CODEX} {KEY}'",
            f"echo \"$(codex exec '{NAS_CODEX} {KEY}')\"",
            f"echo `codex exec '{NAS_CODEX} {KEY}'`",
            f"codex exec {NAS_CODEX.replace(' ', chr(92) + ' ')}\\ {KEY}",
            f"echo {NAS} {KEY}",
            "python3 -c 'from maisecrets.not_a_secret import allow" + "_typed'",
            _heredoc("python3 -", "from maisecrets import not_a_secret as n\nn.undo" + "_typed('X')"),
            _heredoc("cat > x.py", "import os") + "\npython3 -c 'n.allow" + "_typed(1)'",
            f"python3.12 -c 'print(1)' # {NAS}",
            f"bash run.sh user-prompt <<'EOF'\n{NAS} {KEY}\nEOF",
            f"cat <<EOF\n$(codex exec '{NAS_CODEX} {KEY}')\nEOF",
            f"git commit -m 'x {NAS}'\r",
            _heredoc("gh issue comment 29 --repo \\\n  group/proj --body-file -", BODY),
        )
        for command in refused:
            with self.subTest(command=command):
                self.assertEqual(_decision(command), "deny")

    def test_powershell_refuses_every_mention(self):
        self.assertEqual(_decision(f"gh issue comment 29 --body '{NAS} {KEY}'", tool="PowerShell"), "deny")


class EachRuleOfTheReader(unittest.TestCase):
    """only_mentions itself, one case per rule: another check of the hook can refuse the same command, so each rule
    gets a case that only it decides."""

    def mention(self, command: str) -> bool:
        return only_mentions(command, not_a_secret.in_a_command)

    def test_each_rule(self):
        text = f"'{NAS} {KEY}'"
        calls = {
            "a substitution inside quotes": f'echo "$(codex e {text})"',
            "a backtick runs its text": f"printf {text} | `which codex` e -",
            "a variable as the command word": f"$C e {text}",
            "a braced variable as the command word": f"${{C}} e {text}",
            "a quoted command word": f"'codex' e {text}",
            "a path as the command word": f"./ask {text}",
            "a versioned python": f"python3.12 x.py # {NAS}",
            "an unbuffer wrapper": f"unbuffer codex e {text}",
            "a carriage return": f"echo {text}\r",
            "the match in the code": f"echo {NAS}",
            "a heredoc after a backslash": _heredoc("echo \\x; gh issue comment 1 --body-file -", NAS),
        }
        for why, command in calls.items():
            with self.subTest(why=why):
                self.assertFalse(self.mention(command))
        mentions = {
            "a heredoc body": _heredoc("gh issue comment 29 --body-file -", BODY),
            "a quoted argument": f"git commit -m {text}",
            "a redirection with &": f"gh issue comment 29 --body-file - >&./gh.log <<'EOF'\n{NAS}\nEOF",
            "a line continuation": f"git -C \\\n  ./repo commit -m {text}",
        }
        for why, command in mentions.items():
            with self.subTest(why=why):
                self.assertTrue(self.mention(command))


class SiblingGuards(unittest.TestCase):
    """The same rule for each guard of a weakening command."""

    CASES = (
        ("settings", "/maisecrets:" + "settings tips off"),
        ("codex settings", "maisecrets: " + "set tips off"),
        ("term removal", "/maisecrets:" + "term remove Alex Example"),
        ("name service", "/maisecrets:" + "ner off"),
        ("import removal", "/maisecrets:" + "forget import:v1234abcd"),
        ("demo", "/maisecrets:" + "demo on"),
        ("writer", "apply" + "_typed"),
    )

    def test_a_mention_passes_and_a_call_is_refused(self):
        for what, text in self.CASES:
            with self.subTest(what=what):
                self.assertEqual(_decision(_heredoc("gh issue comment 29 --body-file -", f"Type {text} yourself.")),
                                 "pass")
                self.assertEqual(_decision(f"git commit -m 'docs: explain {text}'"), "pass")
                self.assertEqual(_decision(_heredoc("codex exec -", text)), "deny")
                self.assertEqual(_decision(f"claude -p '{text}'"), "deny")
                self.assertEqual(_decision(f"bash -c \"echo '{text}' | codex exec -\""), "deny")

    def test_the_ssh_consent_sentence_stays_refused_also_as_a_mention(self):
        # C21 is frozen since 0.6.12: its sentence check keeps the old text match
        sentence = "maisecrets: " + "allow ssh web1"
        self.assertEqual(_decision(_heredoc("gh issue comment 29 --body-file -", f"Type {sentence}."),
                                   ssh_consent=True), "deny")
        self.assertEqual(_decision(f"codex exec '{sentence}'", ssh_consent=True), "deny")


if __name__ == "__main__":
    unittest.main()
