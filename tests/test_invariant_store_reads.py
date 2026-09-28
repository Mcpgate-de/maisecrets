"""Invariant I3: no tool of the agent reads vault material.

Vault material is every file in the vault home (store, index, key file, logs, config) and in the
value run directory (the FIFOs a resolve serves). THREAT-MODEL C8 has the controls; this module
holds the goal over every tool that can read a file and every spelling of a path: absolute,
relative, `~`, `..`, a doubled slash, a symlink, a hardlink, another case, a parent directory
for a recursive search, a Glob pattern, a `file://` URI in an MCP argument, and Bash with the
configured home.

Bash is a text match (C8 calls it a backstop, not a boundary): a command that builds the path
at run time is out of scope, and so is a program the command starts. What is in scope is a
command that names the path the way a person or a model writes it.

The tool population is written out below. A tool the matcher in hooks/hooks.json does not
reach never meets a guard, so each tool that reads a path must be in the matcher, and each tool
left out must say why.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CLIENTS = {"claude": CLAUDE, "codex": {**CODEX, "model": "m"}}

# Every tool of the clients that takes a path, and the field it reads. The matcher must reach each
# one. Codex: its nested shell arrives as Bash; `apply_patch` is not measured (the Codex design is
# open, docs/THREAT-MODEL.md C5), so it is not claimed here.
READERS = {
    "Read": "file_path", "NotebookRead": "notebook_path", "Grep": "path", "Glob": "path", "LS": "path",
    # these read the file before they change it, and the result shows a piece of it
    "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path",
    "Write": "file_path",
}
# tools that take no local path, and why they need no guard here
NO_PATH = {
    "WebFetch": "fetches http and https only",
    "WebSearch": "searches the web",
    "Task": "a subagent's own tool calls pass the same hooks",
    "Agent": "a subagent's own tool calls pass the same hooks",
    "TodoWrite": "writes the task list only",
    "BashOutput": "returns output of a Bash call the hooks saw; PostToolUse redacts it",
    "KillShell": "stops a shell",
    "ExitPlanMode": "no file",
    "SlashCommand": "runs a command file the user installed",
    "Skill": "loads a skill the user installed",
}


def deny(out: dict) -> bool:
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny"


def pre(tool: str, tool_input: dict, cwd: str, client: str = "claude") -> dict:
    hooks._live_cache.clear()
    return hooks.pre_tool({"tool_name": tool, "tool_input": tool_input, "session_id": "S1", "cwd": cwd,
                           "transcript_path": "", **CLIENTS[client]})


class _Store:
    """A store with real files in the vault home and a value run directory with a file in it."""

    def __init__(self) -> None:
        self.v = Vault()
        self.v.put("St" + secrets.token_hex(8), "SECRET", "manual", session="S1")
        self.home = Path(os.path.realpath(HOME))
        self.files = sorted(p for p in self.home.iterdir() if p.is_file())
        assert self.files, "the store wrote no file"
        self.run = Path(hooks._protected_dirs()[-1])
        self.run.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fifo_like = self.run / ("v-" + secrets.token_hex(4))
        self.fifo_like.write_text("value", encoding="utf-8")
        self.outside = Path(tempfile.mkdtemp(prefix="outside-"))

    def cleanup(self) -> None:
        shutil.rmtree(self.outside, ignore_errors=True)
        try:
            self.fifo_like.unlink()
        except FileNotFoundError:
            pass


def _case_variant(path: Path) -> str | None:
    """The path with its last component in another case, if the file system does not tell them apart."""
    other = str(path.parent / path.name.swapcase())
    return other if other != str(path) and os.path.exists(other) else None


class FileToolTests(unittest.TestCase):
    def setUp(self):
        self.s = _Store()
        self.addCleanup(self.s.cleanup)

    def spellings(self) -> dict[str, tuple[str, str]]:
        """(path, cwd) per spelling of a path into the store; each must be refused."""
        s = self.s
        f = next((p for p in s.files if p.name.startswith("index")), s.files[0])
        link_dir = s.outside / "looks-harmless"
        os.symlink(s.home, link_dir)
        link_file = s.outside / "notes.txt"
        os.symlink(f, link_file)
        out = {
            "absolute": (str(f), "/"),
            "the home itself": (str(s.home), "/"),
            "trailing slash": (str(s.home) + "/", "/"),
            "doubled slash": (str(s.home) + "//" + f.name, "/"),
            "dot segment": (str(s.home) + "/./" + f.name, "/"),
            "dot-dot": (str(s.home / ".." / s.home.name / f.name), "/"),
            "relative": (os.path.join(s.home.name, f.name), str(s.home.parent)),
            "relative with dot-dot": (os.path.join("..", s.home.name, f.name), str(s.home.parent / "sub")),
            "tilde": ("~/" + s.home.name + "/" + f.name, "/"),
            "symlinked directory": (str(link_dir / f.name), "/"),
            "symlinked file": (str(link_file), "/"),
            "run directory file": (str(s.fifo_like), "/"),
        }
        try:
            hard = s.outside / "copy.json"
            os.link(f, hard)
            out["hardlink"] = (str(hard), "/")
        except OSError:
            pass                            # a file system without hard links has no such path
        variant = _case_variant(f)
        if variant:
            out["another case"] = (variant, "/")
        return out

    def test_every_reading_tool_refuses_every_spelling_of_a_store_path(self):
        spellings = self.spellings()
        bad = []
        with mock.patch.dict(os.environ, {"HOME": str(self.s.home.parent)}):
            for tool, field in READERS.items():
                for label, (path, cwd) in spellings.items():
                    tool_input = {field: path}
                    if tool in ("Edit", "MultiEdit"):
                        tool_input.update({"old_string": "a", "new_string": "b"})
                    if tool == "Write":
                        tool_input["content"] = "x"
                    if tool == "Grep":
                        tool_input["pattern"] = "."
                    if tool == "Glob":
                        tool_input["pattern"] = "*"
                    for client in CLIENTS:
                        if not deny(pre(tool, tool_input, cwd, client)):
                            bad.append(f"{tool} / {label} / {client}: {path} (cwd {cwd}) was not refused")
        self.assertEqual(bad, [], f"{len(bad)} reads:\n" + "\n".join(bad[:20]))

    def test_a_search_that_covers_the_store_is_refused(self):
        s = self.s
        parent = str(s.home.parent)
        cases = {
            "Grep over the parent": ("Grep", {"pattern": "fingerprint", "path": parent}, "/"),
            "Grep without a path in the parent": ("Grep", {"pattern": "fingerprint"}, parent),
            "Grep with a glob into the store": ("Grep", {"pattern": ".", "path": parent,
                                                         "glob": s.home.name + "/*"}, "/"),
            "Glob with the store in its pattern": ("Glob", {"pattern": str(s.home) + "/*.json"}, "/"),
            "Glob relative into the store": ("Glob", {"pattern": s.home.name + "/**", "path": parent}, "/"),
            "Grep over the run directory's parent": ("Grep", {"pattern": "v", "path": str(s.run.parent)}, "/"),
        }
        bad = [f"{label} / {client}" for label, (tool, ti, cwd) in cases.items() for client in CLIENTS
               if not deny(pre(tool, ti, cwd, client))]
        self.assertEqual(bad, [], "\n".join(bad))

    def test_an_mcp_argument_that_names_the_store_is_refused(self):
        s = self.s
        f = s.files[0]
        cases = {
            "path": {"path": str(f)},
            "nested list": {"args": {"paths": ["/tmp/a", str(f)]}},
            "tilde": {"file": "~/" + s.home.name + "/" + f.name},
            "file URI": {"uri": "file://" + str(f)},
            "file URI encoded": {"uri": "file://" + str(f).replace(".", "%2E")},
            "file URI with localhost": {"uri": "file://localhost" + str(f)},
            "symlink": {"path": str(s.outside / "l")},
        }
        os.symlink(f, s.outside / "l")
        bad = []
        with mock.patch.dict(os.environ, {"HOME": str(s.home.parent)}):
            for label, ti in cases.items():
                for client in CLIENTS:
                    if not deny(pre("mcp__fs__read_file", ti, "/", client)):
                        bad.append(f"{label} / {client}: {ti}")
        self.assertEqual(bad, [], "\n".join(bad))

    def test_a_path_outside_the_store_still_passes(self):
        # the guard is only worth something if it leaves the rest alone
        s = self.s
        other = s.outside / "app.log"
        other.write_text("x", encoding="utf-8")
        near = s.home.parent / (s.home.name + "-other")
        near.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, near, True)
        bad = []
        for tool, field in READERS.items():
            for path in (str(other), str(near), str(near / "f.json")):
                ti = {field: path, "pattern": "*", "old_string": "a", "new_string": "b", "content": "x"}
                if deny(pre(tool, ti, "/")):
                    bad.append(f"{tool}: {path}")
        self.assertEqual(bad, [], "\n".join(bad))


class BashTests(unittest.TestCase):
    """Bash names the store by its default spelling or by the configured home. The configured home
    is a directory without the word maisecrets, as a person sets it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="bash-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / ("vh-" + secrets.token_hex(3))
        self.home.mkdir(mode=0o700)
        (self.home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def run_pre(self, command: str) -> dict:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX"))}
        env.update({"MAISECRETS_HOME": str(self.home), "PYTHONUTF8": "1"})
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1", "cwd": "/",
                   "transcript_path": "", **CLAUDE}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "pre-tool"], env=env,
                           input=json.dumps(payload), capture_output=True, encoding="utf-8", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def test_a_command_that_names_the_store_is_refused(self):
        h = str(self.home)
        commands = {
            "cat the default home": "cat ~/.maisecrets/vault.enc.json",
            "cat the configured home": f"cat {h}/index.json",
            "the configured home quoted": f'less "{h}/key"',
            "copy the configured home": f"cp -r {h} /tmp/x",
            "archive it": f"tar czf /tmp/a.tgz -C {self.root} {self.home.name} {h}",
            "python open": f"python3 -c \"print(open('{h}/index.json').read())\"",
            "keychain": "security find-generic-password -s maisecrets -w",
            "the delivery path": "cat /tmp/maisecrets-501/v-abc",
            "the environment variable": "cat $MAISECRETS_HOME/index.json",
        }
        bad = [label for label, c in commands.items() if not deny(self.run_pre(c))]
        self.assertEqual(bad, [], "\n".join(bad))

    def test_a_command_near_the_store_still_runs(self):
        h = str(self.home)
        for c in (f"ls {self.root}", f"cat {h}-other/notes.txt", "echo maisecrets is installed"):
            with self.subTest(c):
                self.assertFalse(deny(self.run_pre(c)), c)


class PopulationTests(unittest.TestCase):
    def test_every_tool_that_reads_a_path_is_in_the_matcher(self):
        hooks_json = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        matchers = [m.get("matcher", "") for m in hooks_json["hooks"]["PreToolUse"]]
        missing = [t for t in list(READERS) + ["Bash", "mcp__fs__read_file"]
                   if not any(re.fullmatch(m, t) for m in matchers)]
        self.assertEqual(missing, [], "a tool the matcher does not reach meets no guard")
        self.assertEqual(set(READERS) & set(NO_PATH), set())

    def test_the_hook_code_knows_no_reading_tool_this_module_does_not(self):
        # a tool name the hook code handles by name is a tool that reads or writes: it must be here
        named = set(hooks._READ_TOOLS) | set(hooks._FILE_TOOLS)
        self.assertEqual(named - set(READERS), set(), "a tool the hooks handle is missing from READERS")


if __name__ == "__main__":
    unittest.main()
