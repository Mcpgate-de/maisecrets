"""PRIVACY.md "What it reads": the hooks read only the files that section lists.

Every hook event runs as a subprocess in a sandbox with decoy files of the person: a private key in ~/.ssh, a note in
~/Documents, a `.env` and a source file in the project. A `sys.addaudithook` in sitecustomize writes each path that the
process (and each Python child it starts) opens or lists. Each path must fall into one category of the section: the
text the client hands the hooks comes on stdin and needs no file; maisecrets' own files (its home, the machine policy,
the plugin folder); the client's transcript; the client's configuration; the file of a tool call; and the files of
Python and of the system that hold no data of the person.

It checks the paths of the events and settings it runs, not every branch: a read that only a setting it leaves off
starts (rule_dirs, value_files, a name service, a vault server) is outside it, and so is a program the hooks start
(its own reads do not reach the audit hook). A `stat` or an `exists` is no read here: they show that a file is there,
not what it holds."""
from __future__ import annotations

import json
import os
import re
import signal
import site
import subprocess
import sys
import sysconfig
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
import _hygiene  # noqa: E402
from test_cli_matrix import JSONFILE, ROOT, Sandbox, fake_value  # noqa: E402

# the fd is open before the hook is in place, and os.write raises no audit event: the hook cannot call itself
_AUDIT = '''
import os, sys
_ms_log = os.environ.get("MS_TEST_READS")
if _ms_log:
    _ms_fd = os.open(_ms_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    def _ms_audit(event, args, _fd=_ms_fd):
        if event not in ("open", "os.listdir", "os.scandir", "glob.glob") or not args:
            return
        p = args[0]
        if p is None or isinstance(p, int):
            return
        if event == "open":
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            if isinstance(mode, str) and not set(mode) & set("r+"):
                return                              # open(..., "w" / "a" / "x"): a write only
            if mode is None and flags & 3 == os.O_WRONLY:
                return                              # os.open for writing only
        try:
            p = os.fsdecode(p)
        except Exception:
            return
        os.write(_fd, ("%s\\t%s\\n" % (event, p.replace("\\n", " "))).encode("utf-8", "replace"))
    sys.addaudithook(_ms_audit)
'''


def _under(path: str, roots) -> bool:
    for r in roots:
        r = str(r).rstrip(os.sep)
        if r and (path == r or path.startswith(r + os.sep)):
            return True
    return False


class World:
    """The sandbox with the decoy files, and the categories of PRIVACY.md "What it reads" as paths."""

    def __init__(self, case: unittest.TestCase):
        self.sb = Sandbox(JSONFILE, backend="jsonfile")
        case.addCleanup(self.sb.remove)
        case.addCleanup(self.stop_serving)          # runs first: the children work in the sandbox folder
        root, home = self.sb.root, self.sb.user_home
        site_dir = root / "site"
        site_dir.mkdir()
        fakes = Path(_isolate.SITE, "sitecustomize.py").read_text(encoding="utf-8")
        (site_dir / "sitecustomize.py").write_text(_AUDIT + "\n" + fakes, encoding="utf-8")
        self.log = root / "reads.log"
        self.env = self.sb.env(PYTHONPATH=str(site_dir), MS_TEST_READS=str(self.log), MAISECRETS_GUARD_WAIT="0.5")
        self.project = root / "proj"
        # the decoys: files of the person that no hook may read
        self.decoys = [home / ".ssh" / "id_ed25519", home / "Documents" / "notes.txt", self.project / ".env",
                       self.project / "src" / "app.py", home / ".aws" / "credentials"]
        for d in self.decoys:
            d.parent.mkdir(parents=True, exist_ok=True)
            d.write_text("decoy\n", encoding="utf-8")
        # the client's configuration, as Claude Code keeps it
        claude = home / ".claude"
        (claude / "commands").mkdir(parents=True)
        (claude / "settings.json").write_text(json.dumps({"enabledPlugins": {"maisecrets@maisecrets": True}}),
                                              encoding="utf-8")
        (self.project / ".claude").mkdir()
        (self.project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        # with CLAUDE_CONFIG_DIR set (the sandbox sets it), the client's config file lies in that folder
        servers = json.dumps({"mcpServers": {"srv": {"type": "http", "url": "https://mcp.example.com/"}}})
        for f in (home / ".claude.json", claude / ".claude.json"):
            f.write_text(servers, encoding="utf-8")
        self.read_file = self.project / "README.md"           # the file of a Read tool call
        self.read_file.write_text("hello\n", encoding="utf-8")
        self.transcript = claude / "projects" / "proj" / "S1.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("{}\n", encoding="utf-8")

    def stop_serving(self) -> None:
        """A pre-tool Bash call with a placeholder leaves a child that serves the value for up to 120 s; nobody reads
        it here. Another module's check for such children must not find them."""
        for pid in _hygiene.serving_children(cwd_root=str(self.sb.root)):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        left = _hygiene.wait_for_no_serving_child(cwd_root=str(self.sb.root))
        if left:
            raise AssertionError(f"value-serving children still run: {left}")

    def category(self, path: str) -> str | None:
        """The category of PRIVACY.md "What it reads" that a path falls into, or None."""
        sb, home = self.sb, self.sb.user_home
        claude = home / ".claude"
        for p in {path, os.path.realpath(path)}:
            name = os.path.basename(p)
            parent = os.path.dirname(p)
            if _under(p, [sb.home, ROOT, sb.root / "site"]) or p in (str(self.log),) or \
                    p.startswith(str(sb.home) + ".") or _under(p, [os.path.dirname(x) for x in _policy_paths()]):
                return "its own files"
            if p == str(self.transcript) or _under(p, [str(self.transcript)[:-len(".jsonl")]]):
                return "the client's transcript"
            if p in (str(home / ".claude.json"), str(claude / ".claude.json"), str(claude / ".config.json")) or \
                    (name in ("settings.json", "settings.local.json") and os.path.basename(parent) == ".claude") or \
                    p == str(claude) or _under(p, [claude / "commands", claude / "plugins"]) or p in _managed():
                return "the client's configuration"
            if p == str(self.read_file):
                return "the file of a tool call"
            if _under(p, _python_dirs() + _pycache(home)) or p == "/etc/os-release" or _under(p, ["/proc", "/dev"]):
                return "Python and the system"
            if _under(p, [sb.root / "tmp"]):
                return "its own temp files"
        return None

    def run(self, event: str, payload: dict, script: Path | None = None) -> tuple[subprocess.CompletedProcess, list]:
        self.log.write_text("", encoding="utf-8")
        body = json.dumps({"transcript_path": str(self.transcript), "cwd": str(self.project), **payload})
        if script is None:
            r = self.sb.run(event, stdin=body, env=self.env)
        else:
            r = subprocess.run([sys.executable, str(script)], input=body, capture_output=True, encoding="utf-8",
                               errors="replace", timeout=60, env=self.env, cwd=str(self.sb.root))
        seen = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            what, _, p = line.partition("\t")
            seen.append((what, p))
        return r, seen


def _managed() -> list[str]:
    """The managed settings of Claude Code, as hooks/guard.py reads them."""
    sys.path.insert(0, str(ROOT / "hooks"))
    try:
        import guard
    finally:
        sys.path.pop(0)
    return list(guard.MANAGED.values())


def _policy_paths() -> list[str]:
    from maisecrets.home import POLICY_PATHS
    return [str(p) for p in POLICY_PATHS.values()]


def _pycache(home: Path) -> list[str]:
    """The byte code cache of a Python with a pycache prefix in the home folder (Apple's /usr/bin/python3 uses
    ~/Library/Caches/com.apple.python): in the sandbox it lies under the sandbox home."""
    prefix = sys.pycache_prefix or ""
    real = os.path.expanduser("~")
    if prefix and _under(prefix, [real]):
        return [str(home / os.path.relpath(prefix, real))]
    return [prefix] if prefix else []


def _python_dirs() -> list[str]:
    dirs = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, *sysconfig.get_paths().values()}
    try:
        dirs.update(site.getsitepackages())
    except AttributeError:
        pass
    dirs.add(site.getusersitepackages())
    # the parent directory of the executable's framework on macOS (Homebrew links lib/pythonX.Y there)
    dirs.update(os.path.realpath(d) for d in list(dirs))
    return sorted(d for d in dirs if d)


def payloads(ref: str, world: World) -> list[tuple[str, dict]]:
    """One payload per hook event on the path that does the most work, and a Read of a file."""
    value = fake_value("Rd")
    read = {"tool_name": "Read", "tool_input": {"file_path": str(world.read_file)}, "session_id": "S1"}
    return [
        ("session-start", {"session_id": "S1", "source": "startup"}),
        ("user-prompt", {"prompt": f"password: {value}", "session_id": "S1", "prompt_id": "p1"}),
        ("user-prompt", {"prompt": f"use {ref}", "session_id": "S1", "prompt_id": "p2"}),
        ("pre-tool", {"tool_name": "Bash", "tool_input": {"command": f"printf %s {ref}"}, "session_id": "S1",
                      "prompt_id": "p3"}),
        ("pre-tool", {"tool_name": "mcp__srv__echo", "tool_input": {"token": ref}, "session_id": "S1",
                      "prompt_id": "p4"}),
        ("pre-tool", {**read, "prompt_id": "p5"}),
        ("post-tool", {**read, "prompt_id": "p5", "tool_response": {"type": "text", "file": {
            "filePath": str(world.read_file), "content": f"api_key={fake_value('Rr')}", "numLines": 1,
            "startLine": 1, "totalLines": 1}}}),
        ("post-tool", {"tool_name": "Bash", "session_id": "S1", "prompt_id": "p6",
                       "tool_response": {"stdout": f"api_key={fake_value('Rb')}"}}),
        ("post-tool", {"tool_name": "mcp__srv__echo", "session_id": "S1", "prompt_id": "p7",
                       "tool_response": [{"type": "text", "text": f"token {fake_value('Rm')}"}]}),
        ("post-tool", {"tool_name": "Bash", "session_id": "S1", "turn_id": "t", "model": "m",
                       "tool_response": {"stdout": f"api_key={fake_value('Rc')}"}}),
        ("session-end", {"session_id": "S1", "reason": "clear"}),
    ]


@unittest.skipIf(sys.platform == "win32", "the categories name POSIX system paths (/dev, /proc); the Linux and macOS "
                 "runs check the same hook code")
class ReadsOnlyListedFilesTests(unittest.TestCase):
    """PRIVACY.md: "It reads no other file of yours, except through a tool call that you or the agent makes." """

    def setUp(self):
        _hygiene.watch_children(self)

    def test_the_audit_sees_a_read_of_a_decoy(self):
        # the premise: a green run proves nothing if the hook does not see a read in a child process
        w = World(self)
        decoy = w.decoys[0]
        w.log.write_text("", encoding="utf-8")
        code = f"open({str(decoy)!r}).read(); import os; os.listdir({str(decoy.parent)!r})"
        subprocess.run([sys.executable, "-c", code], env=w.env, check=True, timeout=30)
        seen = w.log.read_text(encoding="utf-8")
        self.assertIn(f"open\t{decoy}", seen)
        self.assertIn(f"os.listdir\t{decoy.parent}", seen)
        self.assertIsNone(w.category(str(decoy)))

    def test_every_hook_event_reads_only_the_listed_files(self):
        w = World(self)
        out = w.sb.run("put", stdin=fake_value("Rf"), env=w.env).stdout
        key = re.search(r"placeholder (?:is )?⟦(\w+)", out).group(1)
        outside: list[str] = []
        categories: set = set()
        for event, payload in payloads(f"⟦{key}⟧", w):
            with self.subTest(event=event, prompt=payload.get("prompt_id")):
                r, seen = w.run(event, payload)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("Traceback", r.stderr)
                self.assertTrue(seen, "the audit saw no read at all")
                for what, p in seen:
                    c = w.category(p)
                    categories.add(c)
                    if c is None:
                        outside.append(f"{event} {payload.get('prompt_id', '')}: {what} {p}")
        self.assertEqual(outside, [])
        # the run reaches the categories it is for
        self.assertLessEqual({"its own files", "the client's transcript", "the client's configuration"}, categories)

    def test_the_guard_reads_only_the_client_configuration(self):
        w = World(self)
        # the guard reads the settings to tell whether maisecrets should run here
        r, seen = w.run("", {"hook_event_name": "UserPromptSubmit", "session_id": "S1", "prompt_id": "g1",
                             "prompt": "hi"}, script=ROOT / "hooks" / "guard.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        outside = [f"{what} {p}" for what, p in seen if w.category(p) is None]
        self.assertEqual(outside, [])
        self.assertIn("the client's configuration", {w.category(p) for _w, p in seen})


if __name__ == "__main__":
    unittest.main()
