"""I5: a network connection can start only in the code of a service the person set up (docs/THREAT-MODEL.md, C33).

A static check over every Python module of the plugin and the skill, and over the mod. Each list below names a module
and why it may reach for the network or start a program; a module that starts to import a network library, or a new
place that starts a program, fails, and so does an entry that no longer matches its module, so the lists cannot rot.
tests/test_promises.py NoNetworkTests checks the other side at run time: with the default settings no hook connects.
What this check cannot see: a library that another module imports for it, a name built at run time
(`__import__(name)`, `getattr`), a module or `$` handed on under another name, and what a started program does."""
import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir

SOURCES = ("maisecrets", "hooks", "skills")
NETWORK = {"socket", "ssl", "http.client", "http.server", "urllib.request", "socketserver", "ftplib", "smtplib",
           "imaplib", "poplib", "telnetlib", "xmlrpc.client", "xmlrpc.server", "asyncio", "webbrowser", "requests",
           "httpx", "urllib3", "aiohttp", "websocket", "websockets"}
PROCESS = {"subprocess", "multiprocessing", "pty", "concurrent.futures.process"}
# the calls that start a program, by their full name
STARTS = {f"subprocess.{f}" for f in ("run", "Popen", "call", "check_call", "check_output", "getoutput",
                                      "getstatusoutput")} | \
    {f"os.{f}" for f in ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp")} | \
    {f"os.{p}{s}" for p in ("exec", "spawn") for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")} | \
    {"multiprocessing.Process", "multiprocessing.Pool", "pty.spawn", "pty.fork",
     "concurrent.futures.ProcessPoolExecutor", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"}
# path helpers of urllib.request that open nothing
NOT_NETWORK = {("urllib.request", "url2pathname"), ("urllib.request", "pathname2url")}

# the modules of a service the person set up, and the library each one may import
MAY_CONNECT = {
    "maisecrets/detection/remote.py": ({"socket", "ssl", "http.client"}, "the name service client (C30)"),
    "maisecrets/ner_setup.py": ({"socket", "urllib.request"}, "/maisecrets:ner sets up and checks a name service"),
    "maisecrets/ner_health.py": ({"socket"}, "the health of the name service the person set up"),
    "maisecrets/ner_metrics.py": ({"urllib.request"}, "the load of the name service the person set up"),
    "maisecrets/sref_client.py": ({"socket", "ssl", "http.server"},
                                  "the gateway of Sensitive References (C31), its login with a loopback redirect"),
    "maisecrets/vault_refs.py": ({"ssl", "http.client"}, "the server that offers vault references (C27)"),
    "maisecrets/cli.py": ({"webbrowser"}, "opens the login page of a typed /maisecrets:sref login"),
    "hooks/proxy_connect.py": ({"socket"}, "the ssh ProxyCommand of a command with a value, to the sandbox proxy"),
    "hooks/sandbox_probe.py": ({"socket"}, "the first step of such a command: is it inside the sandbox"),
}
# the modules that start a program: how many places start one, and what they start. A new place is a new entry.
MAY_START = {
    "hooks/guard.py": (1, "the clipboard tool, with the restart command"),
    "maisecrets/codex_helper.py": (1, "ps, for the parent process"),
    "maisecrets/file_reads.py": (3, "a text extractor for a PDF, ps and ldd"),
    "maisecrets/hooks.py": (5, "the clipboard tool (read, write), and Python children: a later transcript scrub, "
                               "the server of a value through a FIFO, the scrub of a failed prompt"),
    "maisecrets/hub.py": (1, "maisecrets.cli ner start, for the name service the person set up"),
    "maisecrets/ner_setup.py": (2, "the container tool of the name service the person set up, and its keeper"),
    "maisecrets/sref_client.py": (1, "a Python child that serves a gateway value through a FIFO"),
    "maisecrets/user_rules.py": (1, "a Python child that checks a rule of the person"),
    "maisecrets/vault.py": (1, "the tool of the operating system's store"),
    "skills/secret-hygiene/scripts/_detector.py": (2, "worker processes of the scan, and git log for the history"),
    "skills/secret-hygiene/scripts/protection_status.py": (2, "Python and claude plugin list, for the status"),
    "skills/secret-hygiene/scripts/redact_copy.py": (1, "git rev-parse"),
    "skills/secret-hygiene/scripts/scan_secrets.py": (1, "git, for the repository the person asked to scan"),
}
# modules that import a process library and start nothing with it
NAMES_ONLY = {"maisecrets/incidents.py": "names subprocess.TimeoutExpired"}
# the members of `$` the mod may use, and of globalThis; none of them reaches the network
MOD_MEMBERS = {"clock", "command", "env", "plugin", "process", "prompt", "session", "state", "store", "ui"}
MOD_GLOBALS = {"crypto"}
MOD_FORBIDDEN = (r"\bfetch\b", r"\bXMLHttpRequest\b", r"\bWebSocket\b", r"\bEventSource\b", r"\bnavigator\b",
                 r"\bwindow\b", r"\bimport\s*\(", r"\brequire\s*\(", r"^\s*import\s", r"\bnode:", r"\bchild_process\b",
                 r"\$\s*\[", r"\}\s*=\s*\$(?![\w.])", r"=\s*\$\s*(?:[;\n,)]|$)", r"\bglobalThis\s*\[")
# the hook name the mod registers is no use of the API
MOD_HOOK_NAMES = ("'http.fetch'", '"http.fetch"')


def modules():
    files = [p for d in SOURCES for p in sorted((ROOT / d).rglob("*.py"))]
    return [(p.relative_to(ROOT).as_posix(), ast.parse(p.read_text(encoding="utf-8"))) for p in files]


def bindings(tree):
    """Each local name an import binds, to the full name it stands for: `import os as o` binds o to os,
    `from subprocess import run` binds run to subprocess.run. Scopes are not told apart."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    names[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    names[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                names[a.asname or a.name] = f"{node.module}.{a.name}"
    return names


def full_name(node, names):
    """The full name of a call target through the imports: o.system -> os.system, run -> subprocess.run."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in names:
        return None
    return ".".join([names[node.id], *reversed(parts)])


def imports(tree, libs):
    """The libraries of `libs` that a module imports, by any spelling: import a.b, from a import b, from a.b import c,
    and __import__ or import_module with a constant name."""
    found = set()

    def hit(name, member=None):
        if (name, member) in NOT_NETWORK:
            return
        for full in (name, f"{name}.{member}" if member else None, name.split(".")[0]):
            if full in libs:
                found.add(full)

    names = bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                hit(a.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                hit(node.module, a.name)
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            f = node.func
            target = full_name(f, names) or (f.id if isinstance(f, ast.Name) else None)
            if target in ("__import__", "importlib.import_module") or \
                    (isinstance(f, ast.Attribute) and f.attr == "import_module"):
                hit(node.args[0].value)
    return found


def program_starts(tree):
    """The number of calls that start a program, through any import spelling of the module."""
    names = bindings(tree)
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call) and full_name(n.func, names) in STARTS)


def code_of(js):
    """The mod's code without its comment lines and the name of its http.fetch hook."""
    code = "\n".join(line for line in js.splitlines() if not line.lstrip().startswith(("//", "*", "/*")))
    for name in MOD_HOOK_NAMES:
        code = code.replace(name, "''")
    return code


def mod_findings(js):
    code = code_of(js)
    out = [p for p in MOD_FORBIDDEN if re.search(p, code, re.M)]
    out += [f"$.{m}" for m in sorted(set(re.findall(r"\$\.(\w+)", code)) - MOD_MEMBERS)]
    out += [f"globalThis.{m}" for m in sorted(set(re.findall(r"\bglobalThis\.(\w+)", code)) - MOD_GLOBALS)]
    return out


class NetworkImportTests(unittest.TestCase):
    def test_only_the_modules_of_a_service_the_person_set_up_import_a_network_library(self):
        found = {}
        population = modules()
        self.assertGreater(len(population), 50, "a population test must fail on an empty population")
        for name, tree in population:
            libs = imports(tree, NETWORK)
            if libs:
                found[name] = libs
        allowed = {name: libs for name, (libs, _why) in MAY_CONNECT.items()}
        for name, libs in sorted(found.items()):
            self.assertIn(name, allowed, f"{name} imports {sorted(libs)}; only a service the person set up may (C33)")
            self.assertLessEqual(libs, allowed[name], f"{name} imports {sorted(libs - allowed[name])} too")
        self.assertEqual(sorted(allowed), sorted(found), "an entry of MAY_CONNECT whose module no longer needs it")

    def test_only_the_listed_places_start_a_program(self):
        starts, importers = {}, set()
        for name, tree in modules():
            n = program_starts(tree)
            if n:
                starts[name] = n
            if imports(tree, PROCESS):
                importers.add(name)
        self.assertEqual(starts, {name: n for name, (n, _why) in MAY_START.items()},
                         "a module starts a program at a place MAY_START does not count; say what it starts, and why")
        self.assertEqual(sorted(importers - set(MAY_START)), sorted(NAMES_ONLY),
                         "a module imports a process library and starts nothing that this check sees")

    def test_the_check_sees_each_spelling(self):
        for code in ("import socket", "import http.client", "from http import client", "from urllib import request",
                     "from urllib.request import urlopen", "__import__('ssl')", "importlib.import_module('socket')",
                     "from importlib import import_module\nimport_module('socket')", "import asyncio.streams",
                     "def f():\n    import urllib.request as u"):
            with self.subTest(code):
                self.assertTrue(imports(ast.parse(code), NETWORK), code)
        for code in ("from urllib.request import url2pathname", "import urllib.parse", "from http import HTTPStatus"):
            with self.subTest(code):
                self.assertFalse(imports(ast.parse(code), NETWORK), code)
        for code in ("import subprocess\nsubprocess.run(['x'])", "import os\nos.system('x')",
                     "from os import system\nsystem('x')", "import os as o\no.execvp('x', [])",
                     "from subprocess import Popen as P\nP(['x'])", "import multiprocessing\nmultiprocessing.Pool()",
                     "def f():\n    import subprocess as s\n    return s.check_output(['x'])"):
            with self.subTest(code):
                self.assertEqual(program_starts(ast.parse(code)), 1, code)
        for code in ("import subprocess\nisinstance(e, subprocess.TimeoutExpired)", "import os\nos.getpid()"):
            with self.subTest(code):
                self.assertEqual(program_starts(ast.parse(code)), 0, code)


class ModNetworkTests(unittest.TestCase):
    def test_the_mod_uses_no_network_api(self):
        mods = sorted((ROOT / "claude-mod").rglob("*.mjs"))
        self.assertTrue(mods, "a population test must fail on an empty population")
        for path in mods:
            js = path.read_text(encoding="utf-8")
            self.assertTrue(re.findall(r"\$\.(\w+)", code_of(js)), "the pattern no longer reads the mod's use of $")
            self.assertEqual(mod_findings(js), [], path.name)

    def test_the_mod_check_sees_each_spelling(self):
        for js in ("await fetch('https://example.com')", "const r = globalThis.fetch", "const { net } = $",
                   "const n = $\nn.net()", "$['net'].run()", "$.net.run()", "globalThis.process.exit()",
                   "globalThis['fetch']('x')", "const ws = new WebSocket('wss://x')", "await import('node:http')"):
            with self.subTest(js):
                self.assertTrue(mod_findings(js), js)
        for js in ("on('http.fetch', h)", "// a fetch in a comment", "$.process.run(argv, init)",
                   "globalThis.crypto.getRandomValues(a)", "if (await inDemo($) === false) return next(e)"):
            with self.subTest(js):
                self.assertEqual(mod_findings(js), [], js)


if __name__ == "__main__":
    unittest.main()
