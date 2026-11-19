"""I5: a network connection can start only in the code of a service the person set up (docs/THREAT-MODEL.md, C33).

A static check over every Python module of the plugin and the skill, and over the mod. Each list below names a module
and why it may reach for the network or start a process; a module that starts to import such a library fails, and so
does an entry whose module no longer needs it, so the lists cannot rot. tests/test_promises.py NoNetworkTests checks
the other side at run time: with the default settings no hook connects. What this check cannot see: a library that
another module imports for it, a name built at run time (`__import__(name)`), and what a started program does."""
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
PROCESS_CALLS = {"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp"} | \
    {f"{p}{s}" for p in ("exec", "spawn") for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")}
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
# the modules that start a program, and what they start
MAY_START = {
    "hooks/guard.py": "the clipboard tool, with the restart command",
    "maisecrets/codex_helper.py": "ps, for the parent process",
    "maisecrets/file_reads.py": "a text extractor for a PDF, ps and ldd",
    "maisecrets/hooks.py": "the clipboard tool, and Python children that serve a value through a FIFO",
    "maisecrets/hub.py": "maisecrets.cli ner start, for the name service the person set up",
    "maisecrets/incidents.py": "nothing: it names subprocess.TimeoutExpired",
    "maisecrets/ner_setup.py": "the container tool of the name service the person set up",
    "maisecrets/sref_client.py": "a Python child that serves a gateway value through a FIFO",
    "maisecrets/user_rules.py": "a Python child that checks a rule of the person",
    "maisecrets/vault.py": "the tool of the operating system's store",
    "skills/secret-hygiene/scripts/_detector.py": "git log, for the history the person asked to scan",
    "skills/secret-hygiene/scripts/protection_status.py": "Python and claude plugin list, for the status",
    "skills/secret-hygiene/scripts/redact_copy.py": "git rev-parse",
    "skills/secret-hygiene/scripts/scan_secrets.py": "git, for the repository the person asked to scan",
}
# the members of `$` the mod may use; none of them reaches the network
MOD_MEMBERS = {"clock", "command", "env", "plugin", "process", "prompt", "session", "state", "store", "ui"}
MOD_FORBIDDEN = (r"\bfetch\s*\(", r"\bXMLHttpRequest\b", r"\bWebSocket\b", r"\bEventSource\b", r"\bnavigator\.",
                 r"\bimport\s*\(", r"\brequire\s*\(", r"^\s*import\s", r"\bnode:", r"\bchild_process\b")


def modules():
    files = [p for d in SOURCES for p in sorted((ROOT / d).rglob("*.py"))]
    return [(p.relative_to(ROOT).as_posix(), ast.parse(p.read_text(encoding="utf-8"))) for p in files]


def imports(tree, names):
    """The libraries of `names` that a module imports, by any spelling: import a.b, from a import b, from a.b import c,
    and __import__ or importlib.import_module with a constant name."""
    found = set()

    def hit(name, member=None):
        for full in (name, f"{name}.{member}" if member else None):
            if full and full in names and (name, member) not in NOT_NETWORK:
                found.add(full)
        top = name.split(".")[0]
        if top in names and (name, member) not in NOT_NETWORK:
            found.add(top)

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
            if (isinstance(f, ast.Name) and f.id == "__import__") or \
                    (isinstance(f, ast.Attribute) and f.attr == "import_module"):
                hit(node.args[0].value)
    return found


def starts_a_program(tree):
    if imports(tree, PROCESS):
        return True
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in PROCESS_CALLS
               and isinstance(n.func.value, ast.Name) and n.func.value.id == "os" for n in ast.walk(tree))


def code_of(js):
    """The mod's code without its comment lines: a comment may name a hook such as http.fetch."""
    return "\n".join(line for line in js.splitlines() if not line.lstrip().startswith(("//", "*", "/*")))


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

    def test_only_the_listed_modules_start_a_program(self):
        found = sorted(name for name, tree in modules() if starts_a_program(tree))
        for name in found:
            self.assertIn(name, MAY_START, f"{name} starts a program; say what it starts in MAY_START, and why")
        self.assertEqual(sorted(MAY_START), found, "an entry of MAY_START whose module no longer starts a program")

    def test_the_check_sees_each_spelling(self):
        for code in ("import socket", "import http.client", "from http import client", "from urllib import request",
                     "from urllib.request import urlopen", "__import__('ssl')", "importlib.import_module('socket')",
                     "import asyncio.streams", "def f():\n    import urllib.request as u"):
            with self.subTest(code):
                self.assertTrue(imports(ast.parse(code), NETWORK), code)
        for code in ("from urllib.request import url2pathname", "import urllib.parse", "from http import HTTPStatus"):
            with self.subTest(code):
                self.assertFalse(imports(ast.parse(code), NETWORK), code)
        for code in ("import subprocess", "os.system('x')", "os.execvp('x', [])", "from multiprocessing import Pool"):
            with self.subTest(code):
                self.assertTrue(starts_a_program(ast.parse(code)), code)


class ModNetworkTests(unittest.TestCase):
    def test_the_mod_uses_no_network_api(self):
        mods = sorted((ROOT / "claude-mod").rglob("*.mjs"))
        self.assertTrue(mods, "a population test must fail on an empty population")
        for path in mods:
            code = code_of(path.read_text(encoding="utf-8"))
            for pattern in MOD_FORBIDDEN:
                with self.subTest(file=path.name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, code, re.M), f"{path.name}: {pattern}")
            members = set(re.findall(r"\$\.(\w+)", code))
            self.assertTrue(members, "the mod uses no member of $: the pattern no longer reads it")
            self.assertLessEqual(members, MOD_MEMBERS, f"{path.name} uses $.{sorted(members - MOD_MEMBERS)}")


if __name__ == "__main__":
    unittest.main()
