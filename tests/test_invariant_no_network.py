"""I5: a network connection can start only in the code of a service the person set up (docs/THREAT-MODEL.md, C33).

A static check over every Python module of the plugin and the skill, and over the mod. Each list below names a module
and why it may reach for the network or start a program; a module that starts to import a network library, or a new
place that starts a program (a reference to a starting call, or a call of a local function or name that leads to
one, at any depth), fails,
and so does an entry that no longer matches its module, so the lists cannot rot.
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
PROCESS = {"subprocess", "multiprocessing", "pty", "concurrent.futures.process",
           "concurrent.futures.ProcessPoolExecutor"}
# the calls that start a program, by their full name
STARTS = {f"subprocess.{f}" for f in ("run", "Popen", "call", "check_call", "check_output", "getoutput",
                                      "getstatusoutput")} | \
    {f"os.{f}" for f in ("system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile")} | \
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
# the modules that start a program: how many places start one (program_starts: each start, and each call of a
# function that makes one), and what they start. A new place is red until it is counted here, with a reason.
MAY_START = {
    "hooks/guard.py": (6, "the clipboard tool, with the restart command"),
    "maisecrets/codex_helper.py": (5, "ps, for the parent process"),
    "maisecrets/file_reads.py": (27, "a text extractor for a PDF, ps and ldd"),
    "maisecrets/hooks.py": (58, "the clipboard tool (read, write), and Python children: a later transcript scrub, "
                               "the server of a value through a FIFO, the scrub of a failed prompt"),
    "maisecrets/ner_setup.py": (36, "the container tool of the name service the person set up, its keeper, and its "
                                    "typed start"),
    "maisecrets/sref_client.py": (5, "a Python child that serves a gateway value through a FIFO"),
    "maisecrets/user_rules.py": (6, "a Python child that checks a rule of the person"),
    "maisecrets/vault.py": (54, "the tool of the operating system's store"),
    "skills/secret-hygiene/scripts/_detector.py": (2, "worker processes of the scan, and git log for the history"),
    "skills/secret-hygiene/scripts/protection_status.py": (6, "Python and claude plugin list, for the status"),
    "skills/secret-hygiene/scripts/redact_copy.py": (3, "git rev-parse"),
    "skills/secret-hygiene/scripts/scan_secrets.py": (12, "git, for the repository the person asked to scan"),
}
# modules that import a process library and start nothing with it
NAMES_ONLY = {"maisecrets/incidents.py": "names subprocess.TimeoutExpired"}
# the members of `$` the mod may use, and of globalThis; none of them reaches the network. $.process starts a program
# (run, or spawn for a streamed answer): the mod has MOD_PROCESS_RUNS places that do (tests/mod.test.ts checks their
# command lines), and a new one fails.
MOD_MEMBERS = {"clock", "command", "env", "plugin", "process", "prompt", "session", "state", "store", "ui"}
MOD_GLOBALS = {"crypto"}
MOD_PROCESS_RUNS = 9     # each $.process.run( or $.process.spawn(; any other use of $.process is a finding
MOD_FORBIDDEN = (r"\bfetch\b", r"\bXMLHttpRequest\b", r"\bWebSocket\b", r"\bEventSource\b", r"\bnavigator\b",
                 r"\bwindow\b", r"\bimport\s*\(", r"\brequire\s*\(", r"^\s*import\s", r"\bchild_process\b",
                 r"\$\s*\[", r"(?:^|[^}\s])\s*=\s*\$\s*(?:[;\n,)]|$)", r"\bglobalThis\s*\[",
                 r"\$\.process(?!\.(?:run|spawn)\s*\()", r"\}\s*\}\s*=\s*\$(?![\w.])")


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


def _starts_here(node, names):
    """A reference to a call that starts a program: a name in STARTS, or anything of multiprocessing."""
    f = full_name(node, names)
    if f in STARTS:
        return True
    while isinstance(node, (ast.Attribute, ast.Call)):        # multiprocessing.get_context("spawn").Process
        node = node.value if isinstance(node, ast.Attribute) else node.func
    return isinstance(node, ast.Name) and names.get(node.id, "").split(".")[0] == "multiprocessing" \
        and f != "multiprocessing"


def program_starts(tree):
    """The places of a module that start a program: each outermost reference to a starting call (also one bound to a
    name, `run = subprocess.run`), and each reference to a local function that leads to one (a wrapper such as
    `def _git(*a): return subprocess.run(...)`), through any import spelling. A function that calls a wrapper is a
    wrapper too, at any depth, and so is a module-level name bound to a start or a wrapper (`run = subprocess.run`)."""
    names = bindings(tree)
    parent = {id(c): n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}

    def continued(n):
        """n is part of a longer chain a.b(...).c: the chain counts once, at its top."""
        p = parent.get(id(n))
        if isinstance(p, ast.Attribute) and p.value is n:
            return True
        if isinstance(p, ast.Call) and p.func is n:
            g = parent.get(id(p))
            return isinstance(g, ast.Attribute) and g.value is p
        return False

    def chain(top):
        n = top
        while isinstance(n, (ast.Name, ast.Attribute, ast.Call)):
            yield n
            n = n.value if isinstance(n, ast.Attribute) else n.func if isinstance(n, ast.Call) else None

    def refs(node, wrappers):
        out = 0
        for n in ast.walk(node):
            if not isinstance(n, (ast.Name, ast.Attribute)) or not isinstance(n.ctx, ast.Load) or continued(n):
                continue
            for m in chain(n):
                if _starts_here(m, names) or (isinstance(m, ast.Name) and m.id in wrappers) or \
                        (isinstance(m, ast.Attribute) and m.attr in wrappers and isinstance(m.value, ast.Name)
                         and m.value.id in ("self", "cls")):
                    out += 1
                    break
        return out

    # every depth: measured over 59 commits of next, the count of every depth changed in 7, one level in 8
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    aliases = [n for n in tree.body if isinstance(n, ast.Assign) and all(isinstance(x, ast.Name) for x in n.targets)]
    wrappers: set = set()
    while True:
        more = {f.name for f in functions if f.name not in wrappers and refs(f, wrappers)}
        more |= {x.id for a in aliases if refs(a.value, wrappers) for x in a.targets if x.id not in wrappers}
        if not more:
            return refs(tree, wrappers)
        wrappers |= more


def code_of(js):
    """The mod's code without its comments and the text of its strings ('…', "…" and the text of a template literal
    become empty; the ${…} expressions of a template stay code)."""
    out, i, n = [], 0, len(js)
    while i < n:
        c = js[i]
        if js.startswith("//", i):
            j = js.find("\n", i)
            i = n if j < 0 else j
        elif js.startswith("/*", i):
            j = js.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(" " + "\n" * js.count("\n", i, j))
            i = j
        elif c == "/" and re.search(r"(?:^|[(,=:\[!&|?{};+\-*%<>~^]|\breturn|\btypeof)\s*$", "".join(out[-40:])):
            # a regex literal: skip to its closing slash, past escapes and character classes
            j, in_class = i + 1, False
            while j < n and js[j] != "\n" and (in_class or js[j] != "/"):
                if js[j] == "\\":
                    j += 1
                elif js[j] == "[":
                    in_class = True
                elif js[j] == "]":
                    in_class = False
                j += 1
            out.append("/./")
            i = j + 1
        elif c == "`":
            j, depth = i + 1, 0
            out.append("``")
            while j < n and (depth or js[j] != "`"):
                if depth == 0 and js[j] == "\\":
                    j += 2
                    continue
                if depth == 0 and js.startswith("${", j):
                    depth, j = 1, j + 2
                    out.append(" ")
                    continue
                if depth:
                    depth += {"{": 1, "}": -1}.get(js[j], 0)
                    out.append(js[j] if depth else " ")
                elif js[j] == "\n":
                    out.append("\n")
                j += 1
            i = j + 1
        elif c in "'\"":
            j = i + 1
            while j < n and js[j] != c and js[j] != "\n":
                j += 2 if js[j] == "\\" else 1
            out.append(c + c)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def mod_findings(js):
    code = code_of(js)
    out = [p for p in MOD_FORBIDDEN if re.search(p, code, re.M)]
    out += [f"$.{m}" for m in sorted(set(re.findall(r"\$\.(\w+)", code)) - MOD_MEMBERS)]
    out += [f"globalThis.{m}" for m in sorted(set(re.findall(r"\bglobalThis\.(\w+)", code)) - MOD_GLOBALS)]
    # a destructured member of $ is used without "$.": it must be an allowed one, and process stays "$.process.run"
    for group in re.findall(r"\{([^{}]*)\}\s*=\s*\$(?![\w.])", code):
        for part in group.split(","):
            name = part.split(":")[0].strip().lstrip(".")
            if name and (name not in MOD_MEMBERS or name == "process"):
                out.append(f"{{ {name} }} = $")
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
                     "def f():\n    import subprocess as s\n    return s.check_output(['x'])",
                     "import os\nos.startfile('x')",
                     "import multiprocessing\nmultiprocessing.get_context('spawn').Process()",
                     "import subprocess\n_RUN = subprocess.run",
                     "from concurrent.futures import ProcessPoolExecutor as P\nP()"):
            with self.subTest(code):
                self.assertEqual(program_starts(ast.parse(code)), 1, code)
        # a wrapper: its own start, and each call of it, are places
        wrapped = ("import subprocess\ndef _git(*a):\n    return subprocess.run(['git', *a])\n"
                   "def _two(*a):\n    return _git(*a)\n_git('status')\n_two('fetch')\n")
        self.assertEqual(program_starts(ast.parse(wrapped)), 4, "the start, and the calls of _git, _git and _two")
        method = ("import subprocess\nclass C:\n    def _run(self):\n        subprocess.run(['x'])\n"
                  "    def go(self):\n        self._run()\n        self._run()\n")
        self.assertEqual(program_starts(ast.parse(method)), 3)
        deep = ("import subprocess\ndef _a(x):\n    return subprocess.run(x)\ndef _b(x):\n    return _a([x])\n"
                "def _c():\n    return _b('fetch')\n_c()\n")
        self.assertEqual(program_starts(ast.parse(deep)), 4, "the start, and the calls of _a, _b and _c")
        alias = "import subprocess\nrun = subprocess.run\nrun(['x'])\nrun(['y'])\n"
        self.assertEqual(program_starts(ast.parse(alias)), 3, "the binding, and each call of the bound name")
        self.assertEqual(program_starts(ast.parse(method)), 3)
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
        for path in mods:
            # the reader must not swallow code (a misread regex or string): each line that starts with a statement
            # word still starts with it after the reader
            js = path.read_text(encoding="utf-8")
            code = code_of(js).split("\n")
            self.assertEqual(len(code), js.count("\n") + 1, f"{path.name}: the reader lost lines")
            starts = [(i, w) for i, line in enumerate(js.split("\n"))
                      for w in [re.match(r"\s*(const|let|return|await|if|for|function|export)\b", line)] if w]
            self.assertGreater(len(starts), 100, "the canary reads no statement of the mod")
            lost = [i + 1 for i, w in starts if not code[i].lstrip().startswith(w.group(1))]
            self.assertEqual(lost, [], f"{path.name}: the reader swallowed code at these lines")
        runs = sum(len(re.findall(r"\$\.process\b", code_of(p.read_text(encoding="utf-8")))) for p in mods)
        self.assertEqual(runs, MOD_PROCESS_RUNS, "a new place in the mod starts a program; count it, and test its "
                                                 "command line in tests/mod.test.ts")

    def test_the_mod_check_sees_each_spelling(self):
        for js in ("await fetch('https://example.com')", "const r = globalThis.fetch", "const { net } = $",
                   "const n = $\nn.net()", "$['net'].run()", "$.net.run()", "globalThis.process.exit()",
                   "globalThis['fetch']('x')", "const ws = new WebSocket('wss://x')", "await import('node:http')",
                   "const { process } = $", "const { ui, net: n } = $", "x(); fetch(u) /* a comment */",
                   "const p = $.process\nawait p.run(['curl'], {})", "const { process: { run } } = $",
                   "const { net: { request } } = $", "log(`${fetch(u)}`)"):
            with self.subTest(js):
                self.assertTrue(mod_findings(js), js)
        for js in ("on('http.fetch', h)", "// a fetch in a comment", "$.process.run(argv, init)",
                   "globalThis.crypto.getRandomValues(a)", "if (await inDemo($) === false) return next(e)",
                   "x(); // fetch later", "/* one\n   window line */", "say('open a new window to log in')",
                   "say('node: v20')", "const { Box, Text } = $.ui.resolve(e)", "const { ui, store } = $",
                   "const u = `https://example.com/${id}`", "note(`the http.fetch hook of ${$.plugin.name}`)"):
            with self.subTest(js):
                self.assertEqual(mod_findings(js), [], js)


if __name__ == "__main__":
    unittest.main()
