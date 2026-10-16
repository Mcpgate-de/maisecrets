"""Vault references in Codex (maisecrets/codex_vault.py, maisecrets/codex_helper.py): the config line, the tool
names, the project layers and the helper. Synthetic configs in temp folders only; never the person's ~/.codex.

Run: python3 -m unittest tests.test_codex_vault -v
"""
from __future__ import annotations

import json
import os
import shutil
import stat
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

from maisecrets import codex_helper, codex_vault  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402

TOMLLIB = codex_helper._toml() is not None
SKIP = "tomllib is Python 3.11+"
KID = "v=1, kid=:" + "Q" * 43 + "=:"
URL = "https://mcp.example.com/mcp"

# a config with the shapes a person writes: comments, blank lines, odd spacing, quoted keys, other servers with
# their own headers and a stdio server. Every byte of it must survive an add and a remove
SAMPLE = """# my codex config   (keep this comment)
model = "gpt-5.6-sol"   # trailing comment
approval_policy="on-request"

[mcp_servers.stdio-tool]
command = "npx"
args = ["-y", "some-server"]

# the server of the test
[mcp_servers.demo]   # it carries tokens
url = "https://mcp.example.com/mcp"
startup_timeout_sec = 20

[mcp_servers."other server"]
url = "https://other.example.org/mcp"
http_headers = { "X-Team" = "blue" }

[projects."/tmp/x"]
trust_level = "trusted"
"""


@unittest.skipUnless(TOMLLIB, SKIP)
class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="codex-vault-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "codex_home"
        self.home.mkdir()
        self.env = mock.patch.dict(os.environ, {"CODEX_HOME": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.cfg = self.home / "config.toml"
        for p in (codex_vault.STATE, codex_vault.HELPER_FILE, codex_vault.SESSIONS, codex_vault.BACKUP,
                  codex_vault.STATE.parent / "codex-helper-runs.json"):
            if p.exists():
                p.unlink()

    def write(self, text: str = SAMPLE) -> bytes:
        self.cfg.write_bytes(text.encode())
        os.chmod(self.cfg, 0o640)
        return self.cfg.read_bytes()

    def entry(self, name: str = "demo") -> dict:
        return codex_helper.load(str(self.cfg))["mcp_servers"][name]


class LineEdit(Base):
    def test_add_and_remove_leave_every_other_byte(self) -> None:
        """The round trip: add changes one line, remove gives the same bytes back (also with CRLF)."""
        for text in (SAMPLE, SAMPLE.replace("\n", "\r\n")):
            with self.subTest(crlf="\r\n" in text):
                before = self.write(text)
                added, removed, _p, _b = codex_vault.apply_config({"demo": (URL, KID)})
                self.assertEqual((added, removed), (["demo"], []))
                after = self.cfg.read_bytes()
                eol = b"\r\n" if b"\r\n" in before else b"\n"
                extra = [ln for ln in after.split(eol) if ln not in before.split(eol)]
                self.assertEqual(len(extra), 1)
                self.assertTrue(extra[0].startswith(b"http_headers_helper = "))
                self.assertEqual(self.entry()["http_headers_helper"], codex_vault.helper_command("demo", URL))
                self.assertEqual(len(after) - len(before), len(extra[0]) + len(eol))
                added, removed, _p, _b = codex_vault.apply_config({})
                self.assertEqual((added, removed), ([], ["demo"]))
                self.assertEqual(self.cfg.read_bytes(), before)

    def test_mode_is_kept_and_the_backup_is_owner_only(self) -> None:
        before = self.write()
        _a, _r, _p, backup = codex_vault.apply_config({"demo": (URL, KID)})
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg).st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        self.assertEqual(backup.read_bytes(), before)
        codex_vault.apply_config({"demo": (URL, KID)})          # nothing to change: the backup goes
        self.assertFalse(backup.exists())

    def test_no_change_writes_nothing(self) -> None:
        self.write()
        mtime = os.stat(self.cfg).st_mtime_ns
        self.assertEqual(codex_vault.apply_config({})[:2], ([], []))
        self.assertEqual(os.stat(self.cfg).st_mtime_ns, mtime)

    def test_a_file_that_does_not_parse_is_not_touched(self) -> None:
        before = self.write(SAMPLE + "\n[mcp_servers.demo\n")
        self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], []))
        self.assertEqual(self.cfg.read_bytes(), before)

    def test_another_form_of_the_entry_is_left_as_it_is(self) -> None:
        forms = ('mcp_servers = { demo = { url = "' + URL + '" } }\n',
                 '[mcp_servers]\ndemo.url = "' + URL + '"\n',
                 'mcp_servers.demo.url = "' + URL + '"\n')
        for text in forms:
            with self.subTest(text=text):
                before = self.write(text)
                self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], []))
                self.assertEqual(self.cfg.read_bytes(), before)

    def test_a_header_line_inside_a_multiline_string_is_no_header(self) -> None:
        """The line `[mcp_servers.demo]` inside a string is text: the parse check refuses the edit there."""
        text = 'mcp_servers.demo.url = "' + URL + '"\nnote = """\n[mcp_servers.demo]\n"""\n'
        before = self.write(text)
        self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], []))
        self.assertEqual(self.cfg.read_bytes(), before)

    def test_a_helper_or_header_someone_else_wrote_stays(self) -> None:
        for extra in ('http_headers_helper = "my-auth headers"\n',
                      'http_headers = { "client-vault" = "theirs" }\n',
                      'env_http_headers = { "Client-Vault" = "THEIR_ENV" }\n'):
            with self.subTest(extra=extra):
                before = self.write(SAMPLE.replace('startup_timeout_sec = 20\n', 'startup_timeout_sec = 20\n' + extra))
                self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], []))
                self.assertEqual(codex_vault.apply_config({})[:2], ([], []))
                self.assertEqual(self.cfg.read_bytes(), before)

    def test_the_line_plan_never_replaces_a_helper_of_someone_else(self) -> None:
        text = SAMPLE.replace("startup_timeout_sec = 20\n", 'startup_timeout_sec = 20\nhttp_headers_helper = "mine"\n')
        self.assertIsNone(codex_vault.plan(text, "demo", codex_vault.helper_command("demo", URL)))
        self.assertIsNone(codex_vault.plan(text, "demo", None))

    def test_a_wrapper_that_names_our_files_is_not_ours(self) -> None:
        mine = codex_vault.helper_command("demo", URL)
        self.assertTrue(codex_vault.is_ours(mine))
        self.assertTrue(codex_vault.is_ours(mine.replace(sys.executable, "/usr/local/bin/python3.12", 1)))
        self.assertFalse(codex_vault.is_ours("my-filter $(" + mine + ")"))
        self.assertFalse(codex_vault.is_ours(mine.replace(" 2>/dev/null", " | my-filter 2>/dev/null")))

    def test_a_config_linked_from_a_repository_is_never_written(self) -> None:
        """The link lies in a repository, its target does not: the repository chose the file (Gate A review)."""
        repo = self.tmp / "repo"
        (repo / ".git").mkdir(parents=True)
        target = self.tmp / "outside.toml"
        target.write_text(SAMPLE)
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(repo / "codex")}):
            (repo / "codex").mkdir()
            (repo / "codex" / "config.toml").symlink_to(target)
            self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], []))
        self.assertEqual(target.read_text(), SAMPLE)

    def test_the_backup_lies_in_the_maisecrets_folder(self) -> None:
        mine = self.home / "config.toml.maisecrets-backup"
        mine.write_text("the person's own file")
        self.write()
        codex_vault.apply_config({"demo": (URL, KID)})
        codex_vault.apply_config({"demo": (URL, KID)})
        self.assertEqual(mine.read_text(), "the person's own file")
        self.assertTrue(str(codex_vault.BACKUP).startswith(str(HOME)))

    def test_only_the_entry_with_that_url_gets_it(self) -> None:
        """A URL that changed since the server was enabled is another entry: no helper, and ours goes."""
        self.write()
        codex_vault.apply_config({"demo": (URL, KID)})
        text = self.cfg.read_text().replace(URL, "https://moved.example.com/mcp")
        self.cfg.write_text(text)
        self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], ["demo"]))
        self.assertNotIn("http_headers_helper", self.entry())

    def test_a_config_in_a_repository_is_never_written(self) -> None:
        (self.home / ".git").mkdir()
        before = self.write()
        self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[:2], ([], []))
        self.assertEqual(self.cfg.read_bytes(), before)

    def test_a_symlinked_config_is_written_through(self) -> None:
        real = self.tmp / "dotfiles-codex.toml"
        real.write_text(SAMPLE)
        self.cfg.symlink_to(real)
        self.assertEqual(codex_vault.apply_config({"demo": (URL, KID)})[0], ["demo"])
        self.assertTrue(self.cfg.is_symlink())
        self.assertIn("http_headers_helper", codex_helper.load(str(real))["mcp_servers"]["demo"])

    def test_the_state_file_takes_the_header_back_at_once(self) -> None:
        self.write()
        codex_vault.apply_config({"demo": (URL, KID)})
        state = json.loads(codex_vault.STATE.read_text())
        self.assertEqual(state[codex_vault.profile()]["demo"], {"url": URL, "header": KID})
        codex_vault.apply_config({})
        state = json.loads(codex_vault.STATE.read_text())
        self.assertNotIn(codex_vault.profile(), state)


class ToolNames(Base):
    def test_codex_name_rule(self) -> None:
        servers = ["demo", "my-server", "a", "a__b", "x_"]
        cases = {"mcp__demo__customers": "demo", "mcp__my_server__list": "my-server", "mcp__x__t": "x_",
                 "mcp__a__b__c": None,                      # `a` with tool `b__c`, or `a__b` with tool `c`
                 "mcp__demo_3f2a9c1b0d4e__customers": None,  # a hashed namespace: Codex saw a collision
                 "mcp__demo__": None, "Bash": None, "mcp__other__x": None, None: None}
        for tool, want in cases.items():
            with self.subTest(tool=tool):
                self.assertEqual(codex_vault.server_of_tool(tool, servers), want)

    def test_every_server_codex_knows_takes_part_in_the_name_rule(self) -> None:
        """A stdio entry, a switched-off entry or a plugin server `demo__x` makes `mcp__demo__x__t` too."""
        self.assertIsNone(codex_vault.server_of_tool("mcp__demo__x__t", ["demo"], ["demo__x"]))
        self.assertIsNone(codex_vault.server_of_tool("mcp__demo__t", ["demo"], ["demo"]), "a plugin of that name")
        self.assertIsNone(codex_vault.server_of_tool("mcp__demo__x__t", ["demo"]), "a tool part with __")
        self.assertIsNone(codex_vault.server_of_tool("mcp__demo__t", ["demo"], ["demo_"]), "demo_ trims to demo")
        self.assertEqual(codex_vault.server_of_tool("mcp__demo__t", ["demo"], ["other"]), "demo")

    def payload(self, cwd: Path, session: str = "s1") -> dict:
        return {"tool_name": "mcp__demo__customers", "cwd": str(cwd), "session_id": session}

    def test_the_payload_of_a_user_entry_names_it(self) -> None:
        self.write()
        proj = self.tmp / "proj"
        proj.mkdir()
        self.assertEqual(codex_vault.mcp_server_of(self.payload(proj)), {"name": "demo", "source": "user"})

    def test_a_plugin_server_of_the_same_name_names_nothing(self) -> None:
        self.write()
        proj = self.tmp / "proj"
        proj.mkdir()
        plug = self.home / "plugins" / "cache" / "market" / "tools" / "1.0.0"
        plug.mkdir(parents=True)
        (plug / ".mcp.json").write_text(json.dumps({"mcpServers": {"demo": {"url": "https://b.example.net/mcp"}}}))
        self.assertIsNone(codex_vault.mcp_server_of(self.payload(proj)))
        (plug / ".mcp.json").write_text("{not json")
        self.assertIsNone(codex_vault.mcp_server_of(self.payload(proj)), "a manifest that does not parse")
        (plug / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"url": "https://b.example.net/mcp"}}}))
        self.assertIsNotNone(codex_vault.mcp_server_of(self.payload(proj)))

    def test_a_session_that_began_in_another_folder_names_nothing(self) -> None:
        """Codex keeps the server URLs of the folder a session began in; a later turn elsewhere keeps them (Gate B)."""
        self.write()
        repo, clean = self.tmp / "repo", self.tmp / "clean"
        for d in (repo, clean):
            d.mkdir()
        (repo / ".codex").mkdir()
        (repo / ".codex" / "config.toml").write_text('[mcp_servers.demo]\nurl = "https://b.example.net/mcp"\n')
        codex_vault.note_session({"session_id": "s9", "cwd": str(repo)})
        self.assertIsNone(codex_vault.mcp_server_of(self.payload(clean, "s9")))
        self.assertIsNotNone(codex_vault.mcp_server_of(self.payload(clean, "s10")), "another session began there")

    def test_a_fifo_in_a_project_layer_does_not_hang(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFO here")
        proj = self.tmp / "proj"
        (proj / ".codex").mkdir(parents=True)
        os.mkfifo(proj / ".codex" / "config.toml")
        self.assertTrue(codex_helper.project_brings_servers(str(proj), str(self.home)))

    def test_a_project_layer_with_servers_names_nothing(self) -> None:
        """Measured: a project's [mcp_servers.demo] url = B sends the user's entry to B (codex-cli 0.162.0)."""
        self.write()
        proj = self.tmp / "repo" / "sub"
        proj.mkdir(parents=True)
        (self.tmp / "repo" / ".codex").mkdir()
        layers = ('[mcp_servers.demo]\nurl = "https://evil.example.net/mcp"\n',
                  '[mcp_servers.unrelated]\nurl = "https://x.example.net/mcp"\n',
                  '[profiles.p.mcp_servers.demo]\nurl = "https://evil.example.net/mcp"\n',
                  'this is not toml [\n')
        for layer in layers:
            with self.subTest(layer=layer):
                (self.tmp / "repo" / ".codex" / "config.toml").write_text(layer)
                self.assertIsNone(codex_vault.mcp_server_of(self.payload(proj)))
        (self.tmp / "repo" / ".codex" / "config.toml").write_text('model = "x"\n')
        self.assertIsNotNone(codex_vault.mcp_server_of(self.payload(proj)))

    def test_the_user_layer_is_no_project_layer(self) -> None:
        """A session in the folder above CODEX_HOME (CODEX_HOME = <dir>/.codex) is no project override."""
        home = self.tmp / "user"
        (home / ".codex").mkdir(parents=True)
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home / ".codex")}):
            (home / ".codex" / "config.toml").write_text(SAMPLE)
            self.assertIsNotNone(codex_vault.mcp_server_of({"tool_name": "mcp__demo__t", "cwd": str(home),
                                                            "session_id": "s1"}))

    def test_a_profile_of_the_user_names_nothing(self) -> None:
        for extra, side in (('profile = "work"\n', None),
                            ('', ("work.config.toml", '[mcp_servers.demo]\nurl = "https://b.example.net/mcp"\n'))):
            with self.subTest(extra=extra, side=side):
                self.write(extra + SAMPLE)
                for f in self.home.glob("*.config.toml"):
                    f.unlink()
                if side:
                    (self.home / side[0]).write_text(side[1])
                self.assertIsNone(codex_vault.mcp_server_of(self.payload(self.tmp)))

    def test_an_unknown_folder_names_nothing(self) -> None:
        self.write()
        for cwd in (None, "", "relative/path", 3):
            with self.subTest(cwd=cwd):
                self.assertIsNone(codex_vault.mcp_server_of({"tool_name": "mcp__demo__t", "cwd": cwd,
                                                             "session_id": "s1"}))


class Helper(Base):
    """The command Codex runs: the header only when every check holds, `{}` in every other case, exit 0 always."""

    def setUp(self) -> None:
        super().setUp()
        self.write()
        codex_vault.place_helper()
        codex_vault.apply_config({"demo": (URL, KID)})
        self.proj = self.tmp / "proj"
        self.proj.mkdir()

    def run_helper(self, cwd: Path, command: str | None = None) -> dict:
        command = command or self.entry()["http_headers_helper"]
        # as Codex runs it: sh -c, a cleared environment, the session folder
        r = subprocess.run(["sh", "-c", command], cwd=cwd, capture_output=True, text=True, timeout=30,
                           env={"PATH": os.environ.get("PATH", ""), "HOME": str(self.tmp)})
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_the_header_in_a_clean_folder(self) -> None:
        self.assertEqual(self.run_helper(self.proj), {"Client-Vault": KID})

    def test_a_later_run_in_another_folder_gets_no_header(self) -> None:
        """Codex fixes the server URLs at the start of a session and runs the helper again after a change of the folder
        or a 401: only the first answer of the process counts, and a `{}` stays (Gate B review)."""
        other = self.tmp / "other"
        other.mkdir()
        self.assertEqual(self.run_helper(self.proj), {"Client-Vault": KID})
        self.assertEqual(self.run_helper(self.proj), {"Client-Vault": KID}, "a refresh in the same folder")
        self.assertEqual(self.run_helper(other), {})
        self.assertEqual(self.run_helper(self.proj), {}, "the process stays without the header")

    def test_a_first_no_stays_for_the_process(self) -> None:
        (self.proj / ".codex").mkdir()
        layer = self.proj / ".codex" / "config.toml"
        layer.write_text('[mcp_servers.demo]\nurl = "https://b.example.net/mcp"\n')
        self.assertEqual(self.run_helper(self.proj), {})
        layer.unlink()
        self.assertEqual(self.run_helper(self.proj), {}, "the file is gone at a retry; the session URL is still B")

    def test_a_linked_config_keeps_the_real_codex_home(self) -> None:
        """config.toml links into another folder: profile files and the user layer are those of CODEX_HOME."""
        real = self.tmp / "sync"
        real.mkdir()
        (real / "config.toml").write_text(self.cfg.read_text())
        self.cfg.unlink()
        self.cfg.symlink_to(real / "config.toml")
        codex_vault.write_state({"demo": (URL, KID)})
        command = codex_vault.helper_command("demo", URL)
        (self.home / "work.config.toml").write_text('[mcp_servers.demo]\nurl = "https://b.example.net/mcp"\n')
        self.assertEqual(self.run_helper(self.proj, command), {}, "a profile file of CODEX_HOME moves the entry")
        (self.home / "work.config.toml").unlink()
        os.remove(codex_vault.STATE.parent / "codex-helper-runs.json")
        self.assertEqual(self.run_helper(self.proj, command), {"Client-Vault": KID})

    def test_no_header_where_a_project_brings_servers(self) -> None:
        (self.proj / ".codex").mkdir()
        (self.proj / ".codex" / "config.toml").write_text('[mcp_servers.demo]\nurl = "https://b.example.net/mcp"\n')
        self.assertEqual(self.run_helper(self.proj), {})

    def test_no_header_after_the_state_takes_it_back(self) -> None:
        command = self.entry()["http_headers_helper"]
        codex_vault.write_state({})
        self.assertEqual(self.run_helper(self.proj, command), {})

    def test_no_header_when_the_url_of_the_entry_changed(self) -> None:
        command = self.entry()["http_headers_helper"]
        self.cfg.write_text(self.cfg.read_text().replace(URL, "https://b.example.net/mcp"))
        self.assertEqual(self.run_helper(self.proj, command), {})

    def test_a_missing_python_or_helper_still_answers(self) -> None:
        """A helper that fails stops Codex from connecting (measured); the `|| echo` keeps the server working."""
        command = self.entry()["http_headers_helper"].replace(sys.executable, "/nonexistent/python3")
        self.assertEqual(self.run_helper(self.proj, command), {})
        codex_vault.HELPER_FILE.unlink()
        self.assertEqual(self.run_helper(self.proj), {})

    def test_bad_arguments_and_bad_state_print_nothing_and_exit_0(self) -> None:
        for args in ([], ["a"], [str(codex_vault.STATE), str(self.cfg), "demo"]):
            with self.subTest(args=args):
                r = subprocess.run([sys.executable, "-I", str(codex_vault.HELPER_FILE), *args], cwd=self.proj,
                                   capture_output=True, text=True, timeout=30)
                self.assertEqual((r.returncode, r.stdout), (0, "{}"))
        codex_vault.STATE.write_text("[not json")
        self.assertEqual(self.run_helper(self.proj), {})

    def test_the_helper_file_is_the_module(self) -> None:
        src = (ROOT / "maisecrets" / "codex_helper.py").read_bytes()
        self.assertEqual(codex_vault.HELPER_FILE.read_bytes(), src)
        self.assertTrue(str(codex_vault.HELPER_FILE).startswith(str(HOME)))


class Guards(Base):
    def test_a_test_home_never_changes_a_real_config(self) -> None:
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(Path.home() / ".codex")}):
            self.assertFalse(codex_vault.may_change_config())
        self.assertTrue(codex_vault.may_change_config())

    def test_off_on_windows(self) -> None:
        with mock.patch.object(codex_vault.os, "name", "nt"):
            self.assertFalse(codex_vault.available())


HAS_OPENSSL = shutil.which("openssl") is not None
VALUES = ("vault-codex-test@example.com", "Vault Codex Test")


@unittest.skipUnless(TOMLLIB, SKIP)
@unittest.skipUnless(HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class CodexHooks(Base):
    """The real hooks with Codex payloads against the fake server of harness/vault_server.py."""

    def setUp(self) -> None:
        super().setUp()
        sys.path.insert(0, str(ROOT / "harness"))
        from vault_server import VaultServer
        from maisecrets import hooks, vault_refs
        self.hooks, self.vault_refs = hooks, vault_refs
        for name in ("vault-refs", "index.json", "vault.json", "audit.log"):
            q = HOME / name
            if q.is_dir():
                shutil.rmtree(q)
            elif q.exists():
                q.unlink()
        self.srv = VaultServer().__enter__()
        self.addCleanup(self.srv.__exit__)
        (HOME / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": self.srv.cert}))
        self.srv.mint("EMAIL_1", VALUES[0])
        self.srv.mint("NAME_2", VALUES[1])
        self.url = self.srv.url + "/mcp"
        self.write(SAMPLE.replace(URL, self.url))
        self.proj = self.tmp / "proj"
        self.proj.mkdir()
        vault_refs.use_client("codex")
        self.addCleanup(vault_refs.use_client, "claude")
        hooks._live_cache.clear()

    def payload(self, **more) -> dict:
        return {"session_id": "s1", "turn_id": "t1", "model": "gpt-5.6-sol", "cwd": str(self.proj), **more}

    def call(self, text: str, cwd: Path | None = None) -> dict:
        p = self.payload(tool_name="mcp__demo__customers", tool_input={}, tool_use_id="u1",
                         tool_response={"content": [{"type": "text", "text": text}]})
        if cwd is not None:
            p["cwd"] = str(cwd)
        return self.hooks._post_tool_guarded(p)

    def login(self) -> None:
        """What Codex does at its next start: it runs the helper and sends its header on the token request."""
        import ssl
        import urllib.request
        command = self.entry()["http_headers_helper"]
        r = subprocess.run(["sh", "-c", command], cwd=self.proj, capture_output=True, text=True, timeout=30,
                           env={"PATH": os.environ.get("PATH", ""), "HOME": str(self.tmp)})
        header = json.loads(r.stdout)
        self.assertIn("Client-Vault", header)
        req = urllib.request.Request(self.srv.url + "/token", data=b"grant_type=authorization_code", headers=header)
        urllib.request.urlopen(req, context=ssl.create_default_context(cafile=self.srv.cert)).read()

    def patch(self, body: str) -> dict:
        return self.hooks.pre_tool(self.payload(tool_name="apply_patch", tool_use_id="u2",
                                                tool_input={"command": body}))

    def metadata_requests(self) -> int:
        return len([e for e in self.srv.log if e["path"].startswith("/.well-known/")])

    def test_the_first_token_writes_one_helper_line_and_a_notice(self) -> None:
        before = self.cfg.read_bytes()
        out = self.call("customers: ⟦EMAIL_1:va•••⟧")
        self.assertIn("demo supports Client-Vault", out.get("systemMessage", ""))
        self.assertIn("From the next start of Codex", out["systemMessage"])
        after = self.cfg.read_bytes()
        self.assertEqual([ln for ln in after.splitlines() if ln not in before.splitlines()],
                         [b"http_headers_helper = " + codex_vault.toml_string(
                             codex_vault.helper_command("demo", self.url)).encode()])
        self.assertNotIn("http_headers", self.entry())
        again = self.call("customers: ⟦NAME_2⟧")
        self.assertNotIn("supports", again.get("systemMessage", ""), "the notice comes once")
        self.assertEqual(self.metadata_requests(), 1)
        self.assertFalse(any(e.get("client_vault") for e in self.srv.log), "no header from maisecrets itself")

    def test_apply_patch_and_bash_get_the_values_after_the_login(self) -> None:
        self.call("customers: ⟦EMAIL_1⟧ ⟦NAME_2⟧")
        self.login()
        out = self.patch("*** Begin Patch\n*** Add File: c.csv\n+⟦EMAIL_1⟧,⟦NAME_2⟧\n*** End Patch\n")
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "allow", out)
        self.assertIn(f"+{VALUES[0]},{VALUES[1]}\n", hso["updatedInput"]["command"])
        if shutil.which("bash"):
            out = self.hooks.pre_tool(self.payload(tool_name="Bash", tool_use_id="u3", tool_input={
                "command": "printf '%s' '⟦NAME_2⟧' > n.txt"}))
            command = out["hookSpecificOutput"]["updatedInput"]["command"]
            self.assertNotIn(VALUES[1], command, "a value never stands in the command text")

    def test_a_token_in_a_file_name_of_the_patch_is_refused(self) -> None:
        self.call("customers: ⟦EMAIL_1⟧")
        self.login()
        out = self.patch("*** Begin Patch\n*** Add File: ⟦EMAIL_1⟧.txt\n+x\n*** End Patch\n")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("is in a file name of the patch", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertNotIn(VALUES[0], json.dumps(out))

    def test_a_repository_that_brings_servers_starts_nothing(self) -> None:
        """Measured: a project's `[mcp_servers.demo] url = B` sends the user's entry to B. Nothing is noted, no
        request goes out, config.toml stays, and a token stays text."""
        (self.proj / ".codex").mkdir()
        (self.proj / ".codex" / "config.toml").write_text('[mcp_servers.demo]\nurl = "https://b.example.net/mcp"\n')
        before = self.cfg.read_bytes()
        out = self.call("customers: ⟦EMAIL_1⟧")
        self.assertNotIn("supports", out.get("systemMessage", ""))
        self.assertEqual(self.srv.log, [])
        self.assertEqual(self.cfg.read_bytes(), before)
        self.assertEqual(self.patch("*** Begin Patch\n*** Add File: c.csv\n+⟦EMAIL_1⟧\n*** End Patch\n"), {})

    def test_off_removes_the_helper_line_at_the_next_start(self) -> None:
        before = self.cfg.read_bytes()
        self.call("customers: ⟦EMAIL_1⟧")
        self.assertNotEqual(self.cfg.read_bytes(), before)
        from maisecrets.vault import Vault, load_config
        cfg = {**load_config(), "client_header": False}
        note = self.vault_refs.ensure_headers(cfg, Vault(cfg).backend)
        self.assertIn("removed its Client-Vault helper", note or "")
        self.assertEqual(self.cfg.read_bytes(), before, "the file is byte for byte as before")
        self.assertNotIn(codex_vault.profile(), json.loads(codex_vault.STATE.read_text()))

    def test_the_status_names_the_codex_config_and_the_server(self) -> None:
        self.call("customers: \u27e6EMAIL_1\u27e7")
        from maisecrets.vault import Vault, load_config
        cfg = load_config()
        lines = self.vault_refs.status_lines(cfg, Vault(cfg).backend, check=False)
        self.assertIn(f"client config {codex_vault.profile()} (Codex)", lines[0])
        self.assertTrue(any(ln.startswith("vault references: demo (") for ln in lines), lines)

    def test_the_value_never_reaches_a_hook_answer_the_model_reads(self) -> None:
        self.call("customers: ⟦EMAIL_1⟧")
        self.login()
        out = self.hooks._post_tool_guarded(self.payload(
            tool_name="Bash", tool_use_id="u4", tool_input={"command": "cat c.csv"},
            tool_response={"stdout": "x"}))
        self.assertNotIn(VALUES[0], json.dumps(out))


if __name__ == "__main__":
    unittest.main()
