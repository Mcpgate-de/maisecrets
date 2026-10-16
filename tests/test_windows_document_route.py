"""A value for a document on Windows: the file route works, the argument route does not.

Field report, 2026-10-16: Codex in the ChatGPT app on Windows wrote a Python script and gave it the e-mail
placeholder as an argument. On Windows maisecrets refuses a placeholder in every shell command of Codex and in the
PowerShell tool of Claude Code, so that route cannot work; 0.6.28 named it all the same in the primer. The file
tools take the value on Windows as on the other systems. These tests run on every system (the platform is mocked
where it matters) and, unmocked, on the GitHub Windows runner, where the hook entry is the `commandWindows` line
that Codex starts through cmd.exe.
"""
from __future__ import annotations

import json
import os
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
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

ADDRESS = "trade.fair.test" + chr(64) + "example.com"     # invented; a reserved domain
OPEN, CLOSE = "⟦", "⟧"
ARGUMENT_ROUTE = "with the placeholder as its argument"


def _reset() -> None:
    for f in ("index.json", "vault.json", "audit.log"):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def _config(**keys):
    return mock.patch.object(hooks, "load_config", return_value={**hooks.load_config(), **keys})


def _on(system: str):
    return mock.patch.object(hooks.platform, "system", return_value=system)


def _reason(out: dict) -> str:
    hso = out.get("hookSpecificOutput") or {}
    assert hso.get("permissionDecision") == "deny", out
    return hso["permissionDecisionReason"]


class WindowsRefusalNamesTheFileRouteTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.e = Vault().put(ADDRESS, "EMAIL", "email", session="S1")

    def _pre(self, tool: str, command: str, client: dict) -> dict:
        return hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command}, "session_id": "S1", **client})

    def test_codex_on_windows_gets_the_file_route_and_not_the_argument_route(self):
        forms = {"script argument": "python make_pdf.py " + self.e.ref,
                 "inline code": "python -c \"open('a.html','w').write('" + self.e.ref + "')\""}
        for name, cmd in forms.items():
            with self.subTest(name), _on("Windows"):
                why = _reason(self._pre("Bash", cmd, CODEX))
            self.assertIn("cannot be placed in a shell command on Codex for Windows", why)
            self.assertIn(f"write the script with apply_patch and put {OPEN}{self.e.key}{CLOSE} into the file "
                          "content", why)
            self.assertIn("Then run the script with no placeholder in the command", why)
            self.assertNotIn(ARGUMENT_ROUTE, why)
            self.assertNotIn("make_doc.py " + OPEN, why)
            self.assertIn("Do not ask the user to type the value in", why)

    def test_claude_code_powershell_gets_the_file_route_with_write_or_edit(self):
        with _on("Windows"):
            why = _reason(self._pre("PowerShell", "python make_pdf.py " + self.e.ref, CLAUDE))
        self.assertIn("cannot be placed in a PowerShell command", why)
        self.assertIn(f"write the script with Write or Edit and put {OPEN}{self.e.key}{CLOSE}", why)
        self.assertNotIn(ARGUMENT_ROUTE, why)
        self.assertIn("With Git for Windows installed, Claude Code offers Bash instead", why)

    def test_a_setting_that_refuses_the_file_tool_names_no_file_route(self):
        cases = (("block codex", {"rehydration": "block"}, "Bash", CODEX),
                 ("confirm codex", {"rehydration": "confirm"}, "Bash", CODEX),
                 ("no values in files codex", {"resolve_in_files": False}, "Bash", CODEX),
                 ("block powershell", {"rehydration": "block"}, "PowerShell", CLAUDE),
                 ("no values in files powershell", {"resolve_in_files": False}, "PowerShell", CLAUDE))
        for name, keys, tool, client in cases:
            with self.subTest(name), _config(**keys), _on("Windows"):
                why = _reason(self._pre(tool, "python make_pdf.py " + self.e.ref, client))
            self.assertNotIn("into the file content", why)
            self.assertNotIn("Do not ask the user", why)
            self.assertIn("ask the user to run the command themselves", why)
        # Claude Code asks under confirm: the file route works there
        with _config(rehydration="confirm"), _on("Windows"):
            why = _reason(self._pre("PowerShell", "python make_pdf.py " + self.e.ref, CLAUDE))
        self.assertIn("into the file content", why)

    def test_posix_keeps_the_argument_route(self):
        with _on("Linux"):
            why = _reason(self._pre("Bash", "python3 -c 'print(1)' " + self.e.ref, CODEX))
        self.assertIn(ARGUMENT_ROUTE, why)

    def test_the_primer_on_windows_names_the_file_route_only(self):
        with _on("Windows"):
            text = hooks.primer()
        self.assertNotIn("make_pdf.py " + OPEN, text)
        self.assertNotIn(ARGUMENT_ROUTE, text)
        self.assertIn("put the placeholder into the file content with Write, Edit or apply_patch", text)
        self.assertIn("run the script with no placeholder in the command", text)
        with _on("Darwin"):
            self.assertEqual(hooks.primer(), hooks.PRIMER)

    def test_the_session_start_primer_follows_the_system(self):
        # the session start of the launcher on this system: Windows gets the file route, the others the argument
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                           input=json.dumps({"session_id": "S1", "turn_id": "t", "hook_event_name": "SessionStart"}),
                           capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        context = json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        if os.name == "nt":
            self.assertEqual(context, hooks.PRIMER_WINDOWS)
        else:
            self.assertEqual(context, hooks.PRIMER)


def _hook_entry(payload: dict, env: dict | None = None) -> dict:
    """The PreToolUse hook as the client starts it: on Windows the `commandWindows` line through cmd.exe (the form
    Codex uses), elsewhere dispatch.py."""
    data = json.dumps(payload, ensure_ascii=False)
    if os.name == "nt":
        spec = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        line = spec["hooks"]["PreToolUse"][0]["hooks"][0]["commandWindows"].replace("${CLAUDE_PLUGIN_ROOT}",
                                                                                   str(ROOT))
        comspec = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
        r = subprocess.run(f'"{comspec}" /C "{line}"', input=data.encode("utf-8"), capture_output=True,
                           env=env, timeout=120)
    else:
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "pre-tool"],
                           input=data.encode("utf-8"), capture_output=True, env=env, timeout=120)
    out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    assert r.returncode == 0, out + err
    return json.loads(out)


def _added_files(patch: str) -> dict[str, str]:
    """The files of a patch that only adds files: path -> content (the + lines)."""
    files: dict[str, list[str]] = {}
    current = None
    for line in patch.split("\n"):
        if line.startswith("*** Add File: "):
            current = line[len("*** Add File: "):]
            files[current] = []
        elif current is not None and line.startswith("+"):
            files[current].append(line[1:])
    return {p: "\n".join(lines) + "\n" for p, lines in files.items()}


MAKE_DOC = ("address = \"{ref}\"\n"
            "open('account.html', 'w', encoding='utf-8').write('<p>' + address + '</p>')\n")


class WindowsFileToolsTakeTheValueTests(unittest.TestCase):
    """The route the refusal names, end to end at the hook entry: the file tool gets the value, the script is
    written with it and runs with no placeholder in the command."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _reset()
        self.work = Path(tempfile.mkdtemp(prefix="ms-windoc-", dir=str(Path(_isolate.TMP).parent)))
        self.addCleanup(__import__("shutil").rmtree, self.work, True)

    def _run_script(self, name: str, content: str) -> str:
        (self.work / name).write_text(content, encoding="utf-8")
        r = subprocess.run([sys.executable, name], cwd=str(self.work), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return (self.work / "account.html").read_text(encoding="utf-8")

    def _check(self, key: str, ref: str, env: dict | None = None) -> None:
        patch = "*** Begin Patch\n*** Add File: make_doc.py\n+" + MAKE_DOC.format(ref=ref).rstrip("\n").replace(
            "\n", "\n+") + "\n*** End Patch"
        out = _hook_entry({"tool_name": "apply_patch", "tool_input": {"command": patch}, "session_id": "S1",
                           "cwd": str(self.work), "transcript_path": "", "hook_event_name": "PreToolUse",
                           "model": "codex-model", "turn_id": "t1"}, env)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso.get("permissionDecision"), "allow", out)
        files = _added_files(hso["updatedInput"]["command"])
        self.assertNotIn(OPEN, files["make_doc.py"])
        self.assertEqual(self._run_script("make_doc.py", files["make_doc.py"]), f"<p>{ADDRESS}</p>")

        (self.work / "account.html").unlink()
        out = _hook_entry({"tool_name": "Write", "session_id": "S1", "cwd": str(self.work), "transcript_path": "",
                           "hook_event_name": "PreToolUse", "prompt_id": "p",
                           "tool_input": {"file_path": str(self.work / "make_doc2.py"),
                                          "content": MAKE_DOC.format(ref=ref)}}, env)
        hso = out["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", hso, out)      # automatic: Claude Code's own rules decide
        content = hso["updatedInput"]["content"]
        self.assertNotIn(OPEN, content)
        self.assertEqual(self._run_script("make_doc2.py", content), f"<p>{ADDRESS}</p>")

    def test_apply_patch_and_write_put_the_value_into_the_script(self):
        e = Vault().put(ADDRESS, "EMAIL", "email", session="S1")
        self._check(e.key, e.ref)

    @unittest.skipUnless(os.name == "nt" and (os.environ.get("CI") or os.environ.get("MAISECRETS_NATIVE_BACKEND_TEST")
                                              == "1"), "the Credential Locker of the Windows runner")
    def test_the_same_with_the_windows_credential_locker(self):
        home = Path(tempfile.mkdtemp(prefix="ms-winvault-home-", dir=str(Path(_isolate.TMP).parent)))
        (home / "config.json").write_text('{"backend": "windows-vault"}', encoding="utf-8")
        env = dict(os.environ)
        env[_HOME_VAR] = str(home)
        put = ("import json, sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
               "e = Vault().put(sys.argv[2], 'EMAIL', 'email', session='S1'); print(json.dumps([e.key, e.ref]))")
        r = subprocess.run([sys.executable, "-c", put, str(ROOT), ADDRESS], capture_output=True, text=True,
                           env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        key, ref = json.loads(r.stdout)
        forget = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
                  "v = Vault(); v.backend.wipe()")
        self.addCleanup(subprocess.run, [sys.executable, "-c", forget, str(ROOT)], env=env, timeout=120,
                        capture_output=True)
        self._check(key, ref, env)


_HOME_VAR = "MAISECRETS" + "_HOME"


if __name__ == "__main__":
    unittest.main()
