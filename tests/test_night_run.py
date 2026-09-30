"""A night of autonomous work: maisecrets stops nothing, and the one real secret still stays away from the model.

Someone leaves a programming task for the night. The agent reads tests with fixture passwords, a compose file, an
.env.example and docs; it greps, runs pytest, writes a test, starts a subagent and a background command, and a loop
wakes it up. Nobody is there to press /ms. A prompt block or a denied call stops the night, so the run counts
every one. A real key in .env is read once: it must be redacted, and it must stay hunted afterwards.
"""
from __future__ import annotations

import html
import json
import os
import sys
import tempfile
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
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = _isolate.HOME
REAL_KEY = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"          # the one real secret of the night, built at run time
PW = "pass" + "word"                                     # the label, split so the tree scan sees no pair
BEARER = "Bearer " + "abc123" + "def456" + "ghi789"      # a fixture header, split for the same reason

TEST_FILE = f"""import pytest
from app import login

PASSWD = 'testPass'
KEY_{PW.upper()} = "somepass"


def test_login(client):
    assert client.login("bob", "hunter2hunter2")
    assert not client.login("bob", "wrongpassword")


def test_token(client):
    client.headers["Authorization"] = "{BEARER}"
    assert client.get("/me").status_code == 200
"""
COMPOSE = f"""services:
  db:
    image: postgres:16
    environment:
      POSTGRES_{PW.upper()}: postgres
      POSTGRES_USER: postgres
  app:
    environment:
      DATABASE_URL: postgres://postgres:postgres@db:5432/app
"""
ENV_EXAMPLE = f"DB_{PW.upper()}=\nAPI_KEY=\nSECRET_KEY=\n"
DOCS = f"""## Configuration

- `token`: optional API token, see <your-token>
- `{PW}`: required for every call
- Contact: support@example.com
- The resolver is 8.8.8.8; RFC 6749 4.1.2.1 describes the error.
"""
PYTEST_OUT = """============================= FAILURES =============================
___________________________ test_login ___________________________

    def test_login(client):
>       assert client.login("bob", "hunter2hunter2")
E       AssertionError: assert False
E        +  where False = login('bob', 'hunter2hunter2')

tests/test_login.py:9: AssertionError
========================= 1 failed, 3 passed in 0.42s =========================
"""
GREP_OUT = (f"tests/test_login.py:4:PASSWD = 'testPass'\n"
            f"tests/test_login.py:5:KEY_{PW.upper()} = \"somepass\"\n"
            f"src/app/config.py:12:    {PW} = os.environ[\"DB_{PW.upper()}\"]\n"
            f"src/app/config.py:13:    token: str | None = None\n")


class NightRunTests(unittest.TestCase):
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
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-night-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.transcript = self.dir / "night.jsonl"
        self.stops: list[str] = []
        self.redacted: list[str] = []

    # one call of each hook, as the client sends it ---------------------------------------------------------------
    def prompt(self, what: str, text: str) -> None:
        hooks._live_cache.clear()
        out = hooks.user_prompt({"prompt": text, "session_id": "night", "transcript_path": str(self.transcript),
                                 **CLAUDE})
        if out.get("decision") == "block":
            self.stops.append(f"prompt blocked: {what}")

    def tool(self, what: str, name: str, tool_input: dict, response) -> str:
        hooks._live_cache.clear()
        pre = hooks.pre_tool({"tool_name": name, "tool_input": tool_input, "session_id": "night", **CLAUDE})
        if (pre.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny":
            self.stops.append(f"denied: {what}")
            return ""
        post = hooks.post_tool({"tool_name": name, "tool_input": tool_input, "tool_response": response,
                                "session_id": "night", **CLAUDE})
        shown = json.dumps((post.get("hookSpecificOutput") or {}).get("updatedToolOutput", response))
        if post:
            self.redacted.append(what)
        return shown

    def read(self, path: str, content: str) -> str:
        return self.tool(f"Read {path}", "Read", {"file_path": f"/repo/{path}"},
                         {"type": "text", "file": {"filePath": f"/repo/{path}", "content": content}})

    def bash(self, command: str, stdout: str) -> str:
        return self.tool(f"Bash {command}", "Bash", {"command": command},
                         {"stdout": stdout, "stderr": "", "interrupted": False, "isImage": False})

    def subagent_reports(self, answer: str) -> None:
        tool_use = "toolu_01NightAgent"
        with open(self.transcript, "a", encoding="utf-8") as f:
            f.write(json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": tool_use, "name": "Agent", "input": {"prompt": "review the tests"}}]}})
                    + "\n")
        sub = self.dir / "night" / "subagents"
        sub.mkdir(parents=True, exist_ok=True)
        out = sub / "agent-n1.jsonl"
        out.write_text(json.dumps({"type": "assistant", "message": {"id": "m1", "content": [
            {"type": "text", "text": answer}]}}) + "\n", encoding="utf-8")
        self.prompt("subagent report", f"<task-notification>\n<task-id>n1</task-id>\n<tool-use-id>{tool_use}"
                    f"</tool-use-id>\n<output-file>{out}</output-file>\n<status>completed</status>\n"
                    "<summary>Agent finished</summary>"
                    f"\n<result>{html.escape(answer)}</result>\n</task-notification>")

    # the night ---------------------------------------------------------------------------------------------------
    def test_a_night_of_work_is_never_stopped_and_the_real_key_stays_away(self):
        self.transcript.write_text("", encoding="utf-8")
        self.prompt("the task", "Fix the failing login test and add a test for the token refresh. "
                                "Work through the night; run the tests after every change.")
        self.read("tests/test_login.py", TEST_FILE)
        self.read("docker-compose.yml", COMPOSE)
        self.read(".env.example", ENV_EXAMPLE)
        self.read("docs/configuration.md", DOCS)
        self.bash(f"grep -rn '{PW}\\|token' tests src", GREP_OUT)
        self.bash("pytest -q", PYTEST_OUT)
        self.bash("docker ps", "1a2b3c4d5e6f   postgres:16   Up 2 hours   app-postgres-1\n")
        self.tool("Write a new test", "Write", {"file_path": "/repo/tests/test_refresh.py", "content": (
            "def test_refresh(client):\n    client.login('bob', 'testPass')\n    assert client.refresh()\n")},
            {"type": "create", "filePath": "/repo/tests/test_refresh.py"})
        self.subagent_reports(f"The fixtures use PASSWD = 'testPass' and a {BEARER} header; "
                              f"the compose file sets POSTGRES_{PW.upper()}: postgres.")
        self.prompt("background command done", "<task-notification>\n<task-id>b1</task-id>\n<tool-use-id>toolu_01Bg"
                    "</tool-use-id>\n<output-file>/tmp/b1.output</output-file>\n<status>completed</status>\n<summary>"
                    "Background command \"pytest -q\" completed (exit code 0)</summary>\n</task-notification>")
        self.prompt("loop wake-up", "Continue with the next failing test; run pytest afterwards.")
        # the one real secret of the night: a key in .env
        shown = self.read(".env", f"GITLAB_TOKEN={REAL_KEY}\nDEBUG=1\n")
        later = self.bash("env | grep GITLAB", f"GITLAB_TOKEN={REAL_KEY}\n")
        self.prompt("after the key", "Continue; the tests pass now.")

        self.assertEqual(self.stops, [], "nothing stops the night")
        self.assertNotIn(REAL_KEY, shown)
        self.assertNotIn(REAL_KEY, later, "the real key stays hunted")
        self.assertEqual(self.redacted, ["Read .env", "Bash env | grep GITLAB"],
                         "maisecrets steps in only where a real secret goes to the model")


if __name__ == "__main__":
    unittest.main()
