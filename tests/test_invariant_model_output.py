"""Invariant I1: a stored value never reaches a hook output that the model reads.

docs/PROTOCOL.md §5 says "nothing a hook prints contains a value". The mechanism tests each
guard one path; this module holds the goal over every path: every hook event, both clients,
every tool-response shape, every refusal, the fail-closed answers, and the prompt that goes on
to the model. The only exception is `updatedInput` of a PreToolUse answer that resolves: that
is the delivery the user allows, and its copy in the transcript is invariant I4.

The oracle is this file's own. `forms()` builds the encodings without the product's
`_derived_forms` or `_candidates`, so a form the product forgets stays red here.

Every hook runs through `hooks.main`, the entry point `hooks/dispatch.py` calls, with its real
stdin and stdout: the watchdog, the run log and the single-answer lock are in the path.
"""
from __future__ import annotations

import base64
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import quote, quote_plus

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

CLIENTS = {"claude": CLAUDE, "codex": {**CODEX, "model": "m"}}

# The hook output fields of Claude Code and Codex (hooks references). Each is classified: the
# text the model or the person reads, the delivery the user allows, or a flag without text.
MODEL_TEXT = {"reason", "permissionDecisionReason", "additionalContext", "updatedToolOutput",
              "updatedMCPToolOutput", "systemMessage", "stopReason"}
DELIVERY = {"updatedInput"}
FLAGS = {"decision", "hookSpecificOutput", "hookEventName", "permissionDecision", "suppressOriginalPrompt",
         "continue", "suppressOutput"}
KNOWN_FIELDS = MODEL_TEXT | DELIVERY | FLAGS

# every field name an answer in this module carried; the population test demands each text field
SEEN_FIELDS: set[str] = set()


def ph(key: str) -> str:
    """A placeholder, spelled with escapes so no hook resolves it in this file."""
    return chr(0x27E6) + key + chr(0x27E7)


def rand(prefix: str = "Iv") -> str:
    return prefix + secrets.token_hex(8)


def forms(value: str) -> list[str]:
    """The shapes of a value after the encodings a command or a JSON layer applies. Built here,
    independent of the product. Forms shorter than 4 characters are left out: they match by
    chance."""
    raw = value.encode("utf-8")
    out = [value]
    esc_ascii = json.dumps(value)[1:-1]
    esc_utf8 = json.dumps(value, ensure_ascii=False)[1:-1]
    out += [esc_ascii, esc_utf8, json.dumps(esc_ascii)[1:-1]]
    for enc in (base64.b64encode(raw).decode("ascii"), base64.urlsafe_b64encode(raw).decode("ascii")):
        out += [enc, enc.rstrip("=")]
    out += [raw.hex(), raw.hex().upper(), quote(value, safe=""), quote_plus(value)]
    return [f for f in dict.fromkeys(out) if len(f) >= 4]


def encoded(value: str) -> list[str]:
    """The encodings a command applies to a value it read (the inputs; `forms` is the search)."""
    raw = value.encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return [b64, b64.rstrip("="), base64.urlsafe_b64encode(raw).decode("ascii"), raw.hex(), raw.hex().upper(),
            quote(value, safe=""), quote_plus(value), json.dumps(value)[1:-1]]


def model_strings(obj, path: str = "") -> list[tuple[str, str]]:
    """(field path, text) for every string in a hook answer except the allowed delivery."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in DELIVERY:
                continue
            out += model_strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += model_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        out.append((path, obj))
    return out


def leaks(values: list[str], obj) -> list[str]:
    found = []
    for field, text in model_strings(obj):
        for value in values:
            for f in forms(value):
                if f in text:
                    found.append(f"{field} carries {f!r} (a form of {value!r})")
    return found


def run_hook(event: str, payload: dict) -> dict:
    """One hook run through the real entry point; at most one JSON object comes out."""
    hooks._live_cache.clear()
    buf = io.StringIO()
    with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), redirect_stdout(buf):
        rc = hooks.main(["hook", event])
    text = buf.getvalue()
    if not text:
        if rc != 0:
            raise AssertionError(f"{event}: exit {rc} without an answer")
        return {}
    obj = json.loads(text)
    _record_fields(obj)
    return obj


def _record_fields(obj) -> None:
    if isinstance(obj, dict):
        SEEN_FIELDS.update(obj)
        for v in obj.values():
            _record_fields(v)


def reset() -> None:
    for f in ("index.json", "vault.json", "audit.log", "hooks.log", "events.json"):
        try:
            os.unlink(HOME / f)
        except FileNotFoundError:
            pass
    shutil.rmtree(HOME / "pending", ignore_errors=True)
    hooks._live_cache.clear()


class _World:
    """One session S1 with values in each state the hooks must know:

    * resolved: S1 put the value into a call, so it is expected back in any encoding;
    * live: stored in another session and never resolved here, so only its fingerprint is known;
    * nasty: resolved, with a quote, a backslash, a dollar and a space;
    * wide: resolved, outside ASCII;
    * short: resolved, 6 characters (`put` takes a password of any length).
    """

    def __init__(self) -> None:
        reset()
        self.v = Vault()
        self.values: dict[str, str] = {}
        self.refs: dict[str, str] = {}
        specs = {"resolved": (rand("Rs"), True), "live": (rand("Lv"), False),
                 "nasty": ("pa$s'w\"o rd`" + rand("N") + "\\z", True),
                 "wide": ("pässwört-Ωμ-" + rand("W"), True), "short": ("Q" + secrets.token_hex(2) + "!", True)}
        for name, (value, resolved) in specs.items():
            e = self.v.put(value, "SECRET", "manual", session="S1" if resolved else "S0")
            if resolved:
                assert self.v.record_resolve(e.key, "S1", "mcp__x__y", "{}") == "ok"
            self.values[name] = value
            self.refs[name] = e.ref

    @property
    def all_values(self) -> list[str]:
        return list(self.values.values())


def _shapes(text: str) -> dict[str, object]:
    """The tool_response shapes the clients send: Bash, Read, an MCP result, nested JSON."""
    return {
        "bash-stdout": {"stdout": text, "stderr": ""},
        "bash-stderr": {"stdout": "", "stderr": text, "interrupted": False},
        "read": {"type": "text", "file": {"filePath": "/w/app.log", "content": text, "numLines": 1}},
        "mcp-content": [{"type": "text", "text": text}],
        "mcp-json-in-text": {"content": [{"type": "text", "text": json.dumps({"result": {"items": [text]}})}]},
        "plain-string": text,
    }


class PostToolOutputTests(unittest.TestCase):
    """C2 over every shape and client: a value in a tool result is gone before the model reads it."""

    @classmethod
    def setUpClass(cls):
        cls.w = _World()

    def _post(self, client: str, tool: str, response: object) -> dict:
        payload = {"tool_name": tool, "session_id": "S1", "tool_input": {"command": "x"},
                   "tool_response": response, "transcript_path": "", **CLIENTS[client]}
        return run_hook("post-tool", payload)

    def _check(self, texts: dict[str, str], values: list[str]) -> None:
        bad = []
        for label, text in texts.items():
            for shape, response in _shapes(text).items():
                for client in CLIENTS:
                    tool = "Read" if shape == "read" else ("mcp__srv__get" if shape.startswith("mcp") else "Bash")
                    out = self._post(client, tool, response)
                    if not out:
                        bad.append(f"{label} / {shape} / {client}: the raw result went through unchanged")
                        continue
                    bad += [f"{label} / {shape} / {client}: {x}" for x in leaks(values, out)]
        self.assertEqual(bad, [], f"{len(bad)} leaks:\n" + "\n".join(bad[:15]))

    def test_a_resolved_value_is_gone_in_every_encoding_shape_and_client(self):
        names = ("resolved", "nasty", "wide", "short")
        texts = {}
        for name in names:
            value = self.w.values[name]
            texts[f"{name} plain"] = f"done: {value}\n"
            texts[f"{name} in a line"] = f"x{value}y and more"
            for i, enc in enumerate(encoded(value)):
                texts[f"{name} enc{i}"] = f"out {enc} end"
        self._check(texts, [self.w.values[n] for n in names])

    def test_a_live_value_is_gone_in_every_token_position_shape_and_client(self):
        value = self.w.values["live"]
        texts = {
            "alone": value,
            "assignment": f"API_TOKEN={value}\n",
            "header": f"Authorization: Bearer {value}\n",
            "url": f"GET https://ci:{value}@h.example/p?t={value}&z=1 200",
            "json": json.dumps({"config": {"token": value}}),
            "url-encoded": f"t={quote(value + '/+', safe='')}",
            "punctuation": f"({value}), [{value}].",
        }
        self._check(texts, [value])


class RefusalTextTests(unittest.TestCase):
    """A refusal names keys, counts and the next step, never the value: every deny, ask and
    block reason, with the value placed next to the thing that is refused."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        self.w = _World()

    def _pre(self, client: str, tool: str, tool_input: dict) -> dict:
        return run_hook("pre-tool", {"tool_name": tool, "tool_input": tool_input, "session_id": "S1",
                                     "transcript_path": "", "cwd": str(HOME.parent), **CLIENTS[client]})

    def test_no_pre_tool_answer_carries_a_value(self):
        w = self.w
        r, lv, nz = w.refs["resolved"], w.values["live"], w.values["resolved"]
        cases = {
            "store read": ("Bash", {"command": f"cat ~/.maisecrets/vault.json; echo {lv} {nz}"}),
            "nested shell": ("Bash", {"command": f"bash -c 'echo {r} {lv}'"}),
            "encoder": ("Bash", {"command": f"echo {r} {lv} | base64"}),
            "backticks": ("Bash", {"command": f"echo `echo {r}` {lv}"}),
            "unknown key": ("Bash", {"command": f"curl -H 'X: {ph('SECRET_c999')}' {lv}"}),
            "foreign session": ("Bash", {"command": f"echo {w.refs['live']} {nz}"}),
            "mcp key as field name": ("mcp__srv__post", {r: lv, "token": nz}),
            "mcp unknown key": ("mcp__srv__post", {"token": ph("SECRET_c998"), "note": lv}),
            "mcp foreign": ("mcp__srv__post", {"token": w.refs["live"], "id": nz}),
            "mcp published text": ("mcp__slack__post", {"text": f"hi {r}", "channel": lv}),
            "read of the store": ("Read", {"file_path": str(HOME / "vault.json")}),
            "grep of the store": ("Grep", {"pattern": lv, "path": str(HOME)}),
            "write into the store": ("Write", {"file_path": str(HOME / "config.json"), "content": f"{lv} {r}"}),
        }
        bad = []
        for label, (tool, tool_input) in cases.items():
            for client in CLIENTS:
                out = self._pre(client, tool, tool_input)
                bad += [f"{label} / {client}: {x}" for x in leaks(w.all_values, out)]
        self.assertEqual(bad, [], f"{len(bad)} leaks:\n" + "\n".join(bad[:15]))

    def test_a_blocked_prompt_carries_no_value_in_its_answer_or_its_pending_copy(self):
        typed = "ghp_" + secrets.token_hex(18)          # a shape the detector knows
        bad = []
        for client in CLIENTS:
            w = _World()
            for label, prompt in {
                "detected": f"deploy with {typed} please",
                "detected and a stored one": f"password: {rand('Pw')} and the old one {w.values['live']}",
                "a resolved one typed again": f"token={typed} and {w.values['resolved']}",
            }.items():
                with mock.patch.object(hooks, "_clipboard", return_value=False):
                    out = run_hook("user-prompt", {"prompt": prompt, "session_id": "S1", "transcript_path": "",
                                                   "prompt_id": "p1", **CLIENTS[client]})
                values = w.all_values + [typed]
                bad += [f"{label} / {client}: {x}" for x in leaks(values, out)]
                pending = hooks.take_pending("S1")
                if pending is not None:
                    bad += [f"{label} / {client}: pending {x}" for x in leaks(values, {"pending": pending})]
        self.assertEqual(bad, [], f"{len(bad)} leaks:\n" + "\n".join(bad[:15]))

    def test_a_prompt_that_goes_to_the_model_carries_no_stored_value(self):
        # a prompt the hook lets through reaches the model as it is: a value the store knows by
        # its fingerprint must be blocked like a detected one
        bad = []
        for name in ("live", "resolved", "nasty"):
            for client in CLIENTS:
                w = _World()
                prompt = f"please use {w.values[name]} for the login"
                with mock.patch.object(hooks, "_clipboard", return_value=False):
                    out = run_hook("user-prompt", {"prompt": prompt, "session_id": "S1", "transcript_path": "",
                                                   "prompt_id": "p1", **CLIENTS[client]})
                if out.get("decision") != "block":
                    bad.append(f"{name} / {client}: the prompt went to the model with the value")
                bad += [f"{name} / {client}: {x}" for x in leaks([w.values[name]], out)]
        self.assertEqual(bad, [], f"{len(bad)} leaks:\n" + "\n".join(bad[:15]))


class FailClosedTextTests(unittest.TestCase):
    """The answer of a hook that cannot finish names the exception type, never its message:
    a store error can carry the value in its argument list."""

    def setUp(self):
        self.w = _World()

    def test_a_crash_with_the_value_in_its_message_answers_without_it(self):
        value = self.w.values["resolved"]
        boom = RuntimeError(f"security: item {value} not found")

        def crash(_payload):
            raise boom
        bad = []
        for event in ("user-prompt", "pre-tool", "post-tool"):
            for client in CLIENTS:
                payload = {"prompt": "hello", "tool_name": "Bash", "tool_input": {"command": "ls"},
                           "tool_response": {"stdout": "a secret: " + rand()}, "session_id": "S1",
                           "transcript_path": "", **CLIENTS[client]}
                # post-tool fails inside its own guard; the other two in the entry point
                with mock.patch.object(hooks.detect, "scan", side_effect=boom), \
                        mock.patch.dict(hooks.HANDLERS, {"user-prompt": crash, "pre-tool": crash}):
                    out = run_hook(event, payload)
                if not out:
                    bad.append(f"{event} / {client}: no answer (fail open)")
                bad += [f"{event} / {client}: {x}" for x in leaks([value], out)]
        self.assertEqual(bad, [], "\n".join(bad))


class SessionStartTextTests(unittest.TestCase):
    """SessionStart prints the version, a tip and the primer; a value in the store or in the
    configuration never appears there."""

    def test_the_session_start_answer_carries_no_stored_value(self):
        w = _World()
        env = dict(os.environ, MAISECRETS_HOME=str(HOME), PYTHONUTF8="1")
        env.pop("CLAUDECODE", None)
        bad = []
        for config in ({"backend": "jsonfile", "allow_plaintext_store": True},
                       # a value pasted into the configuration by mistake: the warning names the key only
                       {"backend": "jsonfile", "allow_plaintext_store": True, "ttl_hours": w.values["resolved"],
                        w.values["live"]: 1}):
            (HOME / "config.json").write_text(json.dumps(config), encoding="utf-8")
            try:
                r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                                   input=json.dumps({"session_id": "S1", "transcript_path": ""}), env=env,
                                   capture_output=True, timeout=30, encoding="utf-8")
            finally:
                (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            bad += leaks(w.all_values, out)
            bad += [f"stderr carries {v!r}" for v in w.all_values if v in r.stderr]
        self.assertEqual(bad, [], "\n".join(bad))


class PopulationTests(unittest.TestCase):
    """The matrix is only as good as the fields it reaches."""

    def test_every_output_field_the_hooks_can_write_is_classified(self):
        # every string constant in the hook code that names a field of the clients' hook output
        import ast
        client_fields = KNOWN_FIELDS | {"updatedPermissions", "interrupt", "watchPaths", "sessionTitle"}
        named = set()
        for path in (ROOT / "maisecrets" / "hooks.py", ROOT / "hooks" / "dispatch.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Dict):
                    for k in node.keys:
                        if isinstance(k, ast.Constant) and k.value in client_fields:
                            named.add(k.value)
                if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                        and node.slice.value in client_fields:
                    named.add(node.slice.value)
        self.assertEqual(named - KNOWN_FIELDS, set(), "a new output field needs a class here")
        self.assertIn("updatedToolOutput", named, "the scan must find the fields it claims to find")

    def test_the_matrix_reaches_every_text_field_the_hooks_write(self):
        # its own small matrix: the order of the test classes is not a contract
        w = _World()
        run_hook("post-tool", {"tool_name": "Bash", "session_id": "S1", "tool_input": {},
                               "tool_response": {"stdout": w.values["resolved"]}, **CLAUDE})
        run_hook("post-tool", {"tool_name": "Bash", "session_id": "S1", "tool_input": {},
                               "tool_response": {"stdout": w.values["resolved"]}, **CLIENTS["codex"]})
        run_hook("pre-tool", {"tool_name": "Bash", "session_id": "S1",
                              "tool_input": {"command": "cat ~/.maisecrets/x"}, **CLAUDE})
        with mock.patch.object(hooks, "_clipboard", return_value=False):
            run_hook("user-prompt", {"prompt": "ghp_" + secrets.token_hex(18), "session_id": "S1", **CLAUDE})
        run_hook("user-prompt", {"prompt": f"use {w.refs['resolved']}", "session_id": "S1", **CLAUDE})
        written = {"reason", "permissionDecisionReason", "additionalContext", "updatedToolOutput", "systemMessage"}
        self.assertEqual(written - SEEN_FIELDS, set(), "a text field the hooks write was never checked")


if __name__ == "__main__":
    unittest.main()
