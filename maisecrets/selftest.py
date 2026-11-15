"""The self-test of the two protection paths in the real client: `/maisecrets:status test` (Codex: the prompt
`maisecrets: status test`).

1. The PreToolUse hook sees the command `run.sh status test` and registers a fresh test value `ms-selftest-<12>` in
   `selftest.json` of the maisecrets home, with a time to live of 10 minutes. Only the hook writes it: the command
   itself writes nothing, so it also runs in the Codex sandbox, and a command whose PreToolUse hook did not run
   prints no value at all (the hooks of a moved plugin folder, C13).
2. The command prints the value. The PostToolUse hook replaces every `ms-selftest-<12>` in a tool result with
   `⟦SELFTEST⟧` before the model reads it, shows the value to the person only (`systemMessage`), and records
   "tool path passed" when it was the pending value.
3. The person sends the value as the next prompt. The prompt hook blocks a prompt that holds the pending value and
   answers "Self-test passed"; it records the time. A value that is not pending (another, an expired one) gets no
   answer here: the prompt goes on to the ordinary checks.

The test value is no secret: it never goes into the vault, the incident record or /maisecrets:list, and nothing here
lets a prompt or a tool call through that the ordinary checks would stop. Any program of the user can write
`selftest.json`, so a pass is a convenience for the person, not a proof against an agent that evades.
"""
from __future__ import annotations

import json
import os
import re
import time

from .lazy_regex import LazyRx

PREFIX = "ms-selftest-"
PLACEHOLDER = "⟦SELFTEST⟧"
TTL = 600                # the pending value: 10 minutes
ARMED = 60               # the command must run within a minute of its PreToolUse hook
FILE = "selftest.json"
TOKEN_RE = LazyRx(r"ms-selftest-[a-z0-9]{12}(?![a-z0-9])")
# the command of the slash command (commands/status.md) and of the typed Codex form
_COMMAND_RE = LazyRx(r"(?:run\.sh|run\.cmd|maisecrets\.cli)[\"']?\s+status\s+test(?![\w-])")
_TYPED_RE = LazyRx(r"\A\s*maisecrets:\s*status\s+test\s*\Z", re.IGNORECASE)


def _path():
    from .home import HOME
    return HOME / FILE


def load() -> dict:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict) -> None:
    from .home import atomic_write
    atomic_write(_path(), json.dumps(data))


def session_of_this_command() -> str | None:
    """The session that started this command: Claude Code gives a command its session id (hooks/dispatch.py, the
    pending prompt), Codex its thread id."""
    return os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CODEX_THREAD_ID") or None


def _pending(state: dict, now: float | None = None) -> dict | None:
    p = state.get("pending")
    now = time.time() if now is None else now
    if isinstance(p, dict) and isinstance(p.get("value"), str) and float(p.get("expires") or 0) > now:
        return p
    return None


# --- PreToolUse: register the value ------------------------------------------------------------------------------

def arm(payload: dict) -> None:
    """Register a fresh test value when this tool call is the self-test command. Never raises."""
    try:
        ti = payload.get("tool_input")
        cmd = ti.get("command") if isinstance(ti, dict) else None
        if not isinstance(cmd, str) or "status" not in cmd or not _COMMAND_RE.search(cmd):
            return
        import secrets
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        value = PREFIX + "".join(secrets.choice(alphabet) for _ in range(12))
        now = time.time()
        _save({"pending": {"value": value, "at": now, "expires": now + TTL,
                           "session": str(payload.get("session_id") or "")},
               "result": {"started": now, "tool": None, "prompt": None}})
    except Exception:  # noqa: BLE001 - the self-test never changes the answer to a tool call
        pass


# --- the command --------------------------------------------------------------------------------------------------

def command_text(now: float | None = None) -> str:
    """What `status test` prints. The value only when a PreToolUse hook registered it for this command."""
    now = time.time() if now is None else now
    state = load()
    p = _pending(state, now)
    session = session_of_this_command()
    fresh = p is not None and now - float(p.get("at") or 0) <= ARMED
    if fresh and session and p.get("session") and p["session"] != session:
        fresh = False
    if not fresh:
        return ("maisecrets self-test: FAIL. No maisecrets hook registered a test value for this command, so the "
                "tool-call hook did not run for it (or the command ran outside the client). No value is printed.\n"
                "Next: in Claude Code run /reload-plugins or start a new session; in Codex trust the maisecrets "
                "hooks in /hooks. Then run /maisecrets:status test (Codex: send maisecrets: status test) again.")
    return (f"maisecrets self-test, step 1 of 2. The test value: {p['value']}\n"
            f"The AI must read {PLACEHOLDER} in place of the value. If the AI reads a value that starts with "
            f"{PREFIX}, the tool-result hook did not run and the self-test FAILED: run /reload-plugins or start a "
            "new session.\n"
            "Step 2, for the person: send the test value alone as your next prompt (type or paste it). maisecrets "
            "shows the value to you above this output. The prompt hook must then answer \"Self-test passed\".\n"
            f"The value is no secret and works for {TTL // 60} minutes. /maisecrets:status shows the result.")


# --- PostToolUse: mask the value ----------------------------------------------------------------------------------

def _walk(node, found: list):
    if isinstance(node, str):
        if PREFIX not in node:
            return node
        found.extend(TOKEN_RE.findall(node))
        return TOKEN_RE.sub(PLACEHOLDER, node)
    if isinstance(node, list):
        return [_walk(x, found) for x in node]
    if isinstance(node, dict):
        return {(_walk(k, found) if isinstance(k, str) else k): _walk(v, found) for k, v in node.items()}
    return node


def mask(payload: dict) -> tuple[dict, list]:
    """(the payload with every test value in its tool_response replaced, the values found). The rest of the hook then
    sees the placeholder only, so the value is never detected, stored or counted."""
    response = payload.get("tool_response")
    if response is None:
        return payload, []
    found: list = []
    new = _walk(response, found)
    if not found:
        return payload, []
    return {**payload, "tool_response": new}, list(dict.fromkeys(found))


def answer(payload: dict, result: dict, found: list, codex: bool) -> dict:
    """The PostToolUse answer with the test value replaced: the model reads the placeholder, the person the value.
    Records "tool path passed" for the pending value."""
    state = load()
    p = _pending(state)
    passed = p is not None and p["value"] in found
    if passed:
        res = state.get("result") if isinstance(state.get("result"), dict) else {}
        res["tool"] = time.time()
        state["result"] = res
        try:
            _save(state)
        except OSError:
            passed = False
    result = dict(result or {})
    masked = payload.get("tool_response")
    text = masked if isinstance(masked, str) else json.dumps(masked, ensure_ascii=False)
    if codex:
        if result.get("decision") != "block":
            result = {**result, "decision": "block",
                      "reason": ("[maisecrets: the command ran and finished; this is not an error. The self-test value "
                                 f"in its output is replaced by {PLACEHOLDER}. Show the output as it is.]\n\n{text}")}
        try:
            # Codex writes the raw output into its rollout before this hook runs (hooks.post_tool does the same)
            from .hooks import _scrub_transcript, _scrub_transcript_later
            path = str(payload.get("transcript_path") or "")
            if path:
                _scrub_transcript(path, found, [])
                _scrub_transcript_later(path, found, [])
        except Exception:  # noqa: BLE001 - the answer stands; a resumed session could read the test value
            pass
    else:
        hso = dict(result.get("hookSpecificOutput") or {"hookEventName": "PostToolUse"})
        hso.setdefault("updatedToolOutput", masked)
        hso["additionalContext"] = ((hso.get("additionalContext") or "") + " " +
                                    f"maisecrets replaced a self-test value with {PLACEHOLDER}. It is no secret; show "
                                    "the output to the person as it is and do not try to get the value.").strip()
        result["hookSpecificOutput"] = hso
    shown = ", ".join(found)
    line = (f"maisecrets self-test: the tool-result hook ran and replaced the test value {shown} with {PLACEHOLDER} "
            "before the AI saw it. Next, send the test value alone as your next prompt."
            if passed else
            f"maisecrets replaced {shown} (a self-test value that is not pending) with {PLACEHOLDER} before the AI "
            "saw it.")
    result["systemMessage"] = (result["systemMessage"] + " " + line) if result.get("systemMessage") else line
    return result


# --- UserPromptSubmit ---------------------------------------------------------------------------------------------

def claims(prompt) -> bool:
    """The prompt hook answers this prompt itself (the mod passes it on unchanged): the typed command, or the pending
    test value."""
    if not isinstance(prompt, str):
        return False
    if _TYPED_RE.match(prompt):
        return True
    return PREFIX in prompt and _pending_in(prompt) is not None


def _pending_in(prompt: str) -> dict | None:
    p = _pending(load())
    if p is None or p["value"] not in TOKEN_RE.findall(prompt):
        return None
    return p


def prompt_answer(payload: dict, codex: bool) -> dict | None:
    """The answer to the typed command or to the pending test value; None for every other prompt."""
    prompt = payload.get("prompt")
    if not isinstance(prompt, str):
        return None
    if _TYPED_RE.match(prompt):
        from .notices import launcher
        run = launcher()
        how = f'& "{run}" status test' if run.endswith(".cmd") else f'bash "{run}" status test'
        return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": (
            "maisecrets self-test: run exactly this command once and show the person its output as it is, then "
            f"stop: {how}\nIts output holds a test value that maisecrets replaces with {PLACEHOLDER} before you "
            "read it. Do not try to get the value.")}}
    if PREFIX not in prompt:
        return None
    state = load()
    p = _pending(state)
    if p is None or p["value"] not in TOKEN_RE.findall(prompt):
        return None                      # not the pending value: the ordinary checks decide
    res = state.get("result") if isinstance(state.get("result"), dict) else {}
    res["prompt"] = time.time()
    state["result"] = res
    try:
        _save(state)
    except OSError:
        pass
    if res.get("tool"):
        reason = "Self-test passed: the prompt hook ran, and the model did not get the value."
    else:
        reason = ("Self-test, prompt path passed: the prompt hook ran, and the model did not get the value in this "
                  "prompt. The tool-result hook did not record the value, so the AI may have read it in the output "
                  "of the command: run /maisecrets:status.")
    rest = " ".join(TOKEN_RE.sub(" ", prompt).split())
    if rest:
        reason += " The rest of this prompt was not sent either; send it again on its own."
    try:
        from .hooks import _scrub_transcript, _scrub_transcript_later
        path = str(payload.get("transcript_path") or "")
        if path:
            _scrub_transcript(path, [p["value"]], [])
            _scrub_transcript_later(path, [p["value"]], [])
        if rest:
            from .hooks import _scrub_failed_prompt
            _scrub_failed_prompt("user-prompt", payload)
    except Exception:  # noqa: BLE001 - the block stands either way
        pass
    if codex:
        return {"decision": "block", "reason": reason}
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


# --- /maisecrets:status -------------------------------------------------------------------------------------------

def verdict(now: float | None = None) -> tuple[str, str]:
    """(state, text) of the self-test line of /maisecrets:status."""
    from .status_verdict import ago
    now = time.time() if now is None else now
    state = load()
    res = state.get("result") if isinstance(state.get("result"), dict) else {}
    tool, prompt = res.get("tool"), res.get("prompt")
    if tool and prompt:
        return "ok", (f"self-test: passed {ago(now - max(tool, prompt))} (the tool-result hook masked the test value "
                      f"{ago(now - tool)}, the prompt hook stopped it {ago(now - prompt)})")
    p = _pending(state, now)
    if tool and p:
        return "warn", (f"self-test: the tool path passed {ago(now - tool)}; the prompt path is not tested yet. "
                        "Next: send the test value alone as your next prompt")
    if prompt and not tool:
        return "FAIL", (f"self-test: the prompt hook stopped the test value {ago(now - prompt)}, but the tool-result "
                        "hook did not mask it. Next: run /reload-plugins or start a new session, then "
                        "/maisecrets:status test")
    if tool:
        return "warn", (f"self-test: only the tool path passed ({ago(now - tool)}); the test value expired before "
                        "a prompt sent it. Next: /maisecrets:status test")
    if p:
        return "FAIL", ("self-test: a test value is pending, and no tool-result hook masked it. If the AI read the "
                        "value, the hook did not run. Next: run /reload-plugins or start a new session, then "
                        "/maisecrets:status test")
    return "warn", "self-test: not run. Next: /maisecrets:status test (Codex: send maisecrets: status test)"
