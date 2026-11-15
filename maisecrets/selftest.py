"""The self-test of the two protection paths in the real client: `/maisecrets:status test` (Codex: the prompt
`maisecrets: status test`).

1. The PreToolUse hook sees a tool call whose command is `run.sh status test` and registers a fresh test value
   `ms-selftest-<12>` in `selftest.json` of the maisecrets home, with the call's id, its session, the version and a
   time to live of 10 minutes. Only the hook writes it: the command itself writes nothing, so it also runs in the
   Codex sandbox, and a command whose PreToolUse hook did not run prints no value at all (a moved plugin folder, C13).
2. The command prints the value. The PostToolUse hook replaces the pending value, where it stands alone, with
   `⟦SELFTEST⟧` before the rest of the hook reads the output, shows the value to the person only (`systemMessage`),
   and records "tool path passed" only for the call that registered it. Every other text, a token of the same shape
   included, goes to the ordinary checks unchanged. A tool call whose input holds the pending value means the model
   has it: the self-test records a failure.
3. The person sends the value as the next prompt. The prompt hook blocks a prompt that holds the pending value. It
   answers "Self-test passed" only for a prompt the person typed in the session that registered the value; any other
   such prompt is blocked without a pass.

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
FRESH = 4 * 3600         # a pass of another session counts as current for 4 hours
FILE = "selftest.json"
# the command of the slash command (commands/status.md): the launcher, as the command's first word, then `status test`
_COMMAND_RE = LazyRx(r"\A\s*(?:bash\s+|&\s*)?(?:\"[^\"\n]*|'[^'\n]*|[^\s\"']*)(?:run\.sh|run\.cmd)[\"']?"
                     r"\s+status\s+test\s*\Z")
_TYPED_RE = LazyRx(r"\A\s*maisecrets:\s*status\s+test\s*\Z", re.IGNORECASE)
# a value that stands alone: after the start, a blank, a quote, an opening bracket or one of , ; : = and before the
# end, a blank, a quote, a closing bracket, , ; or a full stop at the end of a sentence. A value glued to other
# characters is left to the detector, which then sees the whole token (Gate A: a secret glued after it was cut off)
_LEFT = r"(?<![^\s\"'`(\[{<,;:=])"
_RIGHT = r"(?=\Z|[\s\"'`)\]}>,;]|\.(?:\s|\Z))"
# a value in a prompt or a tool input: not part of a longer word
_WORD_LEFT, _WORD_RIGHT = r"(?<![A-Za-z0-9_\-])", r"(?![A-Za-z0-9_\-])"


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


def _result(state: dict) -> dict:
    res = state.get("result")
    return res if isinstance(res, dict) else {}


def _num(v) -> float:
    """A time from the file; 0 for a wrong type."""
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def sessions_of_this_command() -> list[str]:
    """The sessions that may have started this command: Claude Code gives a command its session id (hooks/dispatch.py,
    the pending prompt), Codex its thread id. Both, when one client runs inside the other: Codex passes on the
    Claude Code variable of the shell that started it (measured with the harness, codex-cli 0.169.0), and the other
    way round. The caller decides between them (the session whose hooks ran)."""
    return [s for s in (os.environ.get("CLAUDE_CODE_SESSION_ID"), os.environ.get("CODEX_THREAD_ID")) if s]


def _pending(state: dict, now: float | None = None) -> dict | None:
    p = state.get("pending")
    now = time.time() if now is None else now
    if isinstance(p, dict) and isinstance(p.get("value"), str) and p["value"].startswith(PREFIX) \
            and _num(p.get("expires")) > now:
        return p
    return None


def _word_in(text: str, value: str) -> bool:
    return isinstance(text, str) and value in text and re.search(_WORD_LEFT + re.escape(value) + _WORD_RIGHT,
                                                                 text) is not None


def _holds(node, value: str) -> bool:
    if isinstance(node, str):
        return _word_in(node, value)
    if isinstance(node, list):
        return any(_holds(x, value) for x in node)
    if isinstance(node, dict):
        return any(_holds(k, value) or _holds(v, value) for k, v in node.items())
    return False


def _has_prefix(node) -> bool:
    if isinstance(node, str):
        return PREFIX in node
    if isinstance(node, list):
        return any(_has_prefix(x) for x in node)
    if isinstance(node, dict):
        return any(_has_prefix(k) or _has_prefix(v) for k, v in node.items())
    return False


# --- PreToolUse: register the value ------------------------------------------------------------------------------

def arm(payload: dict) -> None:
    """Register a fresh test value when this tool call is the self-test command. Never raises."""
    try:
        ti = payload.get("tool_input")
        cmd = ti.get("command") if isinstance(ti, dict) else None
        if not isinstance(cmd, str) or "status" not in cmd or not _COMMAND_RE.match(cmd):
            return
        import secrets
        from pathlib import Path
        from .status_verdict import installed_version
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        value = PREFIX + "".join(secrets.choice(alphabet) for _ in range(12))
        now = time.time()
        session = str(payload.get("session_id") or "")
        version = installed_version(Path(__file__).resolve().parent.parent)
        _save({"pending": {"value": value, "at": now, "expires": now + TTL, "session": session,
                           "tool_use_id": str(payload.get("tool_use_id") or "")},
               "result": {"started": now, "tool": None, "prompt": None, "leak": None, "session": session,
                          "version": version}})
    except Exception:  # noqa: BLE001 - the self-test never changes the answer to a tool call
        pass


# --- the command --------------------------------------------------------------------------------------------------

def command_text(now: float | None = None) -> str:
    """What `status test` prints. The value only when a PreToolUse hook registered it for this command's session."""
    now = time.time() if now is None else now
    p = _pending(load(), now)
    sessions = sessions_of_this_command()
    fresh = (p is not None and now - _num(p.get("at")) <= ARMED and bool(sessions)
             and p.get("session") in sessions)
    if not fresh:
        return ("maisecrets self-test: FAIL. No maisecrets hook registered a test value for this command in this "
                "session, so the tool-call hook did not run for it (or the command ran outside the client). No value "
                "is printed.\n"
                "Next: in Claude Code run /reload-plugins or start a new session; in Codex trust the maisecrets "
                "hooks in /hooks. Then run /maisecrets:status test (Codex: send maisecrets: status test) again.")
    return (f"maisecrets self-test, step 1 of 2. The test value: {p['value']}\n"
            f"The AI must read {PLACEHOLDER} in place of the value. If the AI reads a value that starts with "
            f"{PREFIX}, the tool-result hook did not run and the self-test FAILED: run /reload-plugins or start a "
            "new session.\n"
            "Step 2, for the person: type or paste the test value alone as your next prompt in this session. "
            "maisecrets shows the value to you above this output. The prompt hook must then answer "
            "\"Self-test passed\".\n"
            f"The value is no secret and works for {TTL // 60} minutes. /maisecrets:status shows the result.")


# --- PostToolUse: mask the value ----------------------------------------------------------------------------------

def mask(payload: dict) -> tuple[dict, dict | None]:
    """(the payload with the pending value replaced where it stands alone in its tool_response, what the answer needs
    or None). Only the pending value: the rest of the hook sees every other text as it was. A tool input that holds
    the pending value is recorded as a failure: the model wrote it, so it has it."""
    response, tool_input = payload.get("tool_response"), payload.get("tool_input")
    if not (_has_prefix(response) or _has_prefix(tool_input)):
        return payload, None                                         # most calls: no file read
    state = load()
    p = _pending(state)
    if p is None:
        return payload, None
    value = p["value"]
    leak = _holds(tool_input, value)
    if leak:
        res = _result(state)
        res["leak"] = time.time()
        state["result"] = res
        try:
            _save(state)
        except OSError:
            pass
    rx = re.compile(_LEFT + re.escape(value) + _RIGHT)
    found = [0]

    def walk(node):
        if isinstance(node, str):
            if value not in node:
                return node
            new, n = rx.subn(PLACEHOLDER, node)
            found[0] += n
            return new
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {(walk(k) if isinstance(k, str) else k): walk(v) for k, v in node.items()}
        return node
    new = walk(response)
    if not found[0]:
        return payload, None
    return {**payload, "tool_response": new}, {"value": value, "pending": p, "leak": leak}


def answer(payload: dict, result: dict, info: dict, codex: bool) -> dict:
    """The PostToolUse answer with the pending value replaced: the model reads the placeholder, the person the value.
    Records "tool path passed" only for the tool call that registered the value."""
    value, p = info["value"], info["pending"]
    state = load()
    mine = (not info["leak"] and str(payload.get("tool_use_id") or "") == p.get("tool_use_id")
            and str(payload.get("session_id") or "") == p.get("session"))
    if mine:
        res = _result(state)
        res["tool"] = time.time()
        state["result"] = res
        try:
            _save(state)
        except OSError:
            mine = False
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
                _scrub_transcript(path, [value], [])
                _scrub_transcript_later(path, [value], [])
        except Exception:  # noqa: BLE001 - the answer stands; a resumed session could read the test value
            pass
    else:
        hso = dict(result.get("hookSpecificOutput") or {"hookEventName": "PostToolUse"})
        hso.setdefault("updatedToolOutput", masked)
        hso["additionalContext"] = ((hso.get("additionalContext") or "") + " " +
                                    f"maisecrets replaced a self-test value with {PLACEHOLDER}. It is no secret; show "
                                    "the output to the person as it is and do not try to get the value.").strip()
        result["hookSpecificOutput"] = hso
    line = (f"maisecrets self-test: the tool-result hook ran for the self-test command and replaced the test value "
            f"{value} with {PLACEHOLDER} before the AI saw it. Next, type or paste the test value alone as your next "
            "prompt." if mine else
            f"maisecrets replaced the self-test value {value} with {PLACEHOLDER} in this result before the AI saw it "
            "(not the self-test command, so it does not count as a pass).")
    result["systemMessage"] = (result["systemMessage"] + " " + line) if result.get("systemMessage") else line
    return result


# --- UserPromptSubmit ---------------------------------------------------------------------------------------------

def claims(prompt) -> bool:
    """The prompt hook answers this prompt itself (the mod passes it on unchanged): the typed command, or a prompt
    with the pending test value."""
    if not isinstance(prompt, str):
        return False
    if _TYPED_RE.match(prompt):
        return True
    if PREFIX not in prompt:
        return False
    p = _pending(load())
    return p is not None and _word_in(prompt, p["value"])


def _block(reason: str, codex: bool) -> dict:
    if codex:
        return {"decision": "block", "reason": reason}
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


def prompt_answer(payload: dict, codex: bool) -> dict | None:
    """The answer to the typed command or to a prompt with the pending test value; None for every other prompt."""
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
    if p is None or not _word_in(prompt, p["value"]):
        return None                      # not the pending value: the ordinary checks decide
    _scrub(payload, p["value"], prompt)
    from .settings import came_from, typed_by_the_person
    if str(payload.get("session_id") or "") != p.get("session"):
        return _block("maisecrets: this prompt holds the self-test value of another session, so the self-test does "
                      "not count it. This prompt was not sent. Run /maisecrets:status test in this session.", codex)
    if not typed_by_the_person(payload) or "<task-notification>" in prompt:
        return _block(f"maisecrets: this prompt holds the self-test value, but it came from {came_from(payload)}, not "
                      "from you, so the self-test does not count it. This prompt was not sent.", codex)
    res = _result(state)
    res["prompt"] = time.time()
    state["result"] = res
    try:
        _save(state)
    except OSError:
        pass
    if res.get("leak"):
        reason = ("Self-test FAILED: the prompt hook stopped this prompt, but the AI wrote the test value into a tool "
                  "call before, so it had the value. Run /maisecrets:status.")
    elif res.get("tool"):
        reason = "Self-test passed: the prompt hook ran, and the model did not get the value."
    else:
        reason = ("Self-test, prompt path passed: the prompt hook ran, and the model did not get the value in this "
                  "prompt. The tool-result hook did not record the value, so the AI may have read it in the output "
                  "of the command: run /maisecrets:status.")
    if " ".join(prompt.replace(p["value"], " ").split()):
        reason += " The rest of this prompt was not sent either; send it again on its own."
    return _block(reason, codex)


def _scrub(payload: dict, value: str, prompt: str) -> None:
    """The client keeps a blocked prompt in its transcript: the value, and what the rest of the prompt holds."""
    try:
        from .hooks import _scrub_failed_prompt, _scrub_transcript, _scrub_transcript_later
        path = str(payload.get("transcript_path") or "")
        if path:
            _scrub_transcript(path, [value], [])
            _scrub_transcript_later(path, [value], [])
            if " ".join(prompt.replace(value, " ").split()):
                _scrub_failed_prompt("user-prompt", payload)
    except Exception:  # noqa: BLE001 - the block stands either way
        pass


# --- /maisecrets:status -------------------------------------------------------------------------------------------

def verdict(now: float | None = None, sessions: list | None = None, version: str | None = None) -> tuple[str, str]:
    """(state, text) of the self-test line of /maisecrets:status. `ok` only for a pass of this version, in this
    session or within the last 4 hours."""
    from .status_verdict import ago
    now = time.time() if now is None else now
    sessions = sessions_of_this_command() if sessions is None else sessions
    state = load()
    res = _result(state)
    tool, prompt, leak = _num(res.get("tool")), _num(res.get("prompt")), _num(res.get("leak"))
    if leak:
        return "FAIL", (f"self-test: the AI wrote the test value into a tool call {ago(now - leak)}, so it had the "
                        "value. Next: start a new session, then /maisecrets:status test")
    if tool and prompt:
        last = max(tool, prompt)
        current = (version is None or res.get("version") == version) and (
            res.get("session") in sessions or now - last <= FRESH)
        what = (f"the tool-result hook masked the test value in the output of the self-test command {ago(now - tool)}, "
                f"the prompt hook stopped it {ago(now - prompt)}")
        if current:
            return "ok", f"self-test: passed ({what})"
        return "warn", (f"self-test: passed {ago(now - last)}, in another session or version ({what}). "
                        "Next: /maisecrets:status test")
    p = _pending(state, now)
    if tool and p:
        return "warn", (f"self-test: the tool path passed {ago(now - tool)}; the prompt path is not tested yet. "
                        "Next: type or paste the test value alone as your next prompt")
    if prompt and not tool:
        return "FAIL", (f"self-test: the prompt hook stopped the test value {ago(now - prompt)}, but the tool-result "
                        "hook did not mask it in the self-test command. Next: run /reload-plugins or start a new "
                        "session, then /maisecrets:status test")
    if tool:
        return "warn", (f"self-test: only the tool path passed ({ago(now - tool)}); the test value expired before "
                        "a prompt sent it. Next: /maisecrets:status test")
    if p:
        return "FAIL", ("self-test: a test value is pending, and no tool-result hook masked it in the self-test "
                        "command. If the AI read the value, the hook did not run. Next: run /reload-plugins or start "
                        "a new session, then /maisecrets:status test")
    return "warn", "self-test: not run. Next: /maisecrets:status test (Codex: send maisecrets: status test)"
