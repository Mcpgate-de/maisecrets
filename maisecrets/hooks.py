"""Hook handlers for Claude Code (and, with an adapter, Codex).

Every handler reads one JSON payload from stdin and prints one JSON object.
It never prints a value. It fails closed: an error inside a handler blocks
the action it guards, and says so.

Events:
  user-prompt  UserPromptSubmit  -> block + store + clipboard on a hit
  pre-tool     PreToolUse        -> rehydrate ⟦REF⟧ in Bash commands
  post-tool    PostToolUse       -> redact tool results before the model sees them
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
from typing import Any

from . import detect
from .placeholder import find_refs
from .vault import Vault, load_config

# a Windows path carries a drive letter and backslashes: @C:\Users\x\.env
AT_MENTION_RE = re.compile(r"(?<![\w@])@(?P<path>[\w./~\\:-]+)")


# ---------------------------------------------------------------- helpers --
def client_of(payload: dict) -> str:
    """Which agent sent this payload. Codex marks turn-scoped events with `turn_id` and
    every event with `model`; Claude Code sends `prompt_id`/`effort` and neither of those."""
    if "turn_id" in payload or ("model" in payload and "prompt_id" not in payload):
        return "codex"
    return "claude"


def _out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _clipboard(text: str) -> bool:
    try:
        sysname = platform.system()
        if sysname == "Darwin":
            cmd = ["pbcopy"]
        elif sysname == "Windows":
            cmd = ["clip"]
        else:
            cmd = ["xclip", "-selection", "clipboard"]
        subprocess.run(cmd, input=text.encode(), check=True, timeout=3)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _clipboard_read() -> str:
    try:
        sysname = platform.system()
        if sysname == "Darwin":
            cmd = ["pbpaste"]
        elif sysname == "Windows":
            cmd = ["powershell", "-command", "Get-Clipboard"]
        else:
            cmd = ["xclip", "-selection", "clipboard", "-o"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _replace(text: str, matches: list[detect.Match], vault: Vault, session: str | None) -> tuple[str, list]:
    """Replace every match with its reference, right to left so offsets hold."""
    entries = []
    out = text
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        e = vault.put(m.value, m.type, m.kind, session=session)
        entries.append(e)
        out = out[: m.start] + e.ref + out[m.end:]
    return out, list(reversed(entries))


def _walk_strings(node: Any, fn) -> Any:
    """Apply fn to every string inside a JSON-like structure, keeping the shape."""
    if isinstance(node, str):
        return fn(node)
    if isinstance(node, list):
        return [_walk_strings(x, fn) for x in node]
    if isinstance(node, dict):
        return {k: _walk_strings(v, fn) for k, v in node.items()}
    return node


def _scrub_transcript(path: str, values: list[str], refs: list[str]) -> bool:
    """Best effort: rewrite the transcript lines that carry the raw prompt.

    Claude Code writes the prompt as a queue-operation record before the
    UserPromptSubmit hook runs (measured 2026-09-26), so a blocked prompt is
    already on disk. Replacing it here is the only way to keep the value out
    of ~/.claude/projects.
    """
    try:
        if not path or not os.path.exists(path) or os.path.getsize(path) > 50 * 1024 * 1024:
            return False
        with open(path, encoding="utf-8") as f:
            data = f.read()
        changed = data
        for v, r in zip(values, refs):
            changed = changed.replace(json.dumps(v)[1:-1], json.dumps(r)[1:-1])
        if changed == data:
            return False
        tmp = path + ".maisecrets.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(changed)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


# --------------------------------------------------------- UserPromptSubmit --
def user_prompt(payload: dict) -> dict:
    cfg = load_config()
    prompt = payload.get("prompt", "")
    session = payload.get("session_id")

    # 1. @file mentions inline the file OUTSIDE the hook pipeline. Force a Read.
    if cfg.get("block_at_mentions", True):
        for m in AT_MENTION_RE.finditer(prompt):
            p = os.path.expanduser(m.group("path")).rstrip(".,;:)")
            if os.path.exists(p) or os.path.exists(os.path.join(payload.get("cwd", ""), p)):
                return {
                    "decision": "block",
                    "reason": (
                        f"maisecrets: @{m.group('path')} would inline the file without scanning. "
                        "Ask Claude to read it instead, so the Read result can be redacted."
                    ),
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
                }

    # 2. references the human typed or pasted: this session may resolve them from now on
    typed = find_refs(prompt)
    matches = detect.scan(prompt)
    if typed or matches:
        vault = Vault(cfg)
        for key, _s, _e in typed:
            vault.admit(key, session)
    if not matches:
        return {}
    rewritten, entries = _replace(prompt, matches, vault, session)
    copied = _clipboard(rewritten)
    if cfg.get("scrub_transcript", True):
        _scrub_transcript(payload.get("transcript_path", ""), [m.value for m in matches], [e.ref for e in entries])
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.type] = counts.get(e.type, 0) + 1
    summary = ", ".join(f"{n} {t}" for t, n in counts.items())
    keys = ", ".join(e.key for e in entries)
    where = "in the clipboard: paste and send again" if copied else "below (clipboard unavailable)"
    reason = (
        f"maisecrets: {summary} detected and stored as {keys}. "
        f"The prompt did not reach the model. The rewritten prompt is {where}."
    )
    if not copied:
        reason += "\n\n" + rewritten
    if vault.backend.test_mode:
        reason += "\n(vault backend: jsonfile, TEST MODE)"
    if cfg.get("report_url"):
        reason += f" Wrong? Report it: {cfg['report_url']}"
    if client_of(payload) == "codex":
        return {"decision": "block", "reason": reason}
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    }


# --------------------------------------------------------------- PreToolUse --
# Reads of the store by the agent itself. The value is for the command a human approved,
# not for the agent's context. Text matching, so a backstop and not a boundary; the
# boundary is the grant (a reference resolves only through a nonce this hook minted).
_STORE_READ_RE = re.compile(
    r"(maisecrets(\.cli)?(\.py)?\s+get\b)|(cli\.py\s+get\b)"
    r"|(security\s+(find-generic-password|dump-keychain)[^\n]*maisecrets)"
    r"|(PasswordVault)|(vault\.enc\.json)|(\.maisecrets[/\\](vault|key|index))",
)


def _quote_state(command: str, pos: int) -> str:
    """Bash quoting context at ``pos``: 'sq' inside single quotes, 'dq' inside double quotes, '' outside."""
    sq = dq = False
    i = 0
    while i < pos:
        c = command[i]
        if c == "\\" and not sq:
            i += 2
            continue
        if c == "'" and not dq:
            sq = not sq
        elif c == '"' and not sq:
            dq = not dq
        i += 1
    return "sq" if sq else "dq" if dq else ""


def _resolver_call(key: str, nonce: str) -> str:
    """The command substitution that reads one value under a one-time grant."""
    from pathlib import Path as _P
    py = _P(sys.executable).as_posix()
    script = (_P(__file__).resolve().parent.parent / "hooks" / "resolve.py").as_posix()
    return f'$("{py}" "{script}" {key} --grant {nonce})'


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _updated(payload: dict, new_input: dict) -> dict:
    if client_of(payload) == "codex":
        # Codex accepts updatedInput only together with "allow"; its own approval policy still applies.
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "updatedInput": new_input}}
    # Claude Code: no permissionDecision, the normal permission rules apply to the rewritten input.
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": new_input}}


def _pre_bash(payload: dict, cfg: dict, tool_input: dict) -> dict:
    """Bash: every reference becomes ``$(resolve KEY --grant NONCE)`` in the right quoting
    context. The value is read by the command itself at run time, so the command the user
    approves, the transcript and the tool_use record carry no value, and no value is ever
    spliced into shell syntax (a value with quotes or ``$(`` would otherwise become code)."""
    command = tool_input.get("command", "")
    if _STORE_READ_RE.search(command):
        return _deny("maisecrets: the vault is read by the human (maisecrets get) or by a granted command, "
                     "not by the agent. Use the ⟦REF⟧ placeholder in the command instead.")
    refs = find_refs(command)
    if not refs:
        return {}
    vault = Vault(cfg)
    session = payload.get("session_id")
    failed: list[str] = []
    rewritten = command
    for key, start, end in sorted(refs, key=lambda r: r[1], reverse=True):
        nonce, status = vault.grant(key, session, "Bash", command)
        if status != "ok":
            failed.append(f"{key} ({status})")
            continue
        call = _resolver_call(key, nonce)
        ctx = _quote_state(command, start)
        piece = "'\"" + call + "\"'" if ctx == "sq" else call if ctx == "dq" else '"' + call + '"'
        rewritten = rewritten[:start] + piece + rewritten[end:]
    if failed:
        return _deny(_deny_reason(failed))
    new_input = dict(tool_input)
    new_input["command"] = rewritten
    return _updated(payload, new_input)


def _deny_reason(failed: list[str]) -> str:
    hint = ""
    if any("foreign-session" in f or "no-session" in f for f in failed):
        hint = (" A reference resolves only in a session where a human typed it: paste the "
                "⟦REF⟧ into a prompt to allow it here.")
    if any("limit:" in f for f in failed):
        hint += " Raise the cap in ~/.maisecrets/config.json if this is intended."
    return "maisecrets: cannot run, placeholder not resolvable: " + ", ".join(failed) + hint


def _pre_mcp(payload: dict, cfg: dict, tool: str, tool_input: dict) -> dict:
    """MCP tools: the value must be in the argument (there is no shell to read it later), so it
    is inserted after the session rule and the limiter. The permission prompt of the client then
    shows the value; this is the user's own value at the point where the real call happens."""
    found: list[str] = []

    def collect(s: str) -> str:
        found.extend(k for k, _a, _b in find_refs(s))
        return s
    _walk_strings(tool_input, collect)
    if not found:
        return {}
    vault = Vault(cfg)
    session = payload.get("session_id")
    context = json.dumps(tool_input, ensure_ascii=False)
    values: dict[str, str] = {}
    failed: list[str] = []
    for key in dict.fromkeys(found):
        status = vault.record_resolve(key, session, tool, context)
        if status == "ok":
            value, status = vault.get(key, session)
        if status != "ok":
            failed.append(f"{key} ({status})")
            continue
        values[key] = value
    if failed:
        return _deny(_deny_reason(failed))

    def substitute(s: str) -> str:
        out = s
        for key, start, end in sorted(find_refs(s), key=lambda r: r[1], reverse=True):
            out = out[:start] + values[key] + out[end:]
        return out
    return _updated(payload, _walk_strings(tool_input, substitute))


def pre_tool(payload: dict) -> dict:
    cfg = load_config()
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if tool == "Bash":
        return _pre_bash(payload, cfg, tool_input)
    if tool.startswith("mcp__"):
        # Gateway servers too: the deposit path (gateway resolves ⟦REF⟧ itself, PROTOCOL §4) is not
        # built; until it is, a placeholder that reaches a gateway action is parsed as text
        # (measured 2026-09-26 with gmail_create_draft: the recipient was split at the colon).
        return _pre_mcp(payload, cfg, tool, tool_input)
    return {}


# -------------------------------------------------------------- PostToolUse --
_TOKEN_SPLIT_RE = re.compile(r"[\s\"'`<>()\[\]{},;]+")
_EXACT_MIN_LEN = 8


def _candidates(token: str):
    """The token and the pieces a value usually sits in: after KEY=, inside user:pass@host,
    without trailing punctuation. A base64 value keeps its '=' padding because the split
    at '=' is a second candidate, not a replacement."""
    yield token
    stripped = token.rstrip(".,;:)")
    if stripped != token:
        yield stripped
    if "=" in token:
        yield token.split("=", 1)[1]
    if ":" in token or "@" in token:
        for piece in re.split(r"[:@]", token):
            if len(piece) >= _EXACT_MIN_LEN:
                yield piece


def _exact_redact(text: str, vault: Vault, session: str | None, hit: dict, entries: list) -> str:
    """Values without a known shape (a password stored with `put`, a value from a prior
    prompt) come back from a command in plaintext unless they are matched exactly. The
    match is by keyed fingerprint of each token, so no value is read from the store."""
    live = vault.live_fingerprints()
    if not live:
        return text
    out = text
    seen: set[str] = set()
    tokens = list(_TOKEN_SPLIT_RE.split(text))
    # a value with spaces or quotes survives no tokenizer; the rest of a KEY=value line does
    for line in text.splitlines():
        line = line.strip()
        tokens.append(line)
        for sep in ("=", ":"):
            if sep in line:
                tokens.append(line.split(sep, 1)[1].strip())
    for token in tokens:
        if len(token) < _EXACT_MIN_LEN:
            continue
        for cand in _candidates(token):
            if len(cand) < _EXACT_MIN_LEN or cand in seen:
                continue
            seen.add(cand)
            key = live.get(vault.fingerprint(cand))
            if key is None:
                continue
            vault.admit(key, session)
            from .vault import Entry
            e = Entry(**vault._index["entries"][key])
            out = out.replace(cand, e.ref)
            hit["n"] += out.count(e.ref)
            entries.append(e)
    return out


def post_tool(payload: dict) -> dict:
    cfg = load_config()
    response = payload.get("tool_response")
    if response is None:
        return {}
    session = payload.get("session_id")
    vault: Vault | None = None
    hit = {"n": 0}
    values: list[str] = []
    entries: list = []

    def redact(s: str) -> str:
        nonlocal vault
        matches = detect.scan(s)
        if not matches and not _has_live(cfg):
            return s
        if vault is None:
            vault = Vault(cfg)
        out = s
        if matches:
            out, ents = _replace(s, matches, vault, session)
            hit["n"] += len(matches)
            values.extend(m.value for m in matches)
            entries.extend(ents)
        return _exact_redact(out, vault, session, hit, entries)

    new_response = _walk_strings(response, redact)
    if not hit["n"]:
        return {}
    if client_of(payload) == "codex":
        # Codex has no updatedToolOutput. A "block" replaces the model-visible result with the
        # reason text, so the reason IS the redacted output. Measured on codex-cli 0.155.1
        # (2026-09-26): `continue: false` + stopReason let the RAW output reach the model; "block"
        # kept the request clean (the code-mode script sees a rejected promise, which is acceptable).
        # Codex also writes the raw command output into its rollout file before this hook runs
        # (item_completed / CommandExecution), so that file is scrubbed too.
        text = new_response if isinstance(new_response, str) else json.dumps(new_response, ensure_ascii=False)
        if cfg.get("scrub_transcript", True):
            _scrub_transcript(payload.get("transcript_path", ""), values, [e.ref for e in entries])
        return {"decision": "block",
                "reason": f"[maisecrets redacted {hit['n']} value(s); placeholders are references]\n{text}"}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": new_response,
            "additionalContext": (
                f"maisecrets redacted {hit['n']} value(s) in this tool result; "
                "use the ⟦REF⟧ placeholders as-is."
            ),
        }
    }


_live_cache: dict = {}


def _has_live(cfg: dict) -> bool:
    """Cheap pre-check from the index file: any live entry at all? (no backend read)"""
    if "v" not in _live_cache:
        from .vault import INDEX
        try:
            idx = json.loads(INDEX.read_text())
            _live_cache["v"] = any(not m.get("purged") for m in idx.get("entries", {}).values())
        except (OSError, ValueError):
            _live_cache["v"] = False
    return _live_cache["v"]


HANDLERS = {"user-prompt": user_prompt, "pre-tool": pre_tool, "post-tool": post_tool}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in HANDLERS:
        sys.stderr.write("usage: hook.py user-prompt|pre-tool|post-tool\n")
        return 2
    event = argv[1]
    try:
        payload = json.load(sys.stdin)
    except ValueError as exc:
        sys.stderr.write(f"maisecrets: bad payload: {exc}\n")
        return 2  # fail closed
    try:
        _out(HANDLERS[event](payload))
        return 0
    except Exception as exc:  # noqa: BLE001 - a guard that fails open is no guard
        sys.stderr.write(f"maisecrets {event}: {type(exc).__name__}: {exc}\n")
        return 2
