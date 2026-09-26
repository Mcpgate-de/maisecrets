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
import time
import sys
from typing import Any

from . import detect
from .placeholder import find_refs
from .vault import ConfigError, Vault, load_config

# a Windows path carries a drive letter and backslashes: @C:\Users\x\.env
AT_MENTION_RE = re.compile(r"(?<![\w@])@(?P<path>[\w./~\\:-]+)")


# ---------------------------------------------------------------- helpers --
def client_of(payload: dict) -> str:
    """Which agent sent this payload. The payload shape decides: Claude Code sends `prompt_id`
    on every event, Codex marks turn-scoped events with `turn_id` and every event with `model`.
    The environment is only the fallback for a payload that carries neither: a Claude Code
    started from a shell that exports CODEX_HOME was taken for Codex, which auto-approved its
    Bash commands and answered PostToolUse with a block Claude Code does not apply (review,
    2026-09-26). A Codex payload taken for Claude would answer with updatedToolOutput, which
    Codex ignores: the raw output would reach the model."""
    if "prompt_id" in payload:
        return "claude"
    if "turn_id" in payload or "model" in payload:
        return "codex"
    if any(k.startswith("CODEX_") for k in os.environ):
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
    """Replace every match with its reference, right to left so offsets hold. Keys are minted in
    text order, in one vault transaction; above the per-result cap a value is masked as
    ⟦TYPE⟧ without a key (it is not stored and cannot be resolved)."""
    ordered = sorted(matches, key=lambda x: x.start)
    entries = vault.put_many([(m.value, m.type, m.kind) for m in ordered], session=session)
    out = text
    for m, e in sorted(zip(ordered, entries), key=lambda me: me[0].start, reverse=True):
        out = out[: m.start] + (e.ref if e is not None else f"⟦{m.type}⟧") + out[m.end:]
    return out, [e for e in entries if e is not None]


def _walk_strings(node: Any, fn) -> Any:
    """Apply fn to every string inside a JSON-like structure, keeping the shape."""
    if isinstance(node, str):
        return fn(node)
    if isinstance(node, list):
        return [_walk_strings(x, fn) for x in node]
    if isinstance(node, dict):
        return {k: _walk_strings(v, fn) for k, v in node.items()}
    return node


def _debug(msg: str) -> None:
    """Append a line to $MAISECRETS_DEBUG_LOG when set (harness and troubleshooting); never a value."""
    log = os.environ.get("MAISECRETS_DEBUG_LOG")
    if log:
        try:
            with open(log, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except OSError:
            pass


def _scrub_transcript_later(path: str, values: list[str], refs: list[str], seconds: float = 15.0) -> None:
    """Claude Code 2.1.283 writes the blocked prompt's transcript record AFTER the hook returned
    (measured 2026-09-26: at hook time the transcript file did not exist yet), so a scrub inside
    the hook finds nothing. A detached child polls the file for up to ``seconds`` and scrubs
    it as soon as the raw value appears. Values reach the child on stdin, never as arguments."""
    if not path:
        return
    code = (
        "import json,os,sys,time\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from maisecrets.hooks import _scrub_transcript, _debug\n"
        "spec = json.load(sys.stdin)\n"
        "deadline = time.time() + spec['seconds']\n"
        "while time.time() < deadline:\n"
        "    if _scrub_transcript(spec['path'], spec['values'], spec['refs']):\n"
        "        _debug('scrub-later: done'); break\n"
        "    time.sleep(0.2)\n"
        "else:\n"
        "    _debug('scrub-later: gave up')\n"
    )
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        child = subprocess.Popen([sys.executable, "-c", code, root], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        child.stdin.write(json.dumps({"path": path, "values": values, "refs": refs, "seconds": seconds}).encode())
        child.stdin.close()
    except (OSError, ValueError):
        _debug("scrub-later: could not start")


def _scrub_forms(values: list[str]) -> list[bytes]:
    """Every byte form a value takes in a JSONL transcript: JSON-escaped (with and without
    ASCII escapes for non-ASCII), doubly escaped, and plain; longest first, and the escaped
    forms before the plain one, so a plain replacement cannot eat half of an escape sequence
    (a value ending in a backslash broke the record; review, 2026-09-26)."""
    forms: list[bytes] = []
    for v in values:
        if not v or len(v) < 4 or v.isdigit():
            continue   # a short or all-digit form would mask JSON numbers and unrelated bytes
        esc_a = json.dumps(v)[1:-1]
        esc_u = json.dumps(v, ensure_ascii=False)[1:-1]
        cands = [json.dumps(esc_a)[1:-1], json.dumps(esc_u, ensure_ascii=False)[1:-1], esc_a, esc_u, v]
        for form in cands:
            b = form.encode("utf-8")
            if b and b not in forms:
                forms.append(b)
    forms.sort(key=len, reverse=True)
    return forms


def _scrub_transcript(path: str, values: list[str], refs: list[str]) -> bool:
    """Best effort: overwrite every occurrence of a value in the transcript IN PLACE with a
    mask of the same byte length. Same inode and same mode: a writer that keeps the file open
    keeps writing into it (os.replace lost every later record and turned 0600 into 0644;
    review 2026-09-26). The reference is not written, its length differs; the block notice
    named it. The file is read in chunks with an overlap of the longest form, so a long
    session is scrubbed too (a 50 MB cap skipped it silently before)."""
    try:
        if not path or not os.path.exists(path):
            _debug(f"scrub: skipped, path={'missing' if not path else 'absent'}")
            return False
        forms = _scrub_forms(values)
        if not forms:
            return False
        overlap = max(len(b) for b in forms)
        chunk = 8 * 1024 * 1024
        fd = os.open(path, os.O_RDWR)
        try:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            except ImportError:
                pass
            size = os.fstat(fd).st_size
            hits = 0
            pos = 0
            while pos < size:
                os.lseek(fd, pos, os.SEEK_SET)
                data = os.read(fd, chunk + overlap)
                if not data:
                    break
                # a JSONL record never spans a newline: end the window at the last one, so no
                # escape sequence is cut between two windows (review, 2026-09-26)
                cut = data.rfind(b"\n", 0, chunk) if len(data) > chunk else -1
                if cut > 0:
                    data = data[:cut + 1]
                n_here = 0
                for b in forms:
                    n = data.count(b)
                    if n:
                        n_here += n
                        data = data.replace(b, b"*" * len(b))
                if n_here:
                    hits += n_here
                    os.lseek(fd, pos, os.SEEK_SET)
                    os.write(fd, data)
                pos += len(data)
            if hits:
                os.fsync(fd)
        finally:
            os.close(fd)
        _debug(f"scrub: {os.path.basename(path)} {size} bytes, {hits} value hits")
        return hits > 0
    except OSError:
        return False


def _pending_path(session: str | None):
    from .vault import HOME
    return HOME / "pending" / (f"{session or 'nosession'}.txt")


def _save_pending(rewritten: str, session: str | None) -> None:
    """The rewritten prompt, kept for /maisecrets:send. Over SSH or in Remote Control there is
    no clipboard and no visible notice (field report, 2026-09-26). The file holds placeholders, never
    a value; the prompt text around them is the user's own."""
    try:
        p = _pending_path(session)
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(rewritten)
    except OSError:
        pass


def take_pending(session: str | None = None) -> str | None:
    """Return and delete the pending prompt: the session's own, else the newest one."""
    from .vault import HOME
    d = HOME / "pending"
    cands = []
    if session and _pending_path(session).exists():
        cands = [_pending_path(session)]
    elif d.exists():
        fresh = [c for c in d.glob("*.txt") if time.time() - c.stat().st_mtime < 15 * 60]
        if len(fresh) > 1:
            # two sessions blocked a prompt; without a session id the newest could belong to the
            # other one and its private text would land here (review, 2026-09-26)
            return "(maisecrets: blocked prompts of two sessions are waiting; paste from the clipboard instead)"
        cands = sorted(fresh, key=lambda p: p.stat().st_mtime, reverse=True)[:1]
    cands = [c for c in cands if time.time() - c.stat().st_mtime < 15 * 60]   # a stale prompt is not sent
    if not cands:
        return None
    text = cands[0].read_text(encoding="utf-8")
    try:
        cands[0].unlink()
    except OSError:
        pass
    return text


PRIMER = (
    "maisecrets: a placeholder like ⟦SECRET_c1⟧ or ⟦EMAIL_c2:ma•••@x.de⟧ stands for a value the user "
    "stored locally. Use it unchanged. In a Bash command the value is read when the command runs; in "
    "an MCP tool argument and in the content of Write, Edit, MultiEdit or NotebookEdit it is inserted "
    "at call time. It is NOT resolved in WebFetch or a subagent prompt: there it stays literal text. "
    "In Bash use it as a plain argument, inside '…' or \"…\", "
    "or in an unquoted heredoc; a command with bash -c, sh -c, ssh, eval, backticks, $'…', a quoted heredoc, "
    "base64/xxd/od, ${x:0:4} or set -x is refused, and awk needs V=⟦KEY⟧ awk '… ENVIRON[\"V\"] …'. "
    "Never ask the user for the value, never print, encode or slice it, never read the maisecrets store or "
    "its files, never change its settings. When the user asks for the value in a file or a command, use the "
    "placeholder there as they asked; the hook inserts the value at run time."
)


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
                        "Ask the assistant to read it instead, so the Read result can be redacted."
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
        if typed:
            # the model has never seen the bracket syntax; without this it asks the user for the
            # value, and that value is blocked again (agent review, 2026-09-26)
            return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                           "additionalContext": PRIMER}}
        return {}
    rewritten, entries = _replace(prompt, matches, vault, session)
    copied = _clipboard(rewritten)
    _save_pending(rewritten, session)
    if cfg.get("scrub_transcript", True):
        values, refs = [m.value for m in matches], [e.ref for e in entries]
        # the inline scrub can hit an OLDER record of the same value; the record of this prompt
        # is written after the hook returns, so the delayed child always starts (review, 2026-09-26)
        _scrub_transcript(payload.get("transcript_path", ""), values, refs)
        _scrub_transcript_later(payload.get("transcript_path", ""), values, refs)
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.type] = counts.get(e.type, 0) + 1
    summary = ", ".join(f"{n} {t}" for t, n in counts.items())
    keys = ", ".join(e.key for e in entries)
    where = ("in the clipboard (paste and send), or type /maisecrets:send to send it as is"
             if copied else "saved: type /maisecrets:send to send it as is (clipboard unavailable here)")
    reason = (
        f"maisecrets: {summary} detected and stored as {keys}. "
        f"The prompt did not reach the model. The rewritten prompt is {where}. "
        "A placeholder resolves only in a session where maisecrets is active (the session start "
        "says 'maisecrets <version> active'); elsewhere it stays text."
    )
    if not copied:
        reason += "\n\n" + rewritten
    if vault.backend.test_mode:
        reason += "\n(vault backend: jsonfile, TEST MODE)"
    from . import events
    events.record("UserPromptSubmit", client_of(payload), entries)
    reason += " Wrong? /maisecrets:report prepares an issue without the value."
    if cfg.get("report_url"):
        reason += f" ({cfg['report_url']})"
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
# text matching is a backstop, never the boundary (docs/THREAT-MODEL.md C8); each pattern is
# named so a deny can say what it matched and the user can report a false positive
_STORE_READ_PATTERNS: list[tuple[str, str]] = [
    ("maisecrets get", r"(?<![\w.-])maisecrets(?:\.cli)?(?:\.py)?\s+get\b|(?<![\w-])cli\.py\s+get\b"),
    ("keychain read of the maisecrets service",
     r"security\s+find-generic-password[^\n]*maisecrets|security\s+dump-keychain"),
    ("Credential Locker read", r"PasswordVault[^\n]*maisecrets|maisecrets[^\n]*PasswordVault"),
    ("the vault files", r"vault\.enc\.json|vault\.json[^\n]*maisecrets|maisecrets[^\n]*vault\.json"),
    ("the maisecrets home directory", r"(?i:\.maisecrets)(?![\w-])|MAISECRETS_HOME"),
    ("the value resolver", r"(?<![\w-])hooks[/\\]resolve\.py\b|resolve\.py\s+\S+\s+--grant\b"
                           r"|(?<![\w-])resolve\s+\S+\s+--grant\b|cmd_resolve|\.redeem\("),
    ("a value delivery path", r"maisecrets[/\\]run[/\\]|maisecrets-\d+[/\\]|maisecrets[/\\]v-|__ms_\d+\b"
                              r"|XDG_RUNTIME_DIR[^\n]*maisecrets"),
]
_STORE_READ_RE = re.compile("|".join(f"(?P<p{i}>{rx})" for i, (_n, rx) in enumerate(_STORE_READ_PATTERNS)))


def _store_read_match(command: str) -> str | None:
    """The name of the backstop pattern a command matches, or None."""
    m = _STORE_READ_RE.search(command)
    if not m:
        return None
    for i, (name, _rx) in enumerate(_STORE_READ_PATTERNS):
        if m.group(f"p{i}") is not None:
            return name
    return "store read"


_HEREDOC_RE = re.compile(r"<<(?P<dash>-?)[ \t]*(?P<tag>(?:'[^'\n]*'|\"[^\"\n]*\"|\\[^\s]|[^\s;&|<>()'\"\\])+)")
_REFUSED_CONTEXT = {
    "ansi": "inside $'…' the value would need ANSI-C escaping",
    "backtick": "inside `…` the value would be parsed a second time",
    "hdq": "inside a quoted heredoc nothing expands, the file would get the variable name",
    "hdx": "inside a heredoc that runs a command substitution the placement cannot be proven",
    "arith": "inside $((…)) a value is not a number",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh"}
INLINE_INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "osascript",
                       "deno", "bun"}
INLINE_CODE_FLAGS = re.compile(r"^-(?:[A-Za-z]*[ceE][A-Za-z]*|-eval|-command|-exec)$")
REMOTE_OR_EVAL = {"ssh", "eval", "su", "expect", "script", "sshpass", "plink", "mosh", "screen", "tmux"}
ENCODERS = {"base64", "base32", "xxd", "od", "hexdump", "uuencode", "rev", "b2sum", "cksum"}
WRAPPERS = {"env", "command", "exec", "nice", "time", "nohup", "sudo", "doas", "builtin", "timeout", "stdbuf",
            "caffeinate", "ionice", "chronic"}
_SLICE_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z_0-9]*(?::\s*\d|:\s+-\d|\^|,|//|/|#|%)")


def _shell_contexts(command: str) -> list[str]:
    """One context per character position of a bash command line, as a small state machine
    reads it. Contexts: '' (plain word), 'sq' (inside '…'), 'dq' (inside "…"), 'hd' (body of
    an unquoted heredoc, expands like dq), 'comment', and the ones the rewrite refuses:
    'ansi' ($'…'), 'backtick', 'hdq' (body of a quoted heredoc), 'hdx' (an unquoted heredoc
    body with a command substitution in it), 'arith' ($((…))). A $(…) opens a fresh quoting
    scope on a stack with its own parenthesis depth, so a placeholder inside
    "$(printf '%s' ⟦X⟧)" is placed for the inner single quotes and a `)` of a subshell inside
    does not close the scope (reviews, 2026-09-26)."""
    n = len(command)
    out = [""] * n
    stack: list[str] = [""]          # quoting scope per $( ) level
    depth: list[int] = [0]           # open '(' inside the current $( ) scope
    pending: list[tuple[str, bool]] = []   # heredocs announced on the current line: (tag, quoted)
    i = 0
    while i < n:
        c = command[i]
        st = stack[-1]
        if st == "sq":
            out[i] = "sq"
            if c == "'":
                stack[-1] = ""
            i += 1
            continue
        if st in ("ansi", "backtick"):
            out[i] = st
            if c == "\\":
                if i + 1 < n:
                    out[i + 1] = st
                i += 2
                continue
            if (st == "ansi" and c == "'") or (st == "backtick" and c == "`"):
                if st == "backtick" and len(stack) > 1:
                    stack.pop()
                    depth.pop()
                else:
                    stack[-1] = ""
            i += 1
            continue
        if st == "arith":
            out[i] = "arith"
            if c == "(":
                depth[-1] += 1
            elif c == ")":
                depth[-1] -= 1
                if depth[-1] <= 0:
                    stack.pop()
                    depth.pop()
            i += 1
            continue
        if st == "dq":
            out[i] = "dq"
            if c == "\\":
                if i + 1 < n:
                    out[i + 1] = "dq"
                i += 2
                continue
            if c == '"':
                stack[-1] = ""
                i += 1
                continue
            if c == "$" and command.startswith("$((", i):
                out[i + 1] = out[i + 2] = "arith"
                stack.append("arith")
                depth.append(2)
                i += 3
                continue
            if c == "$" and i + 1 < n and command[i + 1] == "(":
                out[i + 1] = "dq"
                stack.append("")
                depth.append(0)
                i += 2
                continue
            if c == "`":
                out[i] = "backtick"     # a backtick inside "…" starts a substitution too
                stack.append("backtick")
                depth.append(0)
            i += 1
            continue
        # plain
        if c == "\\":
            out[i] = ""
            if i + 1 < n:
                out[i + 1] = ""
            i += 2
            continue
        if c == "\n":
            out[i] = ""
            i += 1
            if pending:
                # heredoc bodies follow, in announcement order, each up to its terminator line
                for tag, quoted, dash in pending:
                    ctx = "hdq" if quoted else "hd"
                    body_start = i
                    while i < n:
                        eol = command.find("\n", i)
                        eol = n if eol < 0 else eol
                        line = command[i:eol].rstrip("\r")
                        probe = line.lstrip("\t") if dash else line
                        if probe == tag:
                            for k in range(i, min(eol + 1, n)):
                                out[k] = ""
                            i = eol + 1
                            break
                        for k in range(i, min(eol + 1, n)):
                            out[k] = ctx
                        i = eol + 1
                    if not quoted:
                        body = command[body_start:i]
                        if "$(" in body or "`" in body:
                            for k in range(body_start, min(i, n)):
                                if out[k] == "hd":
                                    out[k] = "hdx"
                pending = []
            continue
        if c == "#" and (i == 0 or command[i - 1] in " \t\n;&|("):
            eol = command.find("\n", i)
            eol = n if eol < 0 else eol
            for k in range(i, eol):
                out[k] = "comment"
            i = eol
            continue
        if c == "'":
            out[i] = ""
            stack[-1] = "sq"
            i += 1
            continue
        if c == '"':
            out[i] = ""
            stack[-1] = "dq"
            i += 1
            continue
        if c == "$" and i + 1 < n and command[i + 1] == "'":
            out[i] = out[i + 1] = "ansi"
            stack[-1] = "ansi"
            i += 2
            continue
        if c == "$" and command.startswith("$((", i):
            out[i] = out[i + 1] = out[i + 2] = "arith"
            stack.append("arith")
            depth.append(2)
            i += 3
            continue
        if c == "$" and i + 1 < n and command[i + 1] == "(":
            out[i] = out[i + 1] = ""
            stack.append("")
            depth.append(0)
            i += 2
            continue
        if c == "(":
            out[i] = ""
            depth[-1] += 1
            i += 1
            continue
        if c == ")":
            out[i] = ""
            if depth[-1] > 0:
                depth[-1] -= 1
            elif len(stack) > 1:
                stack.pop()
                depth.pop()
            i += 1
            continue
        if c == "`":
            out[i] = "backtick"
            stack.append("backtick")
            depth.append(0)
            i += 1
            continue
        if c == "<" and command.startswith("<<<", i):
            out[i] = out[i + 1] = out[i + 2] = ""      # a here-string is a word, not a heredoc
            i += 3
            continue
        if c == "<" and command.startswith("<<", i):
            m = _HEREDOC_RE.match(command, i)
            if m:
                for k in range(i, m.end()):
                    out[k] = ""
                raw = m.group("tag")
                quoted = any(ch in raw for ch in "'\"\\")
                tag = raw.replace("'", "").replace('"', "").replace("\\", "")
                pending.append((tag, quoted, bool(m.group("dash"))))
                i = m.end()
                continue
        out[i] = ""
        i += 1
    return out


def _quote_state(command: str, pos: int) -> str:
    """Context of the placeholder at ``pos``; see _shell_contexts."""
    ctxs = _shell_contexts(command)
    return ctxs[pos] if pos < len(ctxs) else ""


_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")


def _segments(command: str, ctxs: list[str]) -> list[dict]:
    """The simple commands of a command line, read only in the plain context: text inside
    quotes, comments and heredoc bodies is masked to 'Q' so it never forms a command word
    (`python3 script.py`, a word in a comment and `docker run -e` were taken for a nested
    shell by a substring regex; review, 2026-09-26). Each segment: its words with leading
    assignments and wrappers (env, sudo, nice, …) removed, its command word (basename),
    whether it is fed by a pipe and whether it announces a heredoc."""
    masked = "".join(ch if ctx == "" else ("\n" if ch == "\n" else "Q") for ch, ctx in zip(command, ctxs))
    segs: list[dict] = []
    piped = False
    cur: list[str] = []
    heredoc = False

    def flush(next_piped: bool) -> None:
        nonlocal cur, piped, heredoc
        text = "".join(cur).strip()
        if text:
            segs.append({"text": text, "piped": piped, "heredoc": heredoc})
        cur, piped, heredoc = [], next_piped, False

    i = 0
    while i < len(masked):
        ch = masked[i]
        if masked.startswith("<<", i) and not masked.startswith("<<<", i):
            heredoc = True
        if ch in ";\n()" :
            flush(False)
            i += 1
            continue
        if ch == "|":
            two = masked.startswith("||", i)
            flush(not two)
            i += 2 if two else 1
            continue
        if ch == "&":
            flush(False)
            i += 2 if masked.startswith("&&", i) else 1
            continue
        cur.append(ch)
        i += 1
    flush(False)
    for seg in segs:
        words = seg["text"].split()
        # leading assignments and wrappers
        while words and (_ASSIGN_RE.match(words[0]) or os.path.basename(words[0]) in WRAPPERS):
            w = os.path.basename(words[0])
            words = words[1:]
            if w in ("sudo", "doas", "timeout", "nice", "ionice", "stdbuf", "env"):
                # their own options, with the one argument some take
                while words and words[0].startswith("-"):
                    takes_arg = words[0] in ("-u", "-g", "-h", "-p", "-C", "-n", "-i", "-e", "-o", "-s")
                    words = words[2:] if takes_arg else words[1:]
                if w == "timeout" and words and re.fullmatch(r"[0-9.]+[smhd]?", words[0]):
                    words = words[1:]
        seg["words"] = words
        seg["cmd"] = os.path.basename(words[0]) if words else ""
    return segs


def _refusal_for(command: str, ctxs: list[str]) -> str | None:
    """Why a command that carries placeholders is refused: a shell or an interpreter that would
    parse the value a second time, or a step that would encode, slice or trace it. Command
    words only, so `python3 script.py ⟦K⟧` and `docker run -e T=⟦K⟧ img` pass."""
    plain = "".join(ch if ctx in ("", "dq", "hd") else " " for ch, ctx in zip(command, ctxs))
    for seg in _segments(command, ctxs):
        words, cmd = seg["words"], seg["cmd"]
        if not words:
            continue
        flags = [w for w in words[1:] if w.startswith("-")]
        if cmd in SHELLS:
            if any(INLINE_CODE_FLAGS.match(f) and "c" in f for f in flags) or seg["heredoc"] or seg["piped"]:
                return f"{cmd} would parse the value a second time as shell code"
            if any(re.fullmatch(r"-[A-Za-z]*x[A-Za-z]*", f) for f in flags):
                return f"{cmd} -x would trace the value"
        if cmd in REMOTE_OR_EVAL:
            return f"{cmd} hands the command line to another shell"
        if cmd in INLINE_INTERPRETERS and any(INLINE_CODE_FLAGS.match(f) for f in flags):
            return f"{cmd} with inline code would parse the value as program text"
        if cmd in ENCODERS:
            return f"{cmd} would encode the value"
        if cmd in ("awk", "gawk", "mawk", "nawk") and "-v" in words:
            return "awk -v changes backslashes in the value; use V=⟦KEY⟧ awk '… ENVIRON[\"V\"] …' instead"
        if cmd == "openssl" and len(words) > 1 and words[1] in ("enc", "base64", "dgst"):
            return f"openssl {words[1]} would encode the value"
        if cmd == "set" and any(re.fullmatch(r"-[a-wyz]*x[a-z]*", f) for f in flags):
            return "set -x would trace the value"
        if cmd == "set" and "xtrace" in words:
            return "set -o xtrace would trace the value"
        for w in words[1:]:
            # a shell named later in the segment with its own -c: docker run img sh -c "…"
            if os.path.basename(w) in SHELLS:
                rest = words[words.index(w) + 1:]
                if any(INLINE_CODE_FLAGS.match(r) and "c" in r for r in rest if r.startswith("-")):
                    return f"{os.path.basename(w)} -c would parse the value a second time as shell code"
    if re.search(r"(?<![\w-])PS4=", plain):
        return "a custom PS4 would trace the value"
    m = _SLICE_RE.search(plain)
    if m:
        return f"the parameter expansion {m.group(0)}… would slice or rewrite the value"
    return None


def _resolver_call(key: str, nonce: str) -> str:
    """Windows (Git Bash) only: the command substitution that reads one value under a grant."""
    from pathlib import Path as _P
    py = _P(sys.executable).as_posix()
    script = (_P(__file__).resolve().parent.parent / "hooks" / "resolve.py").as_posix()
    return f'$("{py}" "{script}" {key} --grant {nonce})'


def _serve_value_later(fifo: str, value: str, seconds: float = 120.0) -> bool:
    """Deliver one value once through a FIFO from a detached child. The command runs later, and
    on Codex inside a sandbox that may neither write the vault nor read the keychain (measured:
    resolve.py failed there and the command died); a FIFO in TMPDIR is readable from inside.
    The value lives in the child's memory, never on disk, and is gone after one read or after
    ``seconds``. The value reaches the child on stdin, never as an argument."""
    code = (
        "import json,os,sys,time\n"
        "spec = json.load(sys.stdin)\n"
        "try:\n"
        "    os.mkfifo(spec['fifo'], 0o600)\n"
        "except OSError:\n"
        "    sys.exit(1)\n"
        "deadline = time.time() + spec['seconds']\n"
        "fd = None\n"
        "while time.time() < deadline and fd is None:\n"
        "    try:\n"
        "        fd = os.open(spec['fifo'], os.O_WRONLY | os.O_NONBLOCK)\n"
        "    except OSError:\n"
        "        time.sleep(0.05)\n"
        "if fd is not None:\n"
        "    os.set_blocking(fd, True)\n"
        "    try:\n"
        "        os.write(fd, spec['value'].encode())\n"
        "    finally:\n"
        "        os.close(fd)\n"
        "try:\n"
        "    os.unlink(spec['fifo'])\n"
        "except OSError:\n"
        "    pass\n"
    )
    try:
        child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        child.stdin.write(json.dumps({"fifo": fifo, "value": value, "seconds": seconds}).encode())
        child.stdin.close()
        # the FIFO must exist before the command starts: wait for the child to create it
        for _ in range(100):
            if os.path.exists(fifo):
                return True
            time.sleep(0.01)
        return False
    except (OSError, ValueError):
        return False


def _run_dir() -> str:
    """The directory the value FIFOs live in: $XDG_RUNTIME_DIR/maisecrets when the system offers
    a per-user runtime dir, else <tempdir>/maisecrets-<uid>. Not the vault home: the README asks
    users to deny ~/.maisecrets in the Claude Code sandbox, and the command that reads the FIFO
    runs inside that sandbox (review, 2026-09-26). Not the shared /tmp/maisecrets either: a
    directory another local user created first there would let them swap the FIFO and receive
    the value. The directory is refused unless it is a real directory (no symlink), owned by
    this user, with no group or world bits."""
    import stat as _stat
    import tempfile
    if platform.system() == "Windows":
        # values travel through the resolver script there, never through a FIFO; the directory
        # only serves the sweep and wipe
        base = os.path.join(tempfile.gettempdir(), "maisecrets-" + (os.environ.get("USERNAME") or "user"))
        os.makedirs(base, exist_ok=True)
        return base
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg and os.path.isdir(xdg):
        base = os.path.join(xdg, "maisecrets")
    else:
        base = os.path.join(tempfile.gettempdir(), f"maisecrets-{os.getuid()}")
    try:
        os.mkdir(base, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(base)
    if not _stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or (st.st_mode & 0o077):
        raise RuntimeError(base)
    return base


def _fifo_path(nonce: str) -> str:
    d = _run_dir()
    # a serving child that was killed leaves its FIFO behind; sweep the stale ones
    try:
        for name in os.listdir(d):
            fp = os.path.join(d, name)
            if name.startswith("v-") and time.time() - os.lstat(fp).st_mtime > 300:
                os.unlink(fp)
    except OSError:
        pass
    return os.path.join(d, f"v-{nonce}")


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _updated(payload: dict, new_input: dict) -> dict:
    if client_of(payload) == "codex":
        # Codex accepts updatedInput only together with "allow", and "allow" skips its approval prompt
        # for this call (codex-cli 0.155.1; README "Codex approves nothing here").
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "updatedInput": new_input}}
    # Claude Code: no permissionDecision, the normal permission rules apply to the rewritten input.
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": new_input}}


def _pre_bash(payload: dict, cfg: dict, tool_input: dict) -> dict:
    """Bash: every value is read into a shell variable in the MAIN shell before the command
    runs, and the placeholder becomes that variable in its quoting context. The read fails
    closed for the whole command (``|| exit 97``), also inside pipelines and subshells, where
    a ``kill $$`` behind a substitution did not reach (review, 2026-09-26). The command the
    user approves, the transcript and the tool_use record carry no value. A context the rewrite
    cannot place (a nested shell, a quoted heredoc, $'…', backticks, arithmetic) and a command
    word that would parse, encode, slice or trace the value are refused with the reason. On
    POSIX the value comes through a FIFO in the user's run dir served by a detached child
    (readable from inside Codex's sandbox and from a Claude Code sandbox that denies the vault
    home); no grant is minted there, so nothing is redeemable afterwards. On Windows Git Bash
    the resolver script reads it under a one-time grant. Every key passes the session rule and
    the limiter before anything is recorded or served, so a refused command leaves no audit
    line and no value waiting (reviews, 2026-09-26)."""
    command = tool_input.get("command", "")
    matched = _store_read_match(command)
    if matched:
        return _deny(f"maisecrets: this command touches {matched}, which the agent never reads or changes; "
                     "the human uses the maisecrets CLI for that. The command did not run. If this is a "
                     "false positive, tell the user; do not rephrase the command to get around the check.")
    ctxs = _shell_contexts(command)
    refs = [(k, a, b) for k, a, b in find_refs(command) if ctxs[a] != "comment"]
    if not refs:
        return {}
    keys = ", ".join(f"⟦{k}⟧" for k in dict.fromkeys(k for k, _a, _b in refs))
    windows = platform.system() == "Windows"
    if windows and client_of(payload) == "codex":
        return _deny(f"maisecrets: {keys} cannot be placed in a shell command on Codex for Windows "
                     "(PowerShell quoting is not supported). The command did not run. Use the value "
                     "through an MCP tool, or ask the user to run the command themselves.")
    for k, a, _b in refs:
        why = _REFUSED_CONTEXT.get(ctxs[a])
        if why:
            return _deny(f"maisecrets: ⟦{k}⟧ sits where the value cannot be placed safely: {why}. "
                         "The command did not run. Pass the placeholder as a plain argument of the "
                         "command that needs it.")
    why = _refusal_for(command, ctxs)
    if why:
        return _deny(f"maisecrets: {keys} is refused in this command: {why}. The command did not run. "
                     "Use the placeholder only as a plain argument of the tool that needs the value; "
                     "run a wrapper's inner command directly, and do not encode, slice or trace the value.")
    vault = Vault(cfg)
    session = payload.get("session_id")
    uniq = list(dict.fromkeys(k for k, _a, _b in refs))
    # phase 1: session rule and limiter for every key, before anything is recorded
    failed = [f"{k} ({st})" for k in uniq for st in [vault.status(k, session)] if st != "ok"]
    if failed:
        return _deny(_deny_reason(failed))
    failed = [f"{k} ({st})" for k in uniq for st in [vault._limit(k, session)] if st != "ok"]
    if failed:
        return _deny(_deny_reason(failed))
    # phase 2: record (audit line, limiter) and fetch; a failure here has recorded nothing served
    plan: dict[str, tuple[str | None, str | None]] = {}    # key -> (nonce, value)
    for key in uniq:
        if windows:
            nonce, status = vault.grant(key, session, "Bash", command)
            if status != "ok":
                failed.append(f"{key} ({status})")
                continue
            plan[key] = (nonce, None)
        else:
            status = vault.record_resolve(key, session, "Bash", command)
            if status == "ok":
                value, status = vault.get(key, session)
            if status != "ok":
                failed.append(f"{key} ({status})")
                continue
            plan[key] = (None, value)
    if failed:
        return _deny(_deny_reason(failed))
    # phase 3: serve and rewrite
    prelude: list[str] = []
    var_by_key: dict[str, str] = {}
    served: list[str] = []
    rewritten = command
    for key, (nonce, value) in plan.items():
        var = f"__ms_{len(var_by_key) + 1}"
        var_by_key[key] = var
        if windows:
            read = _resolver_call(key, nonce or "")
        else:
            try:
                fifo = _fifo_path(key_nonce())
            except (OSError, RuntimeError) as exc:
                _unserve(served)
                return _deny(f"maisecrets: the value for ⟦{key}⟧ has no safe place to wait: the run directory "
                             f"{exc} is missing, not private, or not a directory. The command did not run. "
                             "Tell the user to check it; do not retry.")
            if not _serve_value_later(fifo, value or ""):
                _unserve(served)
                return _deny(f"maisecrets: the value for ⟦{key}⟧ could not be prepared for delivery "
                             "(delivery unavailable). The command did not run. Retry once; if this "
                             "message comes again, stop and tell the user.")
            served.append(fifo)
            read = f"$(cat {shlex_quote(fifo)})"
        prelude.append(f'{var}="{read}" || {{ echo "maisecrets: the value for {key} was not delivered '
                       f'(served for 120 s, or read by another process); the command did not run. Run it again '
                       f'once; if it fails again, stop and tell the user" >&2; exit 97; }}')
    for key, start, end in sorted(refs, key=lambda r: r[1], reverse=True):
        var = var_by_key[key]
        ctx = ctxs[start]
        # always braced: ⟦X⟧b inside "…" became $__ms_1b, an empty variable (claims review, 2026-09-26)
        if ctx == "sq":
            piece = "'\"${" + var + "}\"'"
        elif ctx in ("dq", "hd"):
            piece = "${" + var + "}"
        else:
            piece = '"${' + var + '}"'
        rewritten = rewritten[:start] + piece + rewritten[end:]
    new_input = dict(tool_input)
    new_input["command"] = "; ".join(prelude) + "; " + rewritten
    return _updated(payload, new_input)


def key_nonce() -> str:
    import secrets as _secrets
    return _secrets.token_urlsafe(16)


def _unserve(fifos: list[str]) -> None:
    """Take back values already waiting when a later step refuses the command: without the
    FIFO the serving child cannot open it and exits with nothing written."""
    for f in fifos:
        try:
            os.unlink(f)
        except OSError:
            pass


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def _deny_reason(failed: list[str]) -> str:
    """The text the model reads when a placeholder cannot be resolved. Each status names the
    one next step and forbids the wrong ones: guessing another key, asking the user for the
    value, or changing maisecrets settings (review, 2026-09-26)."""
    hints: list[str] = []
    if any("(unknown)" in f for f in failed):
        hints.append("A key marked (unknown) does not exist; do not guess other keys, use only "
                     "placeholders the user gave you.")
    if any("(expired)" in f for f in failed):
        hints.append("A key marked (expired) has no value any more. Ask the user to store it again with "
                     "/maisecrets:put or to paste it into a prompt (maisecrets blocks it and gives a new "
                     "placeholder), then use the new placeholder. Do not ask for the value in any other way.")
    if any("foreign-session" in f or "no-session" in f for f in failed):
        hints.append("A key marked (foreign-session) resolves only in a session where a human typed "
                     "it: ask the user to paste the placeholder, never the value.")
    if any("limit:" in f for f in failed):
        hints.append("The cap is set by the user. Stop and tell the user; do not change maisecrets "
                     "settings yourself.")
    if any("audit" in f for f in failed):
        hints.append("The audit log could not be written, so no value is released. Tell the user.")
    return ("maisecrets: cannot resolve " + ", ".join(failed) + ". The command did not run. "
            + " ".join(hints))


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
    in_keys = [k for k, _a, _b in find_refs(" ".join(_dict_keys(tool_input)))]
    if in_keys:
        return _deny(f"maisecrets: ⟦{in_keys[0]}⟧ is used as a field name, where it is not resolved. "
                     "The call did not run. Put the placeholder into a value, not into a key.")
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
    if cfg.get("scrub_transcript", True):
        # Claude Code writes this hook's stdout (updatedInput, values included) into the transcript
        # as a hook_success attachment (measured 2026-09-26). This hook knows the exact values, so
        # the scrub starts here with them; the fingerprint search in post-tool missed a value
        # with a quote, a comma or fewer than 8 characters (review, 2026-09-26).
        refs = [f"⟦{k}⟧" for k in values]
        _scrub_transcript_later(payload.get("transcript_path", ""), list(values.values()), refs)
    return _updated(payload, _walk_strings(tool_input, substitute))


def _dict_keys(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.append(str(k))
            out.extend(_dict_keys(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_dict_keys(v))
    return out


_FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def _pre_file_tool(payload: dict, cfg: dict, tool: str, tool_input: dict, cwd: str = "") -> dict:
    """Write/Edit/MultiEdit/NotebookEdit: a placeholder in the content is resolved like an MCP
    argument (the value must be inline; the client's permission prompt shows the diff with it),
    under the session rule, the limiter and an audit line that names the file. Writing a value
    into a file on purpose is what the plugin exists for (user decision, 2026-09-26); the first
    version refused it and sent the model to a Bash redirect. The maisecrets home is off limits
    for the agent: a config written by an injected instruction could lift every cap or switch
    the store to plaintext (review, 2026-09-26)."""
    from .vault import HOME
    path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    try:
        expanded = os.path.expanduser(path)
        if expanded and not os.path.isabs(expanded) and cwd:
            expanded = os.path.join(cwd, expanded)   # the client's cwd, not the hook's
        real = os.path.realpath(expanded)
        home = os.path.realpath(str(HOME))
        if platform.system() in ("Darwin", "Windows"):   # case-insensitive file systems (APFS, NTFS)
            real, home = real.lower(), home.lower()
        inside = bool(path) and real.startswith(home + os.sep)
    except (OSError, ValueError):
        inside = False
    if inside or ".maisecrets" in path.lower():
        return _deny(f"maisecrets: {tool} on {path} is refused; the maisecrets home is changed by the human "
                     "only. Nothing was written. Tell the user what you wanted to change there.")
    found: list[str] = []

    def collect(v: str) -> str:
        found.extend(k for k, _a, _b in find_refs(v))
        return v
    _walk_strings(tool_input, collect)
    if not found:
        return {}
    if not cfg.get("resolve_in_files", True):
        names = ", ".join(f"⟦{k}⟧" for k in dict.fromkeys(found))
        return _deny(f"maisecrets: {names} is not resolved in {tool} on this machine (resolve_in_files is off). "
                     "Nothing was written. To put the value into a file, use a Bash command the user approves, "
                     "for example printf '%s' ⟦KEY⟧ > file.")
    vault = Vault(cfg)
    session = payload.get("session_id")
    values: dict[str, str] = {}
    failed: list[str] = []
    for key in dict.fromkeys(found):
        status = vault.record_resolve(key, session, tool, f"{tool} {path}")
        if status == "ok":
            value, status = vault.get(key, session)
        if status != "ok":
            failed.append(f"{key} ({status})")
            continue
        values[key] = value
    if failed:
        return _deny(_deny_reason(failed).replace("The command did not run.", "Nothing was written."))

    def substitute(v: str) -> str:
        out = v
        for key, start, end in sorted(find_refs(v), key=lambda r: r[1], reverse=True):
            out = out[:start] + values[key] + out[end:]
        return out
    if cfg.get("scrub_transcript", True):
        # the client records this hook's updatedInput, values included, in the transcript
        _scrub_transcript_later(payload.get("transcript_path", ""), list(values.values()),
                                [f"⟦{k}⟧" for k in values])
    return _updated(payload, _walk_strings(tool_input, substitute))


def pre_tool(payload: dict) -> dict:
    cfg = load_config()
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if tool == "Bash":
        return _pre_bash(payload, cfg, tool_input)
    if tool in _FILE_TOOLS:
        return _pre_file_tool(payload, cfg, tool, tool_input, str(payload.get("cwd") or ""))
    if tool.startswith("mcp__"):
        # Gateway servers too: the deposit path (gateway resolves ⟦REF⟧ itself, PROTOCOL §4) is not
        # built; until it is, a placeholder that reaches a gateway action is parsed as text
        # (measured 2026-09-26 with gmail_create_draft: the recipient was split at the colon).
        return _pre_mcp(payload, cfg, tool, tool_input)
    return {}


# -------------------------------------------------------------- PostToolUse --
_TOKEN_SPLIT_RE = re.compile(r"[\s\"'`<>()\[\]{},;]+")
_FINE_SPLIT_RE = re.compile(r"[/?&#=:@,;+|\\]")
_EXACT_MIN_LEN = 8


def _candidates(token: str):
    """The token and the pieces a value usually sits in: after KEY=, inside user:pass@host, in
    a URL path or query, without trailing punctuation, JSON-unescaped and URL-decoded. A base64
    value keeps its '=' padding because the split at '=' is a second candidate, not a
    replacement. A value in `?k=<v>&z=1` or `path/<v>/x` reached the model before the fine
    split (review, 2026-09-26)."""
    yield token
    stripped = token.rstrip(".,;:)")
    if stripped != token:
        yield stripped
    if "=" in token:
        yield token.split("=", 1)[1]
    for piece in _FINE_SPLIT_RE.split(token):
        if len(piece) >= _EXACT_MIN_LEN and piece != token:
            yield piece
    if "%" in token:
        from urllib.parse import unquote
        dec = unquote(token)
        if dec != token:
            yield dec
            for piece in _FINE_SPLIT_RE.split(dec):
                if len(piece) >= _EXACT_MIN_LEN and piece != dec:
                    yield piece
    if "\\" in token:
        try:
            dec = json.loads('"' + token + '"')
        except ValueError:
            dec = None
        if dec and dec != token:
            yield dec


def _derived_forms(value: str) -> list[str]:
    """The shapes a value takes after the encodings a command applies on the way out: base64
    (standard and URL-safe, with and without padding), hex, URL-encoded, JSON-escaped. Checked
    as plain substrings for the values this session resolved (review, 2026-09-26: `| base64`
    and `xxd -p` reached the model)."""
    import base64
    from urllib.parse import quote, quote_plus
    raw = value.encode("utf-8")
    forms = [value]
    for f in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
        forms += [f, f.rstrip("=")]
    forms += [raw.hex(), raw.hex().upper(), quote(value, safe=""), quote_plus(value),
              json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]]
    return [f for f in dict.fromkeys(forms) if len(f) >= _EXACT_MIN_LEN]


def _resolved_values(vault: Vault, session: str | None) -> list[tuple[str, str]]:
    """(value, reference) for every key this session resolved in the last hour: a value the hook
    itself inserted into a command or an MCP argument is expected back in the output, in any
    position and any encoding, so it is matched as a substring and not by whole token."""
    now = time.time()
    keys = [r["key"] for r in vault._index.get("resolves", []) if r.get("session") == session and r["ts"] > now - 3600]
    out: list[tuple[str, str]] = []
    from .vault import Entry
    live = [k for k in dict.fromkeys(keys)
            if vault._index["entries"].get(k) and not vault._index["entries"][k].get("purged")]
    if hasattr(vault.backend, "get_many"):
        found = vault.backend.get_many(live)
    else:
        found = {k: v for k in live for v in [vault.backend.get(k)] if v}
    for key in live:
        value = found.get(key)
        if value:
            out.append((value, Entry(**vault._index["entries"][key]).ref))
    return out


def _inserted_values(text: str, vault: Vault) -> list[tuple[str, str]]:
    """(value, reference) for every live vault value that appears in ``text``, found by keyed
    fingerprint of the tokens, so no value is read from the store."""
    live = vault.live_fingerprints()
    if not live:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for token in _TOKEN_SPLIT_RE.split(text):
        for cand in _candidates(token):
            if len(cand) < _EXACT_MIN_LEN or cand in seen:
                continue
            seen.add(cand)
            key = live.get(vault.fingerprint(cand))
            if key is not None:
                from .vault import Entry
                out.append((cand, Entry(**vault._index["entries"][key]).ref))
    return out


def _exact_redact(text: str, vault: Vault, session: str | None, hit: dict, entries: list,
                  resolved: list[tuple[str, str]] | None = None, values: list[str] | None = None) -> str:
    """Values without a known shape (a password stored with `put`, a value from a prior
    prompt) come back from a command in plaintext unless they are matched exactly. The
    match is by keyed fingerprint of each token, so no value is read from the store; the
    values this session itself resolved are matched as substrings in every derived form."""
    out = text
    for value, ref in resolved or []:
        for form in _derived_forms(value):
            if form in out:
                n = out.count(form)
                out = out.replace(form, ref)
                hit["n"] += n
                if values is not None and form not in values:
                    values.append(form)
    live = vault.live_fingerprints()
    if not live:
        return out
    seen: set[str] = set()
    tokens = list(_TOKEN_SPLIT_RE.split(out))
    # a value with spaces or quotes survives no tokenizer; the rest of a KEY=value line does
    for line in out.splitlines():
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
            n = out.count(cand)
            out = out.replace(cand, e.ref)
            hit["n"] += n
            entries.append(e)
            if values is not None and cand not in values:
                values.append(cand)
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
    resolved: list[tuple[str, str]] | None = None

    def redact(s: str) -> str:
        nonlocal vault, resolved
        matches = detect.scan(s)
        if not matches and not _has_live(cfg):
            return s
        if vault is None:
            vault = Vault(cfg)
            resolved = _resolved_values(vault, session)
        out = s
        if matches:
            out, ents = _replace(s, matches, vault, session)
            hit["n"] += len(matches)
            values.extend(m.value for m in matches)
            entries.extend(ents)
        return _exact_redact(out, vault, session, hit, entries, resolved, values)

    new_response = _walk_strings(response, redact)
    if not hit["n"]:
        return {}
    from . import events
    events.record("PostToolUse", client_of(payload), entries)
    refs = [e.ref for e in entries]
    if client_of(payload) == "codex":
        # Codex has no updatedToolOutput. A "block" replaces the model-visible result with the
        # reason text, so the reason IS the redacted output. Measured on codex-cli 0.155.1
        # (2026-09-26): `continue: false` + stopReason let the RAW output reach the model; "block"
        # kept the request clean (the code-mode script sees a rejected promise, which is acceptable).
        # Codex also writes the raw command output into its rollout file before this hook runs
        # (item_completed / CommandExecution), so that file is scrubbed too, with every matched
        # form, not only the detector values (review, 2026-09-26).
        text = new_response if isinstance(new_response, str) else json.dumps(new_response, ensure_ascii=False)
        if cfg.get("scrub_transcript", True):
            path = payload.get("transcript_path", "")
            _scrub_transcript(path, values, refs)
            _scrub_transcript_later(path, values, refs)
        return {"decision": "block",
                "reason": (f"[maisecrets: the command ran and finished; this is not an error. {hit['n']} value(s) "
                           f"in its output are replaced by placeholders. Do not run the command again; continue "
                           f"with the placeholders as they are, they are valid references.]\n{text}")}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": new_response,
            "additionalContext": (
                f"maisecrets redacted {hit['n']} value(s) in this tool result. The tool ran and finished; "
                "do not run it again to see the values. Use the ⟦TYPE_cN⟧ placeholders as they are: in a Bash "
                "command, an MCP argument or the content of Write/Edit they are resolved at run time."
            ),
        }
    }


_live_cache: dict = {}


def _has_live(cfg: dict) -> bool:
    """Cheap pre-check from the index file: any live entry at all? (no backend read)"""
    if "v" not in _live_cache:
        from .vault import INDEX
        try:
            idx = json.loads(INDEX.read_text(encoding="utf-8"))
            _live_cache["v"] = any(not m.get("purged") for m in idx.get("entries", {}).values())
        except (OSError, ValueError):
            _live_cache["v"] = False
    return _live_cache["v"]


def _post_tool_guarded(payload: dict) -> dict:
    """Claude Code ignores exit 2 from PostToolUse: the raw output would reach the model. So a
    failure inside the redaction withholds the output instead (review, 2026-09-26)."""
    try:
        return post_tool(payload)
    except ConfigError as exc:
        return _fail_closed("post-tool", payload, f"configuration error: {exc}. Fix the file named there.", hint=False)
    except Exception as exc:  # noqa: BLE001
        _debug(f"post-tool: {type(exc).__name__}")
        return _fail_closed("post-tool", payload, f"failed ({type(exc).__name__}).")


HANDLERS = {"user-prompt": user_prompt, "pre-tool": pre_tool, "post-tool": _post_tool_guarded}


# under the timeouts hooks/hooks.json gives each event (10 s prompt and pre-tool, 20 s post-tool);
# a client timeout fails OPEN, so the answer must come first
WATCHDOG_SECONDS = {"user-prompt": 7.0, "pre-tool": 7.0, "post-tool": 16.0}


def _fail_closed(event: str, payload: dict, why: str, hint: bool = True) -> dict:
    """The answer that keeps the guard up when the hook itself cannot finish: block the prompt,
    deny the tool, withhold the tool output. Never a value, never an exception text (a keychain
    error carried the value in its argument list; Codex review, 2026-09-26). Each text says
    whether the tool ran, so the model does not repeat a push or a deploy (review, 2026-09-26)."""
    reason = f"maisecrets {event}: {why}"
    codex = client_of(payload) == "codex"
    if event == "user-prompt":
        tail = (" The prompt was not sent; try again. If this message comes again, tell the user that "
                "maisecrets cannot finish (a locked store or a slow disk)." if hint
                else " The prompt was not sent. Tell the user; do not retry.")
        out = {"decision": "block", "reason": reason + tail}
        if not codex:
            out["hookSpecificOutput"] = {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}
        return out
    if event == "pre-tool":
        tail = (" The command did NOT run. Retry once; if this message comes again, stop and tell the user "
                "that maisecrets cannot reach its store." if hint
                else " The command did NOT run. Tell the user; do not retry.")
        return _deny(reason + tail)
    tail = (" The tool ran and finished; its output is withheld because the redaction did not finish. "
            "Do NOT run it again to see the output; tell the user to check the result in their terminal.")
    if codex:
        return {"decision": "block", "reason": reason + tail}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": f"[{reason}{tail}]"}}


def _decision_of(event: str, obj: dict) -> str:
    """One word for the run log: what the hook answered, never why."""
    if not obj:
        return "pass"
    if obj.get("decision") == "block":
        return "block"
    hso = obj.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision") == "deny":
        return "deny"
    if "updatedInput" in hso:
        return "rewrite"
    if "updatedToolOutput" in hso:
        return "redact"
    if "additionalContext" in hso:
        return "context"
    return "answer"


def _run_log(event: str, payload: dict, how: str, decision: str, ms: int) -> None:
    """One line per hook run in ~/.maisecrets/hooks.log: time, event, client, session, tool,
    decision, duration, how it ended. Never a value, never a command. Without it a silent pass
    cannot be told from a hook that did not run (field report, 2026-09-26: a placeholder went
    unchanged into a file and no record said whether the hook ran). Capped at 2000 lines."""
    try:
        from .vault import HOME, atomic_write
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = HOME / "hooks.log"
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
        tool = str(payload.get("tool_name", "-"))[:40]
        sess = str(payload.get("session_id") or "-")[:8]
        line = f"{stamp}\t{event}\t{client_of(payload)}\t{sess}\t{tool}\t{decision}\t{ms}ms\t{how}\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
        if path.stat().st_size > 2000 * 100:
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > 2000:
                atomic_write(path, "\n".join(lines[-2000:]) + "\n")
    except OSError:
        pass


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in HANDLERS:
        sys.stderr.write("usage: dispatch.py user-prompt|pre-tool|post-tool|session-start\n")
        return 2
    event = argv[1]
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.stderr.write("maisecrets: bad payload\n")
        if event == "post-tool":
            # exit 2 is ignored here and the raw output would reach the model
            _out(_fail_closed("post-tool", {}, "got a payload that is not JSON."))
            return 0
        return 2  # fail closed
    import threading
    started = time.time()
    lock = threading.Lock()
    answered = {"v": False}

    def answer(obj: dict, how: str) -> None:
        # exactly one JSON object leaves this process: the watchdog and the handler both call
        # here, and two concatenated objects fail open (review, 2026-09-26)
        with lock:
            if answered["v"]:
                return
            answered["v"] = True
            _out(obj)
        ms = int((time.time() - started) * 1000)
        decision = _decision_of(event, obj)
        _debug(f"{event}: {how} {client_of(payload)} {ms}ms {decision}")
        _run_log(event, payload, how, decision, ms)

    def on_timeout() -> None:
        answer(_fail_closed(event, payload, f"took longer than {WATCHDOG_SECONDS[event]:.0f}s."), "watchdog")
        os._exit(0)
    watchdog = threading.Timer(WATCHDOG_SECONDS[event], on_timeout)
    watchdog.daemon = True
    watchdog.start()
    try:
        answer(HANDLERS[event](payload), "ok")
        return 0
    except ConfigError as exc:
        # the policy file is wrong: fail closed, and say which key (its message never carries
        # a value; a bare type name sent the user to "a locked store"; review, 2026-09-26)
        answer(_fail_closed(event, payload, f"configuration error: {exc}. Fix the file named there.", hint=False),
               "config-error")
        return 0
    except Exception as exc:  # noqa: BLE001 - a guard that fails open is no guard
        # the type only: an exception message may carry a value (subprocess errors list the argv)
        answer(_fail_closed(event, payload, f"failed ({type(exc).__name__})."), f"failed {type(exc).__name__}")
        return 0
    finally:
        watchdog.cancel()
