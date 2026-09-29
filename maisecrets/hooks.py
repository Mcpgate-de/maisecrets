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

from . import detect, rehydration
from .placeholder import find_refs
from .vault import ConfigError, Vault, load_config

# a Windows path carries a drive letter and backslashes: @C:\Users\x\.env
AT_MENTION_RE = re.compile(r"(?<![\w@])@(?P<path>[\w./~\\:-]+)")


# ---------------------------------------------------------------- helpers --
def _client_label(payload: dict) -> str:
    """The client, plus the entry point when the host names one: the Claude desktop app starts
    Cowork sessions with CLAUDE_CODE_ENTRYPOINT=local-agent (read from its bundle, 2026-09-27),
    so a hooks.log line can tell a Cowork run from a terminal run."""
    client = client_of(payload)
    entry = os.environ.get("CLAUDE_CODE_ENTRYPOINT", "")
    return f"{client}/{entry}" if client == "claude" and entry and entry != "cli" else client


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
        data = text.encode()
        if sysname == "Darwin":
            cmd = ["pbcopy"]
        elif sysname == "Windows":
            # clip.exe reads UTF-8 bytes in the console code page, and each bracket of ⟦KEY⟧
            # became three characters. It takes UTF-16 as Unicode; with a byte order mark it keeps
            # the mark in the clipboard (windows-latest, 2026-09-27), so none is sent
            cmd, data = ["clip"], text.encode("utf-16-le")
        else:
            cmd = ["xclip", "-selection", "clipboard"]
        subprocess.run(cmd, input=data, check=True, timeout=3)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _clipboard_read() -> str:
    try:
        sysname = platform.system()
        if sysname == "Darwin":
            cmd = ["pbpaste"]
        elif sysname == "Windows":
            # PowerShell writes in the console code page unless told otherwise; the value is read
            # as UTF-8 so a character outside that page survives. [Text.Encoding]::UTF8 writes a
            # byte order mark first (windows-latest, 2026-09-27); this encoder does not
            cmd = ["powershell", "-NoProfile", "-Command",
                   "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; Get-Clipboard -Raw"]
        else:
            cmd = ["xclip", "-selection", "clipboard", "-o"]
        return subprocess.run(cmd, capture_output=True, timeout=3, check=True).stdout.decode("utf-8", "replace")
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


def _json_string_spans(line: bytes) -> list[tuple[int, int]]:
    """The byte spans of the string contents in one JSON line, escapes skipped."""
    spans, i, n = [], 0, len(line)
    while i < n:
        if line[i] == 0x22:                       # a quote opens a string
            j = i + 1
            while j < n and line[j] != 0x22:
                j += 2 if line[j] == 0x5C else 1  # a backslash escapes the next byte
            spans.append((i + 1, min(j, n)))
            i = j + 1
        else:
            i += 1
    return spans


def _mask_digits_in_strings(data: bytes, digits: list[bytes]) -> tuple[bytes, int]:
    """Mask a value that is only digits where it sits inside a JSON string and no other digit stands next
    to it. A JSON number, a longer digit run and the four hex digits of a \\u escape stay untouched.
    Plain replacement skipped every all-digit value, so a detected tax ID stayed in the transcript
    (external review, 2026-09-28)."""
    buf, hits = bytearray(data), 0
    start = 0
    while start < len(buf):
        end = buf.find(b"\n", start)
        end = len(buf) if end < 0 else end
        line = bytes(buf[start:end])
        if any(d in line for d in digits):
            for a, b in _json_string_spans(line):
                for d in digits:
                    k = line.find(d, a, b)
                    while k >= 0:
                        before = line[k - 1:k]
                        after = line[k + len(d):k + len(d) + 1]
                        esc = line.rfind(b"\\u", max(a, k - 5), k)
                        if not before.isdigit() and not after.isdigit() and not (esc >= 0 and k - esc <= 5):
                            buf[start + k:start + k + len(d)] = b"*" * len(d)
                            hits += 1
                        k = line.find(d, k + len(d), b)
        start = end + 1
    return bytes(buf), hits


def _scrub_digits_by_line(fd: int, digits: list[bytes]) -> int:
    """The all-digit pass, one whole JSONL line at a time, however long: inside an 8 MiB window a record
    that started in the previous window had no opening quote, and a value after it stayed (Codex review,
    2026-09-28). A changed line is written back at its own offset."""
    hits, pos, buf = 0, 0, b""
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        data = os.read(fd, 1 << 20)
        buf += data
        while True:
            nl = buf.find(b"\n")
            if nl < 0 and data:
                break
            line = buf if nl < 0 else buf[:nl]
            if line and any(d in line for d in digits):
                masked, n = _mask_digits_in_strings(line, digits)
                if n:
                    here = os.lseek(fd, 0, os.SEEK_CUR)      # os.pwrite is POSIX only (Windows has none)
                    os.lseek(fd, pos, os.SEEK_SET)
                    os.write(fd, masked)
                    os.lseek(fd, here, os.SEEK_SET)
                    hits += n
            if nl < 0:
                return hits
            pos += nl + 1
            buf = buf[nl + 1:]


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
        digits = sorted({v.encode() for v in values if v and v.isdigit() and len(v) >= 6}, key=len, reverse=True)
        if not forms and not digits:
            return False
        overlap = max((len(b) for b in forms), default=0)
        chunk = 8 * 1024 * 1024
        # binary on Windows: text mode turns \r\n into \n on read, and the in-place write lands at the wrong
        # offset (the GitHub Windows runner, 2026-09-28: the scrubbed records were no longer valid JSON)
        fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
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
            if digits:
                hits += _scrub_digits_by_line(fd, digits)
            if hits:
                os.fsync(fd)
        finally:
            os.close(fd)
        _debug(f"scrub: {os.path.basename(path)} {size} bytes, {hits} value hits")
        return hits > 0
    except OSError:
        return False


_SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


def _pending_path(session: str | None):
    """The session id becomes a file name: only its own shape, never a path (Codex review, 2026-09-28)."""
    from .vault import HOME
    name = session if session and _SESSION_ID_RE.fullmatch(session) else "nosession"
    return HOME / "pending" / f"{name}.txt"


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
    """Return and delete the pending prompt. With a session id, that session's own and nothing else:
    another session's prompt holds another conversation's text. Without one (a client that names no
    session to a command), the only fresh prompt, and a notice when two sessions wait."""
    from .vault import HOME
    d = HOME / "pending"
    cands = []
    if session:
        own = _pending_path(session)
        cands = [own] if own.exists() and _SESSION_ID_RE.fullmatch(session) else []
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
    # Written as what to do, not as a list of what is refused: a primer of prohibitions next to an
    # ordinary ops request (base64, sudo) read like an attempt to get around a control, and a model
    # safeguard paused the session (field report on 0.5.8, 2026-09-28)
    "maisecrets: a placeholder like ⟦SECRET_c1⟧ or ⟦EMAIL_c2:ma•••@x.de⟧ stands for a value the user "
    "stored on this computer. Use the placeholder unchanged where the value belongs; maisecrets puts the "
    "value in when the call runs. In an MCP tool argument and in the content of Write, Edit, MultiEdit or "
    "NotebookEdit it goes in at call time; WebFetch and a subagent prompt keep it as plain text. In Bash, "
    "give it as a plain argument, inside '…' or \"…\", or in an unquoted heredoc; the shell reads the value "
    "when the command runs. For awk, pass it as V=⟦KEY⟧ awk '… ENVIRON[\"V\"] …'. To give a value to a "
    "remote host, pipe it on stdin to the command that reads it, for example "
    "printf '%s' ⟦KEY⟧ | ssh host 'sudo zgrep -F -f - /var/log/app.log' (inside the Claude Code sandbox, "
    "one host per command). A form that would run the value as code or change it "
    "(a nested shell, eval, backticks, $'…', a quoted heredoc, an encoder, a slice, set -x) gets an answer "
    "that names a form that works. The value stays with the user: to use it, use the placeholder; the user "
    "manages the stored values and the settings. When the user asks for the value in a file or a command, "
    "put the placeholder there as they asked."
)


# --------------------------------------------------------- UserPromptSubmit --
TYPE_WORDS = {"SECRET": ("secret", "secrets"), "EMAIL": ("e-mail address", "e-mail addresses"),
              "IBAN": ("IBAN", "IBANs"), "CARD": ("card number", "card numbers"),
              "PHONE": ("phone number", "phone numbers"), "IP": ("IP address", "IP addresses")}
STORE_NAMES = {"KeychainBackend": "the macOS Keychain", "WindowsVaultBackend": "the Windows Credential Locker",
               "EncryptedFileBackend": "an encrypted file in ~/.maisecrets",
               "JsonFileBackend": "a PLAIN TEXT test file"}
NOTICE_PREVIEW = 400


def _hours(seconds: int) -> str:
    if seconds % 86400 == 0 and seconds >= 86400:
        n = seconds // 86400
        return f"{n} day" + ("s" if n != 1 else "")
    n = max(1, round(seconds / 3600))
    return f"{n} hour" + ("s" if n != 1 else "")


def _paste_key() -> str:
    return "⌘V" if platform.system() == "Darwin" else "Ctrl+V"


def block_notice(entries: list, rewritten: str, copied: bool, codex: bool, cfg: dict, vault) -> list[str]:
    """What a person reads when a prompt is blocked, and nothing more: what kind of thing was
    found, that the AI did not get it, and the one next step, set apart by blank lines because
    the clients show plain text. The count, the masked forms and the retention are in
    /maisecrets:list; the report link is built by /maisecrets:report (review with the product
    owner, 2026-09-27: the user does not need to know whether it was 1 e-mail or 13)."""
    kinds = {e.type for e in entries}
    # a value this session resolved matches without an entry of its own; it was stored as a secret
    secret = "SECRET" in kinds or not kinds
    personal = bool(kinds - {"SECRET"})
    what = ("a secret and personal data were" if secret and personal
            else "a secret was" if secret else "personal data was")
    lines = [f"maisecrets: {what} found and kept from the AI.", ""]
    if copied:
        tail = " Then send it." if codex else " Then send it, or type /ms to send it at once."
        lines.append(f"    {_paste_key()}  pastes the cleaned prompt.{tail}")
    elif codex:
        lines += ["    Copy the cleaned prompt from here and send it:", "", "    " + rewritten]
    else:
        lines += ["    Type /ms to send the cleaned prompt, or copy it from here:", "", "    " + rewritten]
    lines.append("")
    if codex:
        lines.append("maisecrets by mcpgate.de")
    else:
        lines.append("Something wrong? /maisecrets:report · maisecrets by mcpgate.de")
    return lines


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
    vault = None
    if typed or matches or _has_live(cfg):
        vault = Vault(cfg)
        for key, _s, _e in typed:
            vault.admit(key, session)
    rewritten, entries = _replace(prompt, matches, vault, session) if matches else (prompt, [])
    values = [m.value for m in matches]
    stored = {"n": 0}
    if vault is not None and _has_live(cfg):
        # a value the store already holds has a known shape: its fingerprint. Without this a stored
        # password typed again, or a value without a detector shape next to a detected one, went to
        # the model (invariant I1, 2026-09-28). Values this session resolved match as substrings
        # from 8 characters; a shorter one would block ordinary words in a prompt.
        resolved = [(v, r) for v, r in _resolved_values(vault, session) if len(v) >= _EXACT_MIN_LEN]
        rewritten = _exact_redact(rewritten, vault, session, stored, entries, resolved, values)
    if not matches and not stored["n"]:
        if typed:
            # the model has never seen the bracket syntax; without this it asks the user for the
            # value, and that value is blocked again (agent review, 2026-09-26)
            return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                           "additionalContext": PRIMER}}
        return {}
    copied = _clipboard(rewritten)
    _save_pending(rewritten, session)
    if cfg.get("scrub_transcript", True):
        refs = [e.ref for e in entries] + [r for v, r in _resolved_values(vault, session) if v in values]
        # the inline scrub can hit an OLDER record of the same value; the record of this prompt
        # is written after the hook returns, so the delayed child always starts (review, 2026-09-26)
        _scrub_transcript(payload.get("transcript_path", ""), values, refs)
        _scrub_transcript_later(payload.get("transcript_path", ""), values, refs)
    codex = client_of(payload) == "codex"
    lines = block_notice(entries, rewritten, copied, codex, cfg, vault)
    from . import events
    events.record("UserPromptSubmit", client_of(payload), entries)
    reason = "\n".join(lines)
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
    ("the ssh approval store", r"ssh-approvals|ssh_approval"),
    # the guard outside the plugin folder: `--off` in its refusal is for the person, not the agent
    ("the maisecrets guard", r"maisecrets-guard\.py"),     # guard.json sits in the home, covered above
    ("a value delivery path", r"maisecrets[/\\]run[/\\]|maisecrets-\d+[/\\]|maisecrets[/\\](?:v-|sealed)|__ms_\d+\b"
                              r"|XDG_RUNTIME_DIR[^\n]*maisecrets"),
]
_STORE_READ_RE = re.compile("|".join(f"(?P<p{i}>{rx})" for i, (_n, rx) in enumerate(_STORE_READ_PATTERNS)))


def _store_read_match(command: str) -> str | None:
    """The name of the backstop pattern a command matches, or None."""
    for d in _store_dir_spellings():
        # a home set by environment variable has no `.maisecrets` in its name (invariant I3, 2026-09-28)
        if re.search(re.escape(d) + r"(?![\w.-])", command):
            return "the maisecrets home directory"
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
# commands that run other commands with arguments they build from their input
ARG_RUNNERS = {"xargs", "parallel", "watch", "flock", "chroot", "nsenter", "unshare", "setsid", "runuser",
               "strace", "ltrace", "gdb", "script", "busybox", "systemd-run", "toybox"}
# variables that name the ssh command another tool runs
_SSH_VAR_RE = re.compile(r"(?<![\w])(?:GIT_SSH_COMMAND|GIT_SSH|RSYNC_RSH|CVS_RSH)=")
# a variable in front of a fixed path is a known command word: "$HOME/bin/tool", ${REPO}/bin/x
_FIXED_TAIL_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z_0-9]*\}?(?:/[^/$`\s]+)+$")
# arguments that name stdin as the file to run
_STDIN_FILES = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
# clients that read statements from stdin when no statement is given
_SQL_CLIENTS = {"mysql", "mariadb", "psql", "sqlite3", "mongo", "mongosh", "redis-cli", "clickhouse-client"}
ENCODERS = {"base64", "base32", "xxd", "od", "hexdump", "uuencode", "rev", "b2sum", "cksum"}
SHELL_KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "case",
                  "esac", "coproc", "function", "select", "in"}
# the options of a wrapper that take the next word as their argument; every other option takes none
# a part that feeds its input to a later shell, a group closer with a redirection, and trace settings
# from outside the shell's own words (reviews of 0.5.4, 2026-09-28)
_EXEC_RE = re.compile(r"^(?:(?:command|builtin)\s+)*exec\b")
_CLOSER_RE = re.compile(r"^(?:(?:\}|\)|done|fi|esac)(?![A-Za-z0-9_])|\d*<)")   # `( bash )<f` leaves `<f`
_TRACE_RE = re.compile(
    r"(?:^|[\s;&|(])(?:SHELLOPTS|BASHOPTS)="                                     # an assignment
    r"|(?:^|[\s;&|(])(?:export|declare|typeset|readonly)\b[^;&|\n]*\b(?:SHELLOPTS|BASHOPTS)\b"
    r"|(?:^|[\s;&|(])set\b[^;&|\n]*\s[-+]o\s+(?:xtrace|verbose)\b"             # set … -o xtrace
    r"|(?:^|[\s;&|(])set\b[^;&|\n]*\s-[A-Za-z]*[xv][A-Za-z]*(?=\s|$|[;&|])"      # set … -x / -v
    r"|(?:^|[\s;&|(])shopt\b[^;&|\n]*\b(?:xtrace|verbose)\b")
ENVS = {"env", "genv"}


def _env_splits(args: list[str]) -> bool:
    """Whether env, given these words after its name, builds its command from a string (-S,
    --split-string or a prefix of it such as --sp). -u, -C and -P take an argument: in `-uS` the S
    is a variable name. Real words, so `/usr/bin/env '-S'` and `\\env -S` count (review, 2026-09-28)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--" or not a.startswith("-") or a == "-":
            return False
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if len(name) > 2 and "--split-string".startswith(name):
                return True
            i += 2 if name in ("--unset", "--chdir") and "=" not in a else 1
            continue
        for j, letter in enumerate(a[1:], 1):
            if letter == "S":
                return True
            if letter in "uCP":
                i += 1 if a[j + 1:] else 2
                break
        else:
            i += 1
    return False


WRAPPER_ARG_OPTIONS = {
    "env": ("-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-P"),
    "sudo": ("-u", "-g", "-h", "-p", "-C", "-U", "-T", "-r", "-t", "-D", "--user", "--group", "--host"),
    "doas": ("-u", "-C"),
    "timeout": ("-s", "--signal", "-k", "--kill-after"),
    "nice": ("-n", "--adjustment"),
    "ionice": ("-c", "-n", "-p", "--class", "--classdata"),
    "stdbuf": ("-i", "-o", "-e"),
    "exec": ("-a",),
    "time": ("-f", "-o", "--format", "--output"),
    "caffeinate": ("-t", "-w"),
    "command": (),
}
WRAPPERS = {"env", "genv", "command", "exec", "nice", "time", "nohup", "sudo", "doas", "builtin", "timeout", "stdbuf",
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
# a redirection word: group 1 is a target glued to the operator
_REDIR_RE = re.compile(r"^(?:\d+|&)?(?:<<<|<<-?|<>|<&|>&|>>|>\||<|>)(.*)$")


def _segments(command: str, ctxs: list[str]) -> list[dict]:
    """The simple commands of a command line, read only in the plain context: text inside
    quotes, comments and heredoc bodies is masked to 'Q' so it never forms a command word
    (`python3 script.py`, a word in a comment and `docker run -e` were taken for a nested
    shell by a substring regex; review, 2026-09-26). Each segment: its words with leading
    assignments and wrappers (env, sudo, nice, …) removed, its command word (basename),
    whether it is fed by a pipe and whether it announces a heredoc."""
    # a backslash before a newline continues the line: `bash \<newline>-c '…'` is `bash -c '…'`, and a
    # split there hid -c from every rule (review, 2026-09-28). Two spaces keep every offset.
    command = re.sub(r"(?<!\\)((?:\\\\)*)\\\n", lambda m: m.group(0) if ctxs[m.end() - 2] not in ("", "dq")
                     else m.group(1) + "  ", command)
    masked = "".join(ch if ctx == "" else ("\n" if ch == "\n" else "Q") for ch, ctx in zip(command, ctxs))
    segs: list[dict] = []
    piped = False
    cur: list[str] = []
    heredoc = False
    start = 0                       # offset of the first character of the current segment

    def flush(next_piped: bool) -> None:
        nonlocal cur, piped, heredoc
        text = "".join(cur).strip()
        if text:
            segs.append({"text": text, "piped": piped, "heredoc": heredoc, "start": start, "end": i})
        cur, piped, heredoc = [], next_piped, False

    i = 0
    while i < len(masked):
        ch = masked[i]
        if not cur:
            start = i
        if masked.startswith("<<", i) and not masked.startswith("<<<", i):
            heredoc = True
        if ch in ";\n()" :
            flush(False)
            i += 1
            continue
        if ch == "|":
            two = masked.startswith("||", i)
            flush(not two)
            # |& pipes stderr as well: still a pipe (final review, 2026-09-28)
            i += 2 if two or masked.startswith("|&", i) else 1
            continue
        if ch == "&" and not ((i and masked[i - 1] in "<>") or masked.startswith("&>", i)):
            # a redirection is no separator: 2>&1, <&3, &>file (the ask showed "2>" for 2>&1)
            flush(False)
            i += 2 if masked.startswith("&&", i) else 1
            continue
        cur.append(ch)
        i += 1
    flush(False)
    import shlex as _shlex
    for seg in segs:
        words = seg["text"].split()
        # the real words, with quotes and backslashes removed as the shell removes them: `\ssh`,
        # `s''sh` and `b''ash '-c'` were not recognised and passed every rule on command words
        # (review, 2026-09-27). A heredoc body line is all 'Q' in the masked text and keeps its mask.
        if set(seg["text"]) - set("Q \t"):
            try:
                words = _shlex.split(command[seg["start"]:seg["end"]]) or words
            except ValueError:
                pass
        # leading assignments, shell keywords and wrappers: the command word is behind them. `{ ssh …; }`,
        # `if …; then ssh …`, `! ssh` and `env -i ssh` hid ssh from every rule (security review, 2026-09-28)
        while words and (_ASSIGN_RE.match(words[0]) or words[0] in SHELL_KEYWORDS or _REDIR_RE.match(words[0])
                         or os.path.basename(words[0]) in WRAPPERS):
            m = _REDIR_RE.match(words[0])
            if m:
                # a redirection before the command word, with its target glued on or as the next word
                # (Codex review, 2026-09-28)
                words = words[1:] if m.group(1) else words[2:]
                continue
            w = os.path.basename(words[0])
            words = words[1:]
            if w in ENVS and _env_splits(words):
                seg["env_split"] = True
            if w == "case":
                # `case WORD in`: the word is matched, not run
                words = words[words.index("in") + 1:] if "in" in words else []
                continue
            if w == "function" and words:
                # `function f { base64; }`: the name is not the command word (review, 2026-09-28)
                words = words[1:]
                continue
            if w in SHELL_KEYWORDS or _ASSIGN_RE.match(w):
                continue
            takes = WRAPPER_ARG_OPTIONS.get(w, ())
            while words and words[0].startswith("-") and words[0] != "-":
                opt = words[0]
                words = words[2:] if opt in takes else words[1:]
            if w == "timeout" and words and re.fullmatch(r"[0-9.]+[smhd]?", words[0]):
                words = words[1:]
        seg["words"] = words
        seg["cmd"] = os.path.basename(words[0]) if words else ""
    return segs


_REF_RE = re.compile(r"⟦[^⟦⟧]*⟧")


def _value_reaches(command: str, ctxs: list[str], segs: list[dict]) -> list[bool]:
    """Which parts of the command can read the value: a part that holds it, and a part fed by a
    pipe after one that holds it. The encoder rule asks this, so that base64 on a remote script
    next to `printf ⟦K⟧ | ssh` is not refused (feedback on 0.5.2, 2026-09-28). A value that can come
    back anywhere else makes every part a reader: a variable, a file, a heredoc, a process
    substitution, a function, an alias, read or mapfile."""
    refs = [m.start() for m in _REF_RE.finditer(command)]
    held = [any(sg["start"] <= r < sg["end"] for r in refs) for sg in segs]
    masked = "".join(ch if ctx == "" else "Q" for ch, ctx in zip(command, ctxs))
    everywhere = bool(refs) and (
        any(sg["heredoc"] for sg in segs) or "<(" in masked or ">(" in masked
        or re.search(r"\(\s*\)|(?:^|[\s;&|({])(?:function|alias|read|mapfile|readarray|tee|source|\.)(?:\s|$)",
                     masked)
        or any(h and re.search(r"[<>]", masked[sg["start"]:sg["end"]]) for h, sg in zip(held, segs)))
    if not everywhere:
        # an assignment keeps the value for later parts: X=⟦K⟧, export X=⟦K⟧, X=$(printf ⟦K⟧)
        for m in re.finditer(r"(?:^|[\s;&|({])[A-Za-z_][A-Za-z_0-9]*\+?=", masked):
            end, depth = m.end(), 0
            while end < len(masked) and (depth or not masked[end].isspace()) and (depth or masked[end] not in ";&|"):
                depth += masked[end] == "("
                depth -= masked[end] == ")" and depth > 0
                end += 1
            if any(m.end() <= r < end for r in refs):
                everywhere = True
                break
    if everywhere:
        return [True] * len(segs)
    reach: list[bool] = []
    for k, sg in enumerate(segs):
        reach.append(held[k] or (sg["piped"] and any(held[:k])))
    return reach


def _refusal_for(command: str, ctxs: list[str]) -> str | None:
    """Why a command that carries placeholders is refused: a shell or an interpreter that would
    parse the value a second time, or a step that would encode, slice or trace it. Command
    words only, so `python3 script.py ⟦K⟧` and `docker run -e T=⟦K⟧ img` pass."""
    plain = "".join(ch if ctx in ("", "dq", "hd") else " " for ch, ctx in zip(command, ctxs))
    unquoted = "".join(ch if ctx == "" else " " for ch, ctx in zip(command, ctxs))
    if "ansi" in ctxs or any(ch == "$" and ctx == "" and command[i + 1:i + 2] == '"'
                             for i, (ch, ctx) in enumerate(zip(command, ctxs))):
        # the rewrite refuses a value inside $'…'; a command word in it is hidden as well (Codex review, 2026-09-28)
        return "$'…' quoting hides the command words from the check"
    segs = _segments(command, ctxs)
    reach = _value_reaches(command, ctxs, segs)
    for seg, reached in zip(segs, reach):
        words, cmd = seg["words"], seg["cmd"]
        if seg.get("env_split") or (cmd in ARG_RUNNERS and any(
                os.path.basename(w) in ENVS and _env_splits(words[k + 1:]) for k, w in enumerate(words))):
            # env -S builds its command from a string: the command word is hidden (final review, 2026-09-28)
            return "env -S builds the command from a string, so its command word cannot be checked"
        if not words:
            continue
        flags = [w for w in words[1:] if w.startswith("-")]
        if cmd in ("watch", "parallel") and not (cmd == "watch" and any(f in ("-x", "--exec") for f in flags)):
            return f"{cmd} runs its command through sh -c, which would parse the value a second time"
        if cmd in ARG_RUNNERS or (cmd == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in words)):
            inner = next((os.path.basename(w) for w in words[1:] if os.path.basename(w) in
                          SHELLS | REMOTE_OR_EVAL | INLINE_INTERPRETERS | {"scp", "sftp", "autossh", "rsync"}), None)
            if inner:
                return f"{cmd} would hand the value to {inner} as an argument"
        if cmd in SHELLS:
            # input that reaches the shell: a redirection in its own part, an `exec <…` before it, or a
            # redirection on a group around it (`{ bash; } <…`, `( bash ) <…`) (Codex review, 2026-09-28).
            # A `<` of another command, such as `mysql … < dump.sql && bash post.sh`, does not count
            # (final review of 0.5.4).
            redirected = "<" in unquoted[seg["start"]:seg["end"]] or any(
                "<" in unquoted[sg["start"]:sg["end"]] and (
                    (_EXEC_RE.match(sg["text"]) and sg["start"] < seg["start"])
                    or (sg["start"] > seg["start"] and (not sg["words"] or _CLOSER_RE.match(sg["text"]))))
                for sg in segs)
            if any(INLINE_CODE_FLAGS.match(f) and "c" in f for f in flags) or seg["heredoc"] or seg["piped"] \
                    or redirected:
                # input from a redirection or a process substitution is read as code too (Codex review, 2026-09-28)
                return f"{cmd} would parse the value a second time as shell code"
            if any(re.fullmatch(r"[-+][A-Za-z]*[xv][A-Za-z]*", f) for f in flags) or \
                    any(w in ("xtrace", "verbose", "--xtrace", "--verbose", "--debugger") for w in words[1:]) or \
                    _TRACE_RE.search(unquoted):
                # a trace from elsewhere: SHELLOPTS=… or BASHOPTS=…, or set -o xtrace / set -x before the
                # shell (Codex review, 2026-09-28). The word verbose in another command does not count
                # (final review of 0.5.4).
                return f"{cmd} with tracing would print the value"
        if cmd in REMOTE_OR_EVAL:
            return f"{cmd} hands the command line to another shell"
        if cmd in (".", "source") and (seg["piped"] or seg["heredoc"] or any(w in _STDIN_FILES for w in words[1:])):
            return f"{cmd} would run the value as shell code"
        if cmd in INLINE_INTERPRETERS and any(INLINE_CODE_FLAGS.match(f) for f in flags):
            return f"{cmd} with inline code would parse the value as program text"
        if cmd in ENCODERS and reached:
            return f"{cmd} would encode the value"
        if cmd in ("awk", "gawk", "mawk", "nawk") and "-v" in words:
            return "awk -v changes backslashes in the value; use V=⟦KEY⟧ awk '… ENVIRON[\"V\"] …' instead"
        if cmd == "openssl" and reached and len(words) > 1 and words[1] in ("enc", "base64", "dgst"):
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
    # ssh in another form, in the parts of the command that carry a value or are piped with one: scp, sftp,
    # autossh or mosh as the command; rsync with a remote shell and the value in its own arguments; a
    # variable that names an ssh command (GIT_SSH_COMMAND, RSYNC_RSH, …) or git -c core.sshCommand anywhere.
    # A word that only mentions ssh (ansible -c ssh, a path ending in /rsync) does not count (final
    # review and differential test against 0.5.2, 2026-09-28)
    segs = _segments(command, ctxs)
    offsets = [a for _k, a, _b in find_refs(command) if ctxs[a] != "comment"]
    if offsets and _SSH_VAR_RE.search(plain):
        return "a variable that names an ssh command would hand the value to ssh in a form that cannot be checked"
    with_value = {n for n, sg in enumerate(segs) if any(sg["start"] <= a < sg["end"] for a in offsets)}
    related = set(with_value)
    for n in sorted(with_value):
        k = n
        while k > 0 and segs[k]["piped"]:
            k -= 1
            related.add(k)
        k = n + 1
        while k < len(segs) and segs[k]["piped"]:
            related.add(k)
            k += 1
    for n in sorted(related):
        sg = segs[n]
        words = sg["words"]
        if sg["cmd"] in ("scp", "sftp", "autossh", "mosh"):
            return (f"{sg['cmd']} hands its arguments to a remote shell; "
                    "a value reaches ssh only as printf '%s' ⟦KEY⟧ | ssh host '…'")
        if sg["cmd"] == "git" and any(w.lower().startswith("core.sshcommand=") for w in words):
            return "git -c core.sshCommand would hand the value to ssh in a form that cannot be checked"
        if sg["cmd"] == "rsync" and n in with_value:
            remote_spec = any(re.match(r"^(?:[^\s/@:]+@)?[\w.-]+:(?!//)", w) for w in words[1:])
            rsh = any(w in ("-e", "--rsh") or w.startswith(("--rsh=", "-e")) for w in words[1:])
            if remote_spec or rsh:
                return "rsync over ssh hands its arguments to a remote shell; pass the value another way"
    m = _SLICE_RE.search(plain)
    if m:
        return f"the parameter expansion {m.group(0)}… would slice or rewrite the value"
    return None


# ssh options that take an argument (OpenSSH 9)
_SSH_ARG_FLAGS = set("BbcDEeFIiJLlmOoPpQRSWw")
# flags and -o options that pick another route, share a connection, change the destination or run a
# local command: the route sets its own, and the user must read the real destination
_SSH_REFUSED_FLAGS = set("JWSMOF")
_SSH_REFUSED_OPTIONS = ("proxycommand", "proxyjump", "proxyusefdpass", "controlmaster", "controlpath",
                        "controlpersist", "hostname", "localcommand", "permitlocalcommand", "knownhostscommand",
                        "remotecommand", "include", "tunnel")


def _ssh_options(toks: list[str], i: int, opts: list) -> int:
    """Read ssh options from toks[i:] into opts as (flag, value); return the index after them."""
    while i < len(toks) and toks[i].startswith("-") and toks[i] != "--" and toks[i] != "-":
        letters, i, took_next = toks[i][1:], i + 1, False
        for n, c in enumerate(letters):
            if c in _SSH_ARG_FLAGS:
                val = letters[n + 1:]
                if not val and i < len(toks):
                    val, took_next = toks[i], True
                opts.append((c, val))
                break
            opts.append((c, None))
        if took_next:
            i += 1
    return i


def _ssh_way(why: str) -> str:
    """The form that works for what the refused remote command wanted to do. The answer names a way,
    not only the rule: an ops user needs root-only logs, and "the remote su would hand the value to
    another shell" left no way forward (field report on 0.5.8, 2026-09-28)."""
    base = ("To give a value to a remote host, pipe it on stdin to the command that reads it, inside the "
            "Claude Code sandbox, one host per command: printf '%s' ⟦KEY⟧ | ssh HOST 'zgrep -F -f - FILE'.")
    # the second hop first: its reason names "another shell or host" too
    if re.search(r"\bremote (?:ssh|sshpass|plink|mosh|autossh|scp|sftp|rsync)\b|\bjump\b|\bproxy\b", why):
        return "For a host behind another host, run one ssh command per host. " + base
    if re.search(r"\b(?:su|sudo|login shell|shell|wrapper)\b", why):
        return ("To read a file only root can read, put sudo in front of the command that reads it, not su "
                "or a shell: printf '%s' ⟦KEY⟧ | ssh HOST 'sudo zgrep -F -f - FILE'. " + base)
    if "encoded" in why:
        return ("Keep the encoder out of the remote command that gets the value; a script can go as the "
                "command's own text instead of through base64. " + base)
    return base


def _remote_refusal(remote: str) -> str | None:
    """Why the remote command would run the value as code, pass it on, or show it encoded. The
    value arrives on its stdin, so a command that reads data there is fine (grep -F -f -, cat > f,
    sh -c 'grep …'); one that reads its program there, or hands the value to another shell or
    host, is not (edge-case review, 2026-09-27: only the first word was checked)."""
    if not remote.strip():
        return "the remote login shell would run the value as shell code; name the command that reads it"
    rctx = _shell_contexts(remote)
    for seg in _segments(remote, rctx):
        words, cmd = seg["words"], seg["cmd"]
        if not words:
            if seg["text"].strip():
                # only a wrapper and its options: sudo -s, sudo -i, env starts a login shell on stdin
                return "the remote wrapper would start a shell that reads the value as shell code"
            continue
        # a redirection glued to the command word: bash</dev/stdin
        cmd = os.path.basename(re.split(r"[<>]", words[0])[0]) or cmd
        if re.search(r"<\s*/dev/(?:stdin|fd/0)", seg["text"]) and cmd in SHELLS | INLINE_INTERPRETERS:
            return f"the remote {cmd} would read the value as its program"
        flags = [w for w in words[1:] if w.startswith("-")]
        args = [w for w in words[1:] if not w.startswith("-") or w == "-"]
        if cmd in ("source", ".") and (not args or args[0] in _STDIN_FILES):
            return "the remote shell would run the value as shell code"
        if cmd in ("crontab", "at", "batch"):
            return f"the remote {cmd} would store the value as code that runs later"
        query_flags = ("-e", "-c", "--execute", "--command", "--eval", "-f", "--file")
        if cmd in _SQL_CLIENTS and not any(f.split("=", 1)[0] in query_flags for f in flags):
            return f"the remote {cmd} would read the value as statements; give the query with -e or -c"
        if cmd == "openssl" and args and args[0] in ("enc", "base64", "dgst"):
            return f"the remote openssl {args[0]} would send the value back encoded"
        if cmd in SHELLS | INLINE_INTERPRETERS and args and args[0] in _STDIN_FILES:
            return f"the remote {cmd} would read the value as its program"
        if "$" in words[0] or "`" in words[0]:
            return "the remote command word is built from a variable and is only known when it runs"
        if cmd in REMOTE_OR_EVAL:
            return f"the remote {cmd} would hand the value to another shell or host"
        if cmd in ENCODERS:
            return (f"the remote {cmd} could send the value back encoded, where the output redaction "
                    "cannot see it")
        if cmd in SHELLS and ("-s" in flags or not any(INLINE_CODE_FLAGS.match(f) and "c" in f for f in flags)):
            return f"the remote {cmd} would read the value as shell code"
        if cmd in SHELLS:
            code = next((words[n + 1] for n, w in enumerate(words[:-1]) if INLINE_CODE_FLAGS.match(w) and "c" in w), "")
            inner = _remote_refusal(code) if code else None
            if inner:
                return inner
        if cmd in INLINE_INTERPRETERS and not [w for w in words[1:] if w != "-" and not w.startswith("-")] \
                and not any(INLINE_CODE_FLAGS.match(f) for f in flags):
            return f"the remote {cmd} would read the value as its program"
        if cmd in ARG_RUNNERS or (cmd == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in words)):
            inner = next((os.path.basename(w) for w in words[1:] if os.path.basename(w) in
                          SHELLS | REMOTE_OR_EVAL | INLINE_INTERPRETERS | {"scp", "sftp", "autossh", "rsync"}),
                         None)
            if inner:
                return f"the remote {cmd} would hand the value to {inner}"
    return None


# remote commands that only read and print: the session approval covers these alone (ssh_approval.py)
READ_ONLY_REMOTE = {"grep", "egrep", "fgrep", "zgrep", "zegrep", "zfgrep", "xzgrep", "bzgrep", "rg", "cat", "zcat",
                    "xzcat", "bzcat", "head", "tail", "journalctl", "wc", "sort", "uniq", "cut", "tr", "jq",
                    "ls", "stat", "uptime", "df", "du", "true"}
# journalctl options that change state or write a file; getopt takes an unambiguous prefix, so a
# prefix of one of these counts too (Codex review, 2026-09-28: --rotate and --vacuum-time passed)
_JOURNALCTL_STATEFUL = ("--rotate", "--vacuum-size", "--vacuum-files", "--vacuum-time", "--flush", "--sync",
                        "--relinquish-var", "--smart-relinquish-var", "--setup-keys", "--update-catalog",
                        "--cursor-file", "--force", "--interval", "--verify-key", "--new-id128",
                        "--synchronize-on-exit")


# wrappers the session approval allows in front of a read-only command, with no option of their own
_READ_ONLY_WRAPPERS = {"sudo", "nice", "command"}
# the only options of sort and uniq the session approval allows: none of them writes a file or runs a
# program (Codex review, 2026-09-28: `sort --out=FILE`, an abbreviation, wrote the value to a file)
_SORT_OK = re.compile(r"^(?:-[bdfghinrsuMV]+|-k\S*|-t\S?|--(?:numeric-sort|reverse|unique|ignore-case|"
                      r"human-numeric-sort|version-sort|month-sort|general-numeric-sort|ignore-leading-blanks|"
                      r"dictionary-order|stable))$")
_UNIQ_OK = re.compile(r"^(?:-[cdiuz]+|-[fsw]\d*|\d+|--(?:count|repeated|unique|ignore-case))$")


def _remote_is_read_only(remote: str) -> bool:
    """Whether every part of the remote command only reads and prints. Each part is a bare command
    word from READ_ONLY_REMOTE, at most behind sudo (or sudo -n), nice or command without other options: no path, no
    assignment such as PATH=, since a command named grep in /tmp is not grep (Codex review,
    2026-09-28). No output redirection, tee, subshell or expansion, and none of the options with
    which a reader writes a file or runs a program."""
    import shlex
    rctx = _shell_contexts(remote)
    unquoted = "".join(ch if ctx == "" else " " for ch, ctx in zip(remote, rctx))
    if any(c in unquoted for c in "><()&") or "`" in remote or "$" in remote:
        return False
    segs = _segments(remote, rctx)
    if not segs:
        return False
    for sg in segs:
        try:
            raw = shlex.split(remote[sg["start"]:sg["end"]])
        except ValueError:
            return False
        while raw and raw[0] in _READ_ONLY_WRAPPERS:
            # sudo -n (never ask for a password) is how ops scripts call sudo, so a missing rule fails
            # instead of hanging; it changes who reads, not what the command does (field report on 0.5.8)
            raw = raw[2:] if raw[0] == "sudo" and raw[1:2] == ["-n"] else raw[1:]
        if not raw or raw[0] not in READ_ONLY_REMOTE:
            return False             # a path, an assignment, a wrapper option or another command
        cmd, args = raw[0], raw[1:]
        if cmd == "sort" and not all(_SORT_OK.match(a) for a in args):
            return False
        if cmd == "uniq" and not all(_UNIQ_OK.match(a) for a in args):
            return False
        if cmd == "rg" and any(a.startswith("--pre") or a.startswith("--se") for a in args):
            return False
        if cmd == "journalctl":
            for a in args:
                name = a.split("=", 1)[0]
                if name.startswith("--") and len(name) > 2 and \
                        any(o.startswith(name) for o in _JOURNALCTL_STATEFUL):
                    return False
    return True


def _ssh_route(command: str, ctxs: list[str], refs: list[tuple[str, int, int]]) -> dict | str:
    """The one way a value may reach ssh: on stdin, through the Claude Code sandbox. Returns the
    plan, or the reason the command is refused. Whether the user confirms is the rehydration
    policy's decision (rehydration.py), not the route's.

    Two review rounds broke a host allowlist that read the destination from the command text (a
    quoted -oProxyCommand after the host reached another host). The sandbox needs no such proof:
    no command reaches the network directly, and its proxy admits only the allowed hosts
    (measured 2026-09-27 on macOS and Debian 13: 200 for an allowed host, 403 for another). What
    the sandbox cannot see is the remote side, which may pass the value on; under "confirm" the
    user reads the remote command first. The value never sits in ssh's arguments, where the remote
    shell would parse it as code."""
    import shlex
    segs = _segments(command, ctxs)
    ssh_idx = [n for n, seg in enumerate(segs) if seg["cmd"] == "ssh"]
    if len(ssh_idx) != 1:
        return "only one ssh per command can take a value; run each ssh as its own command"
    j = ssh_idx[0]
    seg = segs[j]
    if any(seg["start"] <= a < seg["end"] for _k, a, _b in refs):
        if "<<" in command[seg["start"]:seg["end"]]:
            return "a heredoc or here-string into ssh is not supported; pipe it in: printf '%s' ⟦KEY⟧ | ssh host '…'"
        return ("ssh would put the value into the remote command line, where the remote shell parses it; "
                "pipe it in instead: printf '%s' ⟦KEY⟧ | ssh host 'grep -F -f - …'")
    k = j
    while k > 0 and segs[k]["piped"]:
        k -= 1
    if k == j:
        return "the value reaches ssh only on stdin: printf '%s' ⟦KEY⟧ | ssh host '…'"
    lo, hi = segs[k]["start"], segs[j - 1]["end"]
    if any(not lo <= a < hi for _k, a, _b in refs):
        return "every placeholder must sit in the commands that feed ssh on stdin"
    blanked = command[:seg["start"]] + " " * (seg["end"] - seg["start"]) + command[seg["end"]:]
    other = _refusal_for(blanked, _shell_contexts(blanked))
    if other:
        return other
    text = command[seg["start"]:seg["end"]]
    try:
        toks = shlex.split(text)
    except ValueError:
        return "the ssh command line cannot be read"
    at = next((n for n, t in enumerate(toks) if os.path.basename(t) == "ssh" and not _ASSIGN_RE.match(t)), None)
    if at is None:
        return "the ssh command line cannot be read"
    opts: list = []
    i = _ssh_options(toks, at + 1, opts)
    if i < len(toks) and toks[i] == "--":
        i += 1
    if i >= len(toks):
        return "the ssh command names no host"
    dest = toks[i]
    # OpenSSH reads options after the host too (edge-case review, 2026-09-27: -S after the host won)
    i = _ssh_options(toks, i + 1, opts)
    if i < len(toks) and toks[i] == "--":
        i += 1
    remote = toks[i:]
    for c, val in opts:
        if c == "o" and val and ("$" in val or "`" in val):
            return "an ssh option holds an expansion whose result is only known when it runs"
        key = re.split(r"[=\s]+", val.strip(" \t=\"'"), maxsplit=1)[0].strip("\"'").lower() if c == "o" and val else ""
        if c in _SSH_REFUSED_FLAGS or key in _SSH_REFUSED_OPTIONS or key.startswith("canonical"):
            return ("ssh with its own proxy, jump host, shared connection, config file, host name or local "
                    "command is refused; the sandbox route sets the connection itself")
    # ssh joins the remote words with spaces and the remote shell parses the result again, so the check
    # reads exactly that string (final review, 2026-09-28: quoting each word hid a `;` or a `|`)
    if any("$" in t or "`" in t for t in remote):
        return "the remote command holds an expansion ($ or a backtick) whose result is only known when it runs"
    why = _remote_refusal(" ".join(remote))
    if why:
        return why
    # the insertion point: the end of the ssh command word, found among the plain words of the masked
    # text, so it can never land inside a quoted word or an assignment (edge-case review, 2026-09-27)
    masked = "".join(ch if ctx == "" else "Q" for ch, ctx in zip(command[seg["start"]:seg["end"]],
                                                                  ctxs[seg["start"]:seg["end"]]))
    spans = [(m.start(), m.end(), m.group(0)) for m in re.finditer(r"\S+", masked)]
    # skip what _segments skips: assignments, keywords, wrappers with their options and option arguments
    w = 0
    while w < len(spans) and (_ASSIGN_RE.match(spans[w][2]) or spans[w][2] in SHELL_KEYWORDS
                              or os.path.basename(spans[w][2]) in WRAPPERS):
        wrapper = os.path.basename(spans[w][2])
        w += 1
        if wrapper in WRAPPERS:
            while w < len(spans) and spans[w][2].startswith("-") and spans[w][2] != "-":
                w += 2 if spans[w][2] in WRAPPER_ARG_OPTIONS.get(wrapper, ()) else 1
            if wrapper == "timeout" and w < len(spans) and re.fullmatch(r"[0-9.]+[smhd]?", spans[w][2]):
                w += 1
    ssh_span = spans[w] if w < len(spans) and os.path.basename(spans[w][2]) == "ssh" else None
    if ssh_span is None or "Q" in ssh_span[2]:
        return "write ssh as a plain word, not quoted or escaped: printf '%s' ⟦KEY⟧ | ssh host '…'"
    # the line as written, from the ssh word on: redirections such as 2>&1 stay whole
    line = command[seg["start"] + ssh_span[0]:seg["end"]].strip()
    return {"insert_at": seg["start"] + ssh_span[1], "dest": dest, "line": line, "remote": " ".join(remote)}


def _sandbox_guard(py: str | None = None) -> str:
    """The first step of a command that sends a value over ssh: hooks/sandbox_probe.py exits 0 only
    inside the Claude Code sandbox; otherwise the command stops with exit 97 before the value is read."""
    from pathlib import Path as _P
    probe = _P(__file__).resolve().parent.parent / "hooks" / "sandbox_probe.py"
    return (f'{shlex_quote(py or sys.executable)} {shlex_quote(str(probe))} || '
            '{ echo "maisecrets: this command sends a value over ssh and runs only inside the Claude Code '
            'sandbox (sandbox.enabled with network.allowedDomains). The value was not read; the command '
            'did not run." >&2; exit 97; }')


def _proxy_option() -> str:
    from pathlib import Path as _P
    helper = _P(__file__).resolve().parent.parent / "hooks" / "proxy_connect.py"
    # no shared connection either: a master socket opened outside the sandbox would carry the session
    # past the proxy to whatever host it was opened for (Claude Code's own GIT_SSH_COMMAND sets the same).
    # ssh expands % in a ProxyCommand, so a % in a path is doubled
    cmd = f"{shlex_quote(sys.executable)} {shlex_quote(str(helper))}".replace("%", "%%") + " %h %p"
    return " -o ControlMaster=no -o ControlPath=none -o " + shlex_quote(f"ProxyCommand={cmd}")


def _resolver_call(key: str, nonce: str) -> str:
    """Windows (Git Bash) only: the command substitution that reads one value under a grant."""
    from pathlib import Path as _P
    py = _P(sys.executable).as_posix()
    script = (_P(__file__).resolve().parent.parent / "hooks" / "resolve.py").as_posix()
    return f'$("{py}" "{script}" {key} --grant {nonce})'


def _serve_value_later(fifo: str, value: str, seconds: float = 120.0, approve: str | None = None) -> bool:
    """Deliver one value once through a FIFO from a detached child. The command runs later, and
    on Codex inside a sandbox that may neither write the vault nor read the keychain (measured:
    resolve.py failed there and the command died); a FIFO in TMPDIR is readable from inside.
    The value lives in the child's memory, never on disk, and is gone after one read or after
    ``seconds``. The value reaches the child on stdin, never as an argument. A FIFO that is gone
    (`_unserve`, `wipe`) ends the child at once: it retried the open for the full ``seconds``
    with the value in its memory (suite review, 2026-09-27). With ``approve``, the child confirms that
    ssh session-approval token once the value was read. That FIFO sits in the sealed directory, which
    nobody can list: only the command that holds its name can open it, and only the rewritten command
    the user allowed holds that name (ssh_approval.py)."""
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
        "    except FileNotFoundError:\n"
        "        break\n"
        "    except OSError:\n"
        "        time.sleep(0.05)\n"
        "if fd is not None:\n"
        "    os.set_blocking(fd, True)\n"
        "    try:\n"
        "        os.write(fd, spec['value'].encode())\n"
        "    finally:\n"
        "        os.close(fd)\n"
        "    if spec.get('approve'):\n"
        "        try:\n"
        "            sys.path.insert(0, spec['root'])\n"
        "            from maisecrets import ssh_approval\n"
        "            ssh_approval.confirm(spec['approve'])\n"
        "        except Exception:\n"
        "            pass\n"
        "try:\n"
        "    os.unlink(spec['fifo'])\n"
        "except OSError:\n"
        "    pass\n"
    )
    try:
        child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        child.stdin.write(json.dumps({"fifo": fifo, "value": value, "seconds": seconds, "approve": approve,
                                      "root": root}).encode())
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


def _sealed_dir() -> str:
    """<run dir>/sealed with mode 0300: its owner can create and open a file whose name they know,
    but nobody can list it. A blind reader (`cat …/v-*` in a parallel tool call) found the value FIFO
    of an open ask and confirmed the session approval with it (Codex review, 2026-09-28). A code the
    command writes back cannot be the proof: the Claude Code sandbox denies writes there (measured
    on macOS with Claude Code 2.1.283: "Operation not permitted")."""
    import stat as _stat
    d = os.path.join(_run_dir(), "sealed")
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if not _stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise RuntimeError(d)
    # never readable again once made: a sweep that opened it for a moment let a blind reader list it
    # (Codex review, 2026-09-28). Each serving child removes its own FIFO; wipe clears the rest
    if _stat.S_IMODE(st.st_mode) != 0o300:
        os.chmod(d, 0o300)
    return d


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


# MCP argument names that carry text a tool publishes or stores for people to read. A value in
# one of them leaves with the message (review by an ops user, 2026-09-27: a real address went
# into a Slack post); Codex refuses it, Claude Code asks with a warning.
FREE_TEXT_FIELDS = {"text", "message", "msg", "body", "content", "comment", "description", "markdown", "html",
                    "summary", "title", "subject", "note", "notes", "caption", "reply", "blocks", "attachments",
                    "richtext", "memo", "headline", "answer"}


def _ask(new_input: dict, reason: str) -> dict:
    """Claude Code: put the value in and let the user confirm the call. The permission prompt
    shows the rewritten input and the reason to the user, not to the model (hooks reference,
    PreToolUse decision control); a hook's "ask" also forces the prompt in auto mode."""
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": reason, "updatedInput": new_input}}


def _updated(payload: dict, new_input: dict) -> dict:
    if client_of(payload) == "codex":
        # Codex accepts updatedInput only together with "allow". It does not skip Codex's own approval
        # of an MCP tool (codex-cli 0.158.0, 2026-09-28); for a shell command see README "Codex gets allow".
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "updatedInput": new_input}}
    # Claude Code: no permissionDecision, the normal permission rules apply to the rewritten input.
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": new_input}}


def _rehydrated(payload: dict, cfg: dict, path: str, new_input: dict, reason: str) -> dict:
    """The decision for a call that got its values, by the rehydration policy of the path. A deny here
    means the early refusal was skipped: fail closed, the rewritten input stays in the hook."""
    decision = rehydration.outcome(client_of(payload), rehydration.policy(cfg, path))
    if decision == "ask":
        return _ask(new_input, reason)
    if decision in ("defer", "allow"):
        return _updated(payload, new_input)
    return _deny("maisecrets: the rehydration policy refuses this call. Nothing ran.")


_ARGS_END = "MAISECRETS_ARGS_END"
_ARGS_CALL_RE = re.compile(r"\Abash \"[^\"\n$`]*/hooks/run\.sh\" "
                           r"(?:audit|forget|guard|put --clipboard|report|shortcut) "
                           r"--args-stdin <<'" + _ARGS_END + r"'\n(.*)\n" + _ARGS_END + r"\n?\Z", re.S)


def _args_call_refusal(command: str) -> str | None:
    """A slash command passes its arguments in a quoted heredoc. The delimiter is fixed in the
    command file, so a line equal to it in the arguments would end the heredoc early and the rest
    would run as commands (Codex review, 2026-09-28). The call must have exactly the form of the
    command file, with the delimiter only on its last line."""
    if "--args-stdin" not in command:
        return None
    m = _ARGS_CALL_RE.match(command)
    if not m or any(line.strip() == _ARGS_END for line in m.group(1).split("\n")):
        return ("maisecrets: a maisecrets command with --args-stdin must have exactly the form of its command "
                f"file, and its arguments must not contain a line {_ARGS_END}. The command did not run. Tell the "
                "user to write the arguments without that line.")
    return None


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
    bad_args = _args_call_refusal(command)
    if bad_args:
        return _deny(bad_args)
    if re.search(r"(?<![\w])CLAUDE_CODE_SESSION_ID\s*=|\bunset\b[^\n;|&]*\bCLAUDE_CODE_SESSION_ID\b"
                 r"|\benv\b[^\n;|&]*\s-u\s*CLAUDE_CODE_SESSION_ID\b", command):
        # /ms reads the blocked prompt of the session the client names; a command that names another one
        # would take that session's text (Codex review, 2026-09-28)
        return _deny("maisecrets: this command sets or clears the session id, which selects the blocked prompt "
                     "of another session. The command did not run. /ms sends the blocked prompt of this session.")
    matched = _store_read_match(command)
    if matched:
        # said as what the user does next, not as a check to stay inside: "do not rephrase … to get around
        # the check" next to an ops request read like an attempt to get around a control (ops review, 2026-09-28)
        return _deny(f"maisecrets: this command touches {matched}, the user's own store. The user manages it "
                     "with /maisecrets:list and /maisecrets:forget. The command did not run. If the task needs "
                     "something from there, tell the user what; if this is a false positive, "
                     "/maisecrets:report records it.")
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
    ssh_plan, ssh_refused = None, False
    if why == "ssh hands the command line to another shell" and not windows and client_of(payload) == "claude" \
            and cfg.get("ssh_via_sandbox", True):
        route = _ssh_route(command, ctxs, refs)
        if isinstance(route, dict):
            ssh_plan, why = route, None
        else:
            why, ssh_refused = route, True
    if why and ssh_refused:
        return _deny(f"maisecrets: {keys} cannot go to the remote host in this form: {why}. The command did "
                     "not run. " + _ssh_way(why))
    if why:
        return _deny(f"maisecrets: {keys} cannot be placed in this command: {why}. The command did not run. "
                     "Give the placeholder as a plain argument of the tool that needs the value; for a "
                     "wrapper such as bash -c or eval, run its inner command directly.")
    # the value can go in; from here the rehydration policy decides (maisecrets/rehydration.py)
    path = "ssh" if ssh_plan else "bash"
    stop = rehydration.refusal(cfg, path, client_of(payload), keys, "The command did not run.")
    if stop:
        return _deny(stop)
    vault = Vault(cfg)
    session = payload.get("session_id")
    uniq = list(dict.fromkeys(k for k, _a, _b in refs))
    failed = _precheck(vault, uniq, session)
    if failed:
        return _deny(_deny_reason(failed))
    # automatic: no ask of our own. confirm: an ask per command, or with ssh_approval "per-session" an
    # approved value runs without an ask and a first use asks once and gives its token to the serving
    # child, which confirms it when the approved command reads the value. After phase 1: a key
    # this session may not resolve leaves no pending token (review, 2026-09-29)
    ssh_auto, ssh_token = rehydration.policy(cfg, "ssh") == "automatic", None
    if ssh_plan and not ssh_auto and cfg.get("ssh_approval") == "per-session" \
            and _remote_is_read_only(ssh_plan["remote"]):
        from . import ssh_approval
        names = sorted({k for k, _a, _b in refs})
        if ssh_approval.approved(payload.get("session_id"), names):
            ssh_auto = True
        else:
            ssh_token = ssh_approval.remember_pending(payload.get("session_id"), names)
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
            approve = None if served else ssh_token
            if approve:
                # the first use: its FIFO sits where nobody can list it, so reading it proves the yes
                fifo = os.path.join(_sealed_dir(), os.path.basename(fifo))
            if not _serve_value_later(fifo, value or "", approve=approve):
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
    if ssh_plan:
        # the offset is before every placeholder (they all sit left of ssh), so it still holds
        at = ssh_plan["insert_at"]
        shift = len(rewritten) - len(command)
        rewritten = rewritten[:at + shift] + _proxy_option() + rewritten[at + shift:]
        prelude.insert(0, _sandbox_guard())
    new_input = dict(tool_input)
    new_input["command"] = "; ".join(prelude) + "; " + rewritten
    if ssh_plan:
        base = (f"maisecrets: this command sends the value of {keys} on stdin to ssh "
                f"{ssh_plan['dest']}: {ssh_plan['line'][:400]}. It runs only inside the Claude "
                "Code sandbox, so the connection reaches only a host your sandbox allows. ")
        if ssh_auto:
            # automatic, or approved once in this session: the normal permission rules of the client decide
            return _updated(payload, new_input)
        if ssh_token:
            from . import ssh_approval
            return _ask(new_input, base + "If you allow it, these values go on stdin to ssh without asking again "
                                   f"for the rest of this session (at most {ssh_approval.APPROVAL_HOURS} hours), to "
                                   "hosts your sandbox allows and only with read-only remote commands (grep, cat, "
                                   "tail, journalctl and the like). Allow it only if you trust those hosts.")
        return _ask(new_input, base + "The remote command can still pass the value on: allow it only if you trust "
                                      "that host and that command.")
    return _rehydrated(payload, cfg, "bash", new_input,
                       f"maisecrets: this command gets the real value of {keys} through a shell variable; the "
                       "command shown here carries no value. Check the command before you allow it.")


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


def _precheck(vault: Vault, keys: list[str], session: str | None) -> list[str]:
    """Phase 1 of every resolve: the session rule, then the limiter, for every key, before anything is
    recorded or served. A call with a good key and a bad one wrote the good key's audit line before
    the refusal on MCP and file tools (review, 2026-09-29); Bash had this order already."""
    failed = [f"{k} ({st})" for k in keys for st in [vault.status(k, session)] if st != "ok"]
    return failed or vault._limit_all(keys, session)


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
    is inserted after the session rule and the limiter, into every field that holds it, a published
    text field included. The rehydration policy decides whether we ask; a permission prompt of the
    client shows the value, the user's own, at the point where the real call happens."""
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
    fields = _ref_fields(tool_input)
    text_fields = [f for f in fields if is_text_field(f)]
    stop = rehydration.refusal(cfg, "mcp", client_of(payload),
                               ", ".join("⟦" + k + "⟧" for k in dict.fromkeys(found)), "The call did not run.")
    if stop:
        return _deny(stop)
    vault = Vault(cfg)
    session = payload.get("session_id")
    context = json.dumps(tool_input, ensure_ascii=False)
    values: dict[str, str] = {}
    failed = _precheck(vault, list(dict.fromkeys(found)), session)
    if failed:
        return _deny(_deny_reason(failed))
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
    new_input = _walk_strings(tool_input, substitute)
    names = ", ".join(f"⟦{k}⟧" for k in values)
    warn = (f" WARNING: {', '.join(text_fields)} is text that the tool publishes or stores; the real value "
            "goes out with it." if text_fields else "")
    return _rehydrated(payload, cfg, "mcp", new_input,
                       f"maisecrets: this call gets the real value of {names} in {', '.join(fields)} "
                       f"of {tool}.{warn} Check the target and the value before you allow it.")


def _ref_fields(node: Any, path: str = "") -> list[str]:
    """Paths of the string fields that hold a placeholder (`messages[0].text`), once each. A
    string that is itself a JSON object or array is walked too, so `{"params": "{\"text\": …}"}`
    names `params.text` (review, 2026-09-27: the list index cut the path to `messages`)."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(_ref_fields(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(_ref_fields(v, f"{path}[{i}]"))
    elif isinstance(node, str) and find_refs(node):
        inner = None
        if node.lstrip()[:1] in ("{", "["):
            try:
                inner = json.loads(node)
            except ValueError:
                inner = None
        nested = _ref_fields(inner, path) if isinstance(inner, (dict, list)) else []
        out.extend(nested or [path or "(input)"])
    return list(dict.fromkeys(out))


def is_text_field(path: str) -> bool:
    """The last word of the last key names published text: `text`, `messageText`, `text_body`,
    `Body`. Whole words only, so `context`, `plaintext` and `httpStatus` are not text fields
    (second review, 2026-09-27)."""
    keys = [k for k in re.split(r"[.\[\]]", path) if k and not k.isdigit()]
    if not keys:
        return False
    words = [w.lower() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", keys[-1])]
    return bool(words) and (words[-1] in FREE_TEXT_FIELDS or words[0] in FREE_TEXT_FIELDS)


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
# tools that read files by path; they carry no placeholder, but they could read the store itself
_READ_TOOLS = ("Read", "Grep", "Glob", "LS", "NotebookRead")
_PATH_FIELDS = ("file_path", "path", "notebook_path", "directory", "dir", "root", "cwd")
# Claude Code's resource tools read an MCP resource by URI; a filesystem server serves file: URIs, and
# the names carry no mcp__ prefix, so the matcher did not reach them (tool inventory, 2026-09-28)
_MCP_RESOURCE_TOOLS = ("ReadMcpResourceTool", "ReadMcpResourceDirTool")


def _store_dir_spellings() -> list[str]:
    """The protected directories as the configured path and as the real path, longest first."""
    from .vault import HOME
    names = {str(HOME).rstrip(os.sep)} | set(_protected_dirs())
    return sorted((n for n in names if len(n) > 1), key=len, reverse=True)


def _protected_dirs() -> list[str]:
    """The vault home and the value run directory, as real paths: a tool that reads them bypasses every
    gate around a resolve (external review, 2026-09-28: Read was not checked at all)."""
    import tempfile
    from .vault import HOME
    dirs = [str(HOME)]
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    dirs.append(os.path.join(xdg, "maisecrets") if xdg else "")
    dirs.append(os.path.join(tempfile.gettempdir(), f"maisecrets-{os.getuid()}") if hasattr(os, "getuid") else "")
    return [os.path.realpath(os.path.expanduser(d)) for d in dirs if d]


def _identity(path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
        return st.st_dev, st.st_ino
    except OSError:
        return None


def _abs(path: str, cwd: str) -> str:
    p = os.path.expanduser(path.strip())
    return os.path.realpath(p if os.path.isabs(p) else os.path.join(cwd or os.getcwd(), p))


def _touches_store(path: str, cwd: str = "", contains: bool = False) -> bool:
    """Whether the path lies in a protected directory, compared by file identity (device and inode) of the
    path and each of its parents: on a case-insensitive file system another spelling is the same directory
    (Codex review, 2026-09-28). With ``contains``, a protected directory below the path counts too: a
    recursive Grep over a parent reads the store."""
    if not isinstance(path, str) or not path.strip():
        return False
    real = _abs(path, cwd)
    protected = [d for d in _protected_dirs() if os.path.isdir(d)]
    ids = {_identity(d) for d in protected} - {None}
    probe = real
    while True:
        if _identity(probe) in ids or any(probe == d for d in protected):
            return True
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    if _hardlinked_into(real, protected):
        return True
    if contains and os.path.isdir(real):
        me = _identity(real)
        for d in protected:
            q = d
            while True:
                if _identity(q) == me:
                    return True
                parent = os.path.dirname(q)
                if parent == q:
                    break
                q = parent
    return False


def _hardlinked_into(real: str, protected: list[str]) -> bool:
    """A second name of a store file outside the store (`ln`) has no protected parent: the
    file's own identity decides (invariant I3, 2026-09-28). Only a file with more than one
    link is compared, so an ordinary read costs one stat."""
    try:
        st = os.stat(real)
    except OSError:
        return False
    if st.st_nlink < 2 or not os.path.isfile(real):
        return False
    me = (st.st_dev, st.st_ino)
    for d in protected:
        for top, dirs, files in os.walk(d):
            if top.count(os.sep) - d.count(os.sep) >= 2:
                dirs[:] = []
            for name in files:
                if _identity(os.path.join(top, name)) == me:
                    return True
    return False


def _uri_path(v: str) -> str:
    """The local path of a `file:` URI (`file:///p`, `file://localhost/p`, percent-encoded), else the string.
    An MCP file server takes a URI where a path is expected; `file:///…/vault.json` passed the path check
    (invariant I3, 2026-09-28)."""
    if v[:5].lower() != "file:":
        return v
    from urllib.parse import urlparse
    from urllib.request import url2pathname
    u = urlparse(v)
    if u.netloc not in ("", "localhost"):
        return v
    # url2pathname decodes and, on Windows, turns `/C:/Users/…` into `C:\\Users\\…`: an unquoted
    # `/C:/…` named no store on the Windows runner (2026-09-28)
    return url2pathname(u.path)


def _store_path_refusal(tool: str, tool_input: dict, cwd: str) -> dict | None:
    """Refuse a read tool, or an MCP argument, that names a path in the vault home or the run directory.
    A path is only what the field names: a Grep pattern or a free text is not read as a path."""
    hits: list[str] = []
    if tool in _READ_TOOLS:
        hits = [f for f in _PATH_FIELDS if _touches_store(tool_input.get(f, ""), cwd, contains=tool == "Grep")]
        # Grep without a path searches the working directory (Codex review, 2026-09-28)
        if tool == "Grep" and not any(tool_input.get(f) for f in _PATH_FIELDS) \
                and _touches_store(cwd, cwd, contains=True):
            hits.append("cwd")
        pattern = tool_input.get("pattern") if tool == "Glob" else tool_input.get("glob")
        if isinstance(pattern, str) and pattern:
            # a Glob names its directory in the pattern too: the part before the first wildcard
            fixed = re.split(r"[*?\[{]", pattern, maxsplit=1)[0]
            base = os.path.join(tool_input.get("path") or "", fixed) if tool_input.get("path") else fixed
            if fixed and _touches_store(base.rstrip("/") or "/", cwd):
                hits.append("pattern")
    else:
        def look(v: str) -> str:
            path = _uri_path(v)
            if ("/" in path or "\\" in path or path.startswith("~")) and _touches_store(path, cwd):
                hits.append(v[:80])
            return v
        _walk_strings(tool_input, look)
    if not hits:
        return None
    return _deny(f"maisecrets: {tool} would read the maisecrets store or its value directory, the user's own store. "
                 "The user manages it with /maisecrets:list and /maisecrets:forget. The call did not run. If this is "
                 "a false positive, /maisecrets:report records it.")


# the file headers of a Codex patch: Add, Update and Delete name a file, Move to its new name
_PATCH_MARKERS = ("Add File", "Update File", "Delete File", "Move to")


def _patch_headers(patch: str) -> list[tuple[str, str]]:
    """(the header line, the path it names) of a Codex patch. A line is a header by its stripped form:
    codex-cli 0.158.0 trims all whitespace, Unicode included (NBSP, \\f, U+3000), before it reads a
    marker; a regex for spaces and tabs missed the rest (reviews, 2026-09-29)."""
    out = []
    for line in patch.split("\n"):
        t = line.strip()
        for marker in _PATCH_MARKERS:
            if t.startswith(f"*** {marker}:"):
                out.append((line, t[len(marker) + 5:].strip()))
    return out


def _patch_text_ok(patch: object) -> bool:
    """A Codex patch: `*** Begin Patch` first, also inside the heredoc form Codex accepts."""
    if not isinstance(patch, str):
        return False
    lines = [ln.strip() for ln in patch.strip().split("\n")]
    if lines and re.fullmatch(r"<<\s*['\"]?\w+['\"]?", lines[0]):
        lines = lines[1:]
    return bool(lines) and lines[0] == "*** Begin Patch"


def _in_the_home(path: str, cwd: str) -> bool:
    """A path under the maisecrets home or the value run directory, by any spelling or link."""
    from .vault import HOME
    if not path:
        return False
    try:
        expanded = os.path.expanduser(path)
        if expanded and not os.path.isabs(expanded) and cwd:
            expanded = os.path.join(cwd, expanded)   # the client's cwd, not the hook's
        real = os.path.realpath(expanded)
        home = os.path.realpath(str(HOME))
        if platform.system() in ("Darwin", "Windows"):   # case-insensitive file systems (APFS, NTFS)
            real, home = real.lower(), home.lower()
        inside = real == home or real.startswith(home + os.sep)
        # the run directory and a hard link are known by identity only (invariant I3, 2026-09-28)
        inside = inside or _touches_store(path, cwd)
    except (OSError, ValueError):
        inside = False
    return inside or ".maisecrets" in path.lower()


def _pre_file_tool(payload: dict, cfg: dict, tool: str, tool_input: dict, cwd: str = "") -> dict:
    """Write/Edit/MultiEdit/NotebookEdit: a placeholder in the content is resolved like an MCP
    argument (the value must be inline; the client's permission prompt shows the diff with it),
    under the session rule, the limiter and an audit line that names the file. Writing a value
    into a file on purpose is what the plugin exists for (user decision, 2026-09-26); the first
    version refused it and sent the model to a Bash redirect. The maisecrets home is off limits
    for the agent: a config written by an injected instruction could lift every cap or switch
    the store to plaintext (review, 2026-09-26)."""
    if tool == "apply_patch":
        # Codex sends every file edit as one patch in `command` (measured on codex-cli 0.158.0: the
        # matcher aliases Write and Edit, the payload says apply_patch). Each header names a path;
        # the value goes into the content lines only, never into a file name
        patch = tool_input.get("command")
        if not _patch_text_ok(patch):
            # without the patch text nothing names the paths: a placeholder elsewhere would resolve
            # unchecked (review, 2026-09-29)
            return _deny("maisecrets: this apply_patch call carries no patch in `command`. Nothing was written.")
        headers = _patch_headers(patch)
        paths = [path for _line, path in headers]
        in_header = [k for line, _path in headers for k, _a, _b in find_refs(line)]
        if in_header:
            return _deny(f"maisecrets: ⟦{in_header[0]}⟧ is in a file name of the patch, where it is not resolved. "
                         "Nothing was written. Put the placeholder into the content, not into a path.")
    else:
        paths = [str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")]
    for path in paths:
        if _in_the_home(path, cwd):
            return _deny(f"maisecrets: {tool} on {path} is refused; the maisecrets home is changed by the human "
                         "only. Nothing was written. Tell the user what you wanted to change there.")
    path = ", ".join(paths)
    found: list[str] = []

    def collect(v: str) -> str:
        found.extend(k for k, _a, _b in find_refs(v))
        return v
    # a Codex patch resolves in its text only; another field keeps a placeholder as text
    target = {"command": tool_input["command"]} if tool == "apply_patch" else tool_input
    _walk_strings(target, collect)
    if not found:
        return {}
    names = ", ".join(f"⟦{k}⟧" for k in dict.fromkeys(found))
    stop = rehydration.refusal(cfg, "file", client_of(payload), names, "Nothing was written.")
    if stop:
        return _deny(stop)
    vault = Vault(cfg)
    session = payload.get("session_id")
    values: dict[str, str] = {}
    failed = _precheck(vault, list(dict.fromkeys(found)), session)
    if failed:
        return _deny(_deny_reason(failed).replace("The command did not run.", "Nothing was written."))
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
    return _rehydrated(payload, cfg, "file", {**tool_input, **_walk_strings(target, substitute)},
                       f"maisecrets: {tool} writes the real value of {names} into {path}. "
                       "Check the file and the value before you allow it.")


def pre_tool(payload: dict) -> dict:
    cfg = load_config()
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if tool == "Bash":
        return _pre_bash(payload, cfg, tool_input)
    if tool in _READ_TOOLS or tool in _MCP_RESOURCE_TOOLS or tool.startswith("mcp__"):
        refused = _store_path_refusal(tool, tool_input, str(payload.get("cwd") or ""))
        if refused:
            return refused
        if tool in _READ_TOOLS or tool in _MCP_RESOURCE_TOOLS:
            return {}
    if tool in _FILE_TOOLS or tool == "apply_patch":
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
            # a value with an encoded separator (`?t=pa%40ss…`) splits apart once decoded
            for piece in _FINE_SPLIT_RE.split(token):
                if "%" in piece and unquote(piece) != piece:
                    yield unquote(piece)
    if "\\" in token:
        try:
            dec = json.loads('"' + token + '"')
        except ValueError:
            dec = None
        if dec and dec != token:
            yield dec
    yield from _decoded(token)


_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")


def _decoded(token: str):
    """The text a hex or base64 token decodes to. A stored value that another session put in
    and a command printed as `| base64` or `xxd -p` reached the model: the encoded forms were
    checked only for values this session resolved (invariant I1, 2026-09-28). Decoding needs
    no store read; the fingerprint decides."""
    import base64
    import binascii
    t = token.rstrip(".,;:)")
    out = []
    if _HEX_RE.fullmatch(t):
        try:
            out.append(bytes.fromhex(t))
        except ValueError:
            pass
    if _B64_RE.fullmatch(t):
        padded = t + "=" * (-len(t) % 4)
        for alt in (b"+/", b"-_"):
            try:
                out.append(base64.b64decode(padded, altchars=alt, validate=True))
            except (binascii.Error, ValueError):
                pass
    for raw in out:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) >= _EXACT_MIN_LEN and text.isprintable():
            yield text


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
    escaped = [json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]]
    # JSON inside a JSON string (an MCP result whose text is a JSON document) escapes twice
    forms += [raw.hex(), raw.hex().upper(), quote(value, safe=""), quote_plus(value), *escaped,
              *(json.dumps(e)[1:-1] for e in escaped)]
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
            out.append((value, Entry.from_meta(vault._index["entries"][key]).ref))
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
                out.append((cand, Entry.from_meta(vault._index["entries"][key]).ref))
    return out


def _exact_redact(text: str, vault: Vault, session: str | None, hit: dict, entries: list,
                  resolved: list[tuple[str, str]] | None = None, values: list[str] | None = None) -> str:
    """Values without a known shape (a password stored with `put`, a value from a prior
    prompt) come back from a command in plaintext unless they are matched exactly. The
    match is by keyed fingerprint of each token, so no value is read from the store; the
    values this session itself resolved are matched as substrings in every derived form."""
    out = text
    for value, ref in resolved or []:
        # a value this session itself put in is no guess: it goes at any length. The 8-character floor of
        # _derived_forms is for the encoded forms and the fingerprint search below; a 6-character password
        # stored with `put` came back to the model in plain text (external review, 2026-09-28)
        forms = _derived_forms(value)
        if value and 4 <= len(value) < _EXACT_MIN_LEN:
            forms.append(value)       # 4 to 7 characters: everywhere, also between letters
        if value and len(value) < 4:
            # under 4 characters only where no letter or digit stands next to it: a plain substring replace
            # of `a` broke every word of the output (Codex review, 2026-09-28)
            pattern = re.compile(r"(?<![^\W_])" + re.escape(value) + r"(?![^\W_])")   # any letter or digit
            out, n = pattern.subn(lambda _m: ref, out)
            if n:
                hit["n"] += n
                if values is not None and value not in values:
                    values.append(value)
        for form in sorted(forms, key=len, reverse=True):
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
            e = Entry.from_meta(vault._index["entries"][key])
            # a URL-decoded or JSON-unescaped candidate is not in the text; its encoded form is
            raw = cand if cand in out else _raw_form(token, cand)
            n = out.count(raw)
            out = out.replace(raw, e.ref)
            hit["n"] += n
            entries.append(e)
            if values is not None and raw not in values:
                values.append(raw)
    return out


def _raw_form(token: str, cand: str) -> str:
    """The piece of ``token`` that decodes to ``cand`` (URL-encoded or JSON-escaped), shortest
    first; the whole token when no piece does, so the encoded value never stays in the text."""
    from urllib.parse import unquote
    pieces = [token, token.rstrip(".,;:)")] + ([token.split("=", 1)[1]] if "=" in token else [])
    pieces += _FINE_SPLIT_RE.split(token)
    for p in sorted(dict.fromkeys(pieces), key=len):
        if "%" in p and unquote(p) == cand:
            return p
        if "\\" in p:
            try:
                if json.loads('"' + p + '"') == cand:
                    return p
            except ValueError:
                pass
    return token


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
                "reason": (f"[maisecrets: the command ran and finished; this is not an error.\n"
                           f"{hit['n']} value(s) in its output are replaced by placeholders.\n"
                           f"Do not run the command again; continue with the placeholders as they are.]\n\n{text}")}
    shown = ", ".join(dict.fromkeys(refs)) if refs else "values that are already stored"
    return {
        # the person sees what was replaced, not only the model (UX review, 2026-09-27)
        "systemMessage": f"maisecrets replaced {hit['n']} value(s) in this {payload.get('tool_name') or 'tool'} "
                         f"result before the AI saw it: {shown}.",
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
        except OSError:
            _live_cache["v"] = False
        except ValueError:
            # a damaged index is not an empty one: the vault opens and fails, the output is withheld
            _live_cache["v"] = True
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
        line = f"{stamp}\t{event}\t{_client_label(payload)}\t{sess}\t{tool}\t{decision}\t{ms}ms\t{how}\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
        if path.stat().st_size > 2000 * 100:
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > 2000:
                atomic_write(path, "\n".join(lines[-2000:]) + "\n")
    except OSError:
        pass


def _from_a_synced_folder() -> bool:
    """maisecrets runs from a folder the claude.ai organisation sync writes (plugins/synced/…), the one
    install whose update can leave a session without hooks. There the guard may come from the
    organisation's managed settings, which no local file announces, so the heartbeat is always on."""
    root = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
    return f"{os.sep}plugins{os.sep}synced{os.sep}" in root


def _heartbeat(event: str, payload: dict) -> None:
    """Tell the guard (hooks/guard.py, installed outside the plugin folder) that maisecrets runs for
    this call: an empty file named by session, event and the call's id. Only when the guard is
    installed, and only for Claude Code, whose folder swap it watches. Never raises: a heartbeat
    that cannot be written makes the guard refuse, which is the safe side."""
    import hashlib
    from .vault import HOME
    if event not in ("user-prompt", "pre-tool", "post-tool") or client_of(payload) != "claude":
        return
    if not ((HOME / "guard.json").exists() or _from_a_synced_folder()):
        return
    ident = payload.get("prompt_id") if event == "user-prompt" else payload.get("tool_use_id")
    session = payload.get("session_id")
    if not ident or not session:
        return
    try:
        d = HOME / "alive"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = hashlib.sha256(f"{session}\0{event}\0{ident}".encode()).hexdigest()[:32]
        with open(d / name, "w", encoding="utf-8"):
            pass
        now = time.time()
        for n in os.listdir(d):
            # a heartbeat whose guard never came for it (the guard removed, a matcher that differs)
            p = d / n
            if now - p.stat().st_mtime > 600:
                p.unlink()
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
        payload = None
    if not isinstance(payload, dict):
        # `null`, a list or a number parse but are no payload: the handler and then the
        # fail-closed path raised, the process exited 1, and exit 1 lets the action through
        sys.stderr.write("maisecrets: bad payload\n")
        # an answer in JSON for every event: exit 2 is ignored after a tool, and Codex runs the tool on
        # exit 2 before one (Codex review, 2026-09-28)
        _out(_fail_closed(event, {}, "got a payload that is not JSON."))
        return 0
    _heartbeat(event, payload)
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
        # cancel, then wait: a daemon timer thread that still runs while the interpreter shuts down
        # can crash the process, and one hook ended with signal 11 after its answer on a macOS
        # runner (2026-09-27)
        watchdog.cancel()
        watchdog.join(timeout=1)
