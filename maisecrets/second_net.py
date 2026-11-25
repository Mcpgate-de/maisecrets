"""The second net for a tool result (claude-mod/maisecrets-mod.mjs, `session.append` on the door `tool-result`).

In Claude Code a PostToolUse hook that fails does not withhold the output, and a failed command takes the
PostToolUseFailure path, whose answer cannot replace it. The mod sees each row before the client stores and sends it.

The mod decides from positive evidence only. While the settings hooks of a tool result run, the mod sets
MAISECRETS_MOD_NET to `on`, and the tool-result hooks then end their additionalContext with a marker line
(mark_answers): `[maisecrets: result masked MAC HASH]` when the answer replaces the output (HASH: of the texts of that
output, output_hash), else `[maisecrets: result checked MAC]`, and only after the handler scanned a result. MAC is an
HMAC-SHA256 (net_key: a key of 32 random bytes in the maisecrets home, mode 600) of the kind, the call's tool_use_id,
the hash and the rest. The mod gets the key once from `hooks/dispatch.py mod-result` (the request `{"net_key": true}`)
and accepts the marker only as the last line of an entry with the MAC it computes for that call, and `masked` only
when the output that reaches it has the same hash; it takes the marker out, so it never reaches the model. A result
without such a marker goes to mask_result (`hooks/dispatch.py mod-result`).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import stat

from .placeholder import KEY_RE

ENV = "MAISECRETS_MOD_NET"
ON = "on"                    # the mod's literal value while the tool-result hooks run (no other value counts)
KEY_NAME = "second_net.key"  # in the maisecrets home: a Read tool or a Bash command that names it is refused (C8)
_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_CALL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_EVENTS = {"post-tool": "PostToolUse", "post-tool-failure": "PostToolUseFailure"}
_KEY = re.compile("\u27e6(" + KEY_RE + ")(?::[^\u27e7\n]{0,80})?\u27e7")
_AGENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
# The mod waits RESULT_MS (20 s) for mask_result (claude-mod/maisecrets-mod.mjs). Inside it the name check of a tool
# result gets the window of a hook (remote_layer.tool_deadline: min(8 s, half the window), #105): without one, all
# pieces of a long text shared the wait of one piece and the text ended `partial` after the first. 16 s leaves 4 s for
# the Python start, the masking and the answer; the store calls end a second before the window (vault.hook_deadline)
WINDOW_S = 16.0


def _texts_of(node, out: list) -> list:
    """The strings of an output in a fixed order (an object's keys sorted, each key before its value); numbers and the
    rest are left out, because JSON gives them no single written form in both languages."""
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for x in node:
            _texts_of(x, out)
    elif isinstance(node, dict):
        for k in sorted(node, key=str):
            out.append(str(k))
            _texts_of(node[k], out)
    return out


def output_hash(output) -> str:
    """The first 16 hex digits of the SHA-256 of an output's strings joined by NUL: the mod computes the same."""
    return hashlib.sha256("\0".join(_texts_of(output, [])).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def band() -> dict | None:
    """The rest of the name check of this process's result for the mod's band (#105, B11): {"share", "mode"}, or None.
    The share and the mode only, never a text of the result."""
    from . import remote_layer
    b = remote_layer.NER_DOWN.get("band")
    return {"share": int(b[0]), "mode": str(b[1])} if b else None


def _rest() -> str:
    """` rest SHARE MODE` for the marker when the name check left a rest, else ""."""
    try:
        b = band()
    except Exception:  # noqa: BLE001 - no band; the marker stands
        return ""
    return f" rest {b['share']} {b['mode']}" if b else ""


def _make_key(path, replace: bool) -> None:
    """A new key file, mode 600, written whole before it gets its name: a hook that reads at the same moment finds no
    file or a whole one. Without ``replace`` an existing key stays (of two first hooks at once, the first one wins)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{KEY_NAME}.{os.getpid()}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, (secrets.token_hex(32) + "\n").encode("ascii"))
    finally:
        os.close(fd)
    try:
        if replace:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass
            except OSError:              # a file system without hard links
                if not os.path.lexists(path):
                    os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _read_key(path) -> str:
    """The text of the key file: no link followed, no wait on a FIFO or a device (O_NONBLOCK), a regular file only. A
    key file that others may read gets mode 600 again."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("the key of the second net is no regular file")
        if os.name == "posix" and st.st_mode & 0o077:
            os.fchmod(fd, 0o600)
        return os.read(fd, 256).decode("ascii", "replace").strip()
    finally:
        os.close(fd)


def _key_path():
    from .home import HOME, _check_home
    _check_home()
    return HOME / KEY_NAME


def new_net_key() -> bytes:
    """A new key in place of the old one: the mod asks for it at each session start (mod-result, {"net_key": "new"}),
    so a key that leaked into a session's output is worth nothing in the next one. A hook that marks with the old key
    at that moment gives a marker that counts as none: the mod masks that result and asks for the key again."""
    _make_key(_key_path(), replace=True)
    return net_key()


def net_key() -> bytes:
    """The key of the marker: 32 random bytes in the maisecrets home (KEY_NAME, mode 600), made at the first use and
    anew at each start of the mod (new_net_key). A damaged key file is made anew (the mod then asks for the key again:
    a marker with the old key counts as none). Raises when the key can neither be read nor made: the hook then writes
    no marker, and the mod masks the result. The key goes to no log and no answer of a hook: only to the mod, on stdout
    of mod-result. A command of the agent that names it is refused (shell_commands, "the key of the second net"), and
    the result hook masks it wherever it stands in a tool result (hide_key)."""
    path = _key_path()
    for replace in (False, True):
        try:
            text = _read_key(path)
        except FileNotFoundError:
            _make_key(path, replace=False)
            text = _read_key(path)
        if _KEY_HEX.fullmatch(text):
            return bytes.fromhex(text)
        if not replace:
            _make_key(path, replace=True)
    raise ValueError("second net key")


KEY_WITHHELD = "[maisecrets: the key of its second net, withheld]"


def key_forms() -> list[str]:
    """The spellings of the current key that a tool result could show: hex (either case: the replace ignores case),
    base64 and base64url without padding. Read only when the file exists, never made here; [] on any failure."""
    try:
        path = _key_path()
        if not os.path.lexists(path):
            return []
        text = _read_key(path)
    except Exception:  # noqa: BLE001 - no key: nothing to hide
        return []
    if not _KEY_HEX.fullmatch(text):
        return []
    raw = bytes.fromhex(text)
    return [text, base64.b64encode(raw).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")]


def hide_key(text: str, forms: list[str]) -> tuple[str, list[str]]:
    """``text`` with each spelling of the key (key_forms) replaced by KEY_WITHHELD, and the spellings it held (for the
    transcript scrub, as a stored value's). The hex is matched in any case."""
    found = []
    for form in forms:
        # base64 with its padding, if any
        rx = re.compile(re.escape(form), re.IGNORECASE) if form == forms[0] else re.compile(re.escape(form) + "=*")
        if rx.search(text):
            found.extend(dict.fromkeys(m.group(0) for m in rx.finditer(text)))
            text = rx.sub(KEY_WITHHELD, text)
    return text, found


def hide_counted(text: str, forms: list[str], hit: dict, values: list) -> str:
    """hide_key for hooks.post_tool: each spelling found counts as a hit and goes to the transcript scrub."""
    text, found = hide_key(text, forms)
    hit["n"] += len(found)
    values.extend(found)
    return text


def mac(key: bytes, kind: str, call_id: str, digest: str, rest: str) -> str:
    """The proof of a marker: the first 32 hex digits of HMAC-SHA256(key, kind, tool_use_id, output hash, rest), one
    line each. The mod computes the same (claude-mod/maisecrets-mod.mjs, markMac)."""
    text = "\n".join((kind, call_id, digest, rest))
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def mark(obj: dict, event: str, key: bytes, call_id) -> dict:
    """The answer of a tool-result hook with the marker line of maisecrets at the end of its additionalContext, its MAC
    bound to this call (``call_id``: the payload's tool_use_id). A Codex answer (a decision), an event that is no
    tool-result event and a call without a well-formed id stay as they are. Holds no value and not the key."""
    name = _EVENTS.get(event)
    if not name or not isinstance(obj, dict) or "decision" in obj or not isinstance(call_id, str) \
            or not _CALL_ID.fullmatch(call_id):
        return obj
    hso = dict(obj.get("hookSpecificOutput") or {})
    hso["hookEventName"] = name
    out = next((k for k in ("updatedToolOutput", "updatedMCPToolOutput") if k in hso), None)
    rest = _rest() if event == "post-tool" else ""
    kind, digest = ("masked", output_hash(hso[out])) if out else ("checked", "")
    proof = mac(key, kind, call_id, digest, rest[len(" rest "):])
    tag = f"[maisecrets: result {kind} {proof}{' ' + digest if digest else ''}{rest}]"
    ctx = hso.get("additionalContext")
    hso["additionalContext"] = f"{ctx}\n\n{tag}" if isinstance(ctx, str) and ctx else tag
    return {**obj, "hookSpecificOutput": hso}


def mark_answers(hooks_module, event: str) -> None:
    """Every answer this hook process writes after its handler scanned a result (the handler's, the watchdog's, a
    crash's) carries the marker: they all go out through hooks._out. Only while the mod waits for it (ENV is `on`):
    without the mod the text would reach the model. A payload with no result to scan or without a tool_use_id gets
    no marker, and so does every answer when the key cannot be read: the mod then masks the result."""
    if os.environ.get(ENV) != ON or event not in _EVENTS:
        return
    # the key is read here, before the handler runs and outside the lock of the answer: the watchdog's answer and a
    # crash's do no file work. No key: no marker
    try:
        key = net_key()
    except Exception:  # noqa: BLE001 - no key: no marker, and the mod masks the result
        return
    scanned = {"v": False, "id": None}
    name = "post_tool" if event == "post-tool" else "post_tool_failure"
    handler = getattr(hooks_module, name)

    def watched(payload, *args, **kwargs):
        if isinstance(payload, dict) and (payload.get("tool_response") is not None if event == "post-tool" else
                                          isinstance(payload.get("error"), str) and payload.get("error")):
            scanned["v"] = True
            scanned["id"] = payload.get("tool_use_id")
        return handler(payload, *args, **kwargs)
    setattr(hooks_module, name, watched)
    write = hooks_module._out

    def marked(obj):
        if not scanned["v"]:
            return obj
        try:
            return mark(obj, event, key, scanned["id"])
        except Exception:  # noqa: BLE001 - no marker, and the mod masks the result
            return obj
    hooks_module._out = lambda obj: write(marked(obj))


def _keys(text: str) -> set:
    return {m.group(1) for m in _KEY.finditer(text)}


def mask_result(payload: dict) -> dict:
    """The texts of a result that no tool-result hook of maisecrets marked, masked as hooks.post_tool masks them, with
    the note on unchecked names that post_tool's hook adds. Answers {"texts": [...], "changed": bool, "note": str},
    the texts in the same order, or {"withheld": True} when the name setting withholds an unchecked result. Raises on
    any failure: the mod then withholds the result. Writes no row: hooks.log counts hook runs, and this is none."""
    texts = payload.get("texts")
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise ValueError("texts")
    session = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    from . import detect, hooks, vault_refs
    from .home import regions_from_config
    from .placeholder import REFERENCES
    from .sources import PLUGIN_SOURCES
    from .tool_withhold import with_unchecked_names
    from .vault import load_config
    detect.use_regions(regions_from_config)
    detect.use_sources(PLUGIN_SOURCES)
    detect.use_references(REFERENCES)
    vault_refs.use_client("claude")
    # the shape of a Claude Code payload (prompt_id): the answer is Claude's updatedToolOutput. No file path, so a
    # value in a test file is masked here, where post_tool may keep it as a fixture
    tool = str(payload.get("tool_name") or "tool")[:80]
    hook_payload = {"hook_event_name": "PostToolUse", "prompt_id": "mod", "session_id": session,
                    "cwd": str(payload.get("cwd") or ""), "tool_name": tool, "tool_input": {},
                    "tool_response": list(texts)}
    from .vault import hook_deadline
    hook_deadline(WINDOW_S)
    from .remote_layer import NER_DOWN
    NER_DOWN["band"] = None               # the band of this result only
    try:                                  # the window holds until the answer: the store calls of the scrub too
        out = hooks.post_tool(hook_payload)
        out = with_unchecked_names(hook_payload, out if isinstance(out, dict) else {}, False, load_config)
        hso = out.get("hookSpecificOutput") or {}
        new = hso.get("updatedToolOutput")
        note = hso.get("additionalContext") if isinstance(hso.get("additionalContext"), str) else ""
        rest = band()                     # the mod's band: the share and the mode, no text (#105, B11)
        extra = {"rest": rest} if rest else {}
        if new is None:
            return {"texts": texts, "changed": False, "note": note, **extra}
        if isinstance(new, str):
            return {"withheld": True, **extra}     # with_unchecked_names withheld it: one text in place of the result
        if not isinstance(new, list) or len(new) != len(texts) or not all(isinstance(t, str) for t in new):
            raise ValueError("answer")
        _scrub_later(texts, new, session, payload.get("agent_id"))
        return {"texts": new, "changed": new != texts, "note": note, **extra}
    finally:
        hook_deadline(None)


def _scrub_later(texts: list, new: list, session: str | None, agent) -> None:
    """The client keeps the tool's own record of the result (toolUseResult) as the tool made it, and writes the row
    after this answer: a detached child masks the values of the new placeholders in the transcript of this session,
    found by its id, and for a subagent's result in that subagent's transcript (<session>/subagents/agent-<id>.jsonl).
    The values come from the store by the keys the masking put in. Never raises."""
    try:
        from .vault import Vault, load_config
        cfg = load_config()
        if not cfg.get("scrub_transcript", True):
            return
        keys = set().union(*(_keys(t) for t in new)) - set().union(*(_keys(t) for t in texts))
        vault = Vault(cfg)
        values = [v for v in (vault.backend.get(k) for k in sorted(keys)) if v]
        if not values:
            return
        from .hooks import _SESSION_ID_RE, _scrub_transcript_later
        _scrub_transcript_later("", values, [], session=session)
        if isinstance(agent, str) and _AGENT.fullmatch(agent) and session and _SESSION_ID_RE.fullmatch(session):
            from pathlib import Path
            base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
            name = agent if agent.startswith("agent-") else "agent-" + agent
            for path in base.glob(f"*/{session}/subagents/{name}.jsonl"):
                _scrub_transcript_later(str(path), values, [])
    except Exception:  # noqa: BLE001 - the answer stands; the scrub is the transcript's, not the model's
        pass
