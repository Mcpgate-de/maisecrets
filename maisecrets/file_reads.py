"""Reads of PDFs and images: what the person decides with the settings read_pdf and read_image.

maisecrets cannot look inside an image or a PDF: the client sends its bytes to the model, and a scan of the base64
text finds nothing real (a 1 MB image took 30 s and gave one false hit, which also broke the image). So the person
decides per type (C26):

    allow    the file goes to the model as it is (the default; a hint names the setting once)
    ask      Claude Code asks the person first; Codex cannot ask, so it refuses with a hint
    block    the read is refused
    convert  PDF only: the PDF never reaches the model. The text that `pdftotext` extracts on this computer takes
             its place, and the normal redaction masks it.

The shapes are measured (Claude Code 2.1.296, harness/probe_file_reads.py, goldens in harness/golden/). PreToolUse
gets the path; PostToolUse gets {type: "image" | "pdf" | "parts", file: {...}}. Only an answer in the shape of a
text Read removes the image or the PDF from the request: a string fails the client's shape check and the original
is sent, and a PDF-shaped answer with an empty base64 still sends the whole PDF. So every answer here that stands in
for a PDF or an image is `text_result()`, also a refusal. Folders in the list setting clean_dirs are the person's
own decision: a file there that was in place before the session passes as allow. A Bash result that the client
marks isImage (its stdout is a data:image URI) reaches the model as an image; it counts as an image read, and only
its stdout skips the scan. Only the client's own isImage counts: a text that only starts like a data URI is text,
and is scanned as text. A notebook Read whose outputs hold an image counts as an image read too: ask and block send
it as text without the images. A pasted image and an image in an MCP result never reach this module (known gaps,
README).
"""
from __future__ import annotations

import os
import re

MODES = {"read_pdf": ("allow", "ask", "block", "convert"), "read_image": ("allow", "ask", "block")}
SETTING = {"pdf": "read_pdf", "image": "read_image"}
# the extensions the Read tool sends as an image or a document; the response type below is the backstop
_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
TEXT_KEYS = ("filePath", "content", "numLines", "startLine", "totalLines")

# the extraction must end well inside the 16 s watchdog of PostToolUse, and the redaction of its text after it. The
# redaction has no time cap of its own here: the cap on the text is the bound. Measured on 3.9 (stub pdftotext, the
# whole hook): the worst text found, AWS key shapes side by side, took 2.4 s at 32K characters, 8.2 s at 64K and
# 97 s at 256K (one rule grows with the square of the text); prose takes 0.5 s at 32K
EXTRACT_SECONDS = 6.0
MAX_PDF_BYTES = 100 * 1024 * 1024
MAX_TEXT_CHARS = 32 * 1024
# a client started from the desktop has a short PATH; these hold pdftotext from Homebrew, MacPorts and Linux packages
_EXTRA_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin")
INSTALL = ("macOS: brew install poppler; Debian or Ubuntu: sudo apt install poppler-utils; Fedora: sudo dnf install "
           "poppler-utils; Windows: the poppler or Xpdf command line tools")


def kind_of_path(path: str) -> str | None:
    low = path.lower()
    if low.endswith(".pdf"):
        return "pdf"
    if low.endswith(_IMAGE_EXT):
        return "image"
    return None


def kind_of_response(tool: str, response) -> str | None:
    """What the client is about to send as a file: "pdf", "image" or None (text, or not a read)."""
    if not isinstance(response, dict):
        return None
    if tool == "Read":
        if response.get("type") == "notebook":
            return "image" if _notebook_images(response) else None
        return {"pdf": "pdf", "parts": "pdf", "image": "image"}.get(response.get("type"))
    if tool == "Bash" and response.get("isImage") is True:
        # the client's own flag, never a guess from the text: a stdout that only starts like a data URI is text,
        # and text is scanned (a guess here let every Bash output pass unscanned, review of block 4)
        return "image"
    return None


def _notebook_outputs(response: dict):
    file = response.get("file") if isinstance(response.get("file"), dict) else {}
    for cell in file.get("cells") or []:
        if isinstance(cell, dict):
            for out in cell.get("outputs") or []:
                if isinstance(out, dict):
                    yield cell, out


def _notebook_images(response: dict) -> int:
    return sum(1 for _c, out in _notebook_outputs(response) if out.get("image"))


def hold_images(response: dict) -> tuple:
    """A copy of a notebook result whose image data is empty, and the data taken out, in order. The scan walks the
    rest: base64 is no text to scan (300 KB took 7.5 s, review of block 4), the cells are."""
    import copy
    held = []
    out = copy.deepcopy(response)
    for _cell, o in _notebook_outputs(out):
        img = o.get("image")
        if isinstance(img, dict) and isinstance(img.get("image_data"), str):
            held.append(img["image_data"])
            img["image_data"] = ""
    return out, held


def put_back_images(response, held: list) -> None:
    if not isinstance(response, dict):
        return
    data = iter(held)
    for _cell, o in _notebook_outputs(response):
        img = o.get("image")
        if isinstance(img, dict) and img.get("image_data") == "":
            img["image_data"] = next(data, "")


def notebook_has_image(path: str) -> bool:
    """The file holds an image output (a mime type image/... in it). Too large or unreadable: True (ask)."""
    try:
        if os.path.getsize(path) > 50 * 1024 * 1024:
            return True
        with open(path, "rb") as f:
            return b'"image/' in f.read()
    except OSError:
        return True


def notebook_text(response: dict, note: str) -> str:
    """A notebook as text, every image output replaced by the note (measured: the text shape takes a notebook's
    image out of the request too, harness/golden/file_reads_model_view.json nb_replace_text)."""
    file = response.get("file") if isinstance(response.get("file"), dict) else {}
    parts = []
    for cell in file.get("cells") or []:
        if not isinstance(cell, dict):
            continue
        cid = str(cell.get("cell_id") or "")
        parts.append(f'<cell id="{cid}">{cell.get("source") or ""}</cell id="{cid}">')
        for out in cell.get("outputs") or []:
            if not isinstance(out, dict):
                continue
            if out.get("text"):
                parts.append(str(out["text"]))
            if out.get("ename") or out.get("evalue") or out.get("traceback"):
                tb = out.get("traceback")
                tb = "\n".join(map(str, tb)) if isinstance(tb, list) else str(tb or "")
                parts.append(f"{out.get('ename') or ''}: {out.get('evalue') or ''}" + (f"\n{tb}" if tb else ""))
            if out.get("image"):
                parts.append(f"[{note}]")
    return "\n\n".join(parts)


def mode(cfg: dict, kind: str) -> str:
    """The person's mode for this kind. A value that is no mode (a hand-edited file) blocks: it fails closed."""
    key = SETTING[kind]
    value = cfg.get(key, "allow")
    return value if value in MODES[key] else "block"


def _real(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
SEEN_DAYS = 30


def _seen_path(session):
    from .vault import HOME
    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        return None
    return os.path.join(str(HOME), "sessions-seen", session)


NESTED = "nested"
_CLIENTS = ("claude", "codex")


def nested_client() -> bool:
    """A client that runs below another client (an agent that started `claude -p` or `codex exec` in its shell). The
    environment cannot tell: Claude Code sets CLAUDECODE=1 and its own session id for a top-level session too
    (measured on 2.1.296). The process chain can: above the hook there is one client, or two. A process list that
    cannot be read counts as nested (no clean folder)."""
    import subprocess
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,comm="], capture_output=True, text=True, timeout=3,
                             stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError):
        return True
    parent, name = {}, {}
    for line in out.splitlines():
        bits = line.split(None, 2)
        if len(bits) == 3 and bits[0].isdigit() and bits[1].isdigit():
            parent[int(bits[0])], name[int(bits[0])] = int(bits[1]), os.path.basename(bits[2].strip())
    pid, clients, steps = os.getpid(), 0, 0
    if pid not in parent:
        return True
    while pid in parent and pid > 1 and steps < 64:
        clients += name.get(pid) in _CLIENTS
        pid, steps = parent[pid], steps + 1
    # the session's own client and one more above it. A client that runs under another name (an npm install runs as
    # node) is not counted, so one nested in it is not seen (C26)
    return clients >= 2


def note_session_start(payload: dict) -> None:
    """SessionStart: note when this session began, the anchor of clean_dirs (C26). Only here: a prompt or a tool call
    never writes the note, so a note that the agent deletes is not made again with a later time (nothing is clean
    then). Not at a compaction, which the agent can bring about with a long output. A nested client gets a note that
    makes no folder clean."""
    if payload.get("source") == "compact":
        return
    session = payload.get("session_id")
    path = _seen_path(session)
    if not path or os.name == "nt":
        return
    folder = os.path.dirname(path)
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        if os.path.islink(folder) or os.path.lexists(path):
            return
        import time
        text = NESTED if nested_client() else repr(time.time())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    except OSError:
        pass


def prune_sessions() -> None:
    """SessionStart: the notes of sessions older than SEEN_DAYS go."""
    import time
    folder = os.path.dirname(_seen_path("x"))
    try:
        if os.path.islink(folder):
            return
        for name in os.listdir(folder):
            f = os.path.join(folder, name)
            if os.lstat(f).st_mtime < time.time() - SEEN_DAYS * 86400:
                os.unlink(f)
    except OSError:
        pass


def session_start(session) -> float | None:
    """When this session began, or None (no note, a link, a nested client: nothing is clean). The earliest of the
    time written in the note, its mtime and its inode change time: a touch or utime moves the two times of the file,
    never the text in it, and a rewrite of the text moves the change time to now."""
    import stat
    path = _seen_path(session)
    if not path:
        return None
    try:
        if stat.S_ISLNK(os.lstat(os.path.dirname(path)).st_mode):
            return None
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd) as f:
            text = f.read(64).strip()
        if text == NESTED:
            return None
        return min(float(text), st.st_mtime, st.st_ctime)
    except (OSError, ValueError):
        return None


def in_clean_dir(path: str, cwd: str, cfg: dict, session=None) -> bool:
    """The file lies in a folder of clean_dirs and was there before the session began. Both sides are resolved first
    (links and ..), so a link inside a clean folder that points out of it, or a path that climbs out with .., is not
    inside. The file itself must have one name only (a hard link from outside has two) and an inode change time
    older than the start of this session (session_start): a copy, a move or a link that the agent makes into the
    folder changes that time, and no command sets it back. The note of the start lies in the maisecrets folder, which
    the agent's tools may not touch (C8); an obfuscated command can still move it (C8 matches the command text). No
    note: nothing is clean."""
    dirs = [d for d in cfg.get("clean_dirs") or [] if isinstance(d, str) and d.strip()]
    if not dirs or not path or os.name == "nt":
        # Windows: st_ctime is the creation time there, and a move keeps it. clean_dirs is for macOS and Linux
        return False
    full = path if os.path.isabs(os.path.expanduser(path)) else os.path.join(cwd or os.getcwd(), path)
    try:
        real = _real(os.path.expanduser(full))
        inside = False
        for d in dirs:
            d = os.path.expanduser(d.strip())
            if not os.path.isabs(d):
                continue
            base = _real(d)
            if real != base and os.path.commonpath([real, base]) == base:
                inside = True
                break
        if not inside:
            return False
        started = session_start(session)
        st = os.stat(os.path.realpath(os.path.expanduser(full)))
        return started is not None and st.st_nlink == 1 and st.st_ctime < started
    except (OSError, ValueError):
        return False


def text_result(file_path: str, content: str) -> dict:
    """The measured shape of a text Read: the only answer that takes an image or a PDF out of the request."""
    lines = content.count("\n") + 1 if content else 1
    return {"type": "text", "file": {"filePath": file_path, "content": content, "numLines": lines, "startLine": 1,
                                     "totalLines": lines}}


def pdftotext() -> str | None:
    """The fixed folders of the package managers first, then the PATH: a folder early on the PATH that the agent
    can write to must not put its own pdftotext in front of the real one."""
    for d in _EXTRA_DIRS:
        p = os.path.join(d, "pdftotext")
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    import shutil       # here, not at the top: this module loads on every PostToolUse
    return shutil.which("pdftotext")


def missing_tool_text(codex: bool) -> str:
    change = "maisecrets: set read_pdf" if codex else "/maisecrets:settings read_pdf"
    return (f"maisecrets: the setting read_pdf is convert, and convert needs the program pdftotext, which is not "
            f"installed (not on the PATH). Nothing of the PDF reached you. Tell the user to install it ({INSTALL}) "
            f"and to read the PDF again, or to choose another mode with {change} allow, ask or block.")


_PAGES_RE = re.compile(r"\A\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?\Z")


def page_range(pages) -> tuple[int, int] | None | str:
    """The Read tool's `pages` ("3", "1-5") as (first, last); None for the whole file; a text when it is no range."""
    if pages in (None, ""):
        return None
    m = _PAGES_RE.match(str(pages))
    if not m:
        return f"the page range '{str(pages)[:20]}' is not one page or one range like 1-5"
    first, last = int(m.group(1)), int(m.group(2) or m.group(1))
    if first < 1 or last < first:
        return f"the page range '{str(pages)[:20]}' is not one page or one range like 1-5"
    return first, last


def _wait(thread, seconds: float) -> None:
    thread.join(seconds)


def _stop(child) -> None:
    """End pdftotext and its process group, if it still runs."""
    if child.poll() is not None:
        return
    try:
        if os.name == "nt":
            child.kill()
        else:
            import signal
            os.killpg(child.pid, signal.SIGKILL)
    except OSError:
        child.kill()
    child.wait()


def extract(path: str, pages=None) -> tuple[str | None, str]:
    """(text, "") or (None, why). Every failure is a refusal: nothing of the PDF passes when the text is missing."""
    tool = pdftotext()
    if not tool:
        return None, "missing"
    rng = page_range(pages)
    if isinstance(rng, str):
        return None, rng
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, "the file cannot be read"
    if size > MAX_PDF_BYTES:
        return None, f"the file is larger than {MAX_PDF_BYTES // (1024 * 1024)} MB"
    args = [tool, "-q", "-enc", "UTF-8"]
    if rng:
        args += ["-f", str(rng[0]), "-l", str(rng[1])]
    args += [path, "-"]
    import subprocess   # here, not at the top: this module loads on every PostToolUse
    import threading
    try:
        # its own process group: a stop ends pdftotext and anything it started, so nobody holds the pipe open
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 **({} if os.name == "nt" else {"start_new_session": True}))
    except OSError as exc:
        return None, f"pdftotext did not start ({type(exc).__name__})"
    cap = MAX_TEXT_CHARS * 4          # UTF-8 bytes: at most 4 for one character
    buf = bytearray()

    def pump() -> None:
        # read in chunks up to the cap and no further: a huge text is never held in memory as a whole
        try:
            while len(buf) < cap:
                chunk = os.read(child.stdout.fileno(), min(65536, cap - len(buf)))
                if not chunk:
                    return
                buf.extend(chunk)
        except (OSError, ValueError):
            return
    reader = threading.Thread(target=pump, daemon=True)
    full = False
    try:
        reader.start()
        _wait(reader, EXTRACT_SECONDS)
        if reader.is_alive():
            return None, f"pdftotext took longer than {EXTRACT_SECONDS:g} s"
        full = len(buf) >= cap
        if not full:
            try:
                child.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                return None, f"pdftotext took longer than {EXTRACT_SECONDS:g} s"
    finally:
        # any way out, also an exception that a watchdog could raise here: the child ends with the hook. The
        # exception goes on to the fail-closed answer, which withholds the file
        _stop(child)
        reader.join(0.5)
        try:
            child.stdout.close()
        except OSError:
            pass
    if not full and child.returncode != 0:
        return None, f"pdftotext failed (exit {child.returncode}); the file may be damaged or protected by a password"
    text = bytes(buf).decode("utf-8", errors="replace").replace("\f", "\n")
    if full or len(text) > MAX_TEXT_CHARS:
        text = (text[:MAX_TEXT_CHARS] + f"\n[maisecrets: the text stops here, after {MAX_TEXT_CHARS} characters. "
                "Read the PDF again with `pages` set to a smaller range to see the rest.]")
    if not text.strip():
        text = ("[maisecrets: pdftotext found no text in this PDF (a scan or an image). maisecrets does no OCR, so "
                "nothing of it reached you.]")
    return text, ""


# --------------------------------------------------------------- messages --
def refusal(kind: str, why: str, codex: bool) -> str:
    """The text for a read that a mode stops (pre-tool deny, or the text that stands in for the file)."""
    key = SETTING[kind]
    noun = "PDF" if kind == "pdf" else "image"
    change = f"maisecrets: set {key}" if codex else f"/maisecrets:settings {key}"
    others = "allow, ask or convert" if kind == "pdf" else "allow or ask"
    if why == "config":
        return (f"maisecrets: this {noun} was not read. The maisecrets config.json cannot be read, so {key} counts "
                "as block until the file is fixed (the session start named the problem). Do not try to read it "
                "another way. Tell the user to fix the file.")
    if why == "block":
        return (f"maisecrets: this {noun} was not read; the setting {key} is block. Do not try to read it another "
                f"way. If the user wants it read, they send {change} {others} as their own prompt.")
    if why == "ask-codex":
        return (f"maisecrets: this {noun} was not read; the setting {key} is ask, and Codex cannot ask the user "
                "here. Do not try to read it another way. Tell the user: to allow it, they send "
                f"{change} allow alone as their own prompt.")
    if why == "ask-unseen":
        return (f"maisecrets: this {noun} was not shown to you; the setting {key} is ask, and the call did not "
                "name the file in a way maisecrets could ask about first. Tell the user the file name and ask "
                "them to read it themselves, or to change the setting.")
    if why == "missing":
        return missing_tool_text(codex)
    return (f"maisecrets: this PDF was not converted to text ({why}), so nothing of it reached you. Do not try "
            f"to read it another way. Tell the user; they can choose another mode with {change}.")


def ask_reason(kind: str) -> str:
    noun = "PDF" if kind == "pdf" else "image"
    return (f"maisecrets: the AI wants to read this {noun}. maisecrets cannot look inside it, so all of it goes to "
            f"the AI as it is, including any password or personal data (setting {SETTING[kind]} ask). "
            "Allow it only if the file holds nothing secret.")


# ------------------------------------------------------------ hook steps --
def _block_why(cfg: dict) -> str:
    return "config" if cfg.get("read_fallback") else "block"


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def pre_read(payload: dict, cfg: dict, codex: bool) -> dict:
    """PreToolUse of Read: stop a PDF or an image before its bytes exist in the session (the transcript keeps
    them). {} lets the read run."""
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    path = tool_input.get("file_path")
    if isinstance(path, str) and path.lower().endswith(".ipynb") and not codex and mode(cfg, "image") == "ask":
        # a notebook with an image output: ask before it, as for an image (its text is scanned anyway)
        full = path if os.path.isabs(path) else os.path.join(str(payload.get("cwd") or ""), path)
        if notebook_has_image(full) and not in_clean_dir(path, str(payload.get("cwd") or ""), cfg,
                                                         payload.get("session_id")):
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                           "permissionDecisionReason": ask_reason("image")}}
        return {}
    kind = kind_of_path(path) if isinstance(path, str) else None
    if not kind or in_clean_dir(path, str(payload.get("cwd") or ""), cfg, payload.get("session_id")):
        return {}
    how = mode(cfg, kind)
    if how == "allow":
        return {}
    if how == "block":
        return _deny(refusal(kind, _block_why(cfg), codex))
    if how == "ask":
        if codex:
            return _deny(refusal(kind, "ask-codex", codex))
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": ask_reason(kind)}}
    # convert: refuse now what the PostToolUse would refuse anyway, before the client renders the file
    if not pdftotext():
        return _deny(refusal(kind, "missing", codex))
    rng = page_range(tool_input.get("pages"))
    if isinstance(rng, str):
        return _deny(refusal(kind, rng, codex))
    return {}


def _withheld(tool: str, response: dict, path: str, text: str) -> dict:
    if tool == "Bash":
        # the client's own Bash shape with isImage off: the text goes to the model as text
        return {**response, "stdout": text, "stderr": "", "isImage": False}
    return text_result(path, text)


def post_read(payload: dict, cfg: dict, codex: bool) -> tuple | None:
    """PostToolUse: None for any result that is no image or PDF (the normal redaction runs on it); ("pass",) for
    one that goes to the model as it is, unscanned (a Bash image: its stdout only); ("hold",) for a notebook whose
    image data passes while its cells are scanned; ("replace", response, note) for one this hook replaces. The
    replacement is always a text Read (or a text Bash result); the normal redaction then runs on it."""
    tool = payload.get("tool_name") or ""
    response = payload.get("tool_response")
    kind = kind_of_response(tool, response)
    if not kind:
        return None
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    path = tool_input.get("file_path") if isinstance(tool_input.get("file_path"), str) else ""
    if not path and isinstance(response.get("file"), dict):
        path = str(response["file"].get("filePath") or "")
    clean = tool == "Read" and in_clean_dir(path, str(payload.get("cwd") or ""), cfg, payload.get("session_id"))
    how = mode(cfg, kind)
    if tool == "Read" and response.get("type") == "notebook":
        # its cells are text and are scanned as always, its image data is held out of the scan; ask (without the
        # PreToolUse ask: Codex, or a file that changed) and block take the images out
        asked = how == "ask" and not codex and path.lower().endswith(".ipynb")
        if how == "allow" or clean or asked:
            return ("hold",)
        why = _block_why(cfg) if how != "ask" else ("ask-codex" if codex else "ask-unseen")
        n = _notebook_images(response)
        text = notebook_text(response, f"maisecrets: an image output was withheld (setting read_image {how})")
        return ("replace", text_result(path, text + "\n\n[" + refusal(kind, why, codex) + "]"),
                f"maisecrets withheld {n} image(s) of this notebook from the AI (read_image {how}).")
    if clean:
        return ("pass",)
    key = SETTING[kind]
    noun = "PDF" if kind == "pdf" else "image"
    if how == "allow":
        return ("pass",)
    if how == "ask":
        if tool == "Read" and not codex and kind_of_path(path) == kind:
            return ("pass",)          # the PreToolUse asked, and the person said yes
        why = "ask-codex" if codex else "ask-unseen"
        return ("replace", _withheld(tool, response, path, refusal(kind, why, codex)),
                f"maisecrets withheld this {noun} from the AI ({key} ask).")
    if how == "convert" and tool == "Read":
        full = path if os.path.isabs(path) else os.path.join(str(payload.get("cwd") or ""), path)
        text, why = extract(full, tool_input.get("pages"))
        if text is None:
            return ("replace", _withheld(tool, response, path, refusal(kind, why, codex)),
                    f"maisecrets withheld this PDF from the AI: it could not be converted to text ({why}).")
        return ("replace", text_result(path, text),
                "maisecrets sent this PDF to the AI as text only, with secrets and personal data masked "
                "(read_pdf convert).")
    return ("replace", _withheld(tool, response, path, refusal(kind, _block_why(cfg), codex)),
            f"maisecrets withheld this {noun} from the AI ({key} {how}).")


def hint(payload: dict, cfg: dict, codex: bool) -> str | None:
    """The one-time hint for read_pdf or read_image: the first image or PDF that reaches the model while the person
    has not decided. Not in a subagent: it has no conversation with the person."""
    if payload.get("agent_id"):
        return None
    kind = kind_of_response(payload.get("tool_name") or "", payload.get("tool_response"))
    if not kind or mode(cfg, kind) != "allow":
        return None
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    path = tool_input.get("file_path")
    if isinstance(path, str) and in_clean_dir(path, str(payload.get("cwd") or ""), cfg, payload.get("session_id")):
        return None
    from . import settings
    key = SETTING[kind]
    if not settings.hint_due(key, cfg) or not settings.claim_hint(key):
        return None
    return settings.HINTS[key]["codex" if codex else "claude"]


def as_text(response) -> str:
    """Codex has no updatedToolOutput: its block reason is the text the model reads."""
    if isinstance(response, dict) and isinstance(response.get("file"), dict):
        return str(response["file"].get("content", ""))
    if isinstance(response, dict) and "stdout" in response:
        return str(response.get("stdout", ""))
    return response if isinstance(response, str) else ""
