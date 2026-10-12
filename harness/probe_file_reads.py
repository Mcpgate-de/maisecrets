"""One-off probe: what Claude Code's hooks receive for image and PDF reads (epic block 4 research).

Runs the real `claude -p` against harness/fake_anthropic.py with an isolated CLAUDE_CONFIG_DIR and a dummy API key,
without the maisecrets plugin (the payloads do not depend on it). A dump hook records every payload; an optional
control hook answers PreToolUse or PostToolUse to test what a hook can stop or replace. The request bodies the fake
upstream records show what the model would see.

Usage: python3 harness/probe_file_reads.py OUTDIR [probe ...]
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 8797


def png_2x2() -> bytes:
    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * 2 for _ in range(2))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def pdf_hello() -> bytes:
    return pdf_lines("hello", size=24)


def pdf_lines(*lines: str, size: int = 12) -> bytes:
    """A one-page PDF with these lines in Helvetica (latin-1 text), standard library only."""
    content = b" ".join(b"BT /F1 %d Tf 72 %d Td (%s) Tj ET" % (size, 720 - 2 * size * i, ln.encode("latin-1"))
                        for i, ln in enumerate(lines))
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


CONTROL = r'''
import json, os, sys
p = json.load(sys.stdin)
mode = os.environ.get("PROBE_CONTROL", "")
ev = p.get("hook_event_name")
if ev == "PreToolUse" and mode in ("deny", "ask"):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": mode,
                                             "permissionDecisionReason": "PROBE-" + mode.upper() + ": withheld"}}))
elif ev == "PostToolUse" and mode == "replace":
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                             "updatedToolOutput": "PROBE-REPLACED: image withheld"}}))
elif ev == "PostToolUse" and mode == "replace_obj":
    r = p.get("tool_response")
    if isinstance(r, dict) and isinstance(r.get("file"), dict) and "base64" in r["file"]:
        r = json.loads(json.dumps(r)); r["file"]["base64"] = ""
        r["file"]["note"] = "PROBE-REPLACED-OBJ"
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": r}}))
elif ev == "PostToolUse" and mode == "replace_text":
    # the shape of Read's text result, in place of an image or a PDF
    fp = p.get("tool_input", {}).get("file_path", "")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {
        "type": "text", "file": {"filePath": fp, "content": "PROBE-REPLACED-TEXT: withheld", "numLines": 1,
                                 "startLine": 1, "totalLines": 1}}}}))
elif ev == "PostToolUse" and mode == "replace_pdf_obj":
    r = json.loads(json.dumps(p.get("tool_response")))
    r["file"]["base64"] = ""
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": r}}))
elif ev == "UserPromptSubmit" and mode == "block_prompt":
    print(json.dumps({"decision": "block", "reason": "PROBE-BLOCK"}))
else:
    print("{}")
'''

DUMP = r'''
import json, os, sys, time
raw = sys.stdin.read()
p = json.loads(raw)
d = os.environ["PROBE_DUMP"]
name = f"{time.time():.4f}_{p.get('hook_event_name','x')}_{p.get('tool_name','')}.json"
open(os.path.join(d, name), "w").write(raw)
print("{}")
'''

PROBES = {
    "read_png": {"turns": [{"tool": "Read", "input": {"file_path": "{cwd}/tiny.png"}}, {"text": "done"}]},
    "read_pdf": {"turns": [{"tool": "Read", "input": {"file_path": "{cwd}/hello.pdf"}}, {"text": "done"}]},
    "read_pdf_pages": {"turns": [{"tool": "Read", "input": {"file_path": "{cwd}/hello.pdf", "pages": "1"}},
                                 {"text": "done"}]},
    "bash_base64": {"turns": [{"tool": "Bash", "input": {"command": "base64 < tiny.png"}}, {"text": "done"}]},
    "bash_datauri": {"turns": [{"tool": "Bash", "input": {
        "command": "printf 'data:image/png;base64,'; base64 < tiny.png"}}, {"text": "done"}]},
    "png_deny": {"control": "deny", "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/tiny.png"}},
                                              {"text": "done"}]},
    "png_ask": {"control": "ask", "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/tiny.png"}},
                                            {"text": "done"}]},
    "png_replace": {"control": "replace", "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/tiny.png"}},
                                                    {"text": "done"}]},
    "png_replace_obj": {"control": "replace_obj",
                        "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/tiny.png"}}, {"text": "done"}]},
    "pdf_replace": {"control": "replace", "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/hello.pdf"}},
                                                    {"text": "done"}]},
    "png_replace_text": {"control": "replace_text",
                         "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/tiny.png"}}, {"text": "done"}]},
    "pdf_replace_text": {"control": "replace_text",
                         "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/hello.pdf"}}, {"text": "done"}]},
    "pdf_replace_obj": {"control": "replace_pdf_obj",
                        "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/hello.pdf"}}, {"text": "done"}]},
    # a pasted image as the SDK sends it: an image block in a stream-json user message
    "paste_stream_json": {"stream_image": True, "turns": [{"text": "seen"}]},
    "paste_stream_json_block": {"stream_image": True, "control": "block_prompt", "turns": [{"text": "seen"}]},
}


def run(name: str, sc: dict, base: Path) -> None:
    work = base / name
    shutil.rmtree(work, ignore_errors=True)
    cwd, out, dump, cfg = work / "proj", work / "out", work / "dump", work / "config"
    for d in (cwd, out, dump, cfg):
        d.mkdir(parents=True)
    (cwd / "tiny.png").write_bytes(png_2x2())
    (cwd / "hello.pdf").write_bytes(pdf_hello())
    (work / "dump_hook.py").write_text(DUMP)
    (work / "control_hook.py").write_text(CONTROL)
    py = sys.executable
    hooks = {ev: [{"hooks": [{"type": "command", "command": f"{py} {work / 'dump_hook.py'}"}]},
                  {"hooks": [{"type": "command", "command": f"{py} {work / 'control_hook.py'}"}]}]
             for ev in ("UserPromptSubmit", "PreToolUse", "PostToolUse")}
    (work / "settings.json").write_text(json.dumps({"hooks": hooks}))
    turns = json.loads(json.dumps(sc["turns"]).replace("{cwd}", cwd.as_posix()))
    (out / "scenario.json").write_text(json.dumps({"turns": turns}))
    srv = subprocess.Popen([py, str(ROOT / "harness" / "fake_anthropic.py"), str(out / "scenario.json"), str(out),
                            str(PORT)])
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
            break
        except Exception:
            time.sleep(0.1)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "CLAUDE_", "MAISECRETS_"))}
    env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", ANTHROPIC_API_KEY="sk-ant-probe-dummy",
               CLAUDE_CONFIG_DIR=str(cfg), CLAUDE_CODE_MAX_RETRIES="0", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
               PROBE_DUMP=str(dump), PROBE_CONTROL=sc.get("control", ""))
    args = [shutil.which("claude"), "-p", "--settings", str(work / "settings.json"), "--permission-mode", "default",
            "--allowedTools", "Bash,Read", "--max-turns", "3", "--debug-file", str(work / "debug.log")]
    stdin = subprocess.DEVNULL
    inp = None
    if sc.get("stream_image"):
        import base64
        msg = {"type": "user", "message": {"role": "user", "content": [
            {"type": "text", "text": "what is in this image?"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                         "data": base64.b64encode(png_2x2()).decode()}}]}}
        args += ["--input-format", "stream-json", "--output-format", "stream-json", "--verbose"]
        inp, stdin = json.dumps(msg) + "\n", None
    else:
        args.append("read the file")
    try:
        r = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=120, stdin=stdin,
                           input=inp)
    finally:
        srv.terminate()
    (work / "stdout.txt").write_text(r.stdout + "\n--- stderr ---\n" + r.stderr)
    print(f"{name}: rc={r.returncode} requests={len(list(out.glob('request_*.json')))} "
          f"payloads={sorted(p.name.split('_', 1)[1] for p in dump.glob('*.json'))}")


if __name__ == "__main__":
    base = Path(sys.argv[1])
    for n in sys.argv[2:] or list(PROBES):
        run(n, PROBES[n], base)
