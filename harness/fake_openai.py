"""A fake OpenAI Responses endpoint for the Codex harness.

Codex is pointed here with an API-key login (a dummy key) and
``openai_base_url``. The server answers ``GET /v1/models`` with one model,
records every ``POST /v1/responses`` body to disk, and streams a scripted
turn as Responses SSE events: a function call (Codex's shell tool) or a text
message, then ``response.completed``.

Scenario file (JSON): {"turns": [ {"exec": "<javascript>"} | {"tool": "<name>", "args": {...}} | {"text": "..."} ]}

Codex 0.155 runs "code mode": the model calls the custom tool ``exec`` with raw
JavaScript that calls nested tools, e.g. ``await tools.exec_command({cmd: "cat .env"})``.
Request bodies arrive zstd-compressed; they are stored decompressed.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SCENARIO = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {"turns": [{"text": "ok"}]}
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "harness/out"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8792
os.makedirs(OUT_DIR, exist_ok=True)
_lock = threading.Lock()
_state = {"n": 0}


def _sse(events: list[dict]) -> bytes:
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def _turn_events(turn: dict, n: int, model: str) -> bytes:
    rid = f"resp_{n}"
    base = {"id": rid, "object": "response", "model": model, "status": "in_progress", "output": []}
    ev: list[dict] = [{"type": "response.created", "response": base},
                      {"type": "response.in_progress", "response": base}]
    if "exec" in turn:
        code = turn["exec"]
        item = {"type": "custom_tool_call", "id": f"ctc_{n}", "call_id": f"call_{n}", "name": "exec",
                "input": code, "status": "completed"}
        ev += [
            {"type": "response.output_item.added", "output_index": 0,
             "item": {**item, "input": "", "status": "in_progress"}},
            {"type": "response.custom_tool_call_input.delta", "item_id": item["id"], "output_index": 0, "delta": code},
            {"type": "response.custom_tool_call_input.done", "item_id": item["id"], "output_index": 0, "input": code},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
        ]
    elif "tool" in turn:
        args = json.dumps(turn["args"])
        item = {"type": "function_call", "id": f"fc_{n}", "call_id": f"call_{n}", "name": turn["tool"],
                "arguments": args, "status": "completed"}
        ev += [
            {"type": "response.output_item.added", "output_index": 0,
             "item": {**item, "arguments": "", "status": "in_progress"}},
            {"type": "response.function_call_arguments.delta", "item_id": item["id"], "output_index": 0, "delta": args},
            {"type": "response.function_call_arguments.done", "item_id": item["id"], "output_index": 0,
             "arguments": args},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
        ]
    else:
        text = turn.get("text", "ok")
        item = {"type": "message", "id": f"msg_{n}", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}]}
        ev += [
            {"type": "response.output_item.added", "output_index": 0,
             "item": {**item, "content": [], "status": "in_progress"}},
            {"type": "response.content_part.added", "item_id": item["id"], "output_index": 0, "content_index": 0,
             "part": {"type": "output_text", "text": "", "annotations": []}},
            {"type": "response.output_text.delta", "item_id": item["id"], "output_index": 0, "content_index": 0,
             "delta": text},
            {"type": "response.output_text.done", "item_id": item["id"], "output_index": 0, "content_index": 0,
             "text": text},
            {"type": "response.content_part.done", "item_id": item["id"], "output_index": 0, "content_index": 0,
             "part": {"type": "output_text", "text": text, "annotations": []}},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
        ]
    done = {**base, "status": "completed", "output": [item],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                      "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}
    ev.append({"type": "response.completed", "response": done})
    return _sse(ev)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # a WebSocket upgrade against HTTP/1.0 makes Codex retry 5x before it falls back

    def log_message(self, *a):
        pass

    def _json(self, code: int, obj) -> None:
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if "websocket" in self.headers.get("upgrade", "").lower():
            self._json(404, {"error": {"message": "no websocket here, use HTTP"}})   # Codex falls back to HTTP
            return
        if self.path.startswith("/v1/models"):
            self._json(200, {"object": "list", "data": [{"id": "gpt-5.6-sol", "object": "model"}]})
        else:
            self._json(200, {"ok": True, "requests": _state["n"]})

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        if self.headers.get("content-encoding", "").lower() == "zstd" or body[:4] == b"\x28\xb5\x2f\xfd":
            from compression import zstd   # Python 3.14+
            body = zstd.decompress(body)
        if not self.path.startswith("/v1/responses"):
            self._json(404, {"error": {"message": f"no route {self.path}"}})
            return
        with _lock:
            i = _state["n"]
            _state["n"] += 1
        with open(os.path.join(OUT_DIR, f"request_{i:02d}.json"), "wb") as f:
            f.write(body)
        try:
            model = json.loads(body).get("model", "gpt-5.6-sol")
        except ValueError:
            model = "gpt-5.6-sol"
        turns = SCENARIO["turns"]
        turn = turns[i] if i < len(turns) else {"text": "done"}
        payload = _turn_events(turn, i, model)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
