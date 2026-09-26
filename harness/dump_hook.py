#!/usr/bin/env python3
"""Records every hook payload to $MAISECRETS_DUMP, values redacted by the shared detector."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maisecrets import detect  # noqa: E402

payload = json.load(sys.stdin)
d = os.environ.get("MAISECRETS_DUMP")
if d:
    def redact(node):
        if isinstance(node, str):
            out = node
            for m in sorted(detect.scan(node), key=lambda x: x.start, reverse=True):
                out = out[: m.start] + f"<{m.type}_REDACTED>" + out[m.end:]
            return out
        if isinstance(node, list):
            return [redact(x) for x in node]
        if isinstance(node, dict):
            return {k: redact(v) for k, v in node.items()}
        return node
    name = f"{time.time():.3f}_{payload.get('hook_event_name','x')}_{payload.get('tool_name','')}.json"
    with open(os.path.join(d, name), "w") as f:
        json.dump(redact(payload), f, indent=1)
print("{}")
