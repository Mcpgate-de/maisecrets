"""The detect-secrets adapter (Yelp, Apache-2.0). It runs in a new process of the Python that
BENCH_DETECT_SECRETS_PYTHON names (an environment with `pip install detect-secrets==1.5.0`), else this Python.

Each case is written to a file of its own (named as its path, else input.txt) and scanned with
`SecretsCollection.scan_file` under the default settings (all plugins, the default filters), as `detect-secrets scan`
does. A finding is a secret value it reports; its offset is the first place of that value in its line. Every
plugin of detect-secrets finds secrets, so its scope is `secret.`."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

NAME = "detect-secrets"
SCOPE = ("secret.",)
VERSION = "1.5.0"

_WORKER = r'''
import json, os, sys, tempfile, time
t0 = time.perf_counter()
from detect_secrets import SecretsCollection
from detect_secrets.__version__ import VERSION
from detect_secrets.settings import default_settings
first, times = None, []
work = tempfile.mkdtemp(prefix="ds-case-", dir=os.getcwd())
with default_settings() as settings, open(sys.argv[1], encoding="utf-8") as fin, \
        open(sys.argv[2], "w", encoding="utf-8") as fout:
    plugins = sorted(settings.plugins)
    for n, line in enumerate(fin):
        case = json.loads(line)
        text = case["text"]
        name = os.path.basename(case.get("path") or "") or "input.txt"
        d = os.path.join(work, str(n))
        os.mkdir(d)
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        t = time.perf_counter()
        sc = SecretsCollection()
        sc.scan_file(path)
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        lines = text.split("\n")
        starts = [0]
        for ln in lines:
            starts.append(starts[-1] + len(ln) + 1)
        out = []
        for _f, secret in sc:
            v, i = secret.secret_value, secret.line_number - 1
            if v and 0 <= i < len(lines):
                at = lines[i].find(v)
                if at >= 0:
                    out.append([starts[i] + at, starts[i] + at + len(v), "secret", secret.type])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "SecretsCollection.scan_file", "version": VERSION, "plugins": plugins, "cold_start_s": first,
           "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_DETECT_SECRETS_PYTHON") or sys.executable


def describe() -> dict:
    p = subprocess.run([_python(), "-c", "from detect_secrets.__version__ import VERSION; print(VERSION)"],
                       capture_output=True, text=True)
    return {"scanner": NAME, "version": p.stdout.strip() or None, "commit": None,
            "configuration": "default settings (all plugins, default filters), SecretsCollection.scan_file per case",
            "detectors": "all plugins of the release", "network": False,
            "dependencies": "detect-secrets and its requirements (pyyaml, requests)", "region": "none",
            "scope": list(SCOPE), "python": _python()}


def scan(cases):
    tmp = tempfile.mkdtemp(prefix="bench-ds-")
    try:
        inp, out, worker = (os.path.join(tmp, n) for n in ("in.jsonl", "out.jsonl", "worker.py"))
        with open(worker, "w", encoding="utf-8") as f:
            f.write(_WORKER)
        with open(inp, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps({"text": c["text"], "path": c.get("path")}) + "\n")
        p = subprocess.run([_python(), "-I", worker, inp, out], capture_output=True, text=True, cwd=tmp)
        if p.returncode:
            raise RuntimeError(f"detect-secrets worker failed: {p.stderr[-2000:]}")
        timing = json.loads(p.stdout)
        with open(out, encoding="utf-8") as f:
            found = [[tuple(x) for x in json.loads(line)] for line in f]
        return found, timing
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
