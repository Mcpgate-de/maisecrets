"""The Preserve adapter (thirtysix/Preserve, preserve-pii, MIT). It runs in a new process of the Python that
BENCH_PRESERVE_PYTHON names (an environment with preserve-pii installed from the pinned commit).

Each case is one `Scrubber(PreserveConfig()).scrub(text)` with the default configuration (no LLM review, so no
network); a finding is an entry of `result.detections`. Preserve scrubs personal data and secrets, so its scope is both
families. Its type names are mapped to the classes of the benchmark by their words (KEY, TOKEN, ... is a secret)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

NAME = "preserve"
SCOPE = ("secret.", "pii.")
COMMIT = "01dbd77"

_WORKER = r'''
import json, sys, time
t0 = time.perf_counter()
from importlib.metadata import version
from preserve import PreserveConfig, Scrubber
WORDS = [(("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE", "JWT", "WEBHOOK", "CONNECTION"),
          "secret"), (("EMAIL",), "pii.email"), (("PHONE",), "pii.phone"), (("IBAN",), "pii.iban"),
         (("CARD", "CREDIT"), "pii.card"), (("IP",), "pii.ip"), (("NAME", "PERSON"), "pii.name"),
         (("ADDRESS", "STREET"), "pii.address"), (("DOB", "BIRTH"), "pii.birth_date"),
         (("USER",), "pii.username"), (("TAX",), "pii.tax_id")]

def cls_of(t):
    u = t.upper()
    for words, cls in WORDS:
        if any(w in u for w in words):
            return cls
    return "pii.national_id" if any(c.isdigit() for c in u) or "ID" in u or "SSN" in u else "pii.other"

config = PreserveConfig()
scrubber = Scrubber(config)
first, times, types = None, [], set()
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        text = json.loads(line)["text"]
        t = time.perf_counter()
        res = scrubber.scrub(text)
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        out = []
        for d in res.detections:
            types.add(d.replacement_type)
            out.append([d.start, d.end, cls_of(d.replacement_type), d.pattern_name])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "Scrubber.scrub", "version": version("preserve-pii"), "types_seen": sorted(types),
           "config": {k: str(v) for k, v in config.model_dump().items() if not isinstance(v, (list, dict))},
           "cold_start_s": first, "times_s": times}, sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_PRESERVE_PYTHON") or sys.executable


def describe() -> dict:
    p = subprocess.run([_python(), "-c", "from importlib.metadata import version; print(version('preserve-pii'))"],
                       capture_output=True, text=True)
    return {"scanner": NAME, "version": p.stdout.strip() or None, "commit": COMMIT,
            "configuration": "PreserveConfig() defaults (no LLM review)", "detectors": "patterns, validators, "
            "normalcy and context scoring of the defaults", "network": False,
            "dependencies": "pydantic, phonenumbers, email-validator, dateparser, names-dataset, wordfreq, openai "
                            "(imported, not called)", "region": "default", "scope": list(SCOPE),
            "python": _python()}


def scan(cases):
    tmp = tempfile.mkdtemp(prefix="bench-pr-")
    try:
        inp, out, worker = (os.path.join(tmp, n) for n in ("in.jsonl", "out.jsonl", "worker.py"))
        with open(worker, "w", encoding="utf-8") as f:
            f.write(_WORKER)
        with open(inp, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps({"text": c["text"]}) + "\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENAI", "PRESERVE"))}
        p = subprocess.run([_python(), "-I", worker, inp, out], capture_output=True, text=True, cwd=tmp, env=env)
        if p.returncode:
            raise RuntimeError(f"Preserve worker failed: {p.stderr[-2000:]}")
        timing = json.loads(p.stdout)
        with open(out, encoding="utf-8") as f:
            found = [[tuple(x) for x in json.loads(line)] for line in f]
        return found, timing
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
