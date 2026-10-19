"""Run the worker of an adapter in a new process: a minimal environment, a temp directory that is always removed, an
error that names only the scanner and the exit code (stderr can hold a case value), and output that is checked
before it is scored."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

KEEP_ENV = ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")

# the installed distributions of the scanner's Python, for the result file (no lock file can be trusted more)
_FREEZE = ("import json, importlib.metadata as m; print(json.dumps(sorted({d.metadata['Name'] + '==' + d.version "
           "for d in m.distributions()})))")


class AdapterError(RuntimeError):
    pass


def minimal_env(home: str, extra: dict | None = None) -> dict:
    env = {k: v for k, v in os.environ.items() if k in KEEP_ENV}
    env["HOME"] = home
    env.update(extra or {})
    return env


def installed(python: str) -> list:
    tmp = tempfile.mkdtemp(prefix="bench-freeze-")
    try:
        p = subprocess.run([python, "-I", "-c", _FREEZE], capture_output=True, text=True, env=minimal_env(tmp),
                           cwd=tmp)
        return json.loads(p.stdout) if p.returncode == 0 else []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check(name: str, cases: list, found: list) -> list:
    """One list per case; each finding (start, end, cls, rule) with int offsets inside the text of its case."""
    if len(found) != len(cases):
        raise AdapterError(f"{name}: {len(found)} results for {len(cases)} cases")
    out = []
    for i, (c, fs) in enumerate(zip(cases, found)):
        row = []
        for f in fs:
            if len(f) != 4 or not all(isinstance(x, int) and not isinstance(x, bool) for x in f[:2]):
                raise AdapterError(f"{name}: case {i}: a finding is not (start, end, class, rule)")
            s, e = f[0], f[1]
            if not 0 <= s < e <= len(c["text"]):
                raise AdapterError(f"{name}: case {i}: a finding outside the text")
            row.append((s, e, str(f[2]), str(f[3])))
        out.append(row)
    return out


def run_worker(name: str, python: str, worker_src: str, cases: list, fields=("text", "path"), argv=(),
               extra_env: dict | None = None):
    """Write the cases, run the worker (`python -I worker.py IN OUT [argv]`), read and check its findings."""
    tmp = tempfile.mkdtemp(prefix=f"bench-{name}-")
    try:
        home = os.path.join(tmp, "home")
        os.mkdir(home)
        inp, out, worker = (os.path.join(tmp, n) for n in ("in.jsonl", "out.jsonl", "worker.py"))
        with open(worker, "w", encoding="utf-8") as f:
            f.write(worker_src)
        with open(inp, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps({k: c.get(k) for k in fields}) + "\n")
        p = subprocess.run([python, "-I", worker, inp, out, *argv], capture_output=True, text=True, cwd=tmp,
                           env=minimal_env(home, extra_env))
        if p.returncode:
            raise AdapterError(f"{name}: the worker failed with exit code {p.returncode} (its stderr is not shown: "
                               f"it can hold a case value)")
        timing = json.loads(p.stdout)
        with open(out, encoding="utf-8") as f:
            found = [json.loads(line) for line in f]
        return check(name, cases, found), timing
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
