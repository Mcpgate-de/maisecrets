"""The proofs of the PERSON layer in the real hook path (docs/NER-EXPERIMENT.md, "The hook path"), with the real
PostToolUse hook of a maisecrets checkout in a new temp home per run. Counts only, never a value.

    python3 bench/ner/hook_experiment.py CHECKOUT NER_PYTHON BACKEND OUT.json

The corpus: tool results built from the bank's cases (dev), the salted V3 sample of Nemotron's val split and the
developer-text bank's Python code and logs, each as the stdout of a Bash call, in a fixed order. Each run is a new
process with a new temp home, so the placeholders count from c1 in each. The runs:

1. off: the hook as it is (the layer not installed);
2. installed, switched off: must answer byte for byte as off;
3. on, the service answering: every value the off run masked stays masked; the layer adds names; time per call;
4. on, the service 2 s slow with a 300 ms budget: byte for byte as off, and no call waits much longer than the budget;
5. on, the service dying after 20 requests: byte for byte as off for every later call, and no error text;
6. on, the service answering nonsense: byte for byte as off."""
from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME_VAR = "MAISECRETS" + "_HOME"

_RUNNER = r'''
import json, os, sys, time
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2])
from maisecrets import hooks
import hook_layer
mode, sock = sys.argv[3], sys.argv[4]
if mode != "off":
    hook_layer.install(sock, budget_ms=300, active=(mode != "inactive"))
out = []
for line in open(sys.argv[5], encoding="utf-8"):
    p = json.loads(line)
    t = time.perf_counter()
    if mode != "off":
        hook_layer.begin_call()
    r = hooks.post_tool(p)
    out.append({"answer": json.dumps(r, sort_keys=True, ensure_ascii=False), "ms": (time.perf_counter() - t) * 1000})
json.dump({"out": out, "state": {k: v for k, v in hook_layer.STATE.items() if k != "ner_s"},
           "ner_ms": [x * 1000 for x in hook_layer.STATE["ner_s"]]}, open(sys.argv[6], "w"))
'''


def corpus(root_v3: Path, devroot: Path) -> list:
    sys.path.insert(0, str(root_v3))
    from bench import cases as casefmt, run, sources
    texts = [c["text"] for c in casefmt.load_bank(sources.BANK) if c["split"] == "dev"]
    texts += [c["text"] for c in sources.load("nemotron", None, None, 0, collections.Counter())
              if c["split"] == "val" and run.in_sample(c["id"], 25, "v3/")][:200]
    sys.path.insert(0, str(HERE))
    import devtext
    for cat in ("python code", "logs"):
        texts += [c["text"] for c in devtext.cases(devroot, cat)][:60]
    return [{"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
             "tool_input": {"command": "cat data.txt"},
             "tool_response": {"stdout": t, "stderr": "", "interrupted": False, "isImage": False}} for t in texts]


def run_mode(checkout: Path, mode: str, sock: str, payloads: Path, tmp: Path) -> dict:
    home = Path(tempfile.mkdtemp(prefix="ms-hook-", dir=tmp))
    (home / "ms").mkdir()
    (home / "ms" / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MAISECRETS", "CLAUDE"))}
    env.update(HOME=str(home), **{HOME_VAR: str(home / "ms")})
    runner = tmp / "runner.py"
    runner.write_text(_RUNNER)
    out = tmp / f"out-{mode}-{time.monotonic_ns()}.json"
    p = subprocess.run([sys.executable, str(runner), str(checkout), str(HERE), mode, sock, str(payloads), str(out)],
                       env=env, cwd=str(home), capture_output=True, text=True, timeout=7200)
    if p.returncode:
        raise SystemExit(f"run {mode} failed with exit code {p.returncode}")
    return json.loads(out.read_text())


def sidecar(ner_python: str, backend: str, sock: str, *extra: str) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "HF_HOME")}
    env.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    p = subprocess.Popen([ner_python, "-I", str(HERE / "sidecar.py"), sock, backend, *extra], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if p.stdout.readline().strip() != "ready":
        raise SystemExit("the service did not start")
    return p


def main(argv: list) -> int:
    checkout, ner_python, backend, out_path = Path(argv[0]).resolve(), argv[1], argv[2], Path(argv[3])
    _CHECKOUT.append(checkout)
    sys.path.insert(0, str(checkout))
    from maisecrets import detect as _d   # noqa: F401  first, so the bench tree's copy never shadows it
    devroot = Path(os.environ["BENCH_DEVROOT"])
    tmp = Path(tempfile.mkdtemp(prefix="ms-hook-exp-"))
    payloads = tmp / "payloads.jsonl"
    items = corpus(HERE.parent.parent, devroot)
    payloads.write_text("".join(json.dumps(p) + "\n" for p in items), encoding="utf-8")
    sock = str(tmp / "ner.sock")
    report = {"payloads": len(items), "chars": sum(len(p["tool_response"]["stdout"]) for p in items)}

    off = run_mode(checkout, "off", sock, payloads, tmp)
    base = [o["answer"] for o in off["out"]]
    report["off_ms_median"] = sorted(o["ms"] for o in off["out"])[len(base) // 2]
    inactive = run_mode(checkout, "inactive", sock, payloads, tmp)
    report["inactive_byte_identical"] = [o["answer"] for o in inactive["out"]] == base

    def compare(res: dict) -> dict:
        ans = [o["answer"] for o in res["out"]]
        same = sum(a == b for a, b in zip(ans, base))
        # a value masked without the layer stays masked: per answer, each placeholder type other than NAME occurs at
        # least as often as without the layer (the numbers of the placeholders shift when a name comes first), and
        # the answer holds no more deterministic hits than without the layer
        kept = all(all(_types(a)[k] >= n for k, n in _types(b).items() if k != "NAME") for a, b in zip(ans, base))
        residue = sum(_residue(a) for a in ans) - sum(_residue(b) for b in base)
        ms = sorted(o["ms"] for o in res["out"])
        return {"identical_to_off": same, "of": len(ans), "off_placeholders_kept": kept,
                "more_deterministic_hits_left_than_off": residue, "state": res["state"],
                "hook_ms_median": ms[len(ms) // 2], "hook_ms_p95": ms[int(0.95 * (len(ms) - 1))],
                "hook_ms_max": ms[-1]}

    for name, extra in (("on", ()), ("slow", ("--delay-ms", "2000")), ("dies", ("--crash-after", "20")),
                        ("nonsense", ("--garbage",))):
        p = sidecar(ner_python, backend, sock, *extra)
        try:
            report[name] = compare(run_mode(checkout, "on", sock, payloads, tmp))
        finally:
            p.kill()
            p.wait()
    out_path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: (v if not isinstance(v, dict) else {kk: vv for kk, vv in v.items() if kk != "state"})
                      for k, v in report.items()}, indent=1))
    return 0


def _types(answer: str) -> collections.Counter:
    import re
    return collections.Counter(m.group(1) for m in re.finditer(r"⟦([A-Z_]+)_c\d+⟧", answer))


def _residue(answer: str) -> int:
    """Deterministic hits in the text the model gets (the stdout of the answer, or nothing when unchanged)."""
    sys.path.insert(0, str(_CHECKOUT[0]))
    from maisecrets import detect
    assert Path(detect.__file__).resolve().is_relative_to(_CHECKOUT[0]), detect.__file__
    out = json.loads(answer).get("hookSpecificOutput", {}).get("updatedToolOutput", {})
    return len(detect.scan(out.get("stdout", ""), channel="tool")) if out else 0


_CHECKOUT: list = []


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
