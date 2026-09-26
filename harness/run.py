"""Hook harness: drive `claude -p` through scenarios against the fake upstream.

For each scenario:
  1. start fake_anthropic with the scripted turns
  2. run `claude -p` with the plugin loaded (--plugin-dir) and a dump hook that
     records every hook payload (to build/verify golden key sets)
  3. assert: the marker secret never appears in any request body, and the
     expected placeholders do; the transcript on disk carries no secret either
  4. diff hook payload keys against harness/golden/<event>.json

Usage: python3 harness/run.py [--update-golden] [scenario ...]
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "harness" / "golden"
MARK = "glpat-" + "HARNESSxxx1234567890abcd"   # matches gitlab_pat; split so the repo scan stays clean
MAIL = "harness.person@example.org"
MARK2 = "pa$s'w\"ord`x $(echo no) y\\z"     # no known shape; quotes, $( and spaces
PORT = 8791

SCENARIOS = {
    # the typed prompt carries a secret: must be blocked, zero requests
    "prompt_secret": {
        "prompt": f"Please check the token {MARK} in CI",
        "turns": [{"text": "unreachable"}],
        "expect_requests": 0,
        "expect_blocked": True,
    },
    # the model reads a file that holds a secret: PostToolUse must redact it
    "read_env": {
        "prompt": "read the env file",
        "files": {".env": f"GITLAB_TOKEN={MARK}\nMAIL={MAIL}\n"},
        "turns": [{"tool": "Read", "input": {"file_path": "{cwd}/.env"}}, {"text": "done"}],
        "expect_requests": 2,
        "expect_placeholders": ["⟦SECRET_c", "⟦EMAIL_c"],
    },
    # the model runs a command whose output holds a secret
    "bash_echo": {
        "prompt": "print the env",
        "files": {".env": f"TOKEN={MARK}\n"},
        "turns": [{"tool": "Bash", "input": {"command": "cat .env"}}, {"text": "done"}],
        "expect_requests": 2,
        "expect_placeholders": ["⟦SECRET_c"],
    },
    # the model uses a placeholder in Bash: PreToolUse rehydrates, the command sees the value,
    # PostToolUse redacts the echo again
    "bash_rehydrate": {
        # the reference is in the prompt: a session may resolve only what a human typed into it
        "prompt": "use the stored token ⟦SECRET_c1⟧",
        "preload": [(MARK, "SECRET", "gitlab_pat")],
        "turns": [
            {"tool": "Bash", "input": {"command": "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"}},
            {"text": "done"},
        ],
        "expect_requests": 2,
        "expect_placeholders": ["⟦SECRET_c1⟧"],
        "expect_file": ("used.txt", f"got:{MARK}"),
    },
    # a value with quotes, $( and spaces, inside single quotes: it must arrive byte for byte
    # (no splice into shell syntax) and come back redacted although it has no known shape
    "bash_rehydrate_quoted": {
        "prompt": "use the stored password ⟦SECRET_c1⟧",
        "preload": [(MARK2, "SECRET", "manual")],
        "turns": [
            {"tool": "Bash", "input": {"command": "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"}},
            {"text": "done"},
        ],
        "expect_requests": 2,
        "expect_placeholders": ["⟦SECRET_c1⟧"],
        "expect_file": ("used.txt", f"got:{MARK2}"),
    },
    # a reference the session never saw in a prompt is not resolved
    "bash_foreign_ref": {
        "prompt": "run the command",
        "preload": [(MARK, "SECRET", "gitlab_pat")],
        "turns": [
            {"tool": "Bash", "input": {"command": "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"}},
            {"text": "done"},
        ],
        "expect_requests": 2,
        "expect_placeholders": ["⟦SECRET_c1⟧"],
        "expect_file": ("used.txt", "<missing>"),
        "expect_text": "foreign-session",
    },
}


def start_server(turns: list, out: Path) -> subprocess.Popen:
    scen = out / "scenario.json"
    scen.write_text(json.dumps({"turns": turns}))
    p = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"), str(scen), str(out), str(PORT)])
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
            return p
        except Exception:
            time.sleep(0.1)
    p.kill()
    raise RuntimeError("fake upstream did not start")


def run_scenario(name: str, sc: dict, update_golden: bool) -> list[str]:
    fails: list[str] = []
    work = Path(tempfile.mkdtemp(prefix=f"maisecrets-h-{name}-"))
    cwd = work / "proj"
    out = work / "out"
    dump = work / "dump"
    for d in (cwd, out, dump):
        d.mkdir()
    home = work / "vaulthome"
    home.mkdir()
    # preload and hooks must agree on the backend, on every OS: pin the test backend for this home
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile"}))
    env = dict(os.environ, ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", CLAUDE_CODE_MAX_RETRIES="0",
               MAISECRETS_HOME=str(home), MAISECRETS_DUMP=str(dump), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
    for fname, content in sc.get("files", {}).items():
        (cwd / fname).write_text(content)
    if sc.get("preload"):
        # in a subprocess: maisecrets.vault fixes its home at import, and this process runs
        # several scenarios (the second preload landed in the first home, 2026-09-26)
        code = ("import json,sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
                "[Vault().put(v, t, k) for v, t, k in json.load(sys.stdin)]")
        subprocess.run([sys.executable, "-c", code, str(ROOT)], input=json.dumps(sc["preload"]),
                       text=True, check=True, env=env)
    turns = json.loads(json.dumps(sc["turns"]).replace("{cwd}", str(cwd)))
    # dump hook: records every payload so golden keys can be verified
    settings = work / "settings.json"
    dump_cmd = f"{sys.executable} \"{ROOT / 'harness' / 'dump_hook.py'}\""
    settings.write_text(json.dumps({"hooks": {ev: [{"hooks": [{"type": "command", "command": dump_cmd}]}]
                                              for ev in ("UserPromptSubmit", "PreToolUse", "PostToolUse")}}))
    srv = start_server(turns, out)
    try:
        r = subprocess.run(
            ["claude", "-p", sc["prompt"], "--plugin-dir", str(ROOT), "--settings", str(settings),
             "--allowedTools", "Bash,Read", "--max-turns", "3"],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
        )
    finally:
        srv.terminate()
    (out / "claude_stdout.txt").write_text(r.stdout + "\n--- stderr ---\n" + r.stderr)
    bodies = sorted(glob.glob(str(out / "request_*.json")))
    if len(bodies) != sc["expect_requests"]:
        fails.append(f"expected {sc['expect_requests']} requests, got {len(bodies)}")
    joined = "".join(Path(b).read_text() for b in bodies)
    for marker in (MARK, MAIL, MARK2, MARK[-8:]):
        if marker in joined:
            fails.append(f"LEAK: …{marker[-6:]} reached the upstream")
    for ph in sc.get("expect_placeholders", []):
        if ph not in joined:
            fails.append(f"placeholder {ph} missing in requests")
    if sc.get("expect_blocked") and "blocked by hook" not in (r.stdout + r.stderr):
        fails.append("prompt was not blocked")
    if sc.get("expect_file"):
        fname, content = sc["expect_file"]
        got = (cwd / fname).read_text() if (cwd / fname).exists() else "<missing>"
        if got != content:
            fails.append(f"rehydration: {fname} holds {got!r}")
    if sc.get("expect_text") and sc["expect_text"] not in joined:
        fails.append(f"expected {sc['expect_text']!r} in a request body (the deny reason reaches the model)")
    for marker in (MARK, MARK2):
        if marker in "".join(p.read_text(errors="ignore") for p in dump.glob("*.json")):
            fails.append("LEAK: a hook payload (tool_input after rewrite) carried the value")
    # transcript on disk
    proj_dir = Path.home() / ".claude" / "projects" / str(cwd).replace("/", "-")
    for t in proj_dir.glob("*.jsonl"):
        txt = t.read_text()
        if MARK in txt:
            fails.append(f"transcript {t.name} still holds the secret")
    # golden keys
    for pf in sorted(dump.glob("*.json")):
        payload = json.loads(pf.read_text())
        ev = payload.get("hook_event_name", "unknown")
        tool = payload.get("tool_name", "")
        gname = f"{ev}{'_' + tool if tool else ''}.json"
        resp = payload.get("tool_response")
        keys = {
            "top": sorted(payload),
            "tool_input": sorted((payload.get("tool_input") or {}).keys()),
            "tool_response": sorted(resp.keys()) if isinstance(resp, dict) else type(resp).__name__,
        }
        gpath = GOLDEN / gname
        if update_golden or not gpath.exists():
            gpath.write_text(json.dumps(keys, indent=1))
        elif json.loads(gpath.read_text()) != keys:
            fails.append(f"schema drift in {gname}: {keys}")
    print(f"[{'OK ' if not fails else 'FAIL'}] {name}  requests={len(bodies)}  out={out}")
    for f in fails:
        print("     -", f)
    return fails


def main() -> int:
    update = "--update-golden" in sys.argv
    names = [a for a in sys.argv[1:] if not a.startswith("--")] or list(SCENARIOS)
    if shutil.which("claude") is None:
        print("claude not on PATH")
        return 2
    total = 0
    for n in names:
        total += len(run_scenario(n, SCENARIOS[n], update))
    print("\nfailures:", total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
