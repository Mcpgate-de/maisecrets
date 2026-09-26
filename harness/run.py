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
        "prompt": "use the stored token",
        "preload": [(MARK, "SECRET", "gitlab_pat")],
        "turns": [
            {"tool": "Bash", "input": {"command": "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"}},
            {"text": "done"},
        ],
        "expect_requests": 2,
        "expect_placeholders": ["⟦SECRET_c1⟧"],
        "expect_file": ("used.txt", f"got:{MARK}"),
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
    env = dict(os.environ, ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", CLAUDE_CODE_MAX_RETRIES="0",
               MAISECRETS_HOME=str(home), MAISECRETS_DUMP=str(dump), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
    for fname, content in sc.get("files", {}).items():
        (cwd / fname).write_text(content)
    if sc.get("preload"):
        sys.path.insert(0, str(ROOT))
        os.environ["MAISECRETS_HOME"] = str(home)
        from maisecrets.vault import Vault  # noqa: E402
        for value, type_, kind in sc["preload"]:
            Vault({"backend": "jsonfile"}).put(value, type_, kind)
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
    for marker in (MARK, MAIL):
        if marker in joined:
            fails.append(f"LEAK: {marker[:12]}… reached the upstream")
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
