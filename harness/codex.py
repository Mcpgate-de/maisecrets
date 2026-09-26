"""Codex harness: the same scenarios as run.py, driven through `codex exec`.

Isolation: a temporary CODEX_HOME with its own hooks.json (absolute paths into
this repo), a config.toml that disables approvals, and a dummy API-key login
so that ``openai_base_url`` points Codex at harness/fake_openai.py. No real
model call, no credits. With --real, the user's auth.json is copied instead
and a cheap real model answers.

Assertions: the marker secret never appears in any request body, in the
rollout transcript under CODEX_HOME/sessions, or in the final message; the
placeholders do.

Usage: python3 harness/codex.py [--real] [scenario ...]
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "glpat-" + "CodexHarnessXyz123456789"
MODEL = os.environ.get("MAISECRETS_CODEX_MODEL", "gpt-5.6-sol")
PORT = 8792
REAL = "--real" in sys.argv


def _js(cmd: str) -> str:
    return (f"const r = await tools.exec_command({{cmd: {json.dumps(cmd)}}}); "
            "text(typeof r === 'string' ? r : JSON.stringify(r));")

SCENARIOS = {
    "prompt_secret": {
        "prompt": f"Please check the token {MARK} in CI",
        "expect_blocked": True,
    },
    "bash_echo": {
        # a real model refuses "print .env verbatim" on its own (2026-09-26); asking for the
        # variable names makes it run the command, and the redacted output is what it reads
        "prompt": "Run the shell command `cat .env` and tell me which variable names it defines.",
        "files": {".env": f"TOKEN={MARK}\n"},
        "turns": [{"exec": _js("cat .env")}, {"text": "done"}],
        "expect_placeholder": "⟦SECRET_c",
    },
    "bash_rehydrate": {
        "prompt": ("Run exactly this shell command, do not change it: "
                   "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"),
        "preload": True,
        "turns": [{"exec": _js("printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt")}, {"text": "done"}],
        "expect_placeholder": "⟦SECRET_c1⟧",
        "expect_file": ("used.txt", f"got:{MARK}"),
    },
}


def run_scenario(name: str, sc: dict) -> list[str]:
    fails: list[str] = []
    work = Path(tempfile.mkdtemp(prefix=f"maisecrets-codex-{name}-"))
    cwd = work / "proj"
    cwd.mkdir()
    home = work / "vaulthome"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile"}))
    codex_home = work / "codex_home"
    codex_home.mkdir()
    out = work / "out"
    out.mkdir()
    env = dict(os.environ, CODEX_HOME=str(codex_home), MAISECRETS_HOME=str(home))
    # CI containers have no bubblewrap/landlock for Codex's Linux sandbox; the container is disposable,
    # so the job sets MAISECRETS_CODEX_SANDBOX to danger-full-access there
    sandbox = os.environ.get("MAISECRETS_CODEX_SANDBOX", "workspace-write")
    cfg = (f'model = "{MODEL}"\nmodel_reasoning_effort = "low"\napproval_policy = "never"\n'
           f'sandbox_mode = "{sandbox}"\n')
    if REAL:
        shutil.copy(Path.home() / ".codex" / "auth.json", codex_home / "auth.json")
    else:
        # a custom provider: no WebSocket attempts, no login needed, a dummy key from the environment
        cfg += ('model_provider = "fake"\n[model_providers.fake]\nname = "maisecrets fake"\n'
                f'base_url = "http://127.0.0.1:{PORT}/v1"\nwire_api = "responses"\nenv_key = "FAKE_OPENAI_KEY"\n'
                'supports_websockets = false\n')
        env["FAKE_OPENAI_KEY"] = "sk-dummy-maisecrets-harness-key-0000000000"
    (codex_home / "config.toml").write_text(cfg)
    # The plugin is installed the way a user gets it, from this checkout as a local marketplace,
    # so Codex's own plugin and hook discovery is under test. Writing hooks.json into CODEX_HOME
    # (the first version of this harness) hid a discovery failure: with a root plugin.json in the
    # package Codex found 0 of the 4 hooks (measured by a peer session on 0.157.1, 2026-09-26).
    for cmd in (["codex", "plugin", "marketplace", "add", str(ROOT)],
                ["codex", "plugin", "add", "maisecrets@maisecrets"]):
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            print(f"[FAIL] {name}  plugin install: {' '.join(cmd[2:])}: {(r.stderr or r.stdout).strip()[:300]}")
            return ["plugin install failed"]
    for fname, content in sc.get("files", {}).items():
        (cwd / fname).write_text(content)
    if sc.get("preload"):
        sys.path.insert(0, str(ROOT))
        os.environ["MAISECRETS_HOME"] = str(home)
        from maisecrets.vault import Vault  # noqa: E402
        Vault().put(MARK, "SECRET", "gitlab-pat")
    last = work / "last.txt"
    srv = None
    if not REAL:
        (out / "scenario.json").write_text(json.dumps({"turns": sc.get("turns", [{"text": "unreachable"}])}))
        srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_openai.py"),
                                str(out / "scenario.json"), str(out), str(PORT)])
        import time
        import urllib.request
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=0.2)
                break
            except Exception:
                time.sleep(0.1)
    try:
        r = subprocess.run(
            ["codex", "exec", "--dangerously-bypass-hook-trust", "--skip-git-repo-check",
             "-C", str(cwd), "-o", str(last), sc["prompt"]],
            env=env, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL,
        )
    finally:
        (codex_home / "auth.json").unlink(missing_ok=True)
        if srv:
            srv.terminate()
    bodies = "".join(p.read_text(errors="ignore") for p in out.glob("request_*.json"))
    if MARK in bodies or MARK[-8:] in bodies:
        fails.append("LEAK: the marker (or its tail) reached the upstream request body")
    out = r.stdout + "\n--- stderr ---\n" + r.stderr
    (work / "codex_out.txt").write_text(out)
    final = last.read_text() if last.exists() else ""
    rollouts = "".join(p.read_text(errors="ignore") for p in codex_home.rglob("*.jsonl"))
    if MARK in rollouts or MARK[-8:] in rollouts:
        fails.append("LOCAL: the marker is in the rollout transcript on disk (upstream requests were clean)"
                     if MARK not in bodies else "LEAK: the marker is in the rollout transcript")
    if MARK in final or MARK[-8:] in final:
        fails.append("LEAK: the marker (or its tail) is in the final message")
    if sc.get("expect_blocked"):
        if "blocked" not in out.lower() and "maisecrets" not in out:
            fails.append("prompt was not blocked (no notice in output)")
        if rollouts and "SECRET_c" not in rollouts and "maisecrets" not in rollouts:
            pass  # a blocked prompt may leave no rollout at all
    ph = sc.get("expect_placeholder")
    ran_command = '"CommandExecution"' in rollouts or "exec_command" in rollouts
    # with --real there are no recorded request bodies; the tools-router line in codex's own
    # output is the redacted result as the model received it
    if ph and ph not in bodies and ph not in rollouts and ph not in final and not (REAL and ph in out):
        if REAL and not ran_command:
            print(f"     ~ {name}: the real model declined to run the command; nothing to check (not a failure)")
        else:
            fails.append(f"placeholder {ph} missing in upstream requests, rollout and final message")
    if sc.get("expect_file"):
        fname, content = sc["expect_file"]
        got = (cwd / fname).read_text() if (cwd / fname).exists() else "<missing>"
        if got != content:
            fails.append(f"rehydration: {fname} holds {got!r}")
    print(f"[{'OK ' if not fails else 'FAIL'}] {name}  rc={r.returncode}  work={work}")
    for f in fails:
        print("     -", f)
    if fails:
        # what codex itself said, marker redacted: the work dir is gone once a CI job ends
        tail = out.replace(MARK, "<MARK>").splitlines()[-25:]
        print("     codex output (tail):")
        for line in tail:
            print("       |", line[:200])
    return fails


def main() -> int:
    if shutil.which("codex") is None:
        print("codex not on PATH")
        return 2
    names = [a for a in sys.argv[1:] if not a.startswith("--")] or list(SCENARIOS)
    total = sum(len(run_scenario(n, SCENARIOS[n])) for n in names)
    print("\nfailures:", total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
