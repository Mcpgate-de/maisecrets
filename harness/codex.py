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
    # rehydration "automatic" on an MCP text field (`message`): Codex gets "allow" with the value in the
    # argument, the server echoes it, and the echo comes back to the model redacted. Needs a real model:
    # the fake upstream has no MCP tool call (--real only)
    "mcp_text_field_rehydrate": {
        "prompt": "Call the echo tool of the everything MCP server once with the message ⟦SECRET_c1⟧ and "
                  "tell me what it answered.",
        "preload": True,
        "real_only": True,
        "mcp": {"everything": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything@2025.9.25"]}},
        "expect_placeholder": "⟦SECRET_c1⟧",
        "expect_text": "Echo: \u27e6SECRET_c1\u27e7",
        # the echo alone would also read so if the placeholder had stayed text: the proof is hooks.log,
        # a pre-tool "rewrite" and a post-tool "block" (it found the real value in the answer and replaced it)
        "value_goes_to": "mcp__everything__echo",
    },
    # the hook's "allow" carries the rewritten command, not more: Codex's own sandbox still holds. In a
    # read-only sandbox the write is refused although the hook rewrote the command (codex-cli 0.158.0,
    # 2026-09-29). Whether "allow" skips an escalation approval cannot be seen here: codex exec offers none.
    "allow_keeps_the_codex_sandbox": {
        "prompt": ("Run exactly this shell command once, do not change it: "
                   "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"),
        "preload": True,
        "real_only": True,
        "sandbox": "read-only",
        "approval": "on-request",
        "expect_file": ("used.txt", "<missing>"),
        "expect_hook": ("pre-tool", "Bash", "rewrite"),
    },
    # rehydration "confirm": Codex cannot ask with a rewritten input, so the hook refuses the command
    # and it does not run; the model reads the reason, which names the key, not the value
    "bash_rehydrate_confirm": {
        "prompt": ("Run exactly this shell command, do not change it: "
                   "printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt"),
        "preload": True,
        "config": {"rehydration": "confirm"},
        "turns": [{"exec": _js("printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt")}, {"text": "done"}],
        "expect_file": ("used.txt", "<missing>"),
        "expect_text": "Codex cannot ask",
    },
}


def run_scenario(name: str, sc: dict) -> list[str]:
    fails: list[str] = []
    if sc.get("real_only") and not REAL:
        print(f"[SKIP] {name}  needs --real")
        return []
    work = Path(tempfile.mkdtemp(prefix=f"maisecrets-codex-{name}-"))
    cwd = work / "proj"
    cwd.mkdir()
    home = work / "vaulthome"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                  **sc.get("config", {})}))
    codex_home = work / "codex_home"
    codex_home.mkdir()
    out = work / "out"
    out.mkdir()
    env = dict(os.environ, CODEX_HOME=str(codex_home), MAISECRETS_HOME=str(home))
    # CI containers have no bubblewrap/landlock for Codex's Linux sandbox; the container is disposable,
    # so the job sets MAISECRETS_CODEX_SANDBOX to danger-full-access there
    sandbox = sc.get("sandbox") or os.environ.get("MAISECRETS_CODEX_SANDBOX", "workspace-write")
    cfg = (f'model = "{MODEL}"\nmodel_reasoning_effort = "low"\napproval_policy = "{sc.get("approval", "never")}"\n'
           f'sandbox_mode = "{sandbox}"\n')
    if REAL:
        shutil.copy(Path.home() / ".codex" / "auth.json", codex_home / "auth.json")
    else:
        # a custom provider: no WebSocket attempts, no login needed, a dummy key from the environment
        cfg += ('model_provider = "fake"\n[model_providers.fake]\nname = "maisecrets fake"\n'
                f'base_url = "http://127.0.0.1:{PORT}/v1"\nwire_api = "responses"\nenv_key = "FAKE_OPENAI_KEY"\n'
                'supports_websockets = false\n')
        env["FAKE_OPENAI_KEY"] = "sk-dummy-maisecrets-harness-key-0000000000"
    for server, spec in sc.get("mcp", {}).items():
        # the user's own approval for the tool: a hook's "allow" does not skip Codex's MCP approval
        # (codex-cli 0.158.0, measured 2026-09-28: "MCP tool call requires approval")
        cfg += (f'[mcp_servers.{server}]\ncommand = {json.dumps(spec["command"])}\nargs = {json.dumps(spec["args"])}\n'
                'default_tools_approval_mode = "approve"\n')
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
        # in a subprocess: a Vault held in this process would hold the vault lock while codex
        # runs the hooks, and a Codex hook that times out is fail-open (measured 2026-09-26)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import Vault; "
                "Vault().put(sys.stdin.read(), 'SECRET', 'gitlab-pat')")
        subprocess.run([sys.executable, "-c", code, str(ROOT)], input=MARK, text=True, check=True, env=env)
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
    # every built-in tool Codex offered must be classified (harness/inventory.py)
    from inventory import offered, unclassified
    if sorted(out.glob("request_*.json")) and "exec" not in offered(sorted(out.glob("request_*.json"))):
        fails.append("no tool list found in the request bodies: the inventory check read nothing")
    for tool in unclassified("codex", sorted(out.glob("request_*.json"))):
        fails.append(f"UNCLASSIFIED TOOL {tool}: add it to tests/client_tools.json with its class")
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
    lines = [ln.strip() for ln in out.splitlines()]
    failed_hooks = [ln for ln in lines if ln.startswith("hook: ") and ln.endswith("Failed")]
    if failed_hooks:
        # Codex runs the tool anyway when a hook fails (fail-open); a failed hook is never acceptable
        fails.append("hook failed in codex (fail-open): " + ", ".join(sorted(set(failed_hooks))))
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
    if sc.get("expect_hook"):
        log = (home / "hooks.log").read_text(errors="ignore") if (home / "hooks.log").exists() else ""
        event, tool, outcome = sc["expect_hook"]
        rows = [ln.split("\t") for ln in log.splitlines()]
        if not any(r[1:2] == [event] and tool in r and outcome in r for r in rows):
            fails.append(f"hooks.log has no {event} {outcome} for {tool}: the scenario did not reach the rewrite")
    if sc.get("value_goes_to"):
        log = (home / "hooks.log").read_text(errors="ignore") if (home / "hooks.log").exists() else ""
        rows = [ln.split("\t") for ln in log.splitlines()]
        tool = sc["value_goes_to"]
        if not any(r[1:2] == ["pre-tool"] and tool in r and "rewrite" in r for r in rows) or \
                not any(r[1:2] == ["post-tool"] and tool in r and "block" in r for r in rows):
            fails.append(f"rehydration: {tool} did not get the real value (hooks.log has no rewrite and redaction)")
    if sc.get("expect_text") and not any(sc["expect_text"] in t for t in (bodies, rollouts, out)):
        if REAL and not ran_command and "maisecrets" not in rollouts:
            print(f"     ~ {name}: the real model declined to run the command; nothing to check (not a failure)")
        else:
            fails.append(f"expected {sc['expect_text']!r} in the requests, the rollout or the codex output")
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
