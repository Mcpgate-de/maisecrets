"""Run scripted Bash calls in the real Claude Code sandbox: claude -p against the harness fake upstream.

    python3 harness/sandbox/run_in_sandbox.py <workdir> <commands.json> [permission-mode]

env: CLAUDE_BIN (default: claude), SPIKE_SETTINGS (json of the sandbox block), SPIKE_PORT. Only the
dump hook runs, not maisecrets: the commands are already the hook's rewrites. In headless mode
Claude Code refuses a hook's "ask" even with bypassPermissions, so an ask cannot be answered here;
running the rewritten command is what an allowed ask does. Prints each tool result.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLAUDE = os.environ.get("CLAUDE_BIN", "claude")
PORT = int(os.environ.get("SPIKE_PORT", "8797"))
DEFAULT_SANDBOX = {"enabled": True, "allowUnsandboxedCommands": False,
                   "network": {"allowedDomains": ["example.com"], "strictAllowlist": True}}


def main() -> int:
    work = Path(sys.argv[1]).resolve()
    cmds = json.loads(Path(sys.argv[2]).read_text())
    mode = sys.argv[3] if len(sys.argv) > 3 else None
    cwd, out, dump, cfg = (work / n for n in ("proj", "out", "dump", "cfg"))
    for d in (cwd, out, dump, cfg):
        d.mkdir(parents=True, exist_ok=True)
    turns = [{"tool": "Bash", "input": c} for c in cmds] + [{"text": "done"}]
    (out / "scenario.json").write_text(json.dumps({"turns": turns}))
    srv = subprocess.Popen([sys.executable, str(ROOT / "harness" / "fake_anthropic.py"), str(out / "scenario.json"),
                            str(out), str(PORT)])
    time.sleep(1.5)
    dump_cmd = f"{sys.executable} \"{ROOT / 'harness' / 'dump_hook.py'}\""
    sandbox = json.loads(os.environ.get("SPIKE_SETTINGS") or json.dumps(DEFAULT_SANDBOX))
    settings = {"sandbox": sandbox, "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": dump_cmd}]}]}}
    (work / "settings.json").write_text(json.dumps(settings))
    env = dict(os.environ, ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", CLAUDE_CODE_MAX_RETRIES="0",
               MAISECRETS_DUMP=str(dump), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", CLAUDE_CONFIG_DIR=str(cfg),
               ANTHROPIC_API_KEY="sk-dummy-sandbox-run-0000")
    args = [CLAUDE, "-p", "run the checks", "--settings", str(work / "settings.json"), "--allowedTools", "Bash",
            "--max-turns", str(len(cmds) + 2), "--debug-file", str(work / "debug.log")]
    if mode:
        args += ["--permission-mode", mode]
    try:
        r = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=300,
                           stdin=subprocess.DEVNULL)
    finally:
        srv.terminate()
    reqs = sorted(out.glob("request_*.json"))
    last = json.loads(reqs[-1].read_text()) if reqs else {"messages": []}
    n = 0
    for m in last.get("messages", []):
        for c in m.get("content", []) if isinstance(m.get("content"), list) else []:
            if c.get("type") == "tool_result":
                t = c.get("content")
                t = "".join(x.get("text", "") for x in t) if isinstance(t, list) else t
                n += 1
                print(f"=== result {n}\n{t.strip()[:1800]}")
    print("claude exit", r.returncode, r.stderr[-300:])
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
