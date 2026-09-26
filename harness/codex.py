"""Codex harness: the same scenarios as run.py, driven through `codex exec`.

Isolation: a temporary CODEX_HOME with its own hooks.json (absolute paths into
this repo), a config.toml that pins a cheap model and disables approvals, and
a COPY of the user's auth.json (deleted afterwards). The prompt scenario makes
no model call; the two tool scenarios make one small real call each, because
no fake Responses upstream exists yet.

Assertions: the marker secret never appears in the rollout transcript under
CODEX_HOME/sessions nor in the final message; the placeholders do.

Usage: python3 harness/codex.py [scenario ...]
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

SCENARIOS = {
    "prompt_secret": {
        "prompt": f"Please check the token {MARK} in CI",
        "expect_blocked": True,
    },
    "bash_echo": {
        "prompt": "Run exactly this shell command and then reply with its output verbatim: cat .env",
        "files": {".env": f"TOKEN={MARK}\n"},
        "expect_placeholder": "⟦SECRET_c",
    },
    "bash_rehydrate": {
        "prompt": "Run exactly this shell command, do not change it: printf 'got:%s' '⟦SECRET_c1⟧' > used.txt; cat used.txt",
        "preload": True,
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
    shutil.copy(Path.home() / ".codex" / "auth.json", codex_home / "auth.json")
    (codex_home / "config.toml").write_text(
        f'model = "{MODEL}"\nmodel_reasoning_effort = "low"\napproval_policy = "never"\n'
        'sandbox_mode = "workspace-write"\n'
    )
    run_sh = ROOT / "hooks" / "run.sh"
    hooks = {"hooks": {
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": f'bash "{run_sh}" user-prompt', "timeout": 10}]}],
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": f'bash "{run_sh}" pre-tool', "timeout": 10}]}],
        "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": f'bash "{run_sh}" post-tool', "timeout": 20}]}],
    }}
    (codex_home / "hooks.json").write_text(json.dumps(hooks, indent=1))
    for fname, content in sc.get("files", {}).items():
        (cwd / fname).write_text(content)
    env = dict(os.environ, CODEX_HOME=str(codex_home), MAISECRETS_HOME=str(home))
    if sc.get("preload"):
        sys.path.insert(0, str(ROOT))
        os.environ["MAISECRETS_HOME"] = str(home)
        from maisecrets.vault import Vault  # noqa: E402
        Vault().put(MARK, "SECRET", "gitlab-pat")
    last = work / "last.txt"
    try:
        r = subprocess.run(
            ["codex", "exec", "--dangerously-bypass-hook-trust", "--skip-git-repo-check",
             "-C", str(cwd), "-o", str(last), sc["prompt"]],
            env=env, capture_output=True, text=True, timeout=240, stdin=subprocess.DEVNULL,
        )
    finally:
        (codex_home / "auth.json").unlink(missing_ok=True)
    out = r.stdout + "\n--- stderr ---\n" + r.stderr
    (work / "codex_out.txt").write_text(out)
    final = last.read_text() if last.exists() else ""
    rollouts = "".join(p.read_text(errors="ignore") for p in codex_home.rglob("*.jsonl"))
    if MARK in rollouts:
        fails.append("LEAK: the marker is in the rollout transcript")
    if MARK in final:
        fails.append("LEAK: the marker is in the final message")
    if sc.get("expect_blocked"):
        if "blocked" not in out.lower() and "maisecrets" not in out:
            fails.append("prompt was not blocked (no notice in output)")
        if rollouts and "SECRET_c" not in rollouts and "maisecrets" not in rollouts:
            pass  # a blocked prompt may leave no rollout at all
    ph = sc.get("expect_placeholder")
    if ph and ph not in rollouts and ph not in final:
        fails.append(f"placeholder {ph} missing in rollout and final message")
    if sc.get("expect_file"):
        fname, content = sc["expect_file"]
        got = (cwd / fname).read_text() if (cwd / fname).exists() else "<missing>"
        if got != content:
            fails.append(f"rehydration: {fname} holds {got!r}")
    print(f"[{'OK ' if not fails else 'FAIL'}] {name}  rc={r.returncode}  work={work}")
    for f in fails:
        print("     -", f)
    return fails


def main() -> int:
    if shutil.which("codex") is None:
        print("codex not on PATH")
        return 2
    names = sys.argv[1:] or list(SCENARIOS)
    total = sum(len(run_scenario(n, SCENARIOS[n])) for n in names)
    print("\nfailures:", total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
