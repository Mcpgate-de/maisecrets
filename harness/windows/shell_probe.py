"""Which shell runs a plugin hook, and does the hooks.json command protect in each shell.

Part 1 asks the real client: `claude -p` against the fake upstream with one settings hook whose command
is a bash/PowerShell polyglot that writes the name and version of the shell that ran it.

Part 2 runs the UserPromptSubmit command of hooks/hooks.json in each shell this machine has, the way
Claude Code 2.1.284 starts it (bash -c; pwsh or powershell with -NoProfile -NonInteractive
-ExecutionPolicy Bypass -Command, `${CLAUDE_PLUGIN_ROOT}` rewritten to `${env:CLAUDE_PLUGIN_ROOT}`),
with a prompt that carries a synthetic token and umlauts on stdin. The command must answer with a
block, and without the plugin folder it must still block.

Usage: python harness/windows/shell_probe.py      exit 1 when a shell does not block, or when the hook ran in
       another shell than MAISECRETS_EXPECT_HOOK_SHELL names ("Core 7", "Desktop 5.1", "bash")
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "harness"))
import run as harness  # noqa: E402

MARK = harness.MARK
PS_ARGS = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def shells() -> list[tuple[str, list[str]]]:
    found = []
    for name, exe in (("pwsh", shutil.which("pwsh")),
                      ("pwsh-programfiles", os.path.join(os.environ.get("ProgramFiles", ""), "PowerShell", "7",
                                                         "pwsh.exe")),
                      ("powershell-5", os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32",
                                                    "WindowsPowerShell", "v1.0", "powershell.exe"))):
        if exe and os.path.isfile(exe) and all(exe != f[1][0] for f in found):
            found.append((name, [exe, *PS_ARGS]))
    bash = os.environ.get("CLAUDE_CODE_GIT_BASH_PATH") or (shutil.which("bash") if os.name != "nt" else None)
    if bash and os.path.isfile(bash):
        found.append(("bash", [bash, "-c"]))
    return found


def which_shell_runs_hooks() -> str:
    work = Path(tempfile.mkdtemp(prefix="maisecrets-h-shellprobe-"))
    (work / "proj").mkdir()
    (work / "out").mkdir()
    probe = work / "shell.txt"
    p = str(probe).replace("\\", "/")
    cmd = (f"set -- `# <#`\necho \"bash $BASH_VERSION\" > \"{p}\"; exit 0\n#>\n"
           f"\"$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion) $([Environment]::ProcessPath)\" | "
           f"Out-File -Encoding ascii -FilePath \"{p}\"")
    settings = work / "settings.json"
    settings.write_text(json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command",
                                                                               "command": cmd}]}]}}))
    srv = harness.start_server([{"text": "done"}], work / "out")
    try:
        env = dict(os.environ, ANTHROPIC_BASE_URL=f"http://127.0.0.1:{harness.PORT}", CLAUDE_CODE_MAX_RETRIES="0")
        subprocess.run([shutil.which("claude") or "claude", "-p", "hello", "--settings", str(settings),
                        "--debug-file", str(work / "claude-debug.log")],
                       cwd=work / "proj", env=env, capture_output=True, text=True, timeout=120,
                       stdin=subprocess.DEVNULL)
    finally:
        srv.terminate()
    return probe.read_text(errors="replace").strip() if probe.exists() else "(the hook did not run)"


def hook_command(event: str) -> str:
    for entry in json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"][event]:
        return entry["hooks"][0]["command"]
    raise KeyError(event)


def run_in(shell: list[str], root: Path) -> subprocess.CompletedProcess:
    cmd = hook_command("UserPromptSubmit")
    if shell[-1] == "-Command":
        for n in ("CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"):
            cmd = cmd.replace("${" + n + "}", "${env:" + n + "}")
    home = Path(tempfile.mkdtemp(prefix="maisecrets-probe-home-"))
    (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    payload = {"session_id": "probe", "transcript_path": "", "cwd": str(ROOT), "hook_event_name": "UserPromptSubmit",
               "prompt": f"Grüße, mein Token ist {MARK} – bitte prüfen"}
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(root), MAISECRETS_HOME=str(home))
    return subprocess.run([*shell, cmd], input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                          capture_output=True, env=env, timeout=60)


def main() -> int:
    bad = 0
    seen = which_shell_runs_hooks()
    print("shell of a settings hook:", seen)
    # the CI job names the shell it set up; a job that did not reach it tested something else
    expect = os.environ.get("MAISECRETS_EXPECT_HOOK_SHELL", "")
    if expect and not seen.startswith(expect):
        print(f"[FAIL] the hook ran in {seen!r}, the job expects {expect!r}")
        bad += 1
    for name, shell in shells():
        for label, root in (("plugin", ROOT), ("folder gone", ROOT / "gone")):
            r = run_in(shell, root)
            out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
            try:
                blocked = json.loads(out.strip() or "{}").get("decision") == "block"
            except ValueError:
                blocked = False
            blocked = blocked or r.returncode == 2
            leaked = MARK in out
            ok = blocked and not leaked
            bad += not ok
            print(f"[{'OK ' if ok else 'FAIL'}] {name:18} {label:12} exit={r.returncode} stdout={out.strip()[:160]!r}"
                  f" stderr={err.strip()[:200]!r}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
