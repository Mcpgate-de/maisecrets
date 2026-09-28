"""The ssh route and the session approval end to end, in the real Claude Code sandbox, against a real host.

    MAISECRETS_E2E_HOST=<ssh alias> MAISECRETS_E2E_IP=<its address> python3 harness/sandbox/ssh_e2e.py

The alias must log in without a prompt (BatchMode), and the address is what ssh -G <alias> names:
it goes into sandbox.network.allowedDomains. Run it on macOS and on Linux (bubblewrap) before a
release that touches the ssh route: a unit test cannot show what the sandbox allows (the Linux
sandbox logs in to its proxy as `srt`, macOS as `srt.<…>`; only this run showed it).

1. the hook's first answer is "ask"; the rewritten command runs in the sandbox (as after a yes);
   the host prints 1 only when the exact value arrived; the approval then exists
2. the second command gets no ask; it runs in the sandbox; the host prints 1 again
3. a write command still asks; a host outside allowedDomains gets 403 from the sandbox proxy
A synthetic random value only; the remote file is removed at the end.
"""
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = str(HERE.parents[1])
HOST = os.environ["MAISECRETS_E2E_HOST"]
IP = os.environ["MAISECRETS_E2E_IP"]
work = Path(tempfile.mkdtemp(prefix="maisecrets-ssh-e2e-"))
home = work / "vault"
home.mkdir(parents=True)
(home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                              "ssh_approval": "per-session"}))
env = {k: v for k, v in os.environ.items() if not k.startswith(("CODEX_", "CLAUDE_PLUGIN_OPTION_"))}
env["MAISECRETS_HOME"] = str(home)
value = "e2e-" + secrets.token_hex(10)
remote_file = f"/tmp/maisecrets-{work.name}.txt"
key = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.vault import "
                      "Vault; print(Vault().put(sys.stdin.read(), 'SECRET', 'manual', session='S1').key)", REPO],
                     input=value, text=True, capture_output=True, env=env, check=True).stdout.strip()
# setup outside the sandbox: the host holds the value, so a read-only grep can prove it arrived
subprocess.run(["ssh", "-o", "BatchMode=yes", HOST, f"umask 077; cat > {remote_file}"], input=value + "\n",
               text=True, check=True, timeout=30)


def hook(line: str) -> dict:
    payload = {"tool_name": "Bash", "tool_input": {"command": line.replace("KEY", f"⟦{key}⟧")},
               "session_id": "S1", "prompt_id": "p1"}
    r = subprocess.run([sys.executable, f"{REPO}/hooks/dispatch.py", "pre-tool"], input=json.dumps(payload), text=True,
                       capture_output=True, env=env, timeout=30)
    return json.loads(r.stdout)["hookSpecificOutput"]


def in_sandbox(name: str, command: str, allowed: list[str]) -> str:
    d = work / name
    d.mkdir()
    (d / "cmds.json").write_text(json.dumps([{"command": command}]))
    senv = dict(os.environ, SPIKE_SETTINGS=json.dumps(
        {"enabled": True, "allowUnsandboxedCommands": False,
         "network": {"allowedDomains": allowed, "strictAllowlist": True}}))
    r = subprocess.run([sys.executable, str(HERE / "run_in_sandbox.py"), str(d / "run"), str(d / "cmds.json")],
                       capture_output=True, text=True, env=senv, timeout=400)
    return r.stdout


def approvals() -> dict:
    f = home / "ssh-approvals.json"
    return json.loads(f.read_text()).get("approved", {}) if f.exists() else {}


ok = True
def check(label, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + label + (f"  [{detail}]" if detail and not cond else ""))


READ = f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'grep -c -x -F -f - {remote_file}'"
try:
    first = hook(READ)
    check("1a first use asks", first.get("permissionDecision") == "ask", first.get("permissionDecision"))
    check("1b the ask names the session scope", "without asking again" in first.get("permissionDecisionReason", ""))
    check("1c no approval before the command runs", not approvals())
    out1 = in_sandbox("s1", first["updatedInput"]["command"], [IP])
    check("1d in the sandbox the exact value arrived (grep -x -c prints 1)", "\n1\n" in f"\n{out1}\n", out1[-400:])
    time.sleep(1)
    check("1e the read confirmed the approval", key in approvals().get("S1", {}), approvals())

    second = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'grep -c -F -f - {remote_file}'")
    check("2a the second command gets no ask", "permissionDecision" not in second, second.get("permissionDecision"))
    out2 = in_sandbox("s2", second["updatedInput"]["command"], [IP])
    check("2b in the sandbox the value arrived again", "\n1\n" in f"\n{out2}\n", out2[-400:])

    write = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'cat > {remote_file}.w'")
    check("3a a write command still asks", write.get("permissionDecision") == "ask", write.get("permissionDecision"))
    check("3b ...without the session scope", "without asking again" not in write.get("permissionDecisionReason", ""))
    other = hook("printf '%s' KEY | ssh -o BatchMode=yes git@github.com 'grep -F -f - x'")
    check("3c another host: no ask (approved value, read-only)", "permissionDecision" not in other)
    out3 = in_sandbox("s3", other["updatedInput"]["command"], [IP])
    check("3d the sandbox proxy refuses the host outside allowedDomains (403)", "403" in out3, out3[-400:])
    check("3e the value never shows in any sandbox output", value not in out1 + out2 + out3)
finally:
    subprocess.run(["ssh", "-o", "BatchMode=yes", HOST, f"rm -f {remote_file} {remote_file}.w"], timeout=30)
    left = subprocess.run(["ssh", "-o", "BatchMode=yes", HOST, f"ls {remote_file}* 2>/dev/null | wc -l"],
                          capture_output=True, text=True, timeout=30).stdout.strip()
    print("remote files left:", left)
print("RESULT", "ok" if ok else "FAILED")
sys.exit(0 if ok else 1)
