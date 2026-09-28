"""The ssh route and the session approval end to end, in the real Claude Code sandbox, against a real host.

    MAISECRETS_E2E_HOST=<ssh alias> MAISECRETS_E2E_IP=<its address> python3 harness/sandbox/ssh_e2e.py

The alias must log in without a prompt (BatchMode), and the address is what ssh -G <alias> names:
it goes into sandbox.network.allowedDomains. Run it on macOS and on Linux (bubblewrap) before a
release that touches the ssh route: a unit test cannot show what the sandbox allows (the Linux
sandbox logs in to its proxy as `srt`, macOS as `srt.<…>`; only this run showed it).

0. rehydration "automatic" (the default): no ask on the first use, nor on a write command; the value
   arrives in the sandbox; a host outside allowedDomains still gets 403; no approval is written
Cases 1 to 5 run with rehydration "confirm" and ssh_approval "per-session":
1. the hook's first answer is "ask"; the rewritten command runs in the sandbox (as after a yes);
   the host prints 1 only when the exact value arrived; the approval then exists
2. the second command gets no ask; it runs in the sandbox; the host prints 1 again
3. a write command still asks; a host outside allowedDomains gets 403 from the sandbox proxy
4. an ops user's forms: sudo -n before a reader needs no second ask; sudo su -, a second hop and a
   remote encoder are refused, each with the form that works
5. a loop over hosts in one command: no second ask, and the exact value arrives on every pass
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
AUTOMATIC = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIRM = {**AUTOMATIC, "rehydration": "confirm", "ssh_approval": "per-session"}
(home / "config.json").write_text(json.dumps(AUTOMATIC))
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
    auto = hook(READ)
    check("0a automatic: the first use gets no ask", "permissionDecision" not in auto, auto.get("permissionDecision"))
    out0 = in_sandbox("s0", auto["updatedInput"]["command"], [IP])
    check("0b automatic: in the sandbox the exact value arrived", "\n1\n" in f"\n{out0}\n", out0[-400:])
    auto_w = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'cat > {remote_file}.w'")
    check("0c automatic: a write command gets no ask either", "permissionDecision" not in auto_w,
          auto_w.get("permissionDecision"))
    auto_o = hook("printf '%s' KEY | ssh -o BatchMode=yes git@github.com 'grep -F -f - x'")
    out0o = in_sandbox("s0o", auto_o["updatedInput"]["command"], [IP])
    check("0d automatic: the sandbox proxy still refuses a host outside allowedDomains (403)", "403" in out0o,
          out0o[-400:])
    check("0e automatic: no session approval is written", not approvals(), approvals())
    check("0f automatic: the value never shows in any sandbox output", value not in out0 + out0o)
    (home / "config.json").write_text(json.dumps(CONFIRM))

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

    # an ops user's cases (field report on 0.5.8, 2026-09-28): root-only logs through sudo, and the
    # forms that stay refused with a way named. Hook answers only: the host may have no sudo rule.
    sudo = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'sudo -n zgrep -hcF -f - /var/log/syslog'")
    check("4a sudo -n before a reader is read-only: no ask after the approval", "permissionDecision" not in sudo,
          sudo.get("permissionDecision"))
    su = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'sudo su -'")
    su_why = su.get("permissionDecisionReason", "")
    check("4b sudo su - is refused and names sudo before the reader",
          su.get("permissionDecision") == "deny" and "sudo zgrep -F -f - FILE" in su_why, su_why[:200])
    hop = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'ssh aux01 zgrep -F -f - /var/log/x'")
    hop_why = hop.get("permissionDecisionReason", "")
    check("4c a second hop is refused and names one ssh per host",
          hop.get("permissionDecision") == "deny" and "one ssh command per host" in hop_why, hop_why[:200])
    # many hosts in one command: the value is read once and goes to every host of the loop; the run needs
    # one approval and one resolve. One real host here, so the loop visits it twice.
    loop = hook(f"for h in {HOST} {HOST}; do printf '%s' KEY | ssh -o BatchMode=yes $h "
                f"'grep -c -x -F -f - {remote_file}'; done")
    check("5a a loop over hosts after the approval gets no ask", "permissionDecision" not in loop,
          loop.get("permissionDecision"))
    out5 = in_sandbox("s5", loop["updatedInput"]["command"], [IP])
    check("5b in the sandbox the exact value arrived on every pass of the loop",
          [ln for ln in out5.splitlines() if ln.strip() == "1"] == ["1", "1"], out5[-400:])
    check("5c the value never shows in the loop's output", value not in out5)
    b64 = hook(f"printf '%s' KEY | ssh -o BatchMode=yes {HOST} 'echo aGk= | base64 -d | bash'")
    check("4d a remote encoder is refused and names the stdin way",
          b64.get("permissionDecision") == "deny" and "pipe it on stdin" in b64.get("permissionDecisionReason", ""),
          b64.get("permissionDecisionReason", "")[:200])
finally:
    subprocess.run(["ssh", "-o", "BatchMode=yes", HOST, f"rm -f {remote_file} {remote_file}.w"], timeout=30)
    left = subprocess.run(["ssh", "-o", "BatchMode=yes", HOST, f"ls {remote_file}* 2>/dev/null | wc -l"],
                          capture_output=True, text=True, timeout=30).stdout.strip()
    print("remote files left:", left)
print("RESULT", "ok" if ok else "FAILED")
sys.exit(0 if ok else 1)
