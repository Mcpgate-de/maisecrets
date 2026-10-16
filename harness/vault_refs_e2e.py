"""End to end: the real Claude Code client, the fake MCP server of harness/vault_server.py and the fake upstream.

Probe P1 of vault references (docs/PROTOCOL.md section 4) with the real client:

1. A first session starts: maisecrets writes the Client-Vault header on the user-scope server of a client profile
   of its own (CLAUDE_CONFIG_DIR in a temp folder; the person's own profile is never touched).
2. A second session connects with the header; the fake server binds the kid (auto_bind, as after a login).
3. The scripted model calls the server's tool, gets tokens, writes them into a file with Write and with Bash.
4. Checks: the files hold the values; no request to the upstream and no file of the client profile (the transcript)
   holds a value; the header is still in the client config after the client's own writes; the audit names the key.

A second run with client_header false (P2) must leave the tokens in the files and resolve nothing.

Usage: python3 harness/vault_refs_e2e.py        (needs claude and openssl; about a minute)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from run import PORT, start_server  # noqa: E402
from vault_server import VaultServer, kid_from_header  # noqa: E402

OPEN, CLOSE = "⟦", "⟧"
EMAIL, NAME = "e2e-person-one@example.org", "E2E Person Two"


def _claude(prompt: str, turns: list, work: Path, env: dict, tools: str) -> subprocess.CompletedProcess:
    out = work / f"out-{len(list(work.glob('out-*')))}"
    out.mkdir()
    settings = work / "settings.json"
    settings.write_text(json.dumps({"enabledPlugins": {"maisecrets@synced": False,
                                                       "maisecrets@anthropic-plugin-directory": False}}))
    srv = start_server(turns, out)
    try:
        r = subprocess.run([shutil.which("claude") or "claude", "-p", prompt, "--plugin-dir", str(ROOT),
                            "--settings", str(settings), "--permission-mode", "default", "--allowedTools", tools,
                            "--max-turns", "4", "--debug-file", str(out / "debug.log")],
                           cwd=work / "proj", env=env, capture_output=True, text=True, timeout=180,
                           stdin=subprocess.DEVNULL)
    finally:
        srv.terminate()
    r.out = out
    return r


def run(header_on: bool) -> list[str]:
    fails: list[str] = []
    work = Path(tempfile.mkdtemp(prefix="maisecrets-vault-refs-e2e-"))
    proj, profile, home = work / "proj", work / "profile", work / "vaulthome"
    for d in (proj, profile, home):
        d.mkdir()
    with VaultServer() as srv:
        srv.auto_bind = True
        srv.mint("EMAIL_1", EMAIL)
        srv.mint("NAME_2", NAME)
        (profile / ".claude.json").write_text(json.dumps({
            "hasCompletedOnboarding": True,
            "mcpServers": {"demo": {"type": "http", "url": srv.url + "/mcp"}},
            "projects": {str(proj): {"hasTrustDialogAccepted": True}}}, indent=2))
        (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": srv.cert, "client_header": header_on}))
        (home / "guard.json").write_text(json.dumps({"expect": "off"}))
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE_CODE_", "ANTHROPIC_"))
               and k != "CLAUDECODE"}
        env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", ANTHROPIC_API_KEY="harness-fake-key",
                   CLAUDE_CONFIG_DIR=str(profile), MAISECRETS_HOME=str(home), NODE_EXTRA_CA_CERTS=srv.cert,
                   CLAUDE_CODE_MAX_RETRIES="0", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                   MAISECRETS_GUARD_CLIPBOARD="off")
        # session 1: the session start writes the header; the client connected before it, without one
        _claude("Say hello.", [{"text": "hello"}], work, env, "Read")
        cfg = json.loads((profile / ".claude.json").read_text())
        header = cfg["mcpServers"]["demo"].get("headers", {}).get("Client-Vault")
        if header_on and not header:
            return [f"the first session wrote no header (see {work})"]
        if not header_on and header:
            return ["client_header false, and a header was written"]
        # session 2: the header goes to the server; the model gets tokens and writes them
        tokens = f"{OPEN}EMAIL_1{CLOSE},{OPEN}NAME_2{CLOSE}"
        turns = [{"tool": "mcp__demo__customers", "input": {}},
                 {"tool": "Write", "input": {"file_path": str(proj / "kunden.csv"),
                                             "content": f"email,name\n{tokens}\n"}},
                 {"tool": "Bash", "input": {"command": f"printf '%s\\n' {OPEN}NAME_2{CLOSE} > {proj}/name.txt"}},
                 {"text": "done"}]
        r = _claude("Write the customers into kunden.csv.", turns, work, env, "mcp__demo__customers,Write,Bash")
        if header_on:
            sent = [e for e in srv.log if e["path"] == "/mcp" and e["client_vault"] == header]
            if not sent:
                fails.append("the second session sent no Client-Vault header to the MCP server")
            if kid_from_header(header) not in srv.bindings:
                fails.append("the server did not bind the kid")
        want_csv = f"email,name\n{EMAIL},{NAME}\n" if header_on else f"email,name\n{tokens}\n"
        got = (proj / "kunden.csv").read_text() if (proj / "kunden.csv").exists() else "<missing>"
        if got != want_csv:
            fails.append(f"kunden.csv holds {got!r}")
        want_name = f"{NAME}\n" if header_on else f"{OPEN}NAME_2{CLOSE}\n"
        got = (proj / "name.txt").read_text() if (proj / "name.txt").exists() else "<missing>"
        if got != want_name:
            fails.append(f"name.txt holds {got!r}")
        if not header_on and srv.resolved:
            fails.append("client_header false, and the server released values")
        bodies = "".join(p.read_text(errors="ignore") for p in r.out.glob("request_*.json"))
        if f"{OPEN}EMAIL_1" not in bodies:
            fails.append("the token never reached the model (did the MCP tool run?)")
        for value in (EMAIL, NAME):
            if value in bodies:
                fails.append(f"LEAK: {value[:6]}… reached the upstream")
        # the transcript: the hook's updatedInput is written there, and the scrub takes the values out again
        deadline = time.time() + 30
        while True:
            leaked = [p for p in profile.rglob("*.jsonl")
                      if any(v in p.read_text(errors="ignore") for v in (EMAIL, NAME))]
            if not leaked or time.time() > deadline:
                break
            time.sleep(1)
        if leaked:
            fails.append(f"a value stays in {len(leaked)} transcript file(s), e.g. {leaked[0].name}")
        after = json.loads((profile / ".claude.json").read_text())["mcpServers"]["demo"].get("headers", {})
        if header_on and after.get("Client-Vault") != header:
            fails.append("P7: the header is gone after the client's own writes")
        audit = (home / "audit.log").read_text() if (home / "audit.log").exists() else ""
        if header_on and "EMAIL_1@127.0.0.1\tWrite" not in audit:
            fails.append("no audit line for the Write")
        if any(v in audit for v in (EMAIL, NAME)):
            fails.append("a value is in the audit log")
    if fails:
        fails.append(f"work folder: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return fails


def main() -> int:
    if not shutil.which("claude") or not shutil.which("openssl"):
        print("[SKIP] vault_refs_e2e: needs claude and openssl")
        return 0
    bad = 0
    for on in (True, False):
        name = "vault_refs_resolve" if on else "vault_refs_off"
        fails = run(on)
        print(("[FAIL] " if fails else "[ok  ] ") + name + ("".join(f"\n       {f}" for f in fails)))
        bad += bool(fails)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
