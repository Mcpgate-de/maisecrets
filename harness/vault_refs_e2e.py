"""End to end: the real Claude Code client, the fake MCP server of harness/vault_server.py and the fake upstream.

Probe P1 of vault references (docs/PROTOCOL.md section 4) with the real client:

0. A session start alone writes no header and asks no server.
1. A first session calls the server's tool: its first token makes maisecrets read the metadata and write the
   Client-Vault header on that entry of a client profile of its own (CLAUDE_CONFIG_DIR in a temp folder; the person's
   own profile is never touched), with a notice. It prints whether the client sends the header in the same session.
2. A second session connects with the header; the fake server binds the kid (auto_bind, as after a login).
3. The scripted model calls the server's tool, gets tokens, writes them into a file with Write and with Bash.
4. Checks: the files hold the values; no request to the upstream and no file of the client profile (the transcript)
   holds a value; the header is still in the client config after the client's own writes; the audit names the key.

A second run with client_header false (P2) must leave the tokens in the files and resolve nothing. A third run
puts the server entry into a non-empty `.config.json` of the profile and a stale `.claude.json` beside it with the
same server name on another URL: the client then uses `.config.json` (2.1.301), so maisecrets must read and write
that file, and the stale one keeps its bytes.

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


def run(header_on: bool, legacy: bool = False) -> list[str]:
    fails: list[str] = []
    work = Path(tempfile.mkdtemp(prefix="maisecrets-vault-refs-e2e-"))
    proj, profile, home = work / "proj", work / "profile", work / "vaulthome"
    for d in (proj, profile, home):
        d.mkdir()
    with VaultServer() as srv:
        srv.auto_bind = True
        srv.mint("EMAIL_1", EMAIL)
        srv.mint("NAME_2", NAME)
        client_file = profile / (".config.json" if legacy else ".claude.json")
        client_file.write_text(json.dumps({
            "hasCompletedOnboarding": True,
            "mcpServers": {"demo": {"type": "http", "url": srv.url + "/mcp"}},
            "projects": {str(proj): {"hasTrustDialogAccepted": True}}}, indent=2))
        stale = profile / ".claude.json"
        if legacy:
            stale.write_text(json.dumps({"hasCompletedOnboarding": True,
                                         "mcpServers": {"demo": {"type": "http", "url": "https://stale.example/mcp"}},
                                         "projects": {str(proj): {"hasTrustDialogAccepted": True}}}, indent=2))
        stale_before = stale.read_bytes() if legacy else b""
        (home / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": srv.cert, "client_header": header_on}))
        (home / "guard.json").write_text(json.dumps({"expect": "off"}))
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE_CODE_", "ANTHROPIC_"))
               and k != "CLAUDECODE"}
        env.update(ANTHROPIC_BASE_URL=f"http://127.0.0.1:{PORT}", ANTHROPIC_API_KEY="harness-fake-key",
                   CLAUDE_CONFIG_DIR=str(profile), MAISECRETS_HOME=str(home), NODE_EXTRA_CA_CERTS=srv.cert,
                   CLAUDE_CODE_MAX_RETRIES="0", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                   MAISECRETS_GUARD_CLIPBOARD="off")
        # session 0: a start alone writes nothing and asks no server
        _claude("Say hello.", [{"text": "hello"}], work, env, "Read")
        cfg = json.loads(client_file.read_text())
        if cfg["mcpServers"]["demo"].get("headers") or any(e["path"].startswith("/.well-known/") for e in srv.log):
            return ["a session start without a server token wrote a header or asked the server"]
        # session 1: the first result with a server token is the trigger: one metadata request, the header on this
        # entry, a notice. The second call of the same session shows whether the client reads the header again
        n_before = len(srv.log)
        r1 = _claude("List the customers twice.", [{"tool": "mcp__demo__customers", "input": {}},
                                                   {"tool": "mcp__demo__customers", "input": {}}, {"text": "done"}],
                     work, env, "mcp__demo__customers")
        cfg = json.loads(client_file.read_text())
        header = cfg["mcpServers"]["demo"].get("headers", {}).get("Client-Vault")
        if header_on and not header:
            return [f"the first token wrote no header (see {work}; stdout {r1.stdout[-300:]!r})"]
        if not header_on and header:
            return ["client_header false, and a header was written"]
        if header_on:
            calls = [e for e in srv.log[n_before:] if e["path"] == "/mcp" and e["method"] == "POST"]
            same = any(e["client_vault"] == header for e in calls)
            print(f"[MEASURE] vault_refs: MCP requests after the header write in the same session carry it: {same} "
                  f"({len(calls)} POST /mcp in session 1)")
            if "supports Client-Vault" not in (r1.stdout + r1.stderr) and \
                    "supports Client-Vault" not in (r1.out / "debug.log").read_text(errors="ignore"):
                fails.append("no notice for the person after the header write")
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
        after = json.loads(client_file.read_text())["mcpServers"]["demo"].get("headers", {})
        if header_on and after.get("Client-Vault") != header:
            fails.append("P7: the header is gone after the client's own writes")
        if legacy and stale.read_bytes() != stale_before:
            fails.append("the stale .claude.json changed: maisecrets or the client wrote the file the client "
                         "does not use")
        if legacy and (profile / ".claude.json.maisecrets-backup").exists():
            fails.append("a backup lies beside the stale .claude.json")
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
    for name, on, legacy in (("vault_refs_resolve", True, False), ("vault_refs_off", False, False),
                             ("vault_refs_config_json", True, True)):
        fails = run(on, legacy)
        print(("[FAIL] " if fails else "[ok  ] ") + name + ("".join(f"\n       {f}" for f in fails)))
        bad += bool(fails)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
