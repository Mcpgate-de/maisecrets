# maisecrets on Codex: where protection is less than the README claims

Scope: working tree of /Users/akruse/maisecrets on 2026-09-26, codex-cli 0.157.1 installed. `vault.py` changed while I read it. Line numbers are from the last read. Marks: **V** = verified (source given), **A** = assumed.

## 0. Three new findings with the highest risk

**F1. An exception text can carry the value to the model.** `KeychainBackend.put` runs `security add-generic-password … -w <value>` with `check=True` (vault.py:245-248). If the call fails, the `CalledProcessError` text contains the full argv. `main()` writes `{type}: {exc}` to stderr and exits 2 (hooks.py:605-606). On Codex, exit 2 means "block, and use stderr as the reason" (V, learn.chatgpt.com/codex/hooks). For PostToolUse, that reason replaces the tool result, so the model reads it. Measured: the format string prints `Command '['false', '-w', 'VALUE-XYZ']' returned non-zero exit status 1.` (V, measurement). A put fails, for example, when the keychain is locked with no UI (SSH). Claude Code also shows exit-2 stderr to the model (A). Actor: A1. Control: print only the exception type; make backend errors value-free.

**F2. Rehydration cannot work inside the default Codex sandbox on macOS.** The resolver runs inside the command, so it runs inside the sandbox. `redeem` is `@_mutating`, so it writes `index.json`. I ran `codex sandbox -c sandbox_mode="workspace-write"` with a probe (V, measurement):
- open `~/.maisecrets/index.json` for read: OK;
- open for write, create a file in `~/.maisecrets`: `EPERM`;
- `security find-generic-password`: rc 44 "parameters not valid". Outside the sandbox the same call says "could not be found".

So the index write and the keychain read both fail, and `|| kill -TERM $$` stops the command: fail-closed, but the feature does not work. The harness hides this with a vault home under `tempfile.mkdtemp` and `jsonfile` (codex.py:62-72) (V). The probe also shows that the sandbox can **read** `~/.maisecrets`. With `encrypted-file`, the key and the vault are both readable to a sandboxed command; only C8 text matching stops A2.

**F3. On Codex, `allow` skips the approval prompt.** The docs say: "an `allow` lets the request proceed without surfacing the approval prompt" (V, codex/hooks). `_updated` returns `allow` for every rewritten Bash and MCP call. The comment "its own approval policy still applies" (hooks.py:323-326) is wrong, and the README lines "You approve this, and only this" and "the permission prompt … shows your own value" are false on Codex. Actor: A2, with a key the human typed in this session. C4 is then the only gate.

## (a) Fail-open on hook failure and timeouts

Only exit 2 blocks; other exits and timeouts fail open (V, codex/hooks). Plugin timeouts: 10/10/20/30 s (hooks.json) (V). Gaps:
1. dispatch.py imports `maisecrets.hooks` outside a `try` (dispatch.py:7): an import error exits 1 (V).
2. `_Lock` is a blocking `flock` with no deadline, held during backend calls (`put` → `expire(limit=25)`; on Windows one PowerShell per call, up to 15 s each) (V structure). One slow holder or a hung `security` times out every other hook (A).
3. The scan costs about 5 s/MB (TESTING.md:105) (V). At 20 s, an output of about 4 MB times out and reaches the model raw (A: Codex passes the full output).
4. The command is `bash "…/run.sh"`. Codex on Windows does not need Git Bash (A); a missing or WSL `bash` fails all four hooks open. Codex supports `commandWindows` (V).

What the plugin can do:
What the plugin can do:
- A **watchdog** at (timeout − 2 s) prints the block or deny JSON and exits 2.
- A **lock with a deadline** (`LOCK_NB` plus retry). No backend call under the lock; `expire` only at SessionStart or in a detached child.
- **On Codex, cap the output before the scan** (for example 64 KB, marked "truncated"). The reason replaces the result anyway.
- `try/except BaseException` around **all of dispatch.py**, exit 2.
- A **crash journal**: a start marker with no end marker means the client killed the hook. The next hook tells the user.
- A plugin **skill** (loads without hook trust, A) tells the model to warn when the SessionStart `additionalContext` "maisecrets active" is absent (V: SessionStart supports it).
- For admins: `requirements.toml` with `allow_managed_hooks_only` and `command_windows` (V, doc example).

It cannot act on a SIGKILL, an OOM, a missing interpreter, or hooks that nobody trusted.

## (b) Block-as-output on write actions

Codex "replaces the tool result with that feedback" (V, doc). In code mode, the JS sees a **rejected promise** (hooks.py:548-552, authors' measurement) (V). A script or model may send the write again (A; not measured). "the command ran" is unclear for an MCP write.

Skipping the block when the only hits are values the hook inserted is a leak: the echo shows the model a value it had only as a placeholder. Keep the block. A duplicate write is visible and can be repaired; a leak cannot. Reduce the retry risk:
- Use this wording as the first line: `Tool call completed successfully (status: ok). It already took effect; do not call it again. maisecrets replaced N private value(s) in the result with ⟦REF⟧ placeholders; the result follows.` For `mcp__*` tools, add the tool name and "this is the result, not an error".
- Keep the non-secret fields (ids, URLs) so the model can confirm success. Measure with `--real` and a counting MCP server (f).

## (c) Trust hash stability

Measured in `~/.codex/config.toml` (V): the trust keys are `maisecrets@<marketplace>:hooks/hooks.json:<event>:<group>:<index>`. Both installed copies (0.3.17 workspace, 0.3.18 marketplace) show **identical** `trusted_hash` values. So the hash does not depend on the install path or the version. I could not reproduce the hash from the JSON of one hook (A: it covers matcher, command, timeout). hooks.json has not changed since commit 87c06fe (V, git log). So a release prompts again only when a hook entry, timeout, matcher or the **order** changes (the key is positional). Trust covers the command line, not run.sh or hooks.py: code changes run unreviewed; say so in the README. Put the one-time changes (Windows command, timeouts) into **one** release, then freeze hooks.json with a CI check.

## (d) `$$`-kill under `bash -lc` and PowerShell

Under `/bin/bash -lc` (and zsh), `$$` inside `$( … )` is the top shell, so the kill ends the command (V). A model-written `trap '' TERM` continues with an empty value, so this covers accidents, not A2.

PowerShell: the rewrite gives `"$("C:/…/python.exe" "C:/…/resolve.py" K --grant N || kill -TERM $$)"`. A quoted path followed by a string is a parse error without `&`. `||` exists only in PS 7. `$$` is the **last token of the previous line**, not a PID. `kill -TERM` is not valid for `Stop-Process`. So there is no fail-closed. Most variants fail to parse (blocks by accident); one that parses runs with an empty value (A). Control: on Codex for Windows, deny Bash commands with placeholders until a PowerShell adapter exists (`& $py $script …`).

## (e) Two copies

Present on this machine (V): `~/.codex/plugins/cache/workspace-directory/maisecrets/0.3.17` and `…/maisecrets/maisecrets/0.3.18`, both trusted. 0.3.17 does not have the `atomic_write` fix (V, diff). Codex starts matching hooks **concurrently, with no dedupe** (V, doc). Consequences:
- Two grants and two audit lines per call; `max_resolves_per_hour` stops at 30 real calls. Which `updatedInput` wins is unknown (A).
- Two blocks; two concurrent rollout scrubs (g).
- **Version skew**: the old copy runs old bugs next to the fix.

Control: SessionStart warns when `$CODEX_HOME/plugins/cache/*/maisecrets/*` holds more than one copy. Make grants, audit and limiter idempotent per `(session, tool_use_id, key)`. Do not let one copy skip: a crash after the skip decision fails open.

## (f) The Codex harness

It proves: hook discovery from a marketplace install; a prompt block with 0 request leaks; Bash redaction through block; rehydration in code-mode `exec`. It proves these only with `--dangerously-bypass-hook-trust`, `approval_policy=never`, `jsonfile` in TMPDIR, and only `*.jsonl` scanned (codex.py:76-135) (V).

It cannot prove: trust, the real vault and sandbox (F2), approval (F3), MCP, the plain shell tool, Windows, two copies, retries, fail-open. `"maisecrets" in out` also matches a "hook … Failed" line (codex.py:142) (V).

Smallest additions: (1) fail on any `Failed` line and require a debug line per event (S); (2) scan **every** CODEX_HOME file as bytes, sqlite included (S); (3) vault outside the writable roots, default backend, `workspace-write`: red today (S); (4) rollout keeps the final turn records after a scrub (S); (5) a stdio MCP echo-and-count server, with `--real` for retries (M); (6) a run without the bypass flag must report "unprotected" (M).

## (g) Claude-specific behaviour that is silently wrong on Codex

- **The rollout scrub swaps the inode** (`os.replace`, hooks.py:162-165) (V). If Codex keeps the rollout open (A), later records go to the unlinked inode and are lost; the harness still passes. Control: overwrite **in place, same byte length**.
- **`client_of` guesses** from payload keys (hooks.py:31-36). A Codex payload taken as Claude gets `updatedToolOutput`, which Codex ignores: raw leak. Check `PLUGIN_ROOT`/`PLUGIN_DATA` first; only Codex sets them (V, doc).
- **Hints** name `/maisecrets:*` and "Ask Claude" (hooks.py:224, 251-263); Codex plugins ship skills, not `commands/` (V, docs list skills only).
- **The @-mention block** assumes inlining; Codex `@` inserts a path (A), so ordinary prompts are blocked.
- The scrub never touches `history.jsonl` or the sqlite files (A: may hold the raw prompt); addition (2) measures it.
- Subagents and forks get a new `session_id`: `foreign-session` is safe but unclear; name it in `_deny_reason`.
- THREAT-MODEL C5 says "one read"; `GRANT_USES` is 20 (V).

## Ranked recommendations

1. **Value-free error paths** (S): A1 on hook failure (F1).
2. **Fail-closed budget** (M): watchdog, lock deadline, output cap, dispatch `try`, crash journal. Fail-open (a).
3. **Sandbox-proof resolver** (M): the hook serves the value once through a FIFO in TMPDIR; harness (3). Rehydration on real setups (F2).
4. **Own approval for `allow`** (M): deny with a confirm token that UserPromptSubmit records; fix README. A2 exfiltration (F3).
5. **In-place same-length scrub + integrity check** (S/M): A4, lost history.
6. **Correct Codex adapter** (S): env detection, "completed, do not retry" wording, no @-block or `/maisecrets:*` hints, Windows deny plus `commandWindows`. Duplicate writes, Windows fail-open, misclassification.
7. **Duplicate-copy warning, idempotent grants** (S): limiter, audit, version skew.
8. **Harness additions** (S→M): make items 2-7 go red when removed.
