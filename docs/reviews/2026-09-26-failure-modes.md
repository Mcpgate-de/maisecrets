# maisecrets: failure modes and robustness review

Reference point: `/Users/akruse/maisecrets`, HEAD `4f671dd`. The lock change was uncommitted when the review
started and became commit `c723767` while it ran. `4f671dd` adds a Windows retry around `os.replace`.
Unit tests: 58, OK (measured). Probes ran in a scratchpad copy with a temp `MAISECRETS_HOME`.

Client semantics (VERIFIED, https://code.claude.com/docs/en/hooks). When a command hook reaches its timeout,
Claude Code kills it and discards its output: "a timed-out hook renders no decision". This is fail-open.
For `PostToolUse`, "exit code 2 isn't honored", so a redaction failure lets the raw tool output through.
Codex is fail-open on a hook failure (ASSUMED here; the code comment at `vault.py:79ff` says it was measured).

## 1. The per-mutation lock

**Correctness: good for the tested path.** `_Mutation.__enter__` re-reads the index at depth 1 under the lock.
`__exit__` saves on a clean exit (`vault.py:392-408`). Mutation probe, 20 runs each (measured):
- lock disabled: 20/20 failures of the 12-process test;
- no re-read under the lock: 20/20 failures;
- no `@_mutating` decorator: 20/20 failures;
- code as committed: 0/20 failures.

**F1. The lock wait has no deadline (VERIFIED).** `fcntl.flock(fd, LOCK_EX)` blocks (`vault.py:100`).
A second process held the lock for 4 s. A `user-prompt` hook then took 3.77 s wall time (measured).
Work that runs under the lock includes these `security` calls without a timeout (`vault.py:244/252/259`):
- `fp_key` (`vault.py:439`);
- `backend.put`;
- up to 25 deletes per `expire`;
- the whole SessionStart sweep, `expire(limit=None)` (`dispatch.py:29`), at about 10 ms per keychain delete.

If a locked keychain shows a dialog, the lock stays held; every other hook waits to its 10 s timeout and fails
open. A `UserPromptSubmit` timeout sends the raw secret to the model. Actor: none (an operational fault).
Control: R1.

**F2. On Windows, the lock silently turns into no lock (VERIFIED code; timing ASSUMED).**
`msvcrt.locking(LK_LOCK)` tries 10 times at 1 s intervals, then raises `OSError`
(https://docs.python.org/3/library/msvcrt.html#msvcrt.locking). The code catches that as
`except OSError: self.fd = None` (`vault.py:104-105`) and continues without the lock. It also leaks the fd.
The same branch hides `ENOLCK` on NFS and an unwritable home. The resolver process and the CLI have no hook
timeout, so they then write the index without the lock.

**F3. Windows sweep cost (VERIFIED code; timing ASSUMED).** `WindowsVaultBackend` starts one PowerShell for
each delete (`vault.py:345`, `timeout=15`). The sweep cap of 25 fits 10 ms keychain deletes. At
0.5-1.5 s per PowerShell start, one `put` can pass the 10 s hook timeout; `timeout=15` is longer too.

**F4. A second Vault in the same process deadlocks (measured).** `a._exclusive()` followed by `b.admit()`
blocked until SIGALRM fired. No current code path does this.

**F5. The `fp_key` race outside the lock (VERIFIED code).** `vault.fingerprint()` runs outside any mutation
in `_exact_redact` and `_inserted_values` (`hooks.py:457, 488`). On the very first run, a `post-tool` and a
`put` can each create a different fingerprint key. One key overwrites the other (`-U`). The fingerprints in
the index then match nothing, so exact redaction and dedup silently stop working.

**Acceptable:** an exception inside a mutation (inner saves are consistent); a stale `.lock` file (the kernel
releases flock on process death). A hook killed during `atomic_write` leaves `*.<pid>.tmp` files that are
never cleaned up (plaintext for `vault.json`).

## 7. Vault deletion and corruption

**F6. An unreadable index resets to empty, and the next `put` destroys a stored value (measured).**
`_load_index` returns an empty index on `OSError` or `ValueError` (`vault.py:424-428`). The counters restart,
so the next value gets `SECRET_c1` again. For the keychain, `add-generic-password -U` overwrites the old item.
For the file backends, the key is overwritten in the file. The file backends' `_load` also returns `{}` on an
error and then saves, which drops all values. Probe: I stored `SECRET_c1`, cut `index.json` in half, and
stored a new value. The result was `SECRET_c1` again, and the first value was gone from `vault.json`.
Triggers: a crash after a rename without `fsync` (`atomic_write`, `vault.py:50-76`), a manual edit (ASSUMED),
or the F2 fallback on Windows.

This is the only path found that deletes a live user secret.

## 2. Fail-open paths

| Path | Claude Code | Codex | Evidence |
|---|---|---|---|
| Any exception in `post_tool` (unwritable HOME, `openssl` absent, keychain error) | **open**: exit 2 not honored, raw output reaches the model | exit 2 → ASSUMED open | Unwritable HOME probe: `PermissionError`, exit 2 (measured) |
| Any exception in `user_prompt` / `pre_tool` | closed, reason shown | ASSUMED closed | `hooks.py:601-606` |
| Timeout from a lock wait, keychain dialog, PowerShell, or huge-transcript scrub | **open** | **open** | F1, F3 |
| `xclip` forks and keeps the inherited stdout pipe open | hook may hang until timeout → open | same | `hooks.py:53` has no `stdout=DEVNULL` (ASSUMED behaviour of xclip) |
| `_has_live` cached False after a read error | shapeless values pass `post_tool` unredacted | same | `hooks.py:576-585` |
| No Python 3.11+ | closed on prompt/pre; open on post (exit 2) | — | `run.sh:14-15` |
| `openssl` absent (Linux default) | `FileNotFoundError` → as the rows above | — | `vault.py:287-288` does not catch it |

**The docs are wrong here.** `README.md:333` says 30 s; `hooks.json` sets 10 s. The prompt path is not only
the millisecond regex: it waits for the lock and runs the keychain, the clipboard (3 s) and the scrub.

## 3. The detached scrub child

- **F7. Lost records after `os.replace` (measured).** A writer that keeps its fd open appended after the
  scrub. The record went to the orphaned inode and is not in the file. If Claude Code keeps an fd open, all
  later records of the session are lost from disk. If it reopens for each write, only the records written
  in the read→replace window are lost (ASSUMED; the client's write pattern is unknown).
- **F8. The permissions widen from 0600 to 0644 (measured).** `open(tmp, "w")` uses the umask
  (`hooks.py:162-165`). All 487 transcripts in `~/.claude/projects/-Users-akruse` are `-rw-------`.
- **F9. Two scrubbers can undo each other's work (VERIFIED by logic).** Each child reads, replaces, and
  renames with no lock. B read the file before A renamed it. B's write then restores the value that A removed.
  An MCP call spawns a child on every call with inserted values (`hooks.py:541-542`), so overlap is common.
- **F10. No child starts when the in-hook scrub succeeded (VERIFIED, `hooks.py:244-245`).** The in-hook scrub
  finds the `queue-operation` record and returns True. The record written after the hook returns
  (`TESTING.md:44`) then stays unscrubbed. The child also stops at the first success (`break`). It gives up
  silently after 15 s, and it skips files over 50 MB. The user is not told in any of these cases.
- **Windows:** `start_new_session` is POSIX only. If the client kills the hook's job object, the child dies
  (ASSUMED).

## 4. `kill -TERM $$` inside `$(…)`

`$$` is the top-level shell in bash and in zsh. This is correct for a simple command under `bash -c` and
`bash -lc` (rc 143, command not run; measured). **The command still runs with an empty value (measured) in
these cases:**
- in a pipeline element (bash: any element; zsh: every element except the last);
- in `( … )`;
- in `{ …; } &`;
- under `trap '' TERM`.

The killed parent does not stop its forked children. Example:
`curl -u "u:$(…)" url | jq` runs curl with an empty password. The false all-clear from the field report
comes back as `grep -c "⟦X⟧" f | head`. The unit test at `test_gates.py:93` passes only because the command
that prints is in the main shell. Git Bash: ASSUMED to behave like bash (not measured).

## 5. The pending prompt and `/maisecrets:send`

`send.md` runs `run.sh pending` with no session. `take_pending(None)` then returns the newest file across all
sessions (`dispatch.py:9-13`, `hooks.py:191-199`). The files never expire. So a `/maisecrets:send` in
session B can inject session A's prompt from days ago into B. A prompt from another project or conversation
can then act as a user instruction. It is ASSUMED that UserPromptSubmit sees the expanded `!` text. If it
does, `admit()` also gives B the right to resolve A's references. This silently breaks the session rule.
Control: key the file to the session (Claude Code exposes `${CLAUDE_SESSION_ID}` to commands, ASSUMED), add a
TTL (for example 10 min), and refuse the fallback to the newest file.

## 6. The 12-process concurrency test

It is a real proof for `put` on `jsonfile`: every mutation of the lock breaks it (see §1). It does not cover `grant`/`redeem` (a lost `uses` count lets a nonce exceed 20
uses), `admit`, the keychain or PowerShell backends, or the values in `vault.json` (it counts index entries).

## Recommendations (ranked)

1. **Deadline inside each hook (S).** Set an internal timer (SIGALRM, or a thread on Windows) at about 7 s.
   When it fires, print the decision that fails closed and `os._exit`. For `post_tool`, print
   `updatedToolOutput` = "[maisecrets: output withheld, <reason>]" (Codex: `block`). Also acquire the lock
   with `LOCK_NB` polling and a deadline. Prevents: F1 and F3 timeouts that fail open.
2. **`post_tool` fails closed by replacing the output, not by exit 2 (S).** Prevents: a raw secret reaching
   the model when HOME is unwritable, `openssl` is absent, or the keychain errors.
3. **Refuse a corrupt index; never reset it to empty (S).** Raise, keep the file as
   `index.json.corrupt-<ts>`, and add `fsync` to `atomic_write`. Do the same for the file backends' `_load`.
   Prevents: F6, the overwrite of a stored secret.
4. **Resolve in the main shell before the command runs (M).** Emit `__ms1="$(resolve …)" || exit 97;` as a
   prefix, then use `"$__ms1"` at each reference. Prevents: §4, a pipeline, subshell or background command
   that runs with an empty value. This also lets a grant be single-use again.
5. **Scrub in place under a sidecar lock (M).** Replace the value with a mask of the same byte length, with
   `r+` and seek (keeps the inode and the mode). Always start the child, and scrub until the deadline.
   Prevents: F7-F10 (lost records, 0644, scrubbers that undo each other, the record written late).
6. **Key the pending file to the session, with a TTL and no fallback to the newest file (S).**
   Prevents: §5, a stale or foreign prompt in the wrong conversation, and the silent cross-session `admit`.
7. **Make a failed lock fail closed; make the lock state process-wide (S).** Handle the `msvcrt` give-up and
   `ENOLCK` as errors, not as "no lock". Use one lock per process with a counter. Prevents: F2 lost updates,
   the F4 deadlock, and the F5 race (call `fp_key` under the lock).
8. **Keep backend I/O out of the critical section (M).** Mark entries purged under the lock and delete them
   after the release. Add `timeout=` to every `security`/`openssl` call. Make the sweep cap depend on the
   backend (Windows: 1-2). Extend the concurrency test to `grant`/`redeem` uses and to `vault.json` values.
   Prevents: F1/F3 starvation, and a regression that stays hidden.
