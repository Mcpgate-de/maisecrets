# Local diagnostics and reporting (design, 0.6.10)

Status: design for review. Nothing here is built yet.

maisecrets has no telemetry, no server and no automatic error upload, and it keeps it that way. This design
adds a way to learn about real problems: maisecrets records its own internal failures **on this computer**, as
fixed codes, and the person can turn one into a report that they read **before** anything leaves the machine.

## 1. Rules (the invariants)

- **D1 Nothing leaves the machine by itself.** The incident record has no network code. No version, no hash,
  no id is sent anywhere without a step the person takes.
- **D2 A record holds no data of the person.** An incident is a fixed error code, a Python exception class
  name, a hook event, a tool class, a client family, counts, times, the plugin version and the platform. It
  never holds an exception message, a path, a command, a tool name of an MCP server, a prompt, a tool input or
  output, a session id, a user or host name, a key or a value.
- **D3 Only the person sends.** Opening the browser on the issue page and filing with `gh` happen only for a
  prompt the person typed (`source` user, as C22). A tool call never sends: the CLI prints the text and the
  link and does nothing else, and a Bash or PowerShell command that carries the send form is refused.
- **D4 Recording never changes an answer.** A best-effort failure stays best-effort, a fail-closed path stays
  fail-closed. The only visible change: a fail-closed message gets one line that names `/maisecrets:report`.
- **D5 The record is bounded and can go.** At most 50 incident groups; `wipe` deletes it; a damaged file is
  moved aside and never stops a hook.

## 2. What happens today

- `events.log`: one line per detection (rule, type, key), for false-positive reports. Not for failures.
- `hooks.log`: one line per hook run, with `failed <ExceptionType> (<errno>, <file name>)` on a failure. It
  has a session id prefix and a tool name, so it is no report material as it is.
- `_debug()`: 16 places write a line to `$MAISECRETS_DEBUG_LOG` only when that variable is set (harness).
  Nothing keeps them otherwise. 7 places answer fail-closed (`_fail_closed`, `_failure`).
- `/maisecrets:report` (`cli.cmd_report`): `report last` prepares a false-positive issue from `events.log`,
  `report bug|feature <text>` one without an event. On a computer with a desktop it **opens the browser at
  once** on the prefilled issue page, so the issue text reaches GitHub in the page address before the person
  read it. `--create` files it with `gh`. The command text tells the model to use `--create` only when the
  person wrote it; nothing enforces that, and a model can run `run.sh report … --create` as a Bash call.

The design keeps `events.log` and `hooks.log` as they are, reuses the report renderer (`events.link`,
`_report_out`) and the hint record (`settings.claim_hint`), and fixes the two send paths above (D3).

## 3. Data model: `~/.maisecrets/incidents.json`

```json
{
  "version": 1,
  "groups": {
    "destinations.commit/LockTimeout": {
      "code": "destinations.commit", "error": "LockTimeout", "class": "best-effort",
      "event": "PostToolUse", "tool_class": "Bash", "client": "claude",
      "count": 3, "first": "2026-10-09T08:14", "last": "2026-10-09T08:21",
      "version_first": "0.6.10", "version_last": "0.6.10",
      "hinted": false
    }
  }
}
```

- **Key and fingerprint.** The group key is `code/error`. The fingerprint shown to the person and put in the
  report is `code/error/` plus the first 6 hex characters of `sha256(code|error|client)`, for example
  `destinations.commit/LockTimeout/4f73a9`. Two persons with the same failure on the same client family get
  the same fingerprint; nothing in it is theirs.
- **`code`** is a fixed string at the call site, from a closed list in `maisecrets/incidents.py`
  (`CODES`). A test checks that every call site uses a listed code.
- **`error`** is `type(exc).__name__`. Only the class name, never `str(exc)`: an exception message can carry
  a path or a value (a keychain error once carried the value in its argument list).
- **`tool_class`** is one of `Bash`, `PowerShell`, `MCP`, `File`, `Other`, `-`. An MCP tool name names a
  server, which can name a company or a person's service, so only the class is kept.
- **`client`** is `claude` or `codex`.
- **Times** are kept to the minute locally; a report shows the date and the count only.
- **Bound.** 50 groups; above that the group with the oldest `last` goes. A group never grows: it only counts.
- **Version and platform** are not stored per group. The report reads them when it is made: plugin version,
  `platform.system()` and `platform.machine()`, Python `major.minor`. The client's own version is not known to
  the hook (no payload field), so a report says only "Claude Code" or "Codex".

**What could still point to a person (Q2):** the times (a work pattern) and the platform. Both stay local; a
report carries the date and the platform family. The counts say how much the person used maisecrets, which is
why the report shows them per failure and not in total.

## 4. Error codes, not stack hashes (Q3)

The failure places are few and known, so each gets a fixed code:

| Code | Place | Class |
|---|---|---|
| `destinations.pend`, `destinations.commit` | the destination record (C23) | best-effort |
| `hint.post-tool`, `hint.post-tool-failure` | a hint that could not be given | best-effort |
| `scrub.later-start`, `scrub.failed-prompt` | the transcript scrub child | best-effort |
| `mask-hidden` | removal of invisible characters in a file | best-effort |
| `hook.<event>.unexpected` | an exception that reaches `_failure` (each hook event) | fail-closed |
| `config.unreadable` | `config.json` that does not parse (block until fixed) | fail-closed |
| `store.no-write-access` | a `PermissionError` on the store folder | fail-closed |
| `hook.<event>.watchdog` | the watchdog answered before the hook finished | fail-closed |

A stack hash changes with every refactor, can carry a path in a frame name of another package, and says
nothing to a reader. A code is stable across versions, short, and says where to look. An exception that has
no code of its own lands in `hook.<event>.unexpected` with its class name, so it is still grouped.

## 5. Which failures are aggregated, and who sees what (Q4)

All of them are aggregated by `code/error`. What the person sees depends on the class:

- **best-effort** (the call goes on unchanged): recorded only. One hint after the **third** time in the same
  group (see 6). Example: the destination record could not be written.
- **fail-closed** (maisecrets blocks or withholds, as today): the person already sees the refusal. Its text
  gets one line: `This is a maisecrets problem; nothing was sent anywhere. /maisecrets:report last prepares a
  report you can read first.` No extra hint.
- **compatibility** (a part of the client does not work as expected): recorded; one hint after the **second**
  time. V1 has no compatibility code of its own (see 11): the mod's own failures cannot be recorded from the
  mod without a new file-writing call.

## 6. The hint (Q5, Q6)

The hint goes through the same channel as the existing hints (`additionalContext` of a PostToolUse), and only
the model reads it. Text:

> maisecrets recorded the same internal problem more than once (nothing was sent anywhere). Tell the user once,
> in one sentence, that /maisecrets:report last prepares a report they can read before they send it. Do not run
> that command yourself and do not open or file anything.

Anti-spam rules:
- one hint per fingerprint and hint revision, claimed under the lock of `hints.json` (`claim_hint`), so two
  hooks at once give it once;
- at most one incident hint per session;
- never in a subagent, never in a session without a typed prompt (the `interactive` list of C23), never with
  `tips: false`;
- never in the answer of a fail-closed path (that answer already names the report).

## 7. Only the person sends (Q7)

- `maisecrets report …` (the CLI, which a model can run) prints the report and the link. It never opens a
  browser and never runs `gh`. The old behavior (open at once on a desktop) goes.
- The send forms are typed prompts: `/maisecrets:report last --open` opens the browser on the prefilled page,
  `/maisecrets:report last --create` files it with `gh`; in Codex `maisecrets: report last open|create`. The
  UserPromptSubmit hook does it for a prompt whose `source` is the person (`TYPED_SOURCES`, as C22), and then
  lets the slash command run on to show what was done.
- A Bash or PowerShell command that carries a send form (`report … --open|--create`, the Codex sentence) is
  refused, as `IN_A_COMMAND_RE` refuses a settings change.
- Residual, as C22: a nested client fed the sentence built at run time, and Codex, which sends no `source`.

## 8. The same flow in Claude Code and Codex (Q8)

| Step | Claude Code | Codex |
|---|---|---|
| see what is recorded | `/maisecrets:diagnostics` | `maisecrets: diagnostics` |
| read the report | `/maisecrets:report last` (or `<fingerprint>`) | `maisecrets: report last` |
| open it in the browser | `/maisecrets:report last --open` | `maisecrets: report last open` |
| file it with `gh` | `/maisecrets:report last --create` | `maisecrets: report last create` |

`report last` now means the newest **incident**; the false-positive report of the newest detection becomes
`report detection` (a rename, with `report last` kept for a detection when no incident exists).

## 9. Damaged store and `wipe` (Q9, Q10)

- A file that does not parse is moved aside (`incidents.json.corrupt`, a copy is never written over) and a new
  one begins, as `destinations.json` does. A read that fails returns an empty record. Recording catches every
  exception: it never stops a hook and never changes an answer (D4).
- The record is written under a short lock (0.3 s, as the destination record); a busy lock skips the count.
- `wipe` deletes `incidents.json` and its aside copies and says so; `/maisecrets:status` shows the number of
  groups.

## 10. What is reused (Q11)

- `events.link`, `events.tracker_or_error`, `cli._report_out` for the issue page and `gh`;
- `settings.claim_hint` and `hints.json` for the once-only hint, with the key `incident:<fingerprint>`;
- the `interactive` session list of `destinations.json` for "a session with a typed prompt";
- the typed-prompt path of C22 for the send forms;
- `hooks.log` stays as it is (it has session ids and tool names, so it is no report material).

## 11. In 0.6.10, and later (Q12)

In 0.6.10: the record, the codes at the places in 4, `/maisecrets:diagnostics`, `report last|<fingerprint>`,
the typed send forms, the refusal of the send forms in a command, the hint, `wipe` and `status`, README,
PRIVACY.md and a threat-model row (C24) with beliefs for D1 to D5.

Later, on purpose:
- failures inside the mod (no Python, a timeout): the mod would need `$.fs.write` to record them, a new mod
  call the plugin directory reviews;
- the client's own version in a report (no payload field gives it);
- any telemetry, opt-in or not, any id, any ping: not planned.

## 12. Tests that must exist

- every call site uses a code from `CODES`; a code that no site uses fails the test;
- a record written after each failure kind holds only the allowed fields and value forms (an allow list per
  field), and the detector finds nothing in the rendered report, also when the exception message held a
  synthetic secret and a path;
- the CLI `report` never calls the browser or `gh` (patched to raise);
- a typed `/maisecrets:report last --open` opens, the same text from a source other than the person does not,
  and a Bash command with `--open` or `--create` is refused;
- the hint comes once per fingerprint, never in a subagent, never with `tips: false`;
- a damaged or deeply nested `incidents.json` never stops a hook; `wipe` removes it;
- recording on and failing gives the same hook answers (D4), measured on every place in 4.
