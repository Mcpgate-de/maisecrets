# Local diagnostics and reporting (design v3, 0.6.10)

Status: design for review, round 3. Nothing here is built yet. Issue: Mcpgate-de/maisecrets#14.

maisecrets has no telemetry, no server and no automatic error upload, and it keeps it that way. This design
adds a way to learn about real problems: maisecrets records its own internal failures **on this computer**, as
closed codes. The person reads a report and a prefilled link; GitHub's own issue form, with its Submit button,
is where the person looks at the text once more and decides to send it. maisecrets itself sends nothing.

v3 follows the design reviews of rounds 1 and 2 (codex gpt-5.6-sol, Opus, ChatGPT). Section 13 lists the changes.

## 1. Rules (the invariants)

- **D1 maisecrets sends nothing.** No incident code and no report code opens a network connection, starts a
  browser or runs `gh`. No telemetry, no id, no ping.
- **D2 An incident record and an incident report hold only closed values.** Every field is a value from a
  closed list, a bounded number or a date in a short window. The record never holds an exception message, a
  path, a command, an MCP tool name, a prompt, a tool input or output, a session id, a user or host name, a key
  or a value. What it does show about use: the client family, the tool class, the days a failure was seen and a
  coarse count. (The false-positive, bug and feature reports carry text the person typed; that text goes through
  the normal prompt path and its detector, and D2 does not cover it.)
- **D3 Every report needs the person's own Submit.** maisecrets prints the report and a prefilled link to the
  configured tracker; only the person's click on GitHub's Submit button files an issue. Not claimed: a model that
  has read the link can load the page itself; that files nothing, and by D2 the text holds nothing of the person.
- **D4 Recording never changes an answer.** It is queued while the hook works and written after the answer is
  decided, within the watchdog, with one try of a short lock; a failure of the recorder is never recorded.
- **D5 Bounded and removable.** At most 50 groups, one aside copy of a damaged file, at most one marker per code;
  `wipe` and `report incident clear` delete them.

## 2. What happens today (and changes)

- `/maisecrets:report last` (a false positive) **opens the browser at once** on a desktop, so the text reaches
  GitHub before the person read it; `--create` files it with `gh` under the person's login, and a model can run
  that. **Both go:** the report prints the text and the link, the person clicks. `report bug|feature <text>`
  likewise. `report last` keeps its meaning (the newest detection).
- `vault.py` raises `RuntimeError` at 13 places with no code; `destinations.pend` and `commit` swallow their
  errors; 15 `_debug` calls keep nothing unless a debug variable is set; 7 places answer fail-closed.
- A damaged store makes the prompt hook fail closed before it reads the prompt, so the report about it is
  blocked too.

`events.log` and `hooks.log` stay as they are.

## 3. Data model

`~/.maisecrets/incidents.json`:

```json
{
  "version": 1,
  "groups": {
    "store.locker-add/rc": {
      "code": "store.locker-add", "cause": "rc", "number_kind": "exit", "number": 1,
      "class": "fail-closed", "event": "UserPromptSubmit", "tool_class": "-", "client": "codex",
      "days": ["2026-10-08", "2026-10-09"], "seen": "3+", "plugin_version": "0.6.10", "hinted": false
    }
  }
}
```

| Field | Closed form |
|---|---|
| `code` | one of `incidents.CODES` (section 4) |
| `cause` | `permission`, `timeout`, `lock`, `parse`, `io`, `missing`, `rc`, `shape`, `other`, mapped at the call site |
| `number_kind`, `number` | absent, or `errno` 0–4095, `winerror` 0–65535, `exit` −255–255 |
| `class` | `best-effort`, `fail-closed` |
| `event` | a hook event name, `cli`, `launcher`, `guard` |
| `tool_class` | `Bash`, `PowerShell`, `MCP`, `File`, `Other`, `-` |
| `client` | `claude`, `codex`, `-` |
| `days` | real dates within the last 30 days, at most 7 |
| `seen` | `1`, `2`, `3+`, `10+` |
| `plugin_version` | three numbers of at most 3 digits each, no leading zero, or `unknown` |
| `hinted` | `true` or `false` |

- **Key and selector:** `code/cause`. No hash.
- **One schema function** builds a group, loads the file and renders a report: a field outside its form drops
  the whole group; the rendered report is scanned by the detector before it is shown.
- **Sessions with a typed prompt** (for the hint) live in a separate file, `hint-sessions.json` (at most 50,
  never in a report, deleted by `wipe`).
- **Markers** for places that cannot write the record: `~/.maisecrets/pending/<code>`, one empty file per code
  (bash `: >`, cmd `type nul >`, Python `open(…, "w")`); the next hook folds a marker into the record (its mtime
  is the day) and unlinks it. Only file names from `CODES` are folded; any other file there is deleted.

## 4. Where failures are recorded

| Codes | Place | Class |
|---|---|---|
| `store.keychain-add`, `store.keychain-readback`, `store.keychain-delete`, `store.locker-add`, `store.file-read`, `store.file-write`, `store.openssl`, `store.not-deleted`, `store.index-read`, `store.index-shape`, `store.repair` | the 13 `RuntimeError` raise sites in `vault.py` get a code (`vault.py` 551, 649, 651, 679, 701, 733, 749, 767, 823, 949, 952, 1384) | fail-closed |
| `store.timeout-keychain`, `store.timeout-openssl`, `store.timeout-locker` | `_run_store`'s timeout, per backend (598) | fail-closed |
| `store.no-write-access` | a `PermissionError` on the store folder | fail-closed |
| `store.expire`, `store.forget` | failures that expiry and forget swallow (1292, 1325) | best-effort |
| `config.policy-invalid`, `config.user-ignored` | a machine policy that does not load; a user `config.json` ignored with a warning | fail-closed / best-effort |
| `hook.payload` | a payload that is no JSON object | fail-closed |
| `hook.<event>.unexpected` | an exception that reaches `_failure`, and the inner catch of `_post_tool_guarded` | fail-closed |
| `hook.<event>.watchdog` | the watchdog answered (a marker, no JSON write in that path) | fail-closed |
| `hook.session-start` | the separate SessionStart path in `dispatch.py` | best-effort |
| `destinations.pend`, `destinations.commit` | `pend` and `commit` return a closed result instead of swallowing it | best-effort |
| `scrub.start`, `scrub.write` | the scrub child (a marker from the child) | best-effort |
| `prompt.pending`, `prompt.clipboard` | the pending prompt, the clipboard | best-effort |
| `hint.give` | a hint that could not be given | best-effort |
| `mod.dispatch` | the Python side of the mod (`dispatch.py mod-prompt`) | best-effort |
| `launcher.no-python`, `launcher.import` | `run.sh`/`run.cmd` found no Python; `dispatch.py` could not import the plugin (markers) | fail-closed |
| `guard.fired` | the guard refused (a marker) | fail-closed |
| `cli.<command>` | an uncaught exception in a CLI command (in the hook's process only: a CLI run never writes) | best-effort |

A test walks every `raise RuntimeError` and every `except` that ends a hook path, and fails when one has no
listed code; a listed code that no site uses fails too.

**Not observable** (in the docs): a manifest the client rejects, a client timeout that fails open, a failure in
the mod's JavaScript before Python, a failure of the recorder itself.

## 5. Who sees what

- **best-effort:** recorded only; one hint when `seen` reaches `3+` (section 6).
- **fail-closed:** the refusal gets one fixed line, whether or not the record could be written:
  `maisecrets sent no report. /maisecrets:report incident shows one you can read and then send yourself.`
  The refusals for `launcher.*` and `guard.fired` do not name it (no Python or no plugin folder can run it); they
  keep their own text.

## 6. The hint

Through the existing PostToolUse `additionalContext`, read only by the model:

> maisecrets recorded the same internal problem more than once (it sent no report). Tell the user once, in one
> sentence, that /maisecrets:report incident shows a report they can read and send themselves.

Once per group (`hinted`, set under the record's lock); never in a subagent, never in a session without a typed
prompt (`hint-sessions.json`), never with `tips: false`, never in a fail-closed answer.

## 7. Reading and sending

| Step | Claude Code | Codex | Own terminal |
|---|---|---|---|
| list | `/maisecrets:report` (detections and incidents) | `maisecrets: report` | `run.sh report` |
| read an incident report | `/maisecrets:report incident [code/cause]` | the same, as a sentence | `run.sh report incident` |
| send | click the printed link, check the text on GitHub, Submit | the same | the same |
| clear the record | `/maisecrets:report incident clear` | the same | the same |

- The report prints the full text first, then the link. The link is built from the configured `report_url`
  (a policy may set its own tracker or `null`); when the config does not load, the text comes without a link.
- No form of the report opens a browser or runs `gh`; `--create` is removed (the README names
  `gh issue create` for a person who wants it in their terminal).
- **While the hooks fail closed:** `user_prompt` and `pre_tool` recognize only the closed forms (`report`,
  `report incident`, `report incident <code/cause>`, `report incident clear`, full match, no free text) before
  they load the config or open the store; `user_prompt` still ends a pending Codex consent code (C21) first.
  `report last <why>`, `bug` and `feature` take the normal path, so their free text meets the detector.

## 8. Damaged record, wipe, clear

- A record that does not parse is replaced by an empty one; the old file is kept as the one aside copy
  `incidents.json.corrupt` (an older aside is overwritten: the record holds nothing of the person).
- Only a hook writes the record and folds markers. A CLI read never writes; `report incident clear` deletes
  the files (an unlink, no write of a store file).
- `wipe` deletes `incidents.json`, its aside, `hint-sessions.json` and `pending/`; `/maisecrets:status` shows the
  number of groups.

## 9. What is reused

`events.link` and `events.tracker_or_error` for the link (the browser and `gh` calls go); the full-match prompt
forms of C22; the aside handling of `destinations.json`; the PostToolUse hint channel.

## 10. In 0.6.10, and later

In 0.6.10: sections 3 to 9, a threat-model row C24 with beliefs for D1 to D5, README and PRIVACY.md.

Later, on purpose: failures in the mod's JavaScript; the client's own version; a send from inside the client
(the confirm dialog), which needs a client signal for a declined dialog; any telemetry (not planned).

## 11. Tests that must exist

- schema: every field rejects hostile forms (newline, Unicode, a huge or negative number out of range, a boolean
  as a number, a non-finite number, a deep object, an unknown code, an impossible date, a date out of the window,
  a poisoned version); a group with one bad field is dropped;
- every raise and every hook-ending catch has a listed code, and every listed code has a site (both ways);
- the rendered report of every code holds no detector hit, also when the exception message held a synthetic
  secret and a path;
- recording after the answer: the same answers with the recorder on, off, raising, slow and with a held lock; near
  the watchdog the original refusal still wins; the watchdog path writes only a marker;
- no report form calls a browser or `gh` (both patched to raise), also `report last` and `bug`;
- the closed report forms run with a damaged store and a broken config (text without link); free-text forms do
  not take that path; a pending Codex consent code still ends;
- markers: only listed names are folded, others are deleted, a marker is unlinked after the fold;
- the hint: once per group, never in a subagent, never without a typed prompt, never with `tips: false`;
- `wipe` and `clear` remove every file; a CLI read writes nothing.

## 12. Open for the review

- Is the GitHub issue form a sufficient consent step for the product owner's goal (read, then decide)?
- Is `--create` worth keeping for anyone, given that it is the one send without a form in between?

## 13. Changes against v2 (review round 2)

- The send step is gone (codex: the terminal `y/N` is no proof of a person, a declined dialog leaves a grant;
  Opus: the same with a probe, the recognizer and the heredoc, and "a link that the person clicks, and GitHub's
  own Submit button, are both acts of a person"). D3 now says what holds.
- D2 is scoped to incident reports and names the usage metadata it shows; session ids moved to their own file;
  `entry` dropped; tighter bounds (numbers by kind, version, dates, `hinted`).
- The full list of `vault.py` raise sites, the per-backend timeout, the swallowed expiry and forget failures, the
  inner PostToolUse catch, the SessionStart path; a both-ways test.
- Markers (one empty file per code) instead of an append file; the watchdog path writes only a marker.
- The early report path takes closed forms only, needs no config for reading, keeps the C21 code rule.
- The fail-closed line is fixed text, and the launcher and guard refusals do not name a report they cannot run.
