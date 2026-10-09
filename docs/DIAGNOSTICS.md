# Local diagnostics and reporting (design v4, 0.6.10)

Status: design for review, round 4. Nothing here is built yet. Issue: Mcpgate-de/maisecrets#14.

maisecrets has no telemetry, no server and no automatic error upload, and it keeps it that way. This design
adds a way to learn about real problems: maisecrets records its own internal failures **on this computer**, as
closed codes. When the person types the report command, the prompt hook shows the report and a prefilled link
**to the person only**; the prompt does not reach the model. The person clicks the link, checks the text in
GitHub's own issue form and decides there. maisecrets itself sends nothing.

v4 follows the design reviews of rounds 1 to 3 (codex gpt-5.6-sol, Opus, ChatGPT). Section 13 lists the changes.

## 1. Rules (the invariants)

- **D1 maisecrets sends nothing.** No report or incident code opens a network connection, starts a browser or
  runs `gh`; the helpers for both are deleted. No telemetry, no id, no ping.
- **D2 An incident record and an incident report hold only closed values.** Every field is a value from a closed
  list or a bounded number. The record never holds an exception message, a path, a command, an MCP tool name, a
  prompt, a tool input or output, a session id, a user or host name, a key or a value. The report adds no
  platform release string and no error text (a config that does not load is the fixed word `unavailable`). What
  the report does show about use: the client family, the tool class, the number of days in the last 30 on which a
  failure was seen, and a coarse count. The detection, bug and feature reports carry text the person typed; D2
  does not cover them (section 7).
- **D3 maisecrets never files a report.** It shows the text and a link; the intended step is that the person
  clicks the link, checks the text in GitHub's form and presses Submit. Limits, stated in the threat model (C24):
  the click on the link already sends the prefilled text to GitHub in the URL; and an agent with its own browser,
  shell or GitHub tools can file an issue, which maisecrets cannot tell from a person. For the incident report
  the model is not handed the link (section 7), so it would have to read the record itself.
- **D4 Recording never changes an answer.** Codes are queued while the hook works. Only the code path whose answer
  won writes its queue; one try of a short lock on its own lock file, within a deadline below the remaining
  watchdog budget; a failure of the recorder is never recorded. The one write before the answer is the hint claim
  (section 6).
- **D5 Bounded and removable.** At most 50 groups, one aside copy of a damaged record, at most one marker per code;
  `wipe` and `report incident clear` delete them.

## 2. What happens today (and changes)

- `/maisecrets:report last` (a false positive) **opens the browser at once** on a desktop, so the text reaches
  GitHub before the person read it; `--create` files it with `gh` under the person's login, and
  `commands/report.md:4` pre-approves `run.sh report *`, so a model can run it without a question. **Both go.**
  `report`, `report last [why]`, `report bug|feature <text>` keep their meaning and print the text and the link.
  A person who still types `--create` gets the line "--create is gone; open the link".
- `vault.py` raises `RuntimeError` (or a subclass) with no code; `destinations.pend` and `commit` swallow their
  errors; 15 `_debug` calls keep nothing unless a debug variable is set; 7 places answer fail-closed.
- A damaged store or config makes the prompt hook fail closed before it reads the prompt, and a report run as a
  Bash call is withheld again by PostToolUse (`hooks.py:3318`), so today no report about a damaged store reaches
  the person.

`events.log` and `hooks.log` stay as they are.

## 3. Data model

`~/.maisecrets/incidents.json`, written only by a hook:

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
| `event` | a hook event name, `launcher`, `guard` |
| `tool_class` | `Bash`, `PowerShell`, `MCP`, `File`, `Other`, `-` |
| `client` | `claude`, `codex`, `-` |
| `days` | real dates within the last 30 days, at most 7 (the report shows only their number) |
| `seen` | `1`, `2`, `3+`, `10+` |
| `plugin_version` | three numbers of at most 3 digits each, no leading zero, or `unknown` |
| `hinted` | `true` or `false` |

- **Key and selector:** `code/cause`. No hash.
- **One schema function** builds a group, loads the file and renders a report: a field outside its form drops the
  whole group. The rendered report is scanned by the detector; a group with a hit is left out and the report says
  "1 group withheld".
- **Typed sessions** (for the hint) reuse `destinations.mark_interactive`; the mark moves out of the
  `secret_destinations == "observe"` condition (`hooks.py:797`), so it exists in every mode.
- **Markers** for places that cannot write the record: `~/.maisecrets/incident-markers/<code>/`, **one empty
  directory per code**, made with `mkdir` (bash, cmd and Python alike). `mkdir` is atomic and does not follow a
  symlink at the final name. The marker folder is separate from `pending/`, which holds blocked prompts.
  - A writer makes a marker only when `~/.maisecrets` already exists (no folder with the umask mode), after its
    own answer is out, and ignores every error (`2>/dev/null || true`; in `run.sh` with
    `${MAISECRETS_HOME:-$HOME/.maisecrets}` under `set -u`).
  - The fold runs in a hook, under the record's lock: it renames each marker to `<code>.claimed-<pid>`, folds it
    (its `lstat` mtime is the day), writes the record, then removes the claimed marker. A claimed marker left by a
    crash is folded by the next hook. A marker made while one exists coalesces with it, on purpose.
  - Only directory names from `CODES` are folded; any other entry is removed with `lstat`, `rmdir` or `unlink`,
    never followed.

## 4. Where failures are recorded

Each line maps one site to one code. A test walks the AST of `maisecrets/` for every `raise` of `RuntimeError`
and its subclasses (`LockTimeout`, `ConfigError`) and every `except` that ends a hook path, and fails when one has
no listed code; a listed code that no site uses fails too.

| Code | Site (`vault.py` unless named) | Class |
|---|---|---|
| `store.file-read` | 551 (jsonfile), 749 (openssl file) | fail-closed |
| `store.keychain-add`, `store.keychain-readback` | 649, 651 | fail-closed |
| `store.keychain-delete` | 679 | fail-closed |
| `store.openssl` | 733 | fail-closed |
| `store.locker-add` | 823 | fail-closed |
| `store.index-read`, `store.index-shape` | 949, 952 | fail-closed |
| `store.lock` | 220 (`LockTimeout` after `LOCK_DEADLINE`) | fail-closed |
| `store.timeout-keychain`, `store.timeout-openssl`, `store.timeout-locker` | 598; `_run_store` gets a closed backend id. While a store call runs, a module variable names it, and a watchdog that fires then records this code instead of `hook.<event>.watchdog` (the Locker timeout is 15 s, the watchdog 7 s) | fail-closed |
| `store.decrypt` | the swallowed decrypt failure at 789 (the value is then "not available") | best-effort |
| `store.mark-weak` | 997 | best-effort |
| `store.expire` | the swallowed failure in expiry (`except` at 1294) | best-effort |
| `config.policy-invalid` | `ConfigError` (247) and the `config-error` answer in `hooks.py` | fail-closed |
| `config.user-ignored` | a user `config.json` ignored with a warning | best-effort |
| `hook.payload` | a payload that is no JSON object | fail-closed |
| `hook.<event>.unexpected` | an exception that reaches `_failure`, and the inner catch of `_post_tool_guarded` | fail-closed |
| `hook.<event>.watchdog` | the watchdog's answer won (a marker) | fail-closed |
| `hook.session-start` | the SessionStart path in `dispatch.py` (no watchdog there: its recording has its own 0.3 s limit) | best-effort |
| `destinations.pend`, `destinations.commit` | `pend` and `commit` return a closed result instead of swallowing it | best-effort |
| `scrub.start`, `scrub.write` | the scrub child (a marker) | best-effort |
| `prompt.pending` | the pending prompt could not be written | best-effort |
| `prompt.clipboard` | an unexpected clipboard failure only: not a missing tool, not in an SSH session | best-effort |
| `hint.give` | a hint that could not be given | best-effort |
| `mod.dispatch` | the Python side of the mod, `dispatch.py mod-prompt` (a marker) | best-effort |
| `launcher.no-python`, `launcher.import` | `run.sh`/`run.cmd` found no Python; `dispatch.py` could not import the plugin (markers) | fail-closed |
| `guard.fired` | the guard refused (a marker; `guard.py` has its own `_home()`) | fail-closed |

**Not recorded, on purpose:** the sites that only the CLI reaches (`wipe` 701 and 767, `repair` 1384 and 1417,
`forget` 1327): the CLI prints its own error, and a CLI run never writes the record. **Not observable** (in the
docs): a manifest the client rejects, a client timeout that fails open, the "plugin folder is gone" answers in
`hooks/hooks.json` (a change there changes the hook hash that Codex trusts), a failure in the mod's JavaScript
before Python, a failure of the recorder itself.

## 5. Who sees what

- **best-effort:** recorded only; one hint when `seen` reaches `3+` (section 6).
- **fail-closed:** the refusal gets one fixed line, whether or not the record could be written. Claude Code:
  `maisecrets sent no report. Type /maisecrets:report incident to see one you can read and send yourself.`
  Codex: the same with `maisecrets: report incident`. The refusals for `launcher.*` and `guard.fired` keep their own
  text: no Python or no plugin folder can show a report.

## 6. The hint

Through the existing PostToolUse `additionalContext`, read only by the model:

> maisecrets recorded the same internal problem more than once (it sent no report). Tell the user once, in one
> sentence, that typing /maisecrets:report incident shows a report they can read and send themselves.

Once per group; never in a subagent, never in a session without a typed prompt, never with `tips: false`, never in
a fail-closed answer. The `hinted` claim is the one write before an answer: one try of the record's own lock file
(not the vault `.lock`); without the lock there is no hint this time.

## 7. Reading and sending

| Step | Claude Code | Codex | Own terminal |
|---|---|---|---|
| read the incident report | type `/maisecrets:report incident [code/cause]` | type `maisecrets: report incident [code/cause]` | `run.sh report incident [code/cause]` |
| send | click the link, check the text in GitHub's form, Submit | the same | the same |
| clear the record | type `/maisecrets:report incident clear` | type `maisecrets: report incident clear` | `run.sh report incident clear` |
| detections, bugs, features | `/maisecrets:report [last [why] \| bug \| feature …]` as today, without browser and `gh` | as today | as today |

- **The incident report is answered by the prompt hook**, as the typed settings change is today
  (`hooks.py:808-818`): a full match of the closed forms only, as the **first step of `user_prompt`, before
  `load_config()` and before the store**. The answer is a block whose reason is the report and the link, with
  `suppressOriginalPrompt`. The model sees neither the prompt nor the report, and no Bash call, PreToolUse or
  PostToolUse runs, so a damaged store or config cannot withhold it. Before it answers, the early path ends a
  pending Codex consent code (`consent_store.drop_codes(session)`, inside `try`, with no config condition), as
  every other prompt does (C21).
- `clear` counts only from a typed prompt (`source` in `TYPED_SOURCES`); a prompt the client injected gets the
  report and no clear. The model can still delete the files with a Bash call; that is acceptable and stated.
- **One group per link.** Without a selector the report lists the groups (code/cause, class, days, seen) and gives
  the link for the newest one; each other group names its own command. The URL is tested to stay under 4,000
  characters (measured in round 3: 1 group 410, 50 groups 15,845).
- **The link** comes from `events.link` with the configured `report_url`. When the config does not load, the report
  comes without a link and says `link: unavailable (configuration)`; no error text. A GitHub tracker gets the
  record in the query and a fixed title prefix `[incident]` (GitHub applies URL labels only for users with triage
  access); a policy's non-GitHub tracker URL is printed as configured, with no body, and is the administrator's
  text, outside D2.
- The rendered platform is `Darwin`, `Windows`, `Linux` or `other`, and Python is `major.minor`; the incident report
  does not reuse `generic_issue_parts` (`events.py:158` adds `platform.release()`).
- **The terminal form** reads the record without writing it, and loads the policy only after the text is rendered,
  to decide on the link.

## 8. Damaged record, wipe, clear

- A record that does not parse is replaced by an empty one; the old file is kept as the one aside copy
  `incidents.json.corrupt` (an older aside is overwritten: the record holds nothing of the person).
- Only a hook writes the record and folds markers. A CLI read never writes; `clear` removes the files.
- `wipe` (`wipe_everything`, `vault.py:1459`) removes `incidents.json`, its aside, the lock file and
  `incident-markers/` with its directories; `/maisecrets:status` shows the number of groups.

## 9. What changes with the removal of the browser and `gh`

- Code: `events.open_in_browser`, `has_local_browser`, `create_with_gh` deleted; `cli.cmd_report` and
  `_report_out` print text and link only; `cli.py` docstring and help (174-177, 192-193); the texts
  "records it" in `hooks.py` (1995, 2714).
- Command: `commands/report.md` description, `argument-hint` (adds `incident [code/cause|clear]`, keeps the YAML
  quoting), the paragraph about `--create`; `allowed-tools` keeps `run.sh report *` for the other forms.
- Tests: `test_cli_matrix.py` 783, 1416-1450, 1454-1478, 1480-1499; `test_hidden_characters.py` 77, 430;
  `test_frontmatter.py` 38, 44, 66-67.
- Beliefs and scripts: `c6-a-report-files-only-to-report-url` becomes "no report form runs a subprocess or opens a
  browser"; the `find` string of `manifest-every-frontmatter-parses-as-yaml` follows the new `argument-hint`;
  `scripts/lint_plugin.py:5`.
- Docs: README (364-367, 415-419, 722-725), PRIVACY.md (45-50), THREAT-MODEL row C24. The changelog history and the
  SSH parser tests that contain `gh issue create` stay.

## 10. Watchdog and recording

- `answer()` returns whether its answer was the one written. The handler's queue is written only when the
  handler's answer won; the watchdog writes only its marker, and only when its own answer won.
- The recording runs in the `finally` block **before** `watchdog.cancel()`, so the watchdog still guards it, and it
  writes atomically (temp file and rename), because `os._exit` can stop it.
- The watchdog's marker is made in a daemon thread joined with 0.3 s, before `_scrub_failed_prompt` and
  `os._exit`, so a slow disk cannot push the hook past the client's timeout (watchdog 7 s, client 10 s).

## 11. Tests that must exist

- schema: every field rejects hostile forms (newline, Unicode, a number out of range, a boolean as a number, a
  non-finite number, a deep object, an unknown code, an impossible date, a date out of the window, a poisoned
  version); a group with one bad field is dropped; a detector hit drops the group;
- the AST walker both ways (every raise and hook-ending catch has a code, every code has a site);
- the rendered report of every code holds no detector hit, also when the exception message held a synthetic
  secret and a path; a config error that names a path does not appear;
- the prompt-hook report: a damaged index, a broken config and a broken policy each still give the report as a
  block reason with `suppressOriginalPrompt`; `load_config` and the store are patched to raise and are not
  called; a pending Codex consent code still ends; free-text forms and near misses (`report incident please`) do
  not take the early path; `clear` from a non-typed source does not clear;
- recording and the watchdog: the same answers with the recorder on, off, raising, slow and with a held lock; a
  handler paused after it queued a code, a watchdog that wins, then the handler resumes: only the watchdog marker
  survives; a watchdog that fires during a store call records `store.timeout-<backend>`;
- markers: a planted symlink at a marker name and at a claimed name is not followed and its target is unchanged; a
  marker made during a fold survives as the next occurrence; unknown entries are removed; `pending/` is never
  touched (a blocked prompt there survives a fold);
- no report form calls a browser or `gh` (both patched to raise), also `report last`, `bug` and `--create`;
- the URL of the largest valid group stays under the limit;
- the hint: once per group, never in a subagent, never without a typed prompt, never with `tips: false`;
- `wipe` and `clear` remove every file and directory; a CLI read writes nothing.

To measure in the real clients (harness): how Claude Code and Codex show a block reason of about 20 lines with a
link (readable, the link clickable). If a client shows it badly, the fallback is the terminal form, named in
the reason.

## 12. In 0.6.10, and later

In 0.6.10: sections 3 to 11, a threat-model row C24 with beliefs for D1 to D5, README and PRIVACY.md.

Later, on purpose: failures in the mod's JavaScript; the client's own version; any telemetry (not planned).

## 13. Changes against v3 (review round 3)

- **Blockers (both reviewers):** markers moved out of `pending/` (it holds blocked prompts) into
  `incident-markers/`; the incident report is now answered by the prompt hook as a block reason, so no Bash call,
  PreToolUse or PostToolUse can withhold it (PostToolUse loaded the config first, `hooks.py:3318`). This also
  removes the pre-tool early path and with it the risk of a recognizer that accepts any `run.sh` path (Opus H1).
- D3 is narrowed: the link click already sends the text; an agent with its own tools can submit; the model is not
  handed the incident link.
- No error text and no platform release in the report; a non-GitHub tracker URL is named as the administrator's.
- Markers are directories made with `mkdir`, claimed by a rename before the fold.
- Watchdog: only the winner records; recording before `cancel()`; the watchdog marker within 0.3 s; a store timeout
  is named by its backend.
- Codes: `store.lock`, `store.decrypt`, `store.mark-weak` added; the CLI-only sites, `cli.<command>` and
  `store.file-write` dropped (no `RuntimeError` site); clipboard only for unexpected failures; an AST walker;
  line numbers corrected (12 lines plus the timeout at 598; the expiry `except` is 1294).
- One group per link with a URL limit; days shown as a number; the fixed line names the Codex form too; typed
  sessions reuse `mark_interactive`; the full list of tests, beliefs and docs that change with the removal.
