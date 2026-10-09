# Local diagnostics and reporting (design v5, 0.6.10)

Status: design for review, round 5. Nothing here is built yet. Issue: Mcpgate-de/maisecrets#14.

maisecrets has no telemetry, no server and no automatic error upload, and it keeps it that way. This design
adds a way to learn about real problems: maisecrets records its own internal failures **on this computer**, as
closed codes. When the person types the report command, the prompt hook shows the report and a prefilled link
**to the person only**; the prompt does not reach the model. The person clicks the link, checks the text in
GitHub's own issue form and decides there. maisecrets itself sends nothing.

v5 follows the design reviews of rounds 1 to 4 (codex gpt-5.6-sol, Opus, ChatGPT). Section 13 lists the changes.

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
  the click on the link already sends the prefilled text to GitHub in the URL; an agent with its own browser,
  shell or GitHub tools can file an issue, which maisecrets cannot tell from a person; and a model can read the
  record file itself. maisecrets does not hand the incident report or its link to the model (section 7).
- **D4 Recording never changes an answer.** Codes are queued while the hook works. Only the code path whose answer
  won writes its queue, after the answer, with one try of a lock on the record's own lock file and a deadline
  below the remaining watchdog budget. A failure of the recorder is never recorded. No diagnostics write happens
  before an answer.
- **D5 Bounded and removable.** At most 50 groups, one aside copy of a damaged record, at most one marker per code;
  `wipe` and the terminal `report incident clear` delete them.

## 2. What happens today (and changes)

- `/maisecrets:report last` (a false positive) **opens the browser at once** on a desktop, so the text reaches
  GitHub before the person read it; `--create` files it with `gh` under the person's login, and
  `commands/report.md:4` pre-approves `run.sh report *`, so a model can run it without a question. **Both go.**
  `report`, `report last [why]`, `report bug|feature <text>` keep their meaning and print the text and the link.
  A person who still types `--create` gets the line "--create is gone; open the link".
- `vault.py` and `hooks.py` raise `RuntimeError` (or a subclass) with no code; `destinations.pend` and `commit`
  swallow their errors; 15 `_debug` calls keep nothing unless a debug variable is set; 7 places answer
  fail-closed.
- A damaged store or config makes the prompt hook fail closed before it reads the prompt, and a report run as a
  Bash call is withheld again by PostToolUse (`hooks.py:3318`), so today no report about a damaged store reaches
  the person.

`events.log` and `hooks.log` stay as they are. A separate fix found on the way (round 4, Opus H2): the guard
heartbeat raised before the hook's `try` on Python 3.9 with a home that cannot be searched, and the prompt went
through; fixed on its own branch (`fix/a-heartbeat-that-cannot-stat-the-home-does-not-fail-open`), not part of
this design.

## 3. Data model

`~/.maisecrets/incidents.json`, written only by a hook:

```json
{
  "version": 1,
  "groups": {
    "store.locker-add/rc": {
      "code": "store.locker-add", "cause": "rc", "number_kind": "exit", "number": 1,
      "class": "fail-closed", "event": "UserPromptSubmit", "tool_class": "-", "client": "codex",
      "days": ["2026-10-08", "2026-10-09"], "seen": "3+", "plugin_version": "0.6.10"
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

- **Key and selector:** `code/cause`. No hash.
- **One schema function** builds a group, loads the file and renders a report: a field outside its form drops the
  whole group. The rendered report is scanned by the detector; a group with a hit is left out and the report says
  "1 group withheld".
- **Reading the record:** `O_NOFOLLOW|O_NONBLOCK` where the platform has them, then `fstat`: a regular file of at
  most 64 KB, else it counts as damaged (section 8). A FIFO or a symlink cannot make a hook wait.
- **Markers** for places that cannot write the record: `~/.maisecrets/incident-markers/<code>/`, **one empty
  directory per code**.
  - **Writers** (each after its own answer is out, each ignoring every error): `run.sh` and `run.cmd`
    (`launcher.no-python`), `dispatch.py` (`launcher.import`), `guard.py` (`guard.fired`), the watchdog
    (`hook.<event>.watchdog`), the scrub child (`scrub.start`, `scrub.write`). A writer makes a marker only when
    the home already exists: two single `mkdir` steps (the marker root, then the code), never `mkdir -p` or cmd
    `md` with folders in between, with `umask 077` in `run.sh`. An empty home variable resolves the same way in
    all of them: `vault.py`, `guard.py` and `run.sh` use the default home for an empty value (today `vault.py:28`
    differs).
  - **The marker root** must be a real directory owned by the user: the fold `lstat`s it and skips the fold
    otherwise. On POSIX it opens the root with `O_DIRECTORY|O_NOFOLLOW` and does every `listdir`, `rename` and
    `rmdir` relative to that descriptor; on Windows it skips the fold when the root is a reparse point.
  - **The fold** runs in a hook, after the answer, under the record's lock: it renames `<code>` to
    `<code>.claimed-<pid>-<ns>` (a unique name), removes the claimed directory with `rmdir`, and then writes the
    record. **At most once:** a crash between the two loses the occurrence, and it is never counted twice. A
    marker made while one exists coalesces with it (the day of the second is lost), on purpose.
  - **Never `unlink`.** An entry whose name is not in `CODES` and not a claimed name is left alone; a claimed name
    left by a crash is removed with `rmdir` and not counted.
- **The report lists unfolded markers** (read only, the fold stays with the hooks), so the terminal form shows a
  launcher failure before any hook ran again.

## 4. Where failures are recorded

Each line maps one site to one code. A test walks the AST of `maisecrets/` for every `raise` of `RuntimeError`
and its subclasses (`LockTimeout`, `ConfigError`) and every `except` that ends a hook path, and checks it against
an explicit registry of sites (function name and code, not line numbers); a raise with no entry fails, and a code
with no site fails.

| Code | Site (`vault.py` unless named) | Class |
|---|---|---|
| `store.file-read` | 551 (jsonfile), 749 (openssl file) | fail-closed |
| `store.keychain-add`, `store.keychain-readback` | 649, 651 | fail-closed |
| `store.keychain-delete` | 679 | fail-closed |
| `store.openssl` | 733 | fail-closed |
| `store.locker-add` | 823 | fail-closed |
| `store.index-read`, `store.index-shape` | 949, 952 | fail-closed |
| `store.lock` | 220 (`LockTimeout` after `LOCK_DEADLINE`) | fail-closed |
| `store.timeout-keychain`, `store.timeout-openssl`, `store.timeout-locker` | 598; `_run_store` gets a closed backend id instead of display text. A store timeout longer than the watchdog shows up as `hook.<event>.watchdog` | fail-closed |
| `store.decrypt` | the swallowed decrypt failure at 789 (the value is then "not available") | best-effort |
| `store.mark-weak` | 997 | best-effort |
| `store.expire` | the swallowed failure in expiry (`except` at 1327) | best-effort |
| `config.policy-invalid` | a `ConfigError` (raises at `vault.py` 257, 261, 264, 323, 402, 404, 407, 434) that reaches the hook's `config-error` answer | fail-closed |
| `config.user-ignored` | a user `config.json` ignored with a warning: the `except ConfigError` at `vault.py:342` (it catches 323 and the type checks of the user file) | best-effort |
| `hook.run-dir`, `hook.sealed-dir` | `hooks.py` 1874 (`_run_dir`), 1892 (`_sealed_dir`) | fail-closed |
| `hook.payload` | a payload that is no JSON object (`hooks.py:3843`) | fail-closed |
| `hook.<event>.unexpected` | an exception that reaches `_failure` (`hooks.py:3891`), and the inner catch of `_post_tool_guarded` (`hooks.py:3560`) | fail-closed |
| `hook.<event>.watchdog` | the watchdog's answer won (a marker) | fail-closed |
| `hook.session-start` | the SessionStart path in `dispatch.py:96` (no watchdog there: its recording has its own 0.3 s limit) | best-effort |
| `destinations.pend`, `destinations.commit` | `pend` and `commit` (`destinations.py` 233, 253) return a closed result instead of swallowing it | best-effort |
| `scrub.start`, `scrub.write` | the scrub child (`hooks.py:216`; a marker) | best-effort |
| `prompt.pending` | the pending prompt could not be written (`hooks.py:392`) | best-effort |
| `prompt.clipboard` | an unexpected clipboard failure only: not a missing tool, not in an SSH session | best-effort |
| `launcher.no-python`, `launcher.import` | `run.sh`/`run.cmd` found no Python; `dispatch.py` could not import the plugin (markers) | fail-closed |
| `guard.fired` | the guard refused (a marker; `guard.py` has its own `_home()`) | fail-closed |

**Not recorded, on purpose:** the sites that only the CLI reaches (`wipe` 701 and 767, `repair` 1384 and 1417,
`forget` 1294): the CLI prints its own error, and a CLI run never writes the record. The Python side of the mod
(`rewrite_prompt`): its failure ends in the hook, which records it there. **Not observable** (in the docs): a
manifest the client rejects, a client timeout that fails open, the "plugin folder is gone" answers in
`hooks/hooks.json` (a change there changes the hook hash that Codex trusts), a failure in the mod's JavaScript, a
failure of the recorder itself.

## 5. Who sees what

- **best-effort:** recorded only. The person finds it with the report command; there is no hint in 0.6.10
  (section 12).
- **fail-closed:** the refusal gets one fixed line, whether or not the record could be written. Claude Code:
  `maisecrets sent no report. Type /maisecrets:report incident to see one you can read and send yourself.`
  Codex: `maisecrets sent no report. Run hooks/run.sh report incident in a terminal to see one you can read and send
  yourself.` (until the Codex display is measured, section 7). The refusals for `launcher.*` and `guard.fired` keep
  their own text: no Python or no plugin folder can show a report.

## 6. (removed: the hint)

The hint to the model moved to a later version (section 12). It was the only diagnostics write before an answer,
and it needed the typed-session mark in every mode.

## 7. Reading and sending

| Step | Claude Code | Codex | Own terminal |
|---|---|---|---|
| read the incident report | type `/maisecrets:report incident [code/cause]` | the terminal form (the typed form only after the display is measured) | `run.sh report incident [code/cause]` |
| send | click the link, check the text in GitHub's form, Submit | the same | the same |
| clear the record | the terminal form | the terminal form | `run.sh report incident clear` |
| detections, bugs, features | `/maisecrets:report [last [why] \| bug \| feature …]` as today, without browser and `gh` | as today | as today |

- **The incident report in Claude Code is answered by the prompt hook**, as the typed settings change is today
  (`hooks.py:807-821`).
  - **One shared recognizer**, a pure function, runs first in two places: at the top of `user_prompt` and at the
    top of `rewrite_prompt` (the mod's question), each before `load_config()` and before the store. In the mod
    path it returns `{}` (no rewrite), so the prompt reaches the hook unchanged.
  - It **owns every prompt that starts with `/maisecrets:report incident`**. A closed form (`incident`,
    `incident <code/cause>`) gets the report; any other text after `incident` gets a fixed usage line. So a near
    miss never falls through to the slash command, which would run the CLI and print the link into the model's
    context.
  - The answer is a block whose reason is the report and the link, with `suppressOriginalPrompt`. Its first line
    says it is no error: `maisecrets: your incident report (shown to you only; this is not an error).` The model
    sees neither the prompt nor the report, and no Bash call, PreToolUse or PostToolUse runs, so a damaged store or
    config cannot withhold it. Measured in round 4 (`claude -p` 2.1.295): the 20 lines and the whole URL are
    shown.
  - The C21 rule (a pending Codex consent code ends with any other prompt) does not apply: the incident form is
    Claude Code only, and Claude Code has no consent code.
  - `commands/report.md` gets `disable-model-invocation: true`, so the model cannot call the slash command itself.
- **The CLI form** (`run.sh report incident`, also reached by a model's Bash call) prints the report only when
  stdout is a terminal. Otherwise it prints one line that names the typed form and the terminal form. A model can
  still read the record file directly; C24 states it.
- **Codex:** `codex exec` 0.159.2 shows only `hook: UserPromptSubmit Blocked`, without the reason (round 4,
  probe 6). Before Codex gets a typed form, the TUI and the ChatGPT app are measured with the report in
  `systemMessage` and a short fixed `reason`; the measurement also checks that `systemMessage` does not reach the
  model. Until then the terminal form is the Codex path.
- **`clear` only in the terminal** (and `wipe`). Codex sends no `source`, so a prompt cannot prove that a person
  typed it, and a model's Bash call does not reach the terminal-only path (no terminal on stdout).
- **One group per link.** Without a selector the report lists the groups (code/cause, class, days, seen) and gives
  the link for the newest one; each other group names its own command. The URL is tested to stay under 4,000
  characters (measured in round 3: 1 group 410, 50 groups 15,845).
- **The link** comes from `events.link` with the configured `report_url`, called inside `try` after the text is
  rendered. When the config does not load, the report comes without a link and says
  `link: unavailable (configuration)`; no error text. A GitHub tracker gets the record in the query and a fixed
  title prefix `[incident]` (GitHub applies URL labels only for users with triage access); a policy's non-GitHub
  tracker URL is printed as configured, with no body, and is the administrator's text, outside D2.
- The rendered platform is `Darwin`, `Windows`, `Linux` or `other`, and Python is `major.minor`; the incident report
  does not reuse `generic_issue_parts` (`events.py:158` adds `platform.release()`).

## 8. Damaged record, wipe, clear

- A record that does not parse, is not a regular file or is over 64 KB is replaced by an empty one; the old file is
  kept as the one aside copy `incidents.json.corrupt` (an older aside is overwritten: the record holds nothing of
  the person). A symlink is removed, not followed and not kept.
- Only a hook writes the record and folds markers. A CLI read never writes; `clear` removes the files.
- `wipe` (`wipe_everything`, `vault.py:1459`) and `clear` remove `incidents.json`, its aside, its lock file, any
  `incidents.json.*.tmp` (`os._exit` can leave one) and `incident-markers/` with its directories, under the same
  root checks as the fold; `/maisecrets:status` shows the number of groups.

## 9. What changes with the removal of the browser and `gh`

- Code: `events.open_in_browser`, `has_local_browser`, `create_with_gh` deleted; `cli.cmd_report` and
  `_report_out` print text and link only; `cli.py` docstring and help (174-177, 192-193) and the top-level help
  (788); the texts "records it" in `hooks.py` (1995, 2714).
- Command: `commands/report.md` description, `argument-hint` (adds `incident [code/cause]`, keeps the YAML
  quoting), the paragraph about `--create`, and `disable-model-invocation: true`; `allowed-tools` keeps
  `run.sh report *` for the other forms.
- Tests: `test_cli_matrix.py` 783, 1416-1450, 1454-1478, 1480-1499; `test_hidden_characters.py` 77, 430;
  `test_frontmatter.py` 38, 44, 66-67; a test of `cli.main(["--help"])`.
- Beliefs and scripts: `c6-a-report-files-only-to-report-url` becomes "no report form runs a subprocess or opens a
  browser", with a new mutation (a `subprocess.run` call added to `_report_out`), because its old `find` targets
  the deleted `gh` code; the `find` string of `manifest-every-frontmatter-parses-as-yaml` follows the new
  `argument-hint`; `scripts/lint_plugin.py:5`.
- Docs: README (364-367, 415-419, 722-725), PRIVACY.md (45-50), THREAT-MODEL row C24. The changelog history and the
  SSH parser tests that contain `gh issue create` stay.

## 10. Watchdog and recording

- The watchdog timer starts **before** the start heartbeat (`hooks.py:3854`), so no file work runs unguarded.
- `answer()` holds its lock only to claim the win and to write and flush the JSON; it returns whether it won.
  The done heartbeat and `_run_log` run after the lock, and only for the winner.
- `on_timeout` returns at once when its `answer()` did not win: no scrub, no `os._exit`, no marker.
- When the watchdog wins, it makes its marker in a daemon thread joined with 0.3 s, then runs
  `_scrub_failed_prompt` and `os._exit`, so a slow disk cannot push the hook past the client's timeout (watchdog
  7 s, client 10 s).
- When the handler wins, its queue is written in the `finally` block **before** `watchdog.cancel()`, so the
  watchdog still guards it, atomically (temp file and rename).

## 11. Tests that must exist

- schema: every field rejects hostile forms (newline, Unicode, a number out of range, a boolean as a number, a
  non-finite number, a deep object, an unknown code, an impossible date, a date out of the window, a poisoned
  version); a group with one bad field is dropped; a detector hit drops the group; a FIFO, a symlink and a 65 KB
  file at `incidents.json` do not make a hook wait;
- the AST walker against the site registry, both ways;
- the rendered report of every code holds no detector hit, also when the exception message held a synthetic
  secret and a path; a config error that names a path does not appear;
- the prompt-hook report: a damaged index, a broken config and a broken policy each still give the report as a
  block reason with `suppressOriginalPrompt`; the store is patched to raise and is not called; `load_config` is
  called only inside `try`, after the text is rendered; near misses (`incident please`, a selector with a typo) get
  the usage line and never fall through; free text after `report` (`last <why>`, `bug`) does not take the path;
- the mod path: `rewrite_prompt` returns `{}` for every incident form with `load_config`, `_has_live` and `Vault`
  patched to raise, none of them called;
- the CLI form prints the report to a terminal only; through a pipe it prints the one line;
- recording and the watchdog: the same answers with the recorder on, off, raising, slow and with a held lock; a
  handler paused after it queued a code, a watchdog that wins, then the handler resumes: only the watchdog marker
  survives; a watchdog that fires after the handler won does nothing; `_heartbeat` and `_run_log` blocked do not
  delay the watchdog's answer or exit;
- markers: a symlinked marker root (and on Windows a junction) is not followed, and nothing in its target changes;
  a symlink at a marker name and at a claimed name is not followed; a marker made during a fold survives as the
  next occurrence; a crash after the claim counts the occurrence at most once; unknown entries stay; `pending/` is
  never touched;
- no report form calls a browser or `gh` (both patched to raise), also `report last`, `bug` and `--create`;
- the URL of the largest valid group stays under the limit;
- `wipe` and `clear` remove every file and directory; a CLI read writes nothing.

## 12. In 0.6.10, and later

In 0.6.10: sections 3 to 11, a threat-model row C24 with beliefs for D1 to D5, README and PRIVACY.md.

Later, on purpose: the hint to the model after a repeated best-effort failure (needs a write before the answer and
the typed-session mark in every mode); the typed incident form for Codex (after the display measurement); failures
in the mod's JavaScript; the client's own version; any telemetry (not planned).

## 13. Changes against v4 (review round 4)

- **The mod path:** the shared recognizer runs at the top of `rewrite_prompt` too (both reviewers: it loaded the
  config and the store first, `hooks.py:710`).
- **Near misses and the model:** the recognizer owns every `report incident` prompt; the CLI form prints the report
  to a terminal only; the slash command gets `disable-model-invocation` (Opus H3).
- **Codex:** no typed incident form until the display is measured (Opus probe: `codex exec` shows no reason;
  codex: `systemMessage` is the documented person-facing field); `clear` is terminal-only (Codex sends no
  `source`).
- **Markers:** the root is checked and opened without following links, all operations relative to it; never
  `unlink`; a unique claimed name; at-most-once order (claim, `rmdir`, then write); a crash leftover is not counted.
- **Watchdog:** the timer starts before the heartbeat; the winner section only claims and flushes; a losing
  watchdog does nothing; `incidents.json.*.tmp` is wiped.
- **Record read:** no follow, no block, regular file, 64 KB cap.
- **Cut:** the hint (the only write before an answer), the backend variable for the watchdog, the `mod.dispatch`
  marker, `drop_codes` in the early path (the form is Claude Code only).
- **Sites:** expiry 1327 and forget 1294 (they were swapped); `ConfigError` by its raises, not the class line;
  `hooks.py` 1874 and 1892 added; a site registry instead of line numbers; `cli.py:788`.
- **Found on the way:** the heartbeat fail-open on Python 3.9, fixed on its own branch.
