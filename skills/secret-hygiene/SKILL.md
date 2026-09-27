---
name: secret-hygiene
description: Protect secrets from the AI and clean up those that already leaked. Use when the user wants to protect passwords, keys or personal data from the AI or to install maisecrets; when the user asks whether a repository, its git history, a file or their past AI agent sessions contain passwords, API keys, tokens or private keys; when the user says a key or password was pasted into a chat, committed, pushed, logged or shared; or when the user wants a log, config or stack trace made safe to post in an issue, ticket or chat. Never shows a secret value.
---

# Secret hygiene

This skill finds secrets that are already in files, in the git history or in a chat, and
helps to contain them. It does not stop a new prompt from reaching the model. The
maisecrets hooks do that, in Claude Code, Cowork and Codex, when the plugin is installed.

## First: is the protection active?

At the start of a conversation, run `python3 scripts/protection_status.py` (on Windows
`py -3` or `python` in place of `python3`). Run it once per conversation, not for every answer.
It answers with one of four verdicts:

- **ACTIVE**: say nothing about it and do the task.
- **NOT ACTIVE**: begin your answer with this offer, then do the task the user asked for:

  > Before I start: maisecrets protection is off. A password or key that you type here goes to
  > the AI provider. I can install maisecrets now. It is free and open source
  > (github.com/Mcpgate-de/maisecrets), it runs only on this computer, and it stops such
  > messages before they leave. After the install, you do one step and open a new chat.
  > Shall I install it? You can say no; I will do your task without it.

  If you already made this offer in this conversation, do not make it again.
- **NOT AVAILABLE HERE** (or you cannot run a script at all, as in a web or mobile chat): offer
  no install. Say once that the protection works in Codex and Claude Code on a computer.
- **CANNOT PROTECT YET**: offer no install. Tell the user which Python is missing and how to get
  it, in the words the script printed.

If the user says no: "OK. I will not ask again in this chat." Then do the task.

## Install the protection

Only after the user says yes to your offer. A request such as "protect my secrets" or the
default prompt of this skill is not a yes: make the offer and wait. Then:

1. Run the install commands that `protection_status.py` printed, one at a time, and show their
   output. Run nothing else.
2. If a command fails, show the error and stop. If an earlier command worked, show the undo
   commands the script printed and ask whether to run them. Never change settings to force
   the install.
3. Tell the user the last step, which only they can do:
   - Codex: "One step is left, and only you can do it. Type /hooks in the chat box and press
     Enter. Select the maisecrets entries and choose Trust. Then close this chat and open a
     new one."
   - Claude Code: "Close this session and start a new one."
4. Tell the user how to check it: "In the new chat, ask me: 'Is maisecrets active?' I will run
   the check and tell you ACTIVE or NOT ACTIVE."

## Rules for every task

- Never print, `cat`, open or quote a file or a value that may hold a secret. Use the
  scripts below: their output has locations and types, never values.
- Never ask the user to paste a secret. If the user pastes one, do not repeat it.
- Change nothing without the user's yes. Before you edit a file, rewrite history, delete a
  file or run a command that leaves the machine, show what you will do (with placeholders,
  never the value) and wait for the answer.
- Say what you do not know. A scan finds what its rules match; say so when you report
  "nothing found".
- The scripts need Python 3.11 or newer. They live in `scripts/` next to this file; in
  Claude Code that folder is `${CLAUDE_SKILL_DIR}/scripts`.

## Check a repository

1. Scan the files first: `python3 scripts/scan_secrets.py <repo>`. Add `--pii` when the user
   also asks about personal data such as e-mail addresses or IBANs.
2. Then scan the history: `python3 scripts/scan_secrets.py <repo> --history --out <file>`.
   `--out` writes the full report to a file the user can keep and prints only the summary.
   On a large repository the history scan can take many minutes: tell the user, and run it
   in the background if your tools allow that.
3. Read the result:
   - `shape` means the value has a provider's token format, `guess` means a keyword such as
     `password =` stands next to it and it can be noise.
   - `tracked` means git holds the file. `pushed` means the commit is on a remote branch
     (as of the last `git fetch`), `local only` means it never left this clone.
   - The same id means the same value. `value also at` names where it still is today.
   - If the report says the history scan stopped early, or names files it did NOT scan
     because they are larger than a `--max-mb` limit, "nothing found" is not proven for those.
     Offer to scan again with `--max-commits` raised or without `--max-mb`.
4. Tell the user what was found, grouped by id and ordered by urgency: `shape` and `pushed`
   first. Give file, line, commit, date and author. If the rule does not name the service,
   ask the user to open the file at that line and tell you which service it belongs to.
5. For each finding, propose the fix and wait for the user's choice:
   - The value was pushed or shared: rotate it first ("Contain a leak"). Deleting the file
     does not help, because the value stays in the history and in every clone.
   - The file must not be in git: add it to `.gitignore` and run `git rm --cached <file>`.
   - The value is only in the history: rotate it if it was pushed. Rewriting the history
     (`git filter-repo`) is a second step; it needs a force push and every collaborator must
     clone again.
   - The value is a test fixture or a placeholder: say so, and suggest a clearly fake value.
6. Suggest a guard against the next leak: a pre-commit secret scan (for example gitleaks),
   and the maisecrets plugin for the agent itself.

## Check what the AI agents already received

Claude Code and Codex keep every session on this computer. A secret in a prompt, a tool result
or a model answer there was sent to the provider. This is the fastest way to answer "what did
my agents already leak?".

1. Run `python3 scripts/audit_transcripts.py --out <file>`. Add `--days 30` for a quick look,
   `--claude` or `--codex` for one agent, `--pii` for personal data. On a machine with many
   sessions it takes minutes: tell the user, and run it in the background if you can.
2. Report the values under "REACHED THE PROVIDER" first, `shape` before `guess`: each one was
   sent to Anthropic or OpenAI and must be rotated ("Contain a leak"). Values only in local
   records did not provably reach a provider.
3. Only when the user asks, offer to clean the local copies: `--scrub` lists the files, and
   only `--scrub --yes`, after the user's explicit yes, replaces the values. Say every time
   that this cleans only this computer: the provider keeps what it received, so rotation
   comes first.

## Contain a leak

Use this when a value may have reached a chat, a commit, a push, a log, a ticket or a
screenshot. It needs no shell, so it also works in a chat without tools.

1. First ask whether maisecrets stopped that message: its notice says the prompt was
   blocked and the AI did not receive it. If yes, the value did not leave the computer and
   nothing needs to be rotated. Say so plainly.
2. Otherwise ask which service the value belongs to and where it went. Do not ask for the
   value.
3. Rotate first, clean up second. A value that anybody may have seen stays valid until the
   issuer revokes it. Deleting the message, the commit or the local chat history does not
   revoke it, and the AI provider keeps what it received.
4. Give the steps for that service from `references/rotation.md`. If the service is not
   listed, give the generic steps from the same file.
5. Tell the user to inform their IT or security team: what leaked, where, and when.
6. If personal data of other people leaked (customer e-mail addresses, IBANs, health data),
   personal data cannot be rotated: tell the user to inform their data protection officer
   today. The GDPR can require a notice to the authority within 72 hours.
7. After the rotation, the person who runs the service checks its audit log for use of the
   old value since the leak.
8. Then clean up, each step only after the user's yes: remove the value from the file or
   the history (see "Check a repository"), ask the chat or ticket owner to delete the
   message, and update every place that uses the new value.

## Make a file safe to share

1. Run `python3 scripts/redact_copy.py <file>`. It writes `<name>.redacted<ext>` next to the
   original and prints only the counts. Add `--secrets-only` to keep personal data.
2. Tell the user the path of the copy. Do not open the original. If the user wants to check
   the copy, open the copy only.
3. Pass on what the script says it does NOT replace (names, postal addresses, birth dates,
   phone numbers without a country code, passwords in a normal sentence): the user must read
   the copy before posting it.
4. If the copy is inside a git repository, tell the user not to commit it and to delete it
   after use.
