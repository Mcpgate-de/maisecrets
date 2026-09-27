---
name: secret-hygiene
description: Find, contain and clean up secrets that already leaked. Use when the user asks whether a repository, its git history or a file contains passwords, API keys, tokens or private keys; when the user says a key or password was pasted into a chat, committed, pushed, logged or shared; or when the user wants a log, config or stack trace made safe to post in an issue, ticket or chat. Never shows a secret value.
---

# Secret hygiene

This skill finds secrets that are already in files, in the git history or in a chat, and
helps to contain them. It does not stop a new prompt from reaching the model. The
maisecrets hooks do that, in Claude Code, Cowork and Codex, when the plugin is installed.

## Rules for every task

- Never print, `cat`, open or quote a file or a value that may hold a secret. Use the
  scripts below: their output has locations and types, never values.
- Never ask the user to paste a secret. If the user pastes one, do not repeat it. Treat it
  as leaked and follow "Contain a leak".
- When a finding needs a fix in a file, change the file without showing the value, and
  move the value to an environment variable or a secret manager.
- The scripts need Python 3.11 or newer. They live in `scripts/` next to this file; in
  Claude Code that folder is `${CLAUDE_SKILL_DIR}/scripts`.

## Check a repository

1. Run `python3 scripts/scan_secrets.py <repo> --history`. Add `--pii` when the user also
   asks about personal data such as e-mail addresses or IBANs.
2. Read the result. `tracked` means git holds the file. `still in tree` means the value is
   in the current files. `only in history` means an old commit still holds it. The same id
   means the same value.
3. Tell the user what was found, grouped by id, with the file and the commit. Do not guess
   what a value is.
4. For each finding, propose the fix:
   - The value is live: follow "Contain a leak" first. Deleting the file does not help,
     because the value stays in the history and in every clone.
   - The file must not be in git: add it to `.gitignore`, run `git rm --cached <file>`,
     and commit.
   - The value is only in the history and was pushed: rotate it. Rewriting the history
     (`git filter-repo`) is a second step, it needs a force push and every collaborator
     must clone again. Ask the user before a history rewrite or a force push.
   - The value is a test fixture or a placeholder: say so, and suggest a clearly fake value.
5. Suggest a guard against the next leak: a pre-commit secret scan (for example gitleaks),
   and the maisecrets plugin for the agent itself.

## Contain a leak

Use this when a value reached a chat, a commit, a push, a log, a ticket or a screenshot. It
needs no shell, so it also works in a chat without tools.

1. Ask which service the value belongs to and where it went. Do not ask for the value.
2. Rotate first, clean up second: a value that anybody may have seen stays valid until the
   issuer revokes it. Removing it from the chat or the repository does not revoke it.
3. Give the steps for that service from `references/rotation.md`. If the service is not
   listed, give the generic steps from the same file.
4. After the rotation, check the service's audit log for use of the old value in the time
   between the leak and the rotation.
5. Then clean up: remove the value from the file or the history (see "Check a repository"),
   ask the chat or ticket owner to delete the message, and update every place that uses the
   new value.

## Make a file safe to share

1. Run `python3 scripts/redact_copy.py <file>`. It writes `<name>.redacted<ext>` next to the
   original and prints only the counts. Add `--secrets-only` to keep personal data.
2. Tell the user the path of the copy. Do not open the original. If the user wants to check
   the copy, open the copy only.
3. Say that detection is by rules and can miss a value, so the user should read the copy
   before posting it.
