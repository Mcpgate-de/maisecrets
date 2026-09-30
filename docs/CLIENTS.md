# Client coverage: which hook carries which guard

Companion to the "Client support" table in the README. Read from the vendors' hook
documentation on 2026-09-26 unless marked measured.

One core (detector, vault, placeholder), one adapter per provider (manifest,
hook names, block/rewrite fields). Proven by the harness: Claude Code CLI
(hooks: block prompt, rewrite tool I/O) and Codex CLI (same format; output via
block feedback). Same runtime, seen live but not in the harness: the Claude desktop app
(Cowork; a blocked prompt, an MCP resolve with its ask and a redacted Bash output, 2026-09-28) and Codex in the
ChatGPT app (2026-09-27). Same runtime, not measured: the Codex IDE extension. Docs, untested: ChatGPT
Work mode runs plugin hooks in the Codex runtime. OpenCode: own npm plugin, can
rewrite the prompt (correction 2026-09-26: the current plugin API lists
`tool.execute.before/after` as modifiable, no prompt hook). Checked in the
vendor docs on 2026-09-26 (README "Client support" has the marks), hook
names per guard:

| client | block a prompt | rehydrate | redact output |
|---|---|---|---|
| Gemini CLI | `BeforeModel` may rewrite | `BeforeTool` may rewrite | `AfterTool` may redact |
| Cursor | `beforeSubmitPrompt` blocks | `beforeShellExecution` | `postToolUse` for MCP results only; `afterShellExecution` cannot rewrite |
| Copilot CLI | `userPromptSubmitted` → `modifiedPrompt`, SDK hooks only | `preToolUse` → `modifiedArgs` | `postToolUse` → `modifiedResult` |
| OpenCode | none | `tool.execute.before` | `tool.execute.after` |
| Antigravity CLI | none (`PreInvocation` injects only) | `PreToolUse` → `overwrite` | none (`PostToolUse` expects `{}`) |

Unchecked: Kiro. No adapter: Claude Chat, ChatGPT Chat, web, mobile.

Antigravity CLI (`agy` 1.2.11, checked 2026-09-26 from the hook doc embedded
in the binary): own `hooks.json` contract, named hooks in `plugins/<name>/hooks.json`
or `.agents/hooks.json`, camelCase payloads. `PreToolUse` on `run_command` gets
`toolCall.args.CommandLine` and may answer `decision` allow/deny/ask plus
`overwrite` for the arguments, so rehydration and a deny are possible.
`PostToolUse` expects `{}` back: a tool result cannot be rewritten. There is no
prompt hook; `PreInvocation` carries no prompt and can only inject messages.
Two of the three guards (block a prompt, redact a result) have no hook to live
in, so an adapter would only rehydrate and deny. Not built; `agy plugin
validate` accepts the plugin layout but finds no hooks in it.

## Codex file edits: `apply_patch`

Measured on codex-cli 0.158.0 with a real model (2026-09-29): Codex edits files with one tool,
`apply_patch`. A PreToolUse matcher of `Write` or `Edit` reaches it (aliases), but the payload says
`tool_name: "apply_patch"` and holds the whole patch in `tool_input.command`:

```
*** Begin Patch
*** Add File: notes.txt
+key=⟦SECRET_c1⟧
*** End Patch
```

The headers `Add File`, `Update File`, `Delete File` and `Move to` name the paths; Codex also applies
a header indented by spaces or tabs, so the hook reads it as a header too. A call without the patch
text in `command` is refused. maisecrets
refuses a patch that names the maisecrets home, refuses a placeholder in a header, and resolves one
in the content lines, context and removed lines included (the model read the file redacted, so the
patch must match the real text). Each further line of a multi-line value gets the prefix of its line,
so a PEM key lands in the file as it is and never starts a patch operation; the rewritten patch must
name exactly the files the checked one named. A context line that reads like a header is refused
(the safe side), and a value with a carriage return is refused (the format cannot carry it). Codex applies the rewritten patch when the hook answers `allow`.
The captured payload is `tests/client_payloads/codex-apply-patch.json`; the rehydration matrix
builds its Codex file row from it.

## Sessions, subagents and headless runs

A reference resolves in the session that created it or admitted it. A Claude
Code subagent (Task) sends its parent's `session_id`, so it resolves what the
parent may resolve; it receives the same primer at session start. A headless
run (`claude -p`, `codex exec`) is a new session each time: a reference from
an earlier run is `foreign-session` there, and the deny says so. A prompt
built from untrusted text (an issue body, a log) admits every reference in it
as typed by a human; keep such runs on a machine without a vault.
