# maisecrets protocol (draft 0)

This document is the specification that a client (hook plugin) and an
execution point (a gateway) share. The plugin repo owns it; a gateway
implements it.

## 1. Placeholder

`<TYPE_cN>` or `<TYPE_cN:display>`.

- `TYPE` is one of `SECRET`, `EMAIL`, `IBAN`, `CARD`, `IP`, `PHONE`.
- `c` marks a client-minted reference. A gateway mints `<TYPE_N>` without `c`
  and never mints the `c` range, so the two never collide.
- `N` is a per-client, per-type counter. It is never derived from the value.
- Resolution matches the key `TYPE_cN` only. The display part is for humans
  and may be dropped or altered by a model.
- Open: the delimiter matrix (Slack mrkdwn, Markdown, Jira, HTML, shell).
  `<` and `>` are shell redirection when unquoted in Bash.

## 2. Vault entry

| field | meaning |
|---|---|
| key | `TYPE_cN` |
| type, kind | placeholder type; detector pattern name |
| fingerprint | sha256(value)[:12], for "same value, same reference" and for records |
| display | human hint, never for secrets |
| created, last_used, uses | audit |
| expires, max_expires | TTL, renewed on use up to the cap |
| purged | value deleted; metadata kept |

A value never leaves the backend except into (a) a tool's arguments at
execution time, (b) a gateway deposit, (c) `maisecrets get` for a human.

## 3. Rehydration at the client

`PreToolUse` on `Bash`: every `<TYPE_cN>` in `command` is resolved. Unknown
or expired references deny the call with a reason that names the key and the
status. Partial resolution never happens.

`PostToolUse`: every string in `tool_response` is scanned; hits become
references (existing reference when the fingerprint is known). The response
keeps its shape.

## 4. Deposit to a gateway (not built)

`POST /api/vault/deposit` with the user's vault key:

```json
{"ref": "EMAIL_c1", "type": "EMAIL", "fingerprint": "…", "value": "…", "ttl_seconds": 86400}
```

Idempotent by `ref` per user. The gateway stores the value in its per-user
mapping under the same key and rehydrates it in actions that opt in per field.
Its response scrubber returns the same reference for the same value.

Trigger: `PreToolUse` on a gateway MCP tool whose arguments carry a client
reference. The client deposits first, then lets the call through unchanged.

## 5. Failure rules

- A hook that cannot decide fails closed and says why.
- A timeout is fail-open in Claude Code; the detector must stay a regex in
  milliseconds.
- Nothing a hook prints contains a value. Reasons name keys and counts.
