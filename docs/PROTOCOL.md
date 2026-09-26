# maisecrets protocol (draft 0)

This document is the specification that a client (hook plugin) and an
execution point (a gateway) share. The plugin repo owns it; a gateway
implements it.

## 1. Placeholder

`⟦TYPE_cN⟧` or `⟦TYPE_cN:display⟧` (brackets U+27E6/U+27E7, mask character
U+2022 in the display). Chosen by measurement against real parsers in
ai-gateway #1396: `<…>` vanishes in HTML and is a shell redirection, `[…]`
is a Jira link and a regex class, `***` is a regex quantifier; `⟦…⟧` with
`•` survives CommonMark, HTML, XHTML, URL query, regex and SQL LIKE.

- `TYPE` is one of `SECRET`, `EMAIL`, `IBAN`, `CARD`, `IP`, `PHONE`.
- `c` marks a client-minted reference. A gateway mints `<TYPE_N>` without `c`
  and never mints the `c` range, so the two never collide.
- `N` is a per-client, per-type counter. It is never derived from the value.
- Resolution matches the key `TYPE_cN` only. The display part is for humans
  and may be dropped or altered by a model.
- The gateway treats a `⟦…⟧` token as its own only when the display part is
  empty or is itself a display (a fixed point of the mask transformation); a
  real value in token form is still scanned.
- The earlier `<TYPE_cN>` form is recognised for rehydration, never minted.
- Gateway side: ai-gateway MR !2374 (`src/security/pii_display.py` blob
  `fc6e2df2…`, vendored here as `maisecrets/pii_display.py`). A client
  reference in a rehydrate field of a gateway action is answered with
  `UNRESOLVED_CLIENT_REFERENCE` and the API is not called
  (`src/mcp/hooks/pii_hooks.py`, `tool_executor._answer_without_executing`).

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
