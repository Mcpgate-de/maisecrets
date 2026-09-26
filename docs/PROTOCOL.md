# maisecrets protocol (draft 0)

This document is the specification that a client (hook plugin) and an
execution point (a gateway) share. The plugin repo owns it; a gateway
implements it.

## 1. Placeholder

`⟦TYPE_cN⟧` or `⟦TYPE_cN:display⟧` (brackets U+27E6/U+27E7, mask character
U+2022 in the display). Chosen by measurement against real parsers: `<…>` vanishes in HTML and is a shell redirection, `[…]`
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
- The display rules (`maisecrets/pii_display.py`): e-mail shows at most two
  characters of the local part and, for a non-freemail domain, only the
  top-level label; phone shows the first two digits and the last two; card the
  last four; IBAN the first and last four; IPv4 the first two octets; IPv6 the
  first two hextets before `::`. A display hides at least three characters and
  always carries a bullet; a value the rules cannot mask gets no display.
- A gateway that resolves placeholders itself answers a client reference it
  cannot resolve with an error instead of calling the API with the literal
  text.

## 2. Vault entry

| field | meaning |
|---|---|
| key | `TYPE_cN` |
| type, kind | placeholder type; detector pattern name |
| fingerprint | HMAC-SHA256(store key, value)[:16], for "same value, same reference", exact-match redaction and records |
| display | human hint, never for secrets |
| created, last_used, uses | audit |
| expires, max_expires | TTL, renewed on use up to the cap |
| purged | value deleted; metadata kept |

A value never leaves the backend except into (a) a tool's arguments at
execution time, (b) a gateway deposit, (c) `maisecrets get` for a human.

## 3. Rehydration at the client

`PreToolUse` on `Bash`: the command is prefixed with one read per key into a
shell variable (`__ms_1="$(cat <fifo>)" || exit 97;` on POSIX, a resolver call
under a one-time grant on Windows Git Bash), and every `⟦TYPE_cN⟧` becomes that
variable in its quoting context. The value is never in the command text. A
context the rewrite cannot place (a nested shell, a quoted heredoc, `$'…'`,
backticks) and a command that would encode, slice or trace the value are
refused with the reason. Unknown, expired, foreign-session or capped
references deny the call with a reason that names the key and the status.
Partial resolution never happens.

`PreToolUse` on an MCP tool: every string argument is walked; references are
resolved inline under the same session rule and cap. Gateway servers are
included until the deposit path (§4) exists.

Session rule: a reference resolves only in the session that minted it or in
one where a human typed it into a prompt (`UserPromptSubmit` admits it).

`PostToolUse`: every string in `tool_response` is scanned by shape, and every
token (and the rest of a `KEY=value` line) is compared by keyed fingerprint
with the live entries; hits become references (existing reference when the
fingerprint is known). The response keeps its shape.

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
