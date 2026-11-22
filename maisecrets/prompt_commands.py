"""The prompt path's answers that need more than the detector: ms:(…) as the whole prompt (a check, check_answer),
ms:(value) inside a prompt (take_inline), and the mod's answer to the person's own maisecrets commands in Claude Code
(mod_command). They lived in hooks.py, which ships under the release file limit (scripts/check_release_sizes.py).

Every name of hooks.py is read on that module at call time (`h.Vault`, `h._scrub_transcript_later`): a test that
patches one on hooks patches it here too, and this module imports nothing of hooks at its own import.
"""
from __future__ import annotations

import re

from . import check_value, demo, detect, incidents, not_a_secret, term_files, value_files
from .lazy_regex import LazyRx


def _allowed_by_the_list(value: str) -> str | None:
    """Why the allow list lets this value through, or None. Only for a value no rule caught: the scan with every rule,
    without the allow list, shows whether the list took a hit out (`rule: <id>` or an exact value)."""
    return detect.explain_allowed(value)


def _store_unseen(payload: dict, cfg: dict, value: str, session: str | None, exact: bool) -> str:
    """No rule and no stored value caught `value`: store it as /maisecrets:put does, so that it is masked from now
    on, and say where maisecrets finds it again. Each case where storing is not allowed or would not help says so."""
    from . import hooks as h
    from . import settings as settings_mod
    allowed = _allowed_by_the_list(value)
    if allowed:
        from .user_rules import ALLOW_FILE
        why = allowed[len("your allow list "):] if allowed.startswith("your allow list ") else allowed
        return check_value.not_caught(f"Your allow list lets it through: it {why}. It was not stored. To protect it, "
                                      f"remove that line from {ALLOW_FILE}.")
    if not exact:
        return check_value.not_caught("It was not stored, because the prompt does not start with ms:( exactly. Send "
                                      "it again as ms:(…) to store it.")
    # the mod names who sent the prompt: only the person at the terminal or in Remote Control stores (an `sdk` turn can
    # come from a program, as for a settings change)
    if not settings_mod.typed_by_the_person(payload) or payload.get("agent_id") or \
            payload.get("origin") not in (None, "composer", "bridge"):
        return check_value.not_caught("It was not stored: maisecrets stores a value only from a prompt that you "
                                      "type yourself.")
    if h.find_refs(value):
        return check_value.not_caught("It holds a maisecrets placeholder, so it was not stored. Check the value "
                                      "without the placeholder.")
    if "\n" in value or "\r" in value:
        return check_value.not_caught("It has more than one line, so it was not stored. maisecrets finds a stored "
                                      "value only on one line. Use /maisecrets:put for it.")
    if len(value) < h._EXACT_MIN_LEN:
        return check_value.not_caught(f"maisecrets finds a stored value only from {h._EXACT_MIN_LEN} characters on, "
                                      "so it was not stored.")
    if not check_value.looks_like_a_credential(value):
        # a check of ordinary words stored them for good, and every later prompt with them was blocked (field report,
        # 0.6.32): only a value that the credential checks of the detector take is stored here
        return check_value.not_caught(check_value.TEST_VALUE if check_value.names_a_test_value(value)
                                      else check_value.ORDINARY)
    try:
        e = h.Vault(cfg).put(value, "SECRET", "manual", session=session)
    except Exception as exc:  # noqa: BLE001 - the answer says it; the prompt stays blocked
        incidents.note("prompt.check-store", exc)
        return check_value.not_caught(f"It could not be stored (an internal error, {type(exc).__name__}). Try "
                                      "/maisecrets:put, or /maisecrets:report incident.")
    h._live_cache.clear()        # the store holds a value now: the checks below must look for it
    alone = any(h._verdict(value, cfg, session)[1:3])
    in_text = any(h._verdict(f"see {value} here", cfg, session)[1:3])
    seconds = int(round(e.expires - e.created))
    return check_value.stored_text(e.ref, alone, in_text, h._hours(seconds)) + check_value.format_report(value)


def check_answer(payload: dict, groups: list) -> dict:
    """The answer to ms:(…): always a block, whatever the verdict. Each group of the prompt (check_value.parse_all)
    gets its own verdict, from the same calls as a normal prompt with that value. The reason goes to the person and
    says what each hit is masked as and how it was found (maisecrets/verdict.py), never the value; the transcript
    loses the prompt as typed."""
    from . import hooks as h
    cfg = h.load_config()
    session = payload.get("session_id")
    codex = h.client_of(payload) == "codex"
    entries: list = []
    values: list = []
    lines: list = []
    seen: dict = {}
    for value, exact in groups:
        if value in seen:                  # the same value again: the same line, and it is stored once
            lines.append(lines[seen[value]])
            continue
        seen[value] = len(lines)
        got, taken, line = _check_one(payload, cfg, session, value, exact)
        entries += got
        values += taken
        lines.append(line)
    # a value no rule caught is stored after every group has its verdict: a group never sees what a check before it
    # in the same prompt stored, so each verdict is the one its normal prompt gets alone
    stored: dict = {}
    for i, line in enumerate(lines):
        if isinstance(line, tuple):
            if line[1] not in stored:
                stored[line[1]] = _store_unseen(payload, cfg, *line[1:])
            lines[i] = stored[line[1]]
    if len(lines) == 1:
        reason = lines[0] + "\n\n" + check_value.NOT_SENT
    else:
        reason = "\n".join(f"Value {i}: {line}" for i, line in enumerate(lines, 1)) + "\n\n" + check_value.NOT_SENT
    if cfg.get("scrub_transcript", True):
        raw = payload.get("prompt") if isinstance(payload.get("prompt"), str) else ""
        forms = check_value.scrub_forms(raw, [v for v, _exact in groups])
        scrub = [x for x in dict.fromkeys(forms + list(values)) if x]
        h._scrub_transcript(payload.get("transcript_path", ""), scrub, [])
        h._scrub_transcript_later(payload.get("transcript_path", ""), scrub, [], session=session)
    from . import events
    events.record("UserPromptSubmit", h.client_of(payload), entries, outcome="ms:( check")   # key, type, rule: no value
    if codex:
        return {"decision": "block", "reason": reason}
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}


def _check_one(payload: dict, cfg: dict, session: str | None, value: str, exact: bool) -> tuple:
    """(entries, values taken out, verdict line) of one group of a check. The line ends without the sentence that the
    prompt was not sent: check_answer adds it once. For a value no rule caught, the line is a tuple that names the
    store step, which check_answer runs after the verdicts of all groups."""
    from . import hooks as h
    if not value.strip():
        return [], [], check_value.USAGE_LINE
    if check_value.only_placeholders(value, h.find_refs(value)):
        return [], [], check_value.A_PLACEHOLDER_LINE
    entries, matches, n_stored, values = h._verdict(value, cfg, session)
    if matches or n_stored:
        from . import verdict
        return entries, values, verdict.caught(value, matches, entries)
    return entries, values, ("store", value, session, exact)     # check_answer stores it after the last verdict


def take_inline(prompt: str, cfg: dict, session: str | None) -> tuple:
    """ms:(value) inside a prompt the person typed (check_value.inline_marks): each value is stored as /maisecrets:put
    stores it, and its placeholder stands in place of the whole mark. (prompt, entries, values)."""
    from . import hooks as h
    marks = check_value.inline_marks(prompt)
    if not marks:
        return prompt, [], []
    vault = h.Vault(cfg)
    parts, entries, values, last = [], [], [], 0
    for start, end, value in marks:
        if check_value.only_placeholders(value, h.find_refs(value)):
            continue                    # placeholders alone are no value: the mark stays as typed
        # a placeholder next to other text: the whole mark is stored, so the text never goes out (Gate A)
        e = vault.put(value, "SECRET", "manual", session=session)
        parts += [prompt[last:start], e.ref]
        last = end
        entries.append(e)
        values.append(value)
    parts.append(prompt[last:])
    if entries:
        h._live_cache.clear()             # the store holds a value now
    return "".join(parts), entries, values


# the one entry that every client shows (commands/maisecrets.md and commands/ms.md): `/maisecrets NAME ARGS` in Cowork
# and in the terminal (there the mod's own /maisecrets), `/ms NAME ARGS` (Cowork, and the personal shortcut in the
# terminal), `/maisecrets:maisecrets NAME ARGS` and `/maisecrets:ms NAME ARGS` (the plugin's names in the terminal)
ENTRIES = ("maisecrets", "ms")
# the names of the other commands/*.md: the entry takes each as its first word (tests/test_entry.py compares them)
COMMANDS = ("audit", "demo", "forget", "guard", "list", "ner", "not-a-secret", "put", "report", "rules", "send",
            "settings", "shortcut", "sref", "status", "term")
_ENTRY_RE = LazyRx(r"\A\s*/(?:maisecrets(?::(?:maisecrets|ms))?|ms)(?:[ \t]+(?P<name>[A-Za-z][A-Za-z-]*)"
                   r"(?P<rest>(?:[ \t][^\r\n]*)?))?\s*\Z", re.I)


def canonical(prompt):
    """`/maisecrets:NAME ARGS` for an entry form with a command name (`/maisecrets status test`, `/ms term add X`),
    so every path reads it as the colon form; any other prompt as it is. The entry alone stays as it is."""
    m = _ENTRY_RE.match(prompt) if isinstance(prompt, str) else None
    name = (m.group("name") or "").lower() if m else ""
    if name not in COMMANDS:
        return prompt
    return f"/maisecrets:{name}{m.group('rest').rstrip()}"


def entry_alone(prompt) -> bool:
    """The entry with no command name: `/maisecrets`, `/ms`, `/maisecrets:maisecrets`, `/maisecrets:ms`."""
    m = _ENTRY_RE.match(prompt) if isinstance(prompt, str) else None
    return bool(m) and not m.group("name")


_MS_RE = LazyRx(r"\A\s*/ms(?![\w:-])", re.I)


def foreign_ms() -> bool:
    """Whether the person's own /ms is a command of theirs, not the maisecrets shortcut: then `/ms NAME` is theirs.
    In Cowork /ms is the plugin's entry (the person's commands folder of the computer does not reach it)."""
    import os
    from pathlib import Path
    from . import cowork
    if cowork.active():
        return False
    target = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "commands" / "ms.md"
    try:
        text = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    except (OSError, UnicodeDecodeError):
        return True
    from .cli import is_our_shortcut
    return not is_our_shortcut(text)


def with_canonical(payload: dict) -> dict:
    """The payload with its prompt in the colon form (canonical). Codex keeps its prompt: it has no slash commands,
    and spaced_answer names its own form there. `/ms NAME` stays as typed when the person's /ms is their own."""
    from . import hooks as h
    prompt = payload.get("prompt")
    if h.client_of(payload) == "codex":
        return payload
    if isinstance(prompt, str) and _MS_RE.match(prompt) and foreign_ms():
        return payload
    new = canonical(prompt)
    return payload if new is prompt else {**payload, "prompt": new}


# the Codex form of a maisecrets command, `maisecrets: NAME ARGS` (Codex has no plugin slash commands)
_TYPED_FORM_RE = LazyRx(r"\A\s*maisecrets[ \t]*:[ \t]*(?P<name>[a-z][a-z-]*)(?:[ \t]+(?P<args>[^\r\n]*?))?\s*\Z",
                        re.I)


# the slash form of a maisecrets command, one line
_SLASH_FORM_RE = LazyRx(r"\A\s*/maisecrets:(?P<name>[a-z][a-z-]*)(?:[ \t]+(?P<args>[^\r\n]*?))?\s*\Z", re.I)
# the commands whose command file only runs one CLI entry with the typed arguments and shows its output: the entry and
# whether the arguments go on stdin (--args-stdin, as the command file passes them)
_STDIN_ENTRIES = {"list": ["list"], "audit": ["audit"], "report": ["report"], "guard": ["guard"],
                  "shortcut": ["shortcut"], "forget": ["forget"], "settings": ["settings"], "sref": ["sref"],
                  "put": ["put", "--clipboard"]}


COWORK_SREF_LOGIN = ("maisecrets: a gateway login from Cowork is not tested yet. Each Cowork task runs in a new VM, so "
                     "a login there would last one task. Log in to your gateway in Claude Code in the terminal or in "
                     "the desktop app's Code tab.")


# the sref run in Cowork ends inside the mod's budget for one prompt (BUDGET_MS, 8 s, claude-mod/maisecrets-mod.mjs),
# with time left for the start of Python: the child gets COWORK_SREF_S less the wait of a name service on this computer
# in the mask of its answer (COWORK_SREF_MASK_S; a network name service checks no text that was not typed); the
# child's discovery ends earlier still (cli.SREF_COWORK_DISCOVERY_S)
COWORK_SREF_S = 5.0
COWORK_SREF_MASK_S = 1.0
# the child's environment: the run is this one, so cmd_sref ends its discovery early (an AI's own run keeps its time)
COWORK_SREF_ENV = "MAISECRETS_COWORK_SREF"
COWORK_SREF_SLOW = ("maisecrets: the gateway did not answer in time; send maisecrets: sref again, or check it in "
                    "Claude Code in the terminal.")


def _cowork_sref(payload: dict, prompt: str) -> dict | None:
    """Cowork's answer to the person's typed `maisecrets: sref`: the AI may not start it (commands/sref.md), and in
    Cowork a typed command reaches only the AI, which then ran the command file by hand (measured 2026-11-21).
    maisecrets runs the status itself and shows its output (cowork.show_answer); a login gets the line that it is not
    tested in Cowork. The slash form gets None, as every other command: the engine sends a slash line as typed (#44),
    so no answer of the mod reaches the model for it, and the hints in Cowork name the text form (forms.cowork)."""
    import os
    import subprocess
    import sys
    from . import cowork, remote_layer
    m = _TYPED_FORM_RE.match(prompt)
    if not m or m.group("name").lower() != "sref":
        return None
    args = (m.group("args") or "").strip()
    session = payload.get("session_id")
    in_demo = demo.active(session)

    def shown(text: str) -> dict:
        # in a demo session a request to show it would get the demo line: the demo answer carries it. The name service
        # waits at most COWORK_SREF_MASK_S, so the run and the mask end inside COWORK_SREF_S
        with remote_layer.capped_wait(COWORK_SREF_MASK_S * 1000):
            return demo.cowork_own(payload, text) if in_demo else cowork.show_answer(payload, text)
    if in_demo and demo.own_argv(f"maisecrets: sref {args}") is None:
        # the demo runs only the sref forms it permits (a login or a logout goes to the network)
        return shown(demo.own_answer(f"maisecrets: sref {args}", session))
    if args.split()[:1] == ["login"]:
        return shown(COWORK_SREF_LOGIN)
    plan = run_plan("/maisecrets:sref" + (f" {args}" if args else ""))
    if plan is None or plan.get("long"):
        return None
    entry = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks", "dispatch.py")
    env = {**os.environ, "PYTHONUTF8": "1", COWORK_SREF_ENV: "1"}
    if isinstance(session, str):
        env["CLAUDE_CODE_SESSION_ID"] = session
    try:
        # subprocess.run kills the child when the time is up
        r = subprocess.run([sys.executable, entry, *plan["argv"]], input=plan.get("stdin", ""), capture_output=True,
                           text=True, env=env, timeout=COWORK_SREF_S - COWORK_SREF_MASK_S)
        output = (r.stdout + r.stderr).strip() or "maisecrets: the sref command gave no output."
    except subprocess.TimeoutExpired:
        output = COWORK_SREF_SLOW
    except (OSError, subprocess.SubprocessError):
        output = "maisecrets: the sref command could not run. Send it again."
    return shown(output)


def run_plan(prompt) -> dict | None:
    """What the mod runs for a slash command the person typed, in place of its command file: {"argv": the CLI words
    after hooks/dispatch.py (fixed words only), "stdin": the typed arguments for --args-stdin, "long": a run of up to
    two minutes (the login), "server": the server a login names, "view": "ner" for the panel's name-service view or
    "lines" for an answer above the prompt with no panel (forget), "fill": the output goes into the prompt box
    (/maisecrets:send), "markdown": the output is Markdown, "pair": the proposed claude.ai connector whose pairing
    proof the mod asks for after a login that succeeded}. None keeps
    the command file: a form that needs the model or its tool hooks, such as `status test`, whose value only the
    PreToolUse hook makes and whose proof is the tool output path."""
    m = _SLASH_FORM_RE.match(prompt) if isinstance(prompt, str) else None
    if not m:
        return None
    name, args = m.group("name").lower(), (m.group("args") or "").strip()
    words = args.split()
    if name in ENTRIES:
        # the entry alone (the mod gives `/ms` alone as `/maisecrets:maisecrets`): the panel, as /maisecrets alone;
        # where no panel is placed, the overview (cli.cmd_entry)
        return {"argv": ["entry"], "view": "panel"} if not words else None
    if name == "status":
        return {"argv": ["status", *words]} if words in ([], ["all"]) else None
    if name == "rules":
        return {"argv": ["rules"]} if not words else None
    if name == "term":
        return {"argv": ["terms"]} if not words else None          # add and remove: the prompt hook answers them
    if name == "send":
        return {"argv": ["pending"], "fill": True} if not words else None
    if name == "ner":
        # the prompt hook made the change; the output is the view of the source (`all`: its details)
        return {"argv": ["ner", "all"]} if [w.lower() for w in words] == ["all"] else {"argv": ["ner"], "view": "ner"}
    if name not in _STDIN_ENTRIES:
        return None
    if name == "forget" and any(w.lower().startswith("import:") for w in words):
        return None                                                  # the prompt hook answers it
    plan = {"argv": [*_STDIN_ENTRIES[name], "--args-stdin"], "stdin": args}
    if name == "sref" and words[:1] == ["login"]:
        plan["long"] = True
        if len(words) == 2:
            plan["server"] = words[1][:64]
            # #91: a proposed claude.ai connector: after the login the mod asks it for its pairing proof
            from . import vault_refs
            if words[1] in vault_refs.connectors(pending=True) and words[1] not in vault_refs.user_servers():
                plan["pair"] = words[1]
    if name == "settings":
        plan["markdown"] = True
    if name == "forget":
        # a confirmation of one line per key: it stands above the prompt, no panel opens for it (live probe 2026-11-22)
        plan["view"] = "lines"
    return plan


def mod_command(payload: dict) -> dict | None:
    """The mod's answer to the person's own maisecrets command in Claude Code, so that none reaches the model and none
    reads as a block (night UX test, findings C and F): {"drop": answer} for a command the prompt hook answers (the
    same call, hooks.user_prompt) and for a Codex form that runs without the model (demo.own_answer); {"run": plan}
    for a command the mod runs itself (run_plan); {"entry": words} for a command that needs the model, which the mod
    runs through the entry command file. None for every other prompt, and for a prompt the person did not type (the
    hook path stays as it is: Codex, claude -p, a client without the mod)."""
    from . import hooks as h
    if payload.get("origin") == COMMAND_ROUTE:
        return _command_route(payload)
    if payload.get("origin") not in ("composer", "bridge"):
        return None
    # Cowork draws no panel and no dropped-prompt line, so an answer the mod drops is not seen there
    # (maisecrets/cowork.py): a command the hook answers goes to the model as a request to show the answer, and every
    # other command runs through its command file
    from . import cowork
    in_cowork = cowork.active()
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or "maisecrets" not in prompt.lower():
        return None
    # the pending self-test value goes on to the real prompt hook: its pass proves that hook ran (Gate A)
    st = h._selftest()
    if not st.typed_command(prompt) and st.claims(prompt):
        return None
    from . import settings as settings_mod
    slash = prompt.lstrip().startswith("/")
    hook = (incidents.recognize(prompt, "claude") or demo.parse(prompt) or term_files.parse_command(prompt)
            or value_files.parse_removal(prompt) or not_a_secret.parse(prompt)
            # a slash settings change runs on after a success (it shows the new state): the hook keeps it
            or (not slash and settings_mod.parse_prompt(prompt))
            or (h._GRANT_RE.match(prompt) and h.load_config().get("ssh_consent")))
    if hook:
        session = payload.get("session_id")
        # the demo asks the transcript whether the session has a turn; the mod gives no path
        found = demo._find_transcript(session) if isinstance(session, str) and session else None
        out = h.user_prompt({**payload, "prompt_id": "mod", "transcript_path": found or ""})
        if out.get("decision") == "block" and isinstance(out.get("reason"), str):
            if in_cowork and demo.active(session, found):
                # demo on, or a command in a demo session: a request to show the answer would get the demo line, so
                # the demo answer itself carries it, and nothing goes to the AI (demo.cowork_own)
                line = incidents.cowork_line() if incidents.recognize(prompt, "claude") else out["reason"]
                return demo.cowork_own(payload, line)
            if in_cowork and incidents.recognize(prompt, "claude"):
                # the AI never reads the incident report (docs/DIAGNOSTICS.md), and Cowork shows only what it writes
                return cowork.show_answer(payload, incidents.cowork_line())
            return cowork.show_answer(payload, out["reason"]) if in_cowork else {"drop": out["reason"]}
        return {}
    if in_cowork:
        return _cowork_sref(payload, prompt)
    plan = run_plan(prompt) if slash else None
    m = None if slash else _TYPED_FORM_RE.match(prompt)
    name = m.group("name").lower() if m else ""
    # the command names of commands/*.md and the skill (demo.FORMS and the names it leaves out): another word after
    # `maisecrets:` is a question for the AI
    if not slash and name not in demo.FORMS and name not in demo.NOT_PASSED:
        return None
    if not slash and demo.own_command(prompt) and (demo.own_argv(prompt) is not None
                                                   or demo.active(payload.get("session_id"))):
        # in the demo a form that needs the model gets the demo's line that it did not run (demo.own_answer)
        return {"drop": demo.own_answer(prompt, payload.get("session_id"))}
    # a command that needs the model (`status test`, the Codex form of a command): the mod runs the entry command file
    # with these words (commands/maisecrets.md), as the person's Enter would; the single command files are hidden
    entry = None if plan is not None else _entry_words(prompt, m)
    if not slash and entry is None:
        # the skill (maisecrets: secret-hygiene): its slash form goes into the box, and the person's Enter starts it
        form = f"/maisecrets:{name}" + (f" {m.group('args')}" if m.group("args") else "")
        return {"drop": f"maisecrets: in Claude Code this is {form}. It is in your input box: press Enter to run it.",
                "fill": form}
    if plan is None and entry is None:
        return None
    # the prompt hook decides first, with the same call as for the slash command (its value check, a settings or ner
    # change the person typed, the note of a typed forget); its block drops the command
    session = payload.get("session_id")
    found = demo._find_transcript(session) if isinstance(session, str) and session else None
    out = h.user_prompt({**payload, "prompt_id": "mod", "transcript_path": found or ""})
    if out.get("decision") == "block":
        reason = out.get("reason")
        return {"drop": reason if isinstance(reason, str) and reason else "maisecrets: this command did not run."}
    if entry is not None:
        return {"entry": entry}
    # a command file that only runs its CLI entry: the mod runs that entry itself, with no model turn
    context = (out.get("hookSpecificOutput") or {}).get("additionalContext")
    if isinstance(context, str) and context:
        plan["note"] = context
    if plan.get("view") == "ner":
        from . import ner_setup
        plan["starting"] = ner_setup.start_running()
    return {"run": plan}


# the origin the mod gives a command it got from its command.run hook (the mod's own /maisecrets NAME, a hidden
# /maisecrets:NAME): the engine stamps such a run `composer` for every local command, so it is no proof that the person
# typed it. That route never makes a change only the person's own prompt may make (C22): it names the prompt to send
COMMAND_ROUTE = "command"
# the source this module gives the prompt hook for that route: not the person's (settings.TYPED_SOURCES)
_ROUTE_SOURCE = "mod-command-run"
# the refused commands of that route that may wait in an empty input box (_command_route): the mod's SREF_BOX
_BOX_SREF_RE = LazyRx(r"/maisecrets:sref log(?:in|out)(?: [A-Za-z0-9_.-]{1,64})?")


def person_only(prompt: str) -> bool:
    """Whether a colon-form command makes a change that counts only from the person's own prompt: what the prompt hook
    answers (term add or remove, not-a-secret, demo, forget import:ID, the incident report), a settings or name service
    change, a forget (its typed note lets the deletion count as the person's) and a login or logout (it binds a
    claude.ai connector)."""
    from . import hooks as h
    from . import settings as settings_mod
    if (incidents.recognize(prompt, "claude") or demo.parse(prompt) or term_files.parse_command(prompt)
            or value_files.parse_removal(prompt) or not_a_secret.parse(prompt) or settings_mod.parse_prompt(prompt)
            or h._GRANT_RE.match(prompt)):
        return True
    m = _SLASH_FORM_RE.match(prompt)
    name, words = (m.group("name").lower(), (m.group("args") or "").split()) if m else ("", [])
    return name == "forget" or (name == "sref" and words[:1] in (["login"], ["logout"]))


def _command_route(payload: dict) -> dict:
    """The mod's answer for a command its command.run hook got. A change only the person may make is not made: the
    answer names the prompt that makes it, and the person types it: the stamp `composer` is no proof that the person
    typed this command, so nothing here fills the input box. Any other command takes the person's path, with a source
    that is not the person's, so the prompt hook counts nothing of it as typed."""
    prompt = payload.get("prompt")
    if not isinstance(prompt, str):
        return {"drop": "maisecrets: this command did not run."}
    if person_only(prompt):
        from . import forms
        m = _SLASH_FORM_RE.match(prompt)
        words = f"{m.group('name').lower()} {m.group('args') or ''}".strip() if m else ""
        name = words.split()[:1]
        # sref keeps its slash form here: its text form runs only in Cowork (_cowork_sref)
        typed = f"/maisecrets {words}" if name == ["sref"] else forms.cowork(f"/maisecrets {words}")
        if typed.startswith("/") and name in (["ner"], ["settings"]):
            # a ner or settings change has a text form that the prompt hook counts as typed (settings.parse_prompt)
            typed = "maisecrets: " + ("set " + words[len("settings"):].strip() if name == ["settings"] else words)
        if typed.startswith("maisecrets: ") and not person_only(typed):
            # a form the prompt hook does not parse (`ner local --model x`) would change nothing: the slash form below
            typed = f"/maisecrets {words}"
        if typed.startswith("/"):
            # a plugin command the menu shows: the person's Enter goes through the prompt hook. Not the plain entry
            # `/maisecrets NAME`: with the mod it is the mod's own command, which reaches only command.run, never
            # prompt.submit or the prompt hook (claude-mod/maisecrets-mod.mjs runTyped, measured on 2.1.330), and
            # comes back here to be refused again. forget KEY has no text form that counts as typed
            # (events.note_typed_forget reads the slash form only); sref and report start from their own command file
            typed = f"/maisecrets:{words}" if words.split()[:1] in (["sref"], ["report"]) else \
                f"/maisecrets:maisecrets {words}"
        named = _without_values(typed, payload)
        out = {"drop": "maisecrets: this command changes what maisecrets does, so it counts only as your own prompt. "
                       f"Nothing was changed. Send it as a prompt: {named}"}
        if named == typed and _BOX_SREF_RE.fullmatch(typed):
            # a login or a logout may wait in an empty input box for the person's Enter: a logout loosens nothing,
            # and a login opens the browser, where the person gives the consent, and binds a claude.ai connector
            # only with its pairing proof: the same as the login offer at the end of a turn (sref_hooks.LOGIN_FILL).
            # A setting, a term, not-a-secret, the demo, the name service and a forget (it ends the search for a
            # value) are named only: an AI that starts a hidden command could put them there (review of !633)
            out["box"] = typed
        return out
    out = mod_command({**payload, "origin": "composer", "source": _ROUTE_SOURCE})
    return out if out is not None else {"drop": "maisecrets: this command did not run."}


def _without_values(form: str, payload: dict) -> str:
    """The form the refusal names, with no value and no placeholder for the person to copy: a copied placeholder would
    store its own text, not the value. From the first word that holds one, the person types the words."""
    from .placeholder import REF_RE
    masked = _masked_for_the_box(form, payload.get("session_id"), "masked in a command the mod refused")
    text = masked["masked"] if masked is not None else form
    if masked is not None and not masked["count"] and not REF_RE.search(text):
        return text
    kept = []
    for word in text.split(" "):
        ref = REF_RE.search(word)
        if ref or masked is None and len(kept) >= 2:
            kept.append(ref.group("type") or ref.group("ltype") if ref else "ARGS")
            break
        kept.append(word)
    return " ".join(kept) + " (type the words yourself)"


def _entry_words(prompt: str, typed) -> str | None:
    """The words after the entry for a command the mod cannot run itself: `status test` for `/maisecrets:status test`
    or `maisecrets: status test`. None for a command that is no maisecrets command (the skill secret-hygiene)."""
    m = typed or _SLASH_FORM_RE.match(prompt)
    name = m.group("name").lower() if m else ""
    if name not in COMMANDS:
        return None
    return f"{name} {m.group('args') or ''}".strip()


# `/maisecrets NAME ARGS` in Codex, which has no plugin slash commands: the prompt hook names the Codex form and sends
# nothing. In Claude Code it is the entry (canonical), and every path reads it as the colon form
_SPACED_RE = LazyRx(r"\A\s*/maisecrets[ \t]+(?P<name>[a-z][a-z-]*)(?P<rest>(?:[ \t][^\r\n]*)?)\s*\Z", re.I)


def spaced_answer(payload: dict) -> dict | None:
    """In Codex, the block for a maisecrets command typed as a slash command, with the form that runs it; None for any
    other prompt and in Claude Code. It changes nothing, so it needs no check of who typed it: it only keeps the
    command text from the AI."""
    from . import hooks as h
    prompt = payload.get("prompt")
    m = _SPACED_RE.match(prompt) if isinstance(prompt, str) else None
    name = m.group("name").lower() if m else ""
    if name not in COMMANDS or h.client_of(payload) != "codex":
        return None
    rest = m.group("rest").rstrip()
    return {"decision": "block", "reason": f"maisecrets: in Codex, send maisecrets: {name}{rest}. This prompt "
                                           "was not sent to the AI."}


def fill_check(payload: dict) -> dict:
    """The mod's value check of a command it puts into the input box (`/maisecrets status VALUE` typed with a space, or
    a mistyped name): the colon form with each value taken out, stored and masked as the prompt hook does for a prompt
    that carries one, so the box never gets a value back (Gate A of !591). It runs no command and reads no command
    words. {"masked": text, "count": n}; {} when the text is no maisecrets command or the session id has no valid shape,
    and the mod then fills nothing."""
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.startswith("/maisecrets:"):
        return {}
    return _masked_for_the_box(prompt, payload.get("session_id")) or {}


def _masked_for_the_box(prompt, session, outcome="masked in a command the mod put into the box") -> dict | None:
    """{"masked": text, "count": n} for one line the mod puts into the input box or a refusal names, each value taken
    out, stored and masked as the prompt hook does; None for more than one line or a session id with no valid shape."""
    from . import events
    from . import hooks as h
    if (not isinstance(prompt, str) or "\n" in prompt or "\r" in prompt
            or not isinstance(session, str) or not h._SESSION_ID_RE.fullmatch(session)):
        return None
    cfg = h.load_config()
    matches = h._prompt_hits(prompt)
    if not matches and not h._has_live(cfg):
        return {"masked": prompt, "count": 0}
    rewritten, entries, values, stored, matches = h._take_values_out(prompt, matches, cfg, h.Vault(cfg), session)
    count = len(matches) + stored["n"]
    if count:
        if cfg.get("scrub_transcript", True):
            h._scrub_transcript_later("", values, [], session=session)    # the record of the typed prompt
        events.record("UserPromptSubmit", "claude", entries, outcome=outcome)
    return {"masked": rewritten, "count": count}
