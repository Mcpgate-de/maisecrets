#!/usr/bin/env python3
"""Single entry point for every hook event; the launcher run.sh picks the interpreter."""
import os
import sys

if len(sys.argv) == 2 and sys.argv[1] == "mod-prompt" and sys.version_info < (3, 9):
    sys.exit(3)   # the mod then tries its next Python (claude-mod/maisecrets-mod.mjs); run.sh checks 3.9 for the hooks

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOOK_EVENTS = ("user-prompt", "pre-tool", "post-tool", "post-tool-failure", "session-start")


def _marker(code: str) -> None:
    """An incident marker for /maisecrets:report incident (docs/DIAGNOSTICS.md, section 3): one empty folder made with
    one mkdir in a home that exists and is no link, after the answer, waited for at most 0.3 s. Never raises."""
    import threading

    def make() -> None:
        try:
            home = os.environ.get("MAISECRETS_HOME") or os.path.join(os.path.expanduser("~"), ".maisecrets")
            if os.path.isdir(home) and not os.path.islink(home):
                os.mkdir(os.path.join(home, "incident-marker." + code), 0o700)
        except Exception:  # noqa: BLE001
            pass
    try:
        sys.stdout.flush()
        t = threading.Thread(target=make, daemon=True)
        t.start()
        t.join(0.3)
    except Exception:  # noqa: BLE001
        pass


def _refuse_without_the_code(why: str) -> None:
    """The plugin's own code cannot be loaded (a half-synced folder, a missing module): answer as the
    launcher does without Python. A failed import ended the process with exit 1, which the client
    reads as no objection, so every prompt and tool went through (ops review, 2026-09-28). Nothing of
    maisecrets is imported here, and the text carries the exception type only."""
    event = sys.argv[1] if len(sys.argv) == 2 else ""
    msg = (f"maisecrets cannot load its own code ({why}); the plugin folder may be half updated. "
           "Run /reload-plugins or start a new session.")
    if event == "post-tool-failure":
        import json
        print(json.dumps({"systemMessage": msg}))    # a failed output cannot be withheld: only the reason is named
        _marker("launcher.import")
        sys.exit(0)
    if event == "post-tool":
        import json
        text = f"[{msg} The tool ran and finished; its output is withheld, do not run it again.]"
        # one shape per client: Codex's strict schema drops an answer with Claude's updatedToolOutput
        codex = '"turn_id"' in sys.stdin.read()
        print(json.dumps({"decision": "block", "reason": text} if codex else
                         {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": text}}))
        _marker("launcher.import")
        sys.exit(0)
    if event == "session-start":
        import json
        print(json.dumps({"systemMessage": msg + " Until then every prompt is blocked."}))
        _marker("launcher.import")
        sys.exit(0)
    import json
    text = msg + " Until then every prompt is blocked."
    # JSON, not exit 2: Codex runs the tool when a hook exits 2 (harness/codex.py); both clients read this
    if event == "pre-tool":
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": text}}))
    else:
        print(json.dumps({"decision": "block", "reason": text}))
    _marker("launcher.import")
    sys.exit(0)


try:
    from maisecrets.hooks import main  # noqa: E402
except Exception as exc:  # noqa: BLE001 - a guard that fails open is no guard
    if len(sys.argv) == 2 and sys.argv[1] in HOOK_EVENTS:
        _refuse_without_the_code(type(exc).__name__)
    if len(sys.argv) == 2 and sys.argv[1] == "mod-prompt":
        sys.exit(1)       # no traceback: the mod passes the prompt on and the hook decides (above: it blocks)
    raise

if len(sys.argv) == 2 and sys.argv[1] == "mod-prompt":
    # the mod's question (claude-mod/maisecrets-mod.mjs). Any failure answers nothing: the mod then passes the prompt on
    # unchanged and the settings hook decides it, so a broken rewrite blocks and never lets a value through
    # unauthenticated like every hook entry (user-prompt takes any transcript_path too): a call by the agent
    # names any session id, so it can store values it already knows under that session and mask them in that
    # session's transcript. It learns nothing it did not give. The PreToolUse backstop names the command
    import json
    try:
        if os.environ.get("MAISECRETS_TEST_FAULT") == "mod-prompt":   # harness: prompt_secret_mod_fails
            raise RuntimeError("fault injected for the harness")
        from maisecrets.hooks import rewrite_prompt  # noqa: E402
        payload = json.load(sys.stdin)
        payload = payload if isinstance(payload, dict) else {}
        # the mod starts this in the plugin folder (a fixed command line); an @mention is relative to the session
        if isinstance(payload.get("cwd"), str) and os.path.isdir(payload["cwd"]):
            os.chdir(payload["cwd"])
        answer = rewrite_prompt(payload)
    except Exception:  # noqa: BLE001 - no traceback: what passes back goes through other mods
        sys.exit(1)
    # ASCII JSON: ⟦ as \u27e6. A Windows console code page cannot write ⟦, and the answer was a traceback
    # (GitHub windows-latest, 2026-10-06); JSON.parse in the mod reads the escape as the same text
    print(json.dumps({"maisecrets": "mod-prompt", **answer}))
    sys.exit(0)

if len(sys.argv) >= 2 and sys.argv[1] == "pending":
    from maisecrets.hooks import take_pending  # noqa: E402
    # Claude Code gives a command the id of its session, the same id its hooks get (measured with the
    # harness, 2026-09-28): with two blocked prompts waiting, /ms found neither and pointed to the
    # clipboard, which does not exist over SSH or in Remote Control (field report on 0.5.8)
    text = take_pending(os.environ.get("CLAUDE_CODE_SESSION_ID") or None)
    print(text if text is not None else "(maisecrets: no blocked prompt is waiting)")
    sys.exit(0)

if len(sys.argv) >= 2 and sys.argv[1] in ("report", "put", "status", "list", "audit", "expire", "config",
                                          "wipe", "repair", "scan", "get", "shortcut", "forget", "guard",
                                          "settings"):
    from maisecrets.cli import main as cli_main  # noqa: E402
    sys.exit(cli_main(sys.argv[1:]))

if len(sys.argv) == 2 and sys.argv[1] == "session-start":
    import json
    from maisecrets.vault import HOME, Vault  # noqa: E402
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    payload = payload if isinstance(payload, dict) else {}

    def _is_codex() -> bool:
        """SessionStart has no prompt_id or turn_id, and Claude Code may send `model`, so the
        payload rule of client_of does not decide here. The transcript path decides first (a
        Codex rollout lives under CODEX_HOME, default ~/.codex, also when Codex was started
        from a Claude Code shell that exports CLAUDECODE); then Claude Code's CLAUDECODE=1;
        then any CODEX_ variable (review, 2026-09-27)."""
        path = str(payload.get("transcript_path") or "")
        home = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
        if path:
            return os.path.abspath(path).startswith(os.path.abspath(home) + os.sep)
        if os.environ.get("CLAUDECODE") == "1":
            return False
        return any(k.startswith("CODEX_") for k in os.environ)
    codex = _is_codex()
    from maisecrets.vault import intro_line  # noqa: E402
    import time
    from maisecrets.hooks import PRIMER  # noqa: E402
    from maisecrets.vault import ConfigError, load_config  # noqa: E402
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(json.dumps({"systemMessage": f"maisecrets: configuration error: {exc}. Every prompt is blocked "
                                           "until the file is fixed."}))
        _marker("hook.session-start")
        sys.exit(0)
    try:
        v = Vault(cfg)
        v.expire(limit=None)
        quieted = v.quiet_code_words()
        v.mark_weak_entries()
    except RuntimeError as exc:
        # a damaged index: the message names `maisecrets repair`; a traceback here gave the
        # client no JSON and the person no hint
        print(json.dumps({"systemMessage": f"maisecrets: {exc}."}))
        _marker("hook.session-start")
        sys.exit(0)
    # a blocked prompt older than 15 minutes is never sent; the file goes too (retention)
    pending = HOME / "pending"
    if pending.is_dir():
        for f in pending.glob("*.txt"):
            try:
                if time.time() - f.stat().st_mtime > 15 * 60:
                    f.unlink()
            except OSError:
                pass
    out = {}
    version = "?"
    try:
        manifest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                ".claude-plugin", "plugin.json")
        with open(manifest, encoding="utf-8") as f:
            version = json.load(f).get("version", "?")
    except (OSError, ValueError):
        pass
    marker = HOME / ".announced"
    if v.backend.test_mode or not marker.exists():
        from maisecrets.tips import try_it_line  # noqa: E402
        more = "" if codex else " /maisecrets:status shows the details, /maisecrets:list what is stored."
        out["systemMessage"] = f"maisecrets {version} is on. " + intro_line(v.backend) + more + " " + try_it_line()
        try:
            marker.write_text(type(v.backend).__name__ + "\n")
        except OSError:
            pass
    else:
        from maisecrets.tips import tip_of_the_day  # noqa: E402
        tip = tip_of_the_day(codex=codex)
        # one short line every session, so a lost hook registration is visible by its absence
        # (operator review, 2026-09-26); the tip rotates, the version does not
        out["systemMessage"] = f"maisecrets {version} is on." + (f" {tip}" if tip else "")
    if quieted:
        out["systemMessage"] = (out.get("systemMessage", "") +
                                f" {len(quieted)} stored word(s) are program code, not secrets "
                                f"({', '.join(quieted)}): maisecrets no longer redacts them in other texts. "
                                "/maisecrets:forget deletes them.")
    if cfg.get("config_warning"):
        out["systemMessage"] = out.get("systemMessage", "") + f" Warning: {cfg['config_warning']}."
    # /ms is offered once, not installed: writing ~/.claude/commands without a question was a
    # change behind the user's back, and Codex cannot use it (UX review, 2026-09-27)
    if not codex and cfg.get("shortcut", True) and not (HOME / ".shortcut").exists():
        out["systemMessage"] = (out.get("systemMessage", "") +
                                " Tip: /maisecrets:shortcut adds /ms as a short form of /maisecrets:send.")
        try:
            (HOME / ".shortcut").write_text("offered\n", encoding="utf-8")
        except OSError:
            pass
    # a synced install: keep the guard script outside the plugin folder current and register it once
    # (the guard of README "Updates and open sessions"); "guard": false or `guard remove` keep it off,
    # an entry deleted from settings.json by hand comes back
    if not codex and os.name != "nt" and not (HOME / ".guard-removed").exists():
        from maisecrets.hooks import _from_a_synced_folder  # noqa: E402
        if _from_a_synced_folder():
            from maisecrets.cli import (guard_off_by_policy, place_guard_script,  # noqa: E402
                                        register_guard_for_a_synced_install)
            place_guard_script()
            if cfg.get("guard", True):
                note = register_guard_for_a_synced_install()
                if note:
                    out["systemMessage"] = out.get("systemMessage", "") + " " + note
            else:
                guard_off_by_policy()
    # the model reads what a placeholder is once per session, before it meets one
    out["hookSpecificOutput"] = {"hookEventName": "SessionStart", "additionalContext": PRIMER}
    print(json.dumps(out))
    sys.exit(0)
sys.exit(main(["hook", sys.argv[1] if len(sys.argv) == 2 else ""]))
