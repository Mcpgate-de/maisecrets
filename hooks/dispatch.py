#!/usr/bin/env python3
"""Single entry point for every hook event; the launcher run.sh picks the interpreter."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from maisecrets.hooks import main  # noqa: E402

if len(sys.argv) >= 2 and sys.argv[1] == "pending":
    from maisecrets.hooks import take_pending  # noqa: E402
    text = take_pending()
    print(text if text is not None else "(maisecrets: no blocked prompt is waiting)")
    sys.exit(0)

if len(sys.argv) >= 2 and sys.argv[1] in ("report", "put", "status", "list", "audit", "expire", "config",
                                          "wipe", "repair", "scan", "get", "shortcut"):
    from maisecrets.cli import main as cli_main  # noqa: E402
    sys.exit(cli_main(sys.argv[1:]))

if len(sys.argv) == 2 and sys.argv[1] == "session-start":
    import json
    from maisecrets.vault import HOME, Vault  # noqa: E402
    try:
        json.load(sys.stdin)
    except ValueError:
        pass
    from maisecrets.vault import describe_backend  # noqa: E402
    import time
    from maisecrets.hooks import PRIMER  # noqa: E402
    from maisecrets.vault import ConfigError, load_config  # noqa: E402
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(json.dumps({"systemMessage": f"maisecrets: configuration error: {exc}. Every prompt is blocked "
                                           "until the file is fixed."}))
        sys.exit(0)
    v = Vault(cfg)
    v.expire(limit=None)
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
        out["systemMessage"] = f"maisecrets {version} active. " + describe_backend(v.backend)
        try:
            marker.write_text(type(v.backend).__name__ + "\n")
        except OSError:
            pass
    else:
        from maisecrets.tips import tip_of_the_day  # noqa: E402
        tip = tip_of_the_day()
        # one short line every session, so a lost hook registration is visible by its absence
        # (operator review, 2026-09-26); the tip rotates, the version does not
        out["systemMessage"] = f"maisecrets {version} active." + (f" {tip}" if tip else "")
    if cfg.get("config_warning"):
        out["systemMessage"] = out.get("systemMessage", "") + f" Warning: {cfg['config_warning']}."
    # the personal /ms shortcut, once, unless the user has one or turned it off (a plugin cannot
    # register a command without its namespace; only ~/.claude/commands can)
    if cfg.get("shortcut", True) and not (HOME / ".shortcut").exists() and "CLAUDE_PLUGIN_ROOT" in os.environ:
        try:
            from maisecrets.cli import install_shortcut  # noqa: E402
            done = install_shortcut("ms", only_if_absent=True)
            (HOME / ".shortcut").write_text("installed\n" if done else "kept\n", encoding="utf-8")
            if done:
                out["systemMessage"] = (out.get("systemMessage", "") +
                                        " /ms (short for /maisecrets:send) is set up from the next session on.")
        except OSError:
            pass
    # the model reads what a placeholder is once per session, before it meets one
    out["hookSpecificOutput"] = {"hookEventName": "SessionStart", "additionalContext": PRIMER}
    print(json.dumps(out))
    sys.exit(0)
sys.exit(main(["hook", sys.argv[1] if len(sys.argv) == 2 else ""]))
