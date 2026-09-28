"""maisecrets command line: list, get, expire, scan, hook."""
from __future__ import annotations

import json
import os
import sys
import time

from . import detect
from .hooks import main as hook_main
from .vault import ConfigError, Vault, load_config


def _age(ts: float) -> str:
    d = time.time() - ts
    if d < 3600:
        return f"{int(d // 60)}m"
    if d < 86400:
        return f"{int(d // 3600)}h"
    return f"{int(d // 86400)}d"


def cmd_list(_: list[str]) -> int:
    """What is stored, masked: the same view a person gets from /maisecrets:list. No value."""
    v = Vault()
    rows = v.list()
    if not rows:
        print("Nothing is stored.")
        return 0
    live = [e for e in rows if not e.purged]
    print(f"{len(live)} value(s) stored, {len(rows) - len(live)} expired (only the masked form is kept).")
    print(f"{'key':<14} {'type':<7} {'kind':<18} {'age':>5} {'uses':>4} {'expires in':>10}  shown as")
    for e in sorted(rows, key=lambda x: x.created):
        exp = "expired" if e.purged else f"{int(max(0, e.expires - time.time()) // 3600)}h"
        print(f"{e.key:<14} {e.type:<7} {e.kind:<18} {_age(e.created):>5} {e.uses:>4} {exp:>10}  {e.display or '-'}")
    if v.backend.test_mode:
        print("\nbackend: jsonfile (TEST MODE, plaintext under ~/.maisecrets/)")
    print("\nTo delete one: /maisecrets:forget <key>. To delete everything: /maisecrets:status shows how.")
    return 0


def cmd_forget(args: list[str]) -> int:
    if not args:
        print("usage: maisecrets forget <KEY> [KEY ...]   (keys as /maisecrets:list shows them)", file=sys.stderr)
        return 2
    v, rc = Vault(), 0
    for raw in args:
        key = raw.strip("⟦⟧").split(":", 1)[0]
        status = v.forget(key)
        if status == "ok":
            print(f"{key}: deleted. A placeholder for it no longer resolves anywhere.")
        elif status == "unknown":
            print(f"{key}: not found (see /maisecrets:list)")
            rc = 1
        else:
            print(f"{key}: the store refused to delete it; nothing was changed")
            rc = 1
    return rc


def cmd_get(args: list[str]) -> int:
    if not args:
        print("usage: maisecrets get <KEY>", file=sys.stderr)
        return 2
    value, status = Vault().get(args[0], human=True)
    if status != "ok":
        print(f"{args[0]}: {status}", file=sys.stderr)
        return 1
    print(value)
    return 0


def cmd_resolve(args: list[str]) -> int:
    """Read one value under a one-time grant. The Bash hook writes this call into the command
    in place of the placeholder; nothing else has a valid nonce. Prints the value without a
    trailing newline so a command substitution gets it byte for byte."""
    if len(args) != 3 or args[1] != "--grant":
        print("usage: maisecrets resolve <KEY> --grant <NONCE>", file=sys.stderr)
        return 2
    value, status = Vault().redeem(args[0], args[2])
    if status != "ok":
        print(f"maisecrets resolve {args[0]}: {status}", file=sys.stderr)
        return 1
    sys.stdout.write(value)
    sys.stdout.flush()
    return 0


def cmd_audit(args: list[str]) -> int:
    """The last resolves: when, which session, which key, which tool, the command with its
    placeholders. Values are never written here."""
    from .vault import HOME
    try:
        n = int(args[0]) if args else 20
    except ValueError:
        print("usage: audit [n]", file=sys.stderr)
        return 2
    path = HOME / "audit.log"
    if not path.exists():
        print("(no resolves recorded)")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()[-n:]
    print("time                 session  key            tool            context")
    for line in lines:
        parts = line.split("\t")
        if len(parts) == 5:
            print(f"{parts[0]:<20} {parts[1]:<8} {parts[2]:<14} {parts[3][:15]:<15} {parts[4]}")
    return 0


def cmd_put(args: list[str]) -> int:
    """Store a value you choose (a password, a key without a known shape) and get a reference.

    The value comes from the clipboard (--clipboard) or from stdin, never from an
    argument: an argument lands in the shell history and in the transcript.
    """
    type_ = "SECRET"
    source = "stdin"
    for a in args:
        if a in ("-c", "--clipboard"):
            source = "clipboard"
        elif a.startswith("--type="):
            type_ = a.split("=", 1)[1].upper()
    if source == "clipboard":
        from .hooks import _clipboard_read
        value = _clipboard_read()
    else:
        value = sys.stdin.read()
    value = value.strip()
    if not value:
        print("maisecrets put: no value (empty clipboard/stdin)", file=sys.stderr)
        return 2
    e = Vault().put(value, type_, "manual")
    from .hooks import _clipboard
    copied = _clipboard(e.ref)
    print(f"stored as {e.key} ({len(value)} chars); reference {e.ref} "
          f"{'is in the clipboard' if copied else 'printed above'}")
    return 0


def cmd_report(args: list[str]) -> int:
    """`report` lists the last detections; `report last [note]` or `report <n> [note]` prepares a
    false-positive issue for one of them; `report bug <text>` and `report feature <text>` prepare
    one without an event. It prints the text and a prefilled link, opens the link only on a local
    desktop, and with --create files the issue through the GitHub CLI. Nothing in it is a value."""
    from . import events
    create = "--create" in args
    args = [a for a in args if a != "--create"]
    if args and args[0] in ("bug", "feature"):
        return _report_out(events, *events.generic_issue_parts(args[0], " ".join(args[1:])), create=create)
    evs = events.load(20)
    if not evs:
        print("(no detection recorded yet)")
        return 0
    if not args or args[0] not in ("last", *map(str, range(1, len(evs) + 1))):
        print("n   time                 hook              client  hits")
        for i, e in enumerate(evs, 1):
            hits = ", ".join(f"{h['type']}/{h['kind']}" for h in e.get("hits", []))
            print(f"{i:<3} {e.get('ts', ''):<20} {e.get('hook', ''):<17} {e.get('client', ''):<7} {hits}")
        print("\nmaisecrets report last [note] | report <n> [note] | report bug <text> | report feature <text>"
              "  (add --create to file it with the GitHub CLI)")
        return 0
    ev = evs[-1] if args[0] == "last" else evs[int(args[0]) - 1]
    return _report_out(events, *events.issue_parts(ev, " ".join(args[1:])), create=create)


def _report_out(events, title: str, body: str, label: str, create: bool) -> int:
    url, broken = events.tracker_or_error()
    if url is None and not broken:
        print("reporting is turned off here (report_url is null in the policy or the config)")
        return 0
    # the text itself first: over ssh or Remote Control a link is the same copy problem as before
    print(f"Title: {title}\nLabel: {label}\n\n{body}\n")
    if broken:
        print(f"no link and no issue: the configuration cannot be read ({broken}). Copy the text above.")
        return 0
    if create:
        made = events.create_with_gh(title, body, label)
        if made:
            print(f"created: {made}")
            return 0
        why = ("the tracker is not a GitHub repository" if not events.github_repo(events.tracker())
               else "install gh and run `gh auth login`")
        print(f"could not create it with the GitHub CLI ({why}); copy the text above or use the link.",
              file=sys.stderr)
    url = events.link(title, body, label)
    opened = not create and events.open_in_browser(url)
    prefilled = bool(events.github_repo(url))
    print(("opened in the browser: " if opened else "prefilled link: " if prefilled else "tracker: ") + url)
    return 0


def cmd_expire(_: list[str]) -> int:
    v = Vault()
    n = v.expire(limit=None)
    print(f"purged {n} expired value(s)")
    if v.last_refused:
        print(f"{v.last_refused} expired value(s) are still in the store: the store refused the delete. "
              "The next sweep tries again.", file=sys.stderr)
        return 1
    return 0


def cmd_scan(args: list[str]) -> int:
    # bytes, decoded with replacement: the CI scan of the repo pipes every file in, a PNG among
    # them, and a strict decode crashed without output, which read as "nothing found" (2026-09-27)
    text = " ".join(args) if args else sys.stdin.buffer.read().decode("utf-8", errors="replace")
    for m in detect.scan(text):
        print(f"{m.type:<7} {m.kind:<18} at {m.start}-{m.end} (len {len(m.value)})")
    return 0


def cmd_config(_: list[str]) -> int:
    print(json.dumps(load_config(), indent=2))
    return 0


def cmd_status(_: list[str]) -> int:
    """What support needs first: version, where the plugin runs from, which Python, which
    store, which settings come from a policy, and what the logs counted."""
    import platform
    from pathlib import Path as _P
    from .vault import HOME, describe_backend
    root = _P(__file__).resolve().parent.parent
    version = "?"
    try:
        version = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")).get("version", "?")
    except (OSError, ValueError):
        pass
    print(f"maisecrets {version} at {root}")
    cfg_warning = load_config().get("config_warning")
    if cfg_warning:
        print(f"WARNING: {cfg_warning}")
    print(f"python {platform.python_version()} at {sys.executable}; {platform.system()} {platform.release()}")
    v = Vault()
    live = [e for e in v.list() if not e.purged]
    print(describe_backend(v.backend))
    kept = v.cfg.get("keep_purged_days")
    print(f"entries: {len(live)} live, {len(v.list()) - len(live)} expired (metadata kept {kept} days)")
    policy = v.cfg.get("policy_keys") or []
    print("settings from a machine policy: " + (", ".join(policy) if policy else "none"))
    from . import detect
    def version(name: str) -> str:
        return (detect.RULES_DIR / f"{name}_VERSION").read_text(encoding="utf-8").strip()
    print(f"rules: {len(detect.rules())} (gitleaks {version('GITLEAKS')}, presidio {version('PRESIDIO')}, "
          f"detect-secrets {version('DETECT_SECRETS')})")
    active = detect.active_regions()
    print(f"regions: {', '.join(active.regions)} ({active.source}); "
          f"label languages: {', '.join(active.languages)}")
    for name in ("events.log", "audit.log", "hooks.log"):
        p = HOME / name
        try:
            with open(p, "rb") as f:
                n = sum(1 for _ in f)
        except OSError:
            n = 0
        print(f"{name}: {n} lines")
    return 0


def cmd_wipe(args: list[str]) -> int:
    """Delete every stored value, the metadata and the logs of this vault: offboarding."""
    if "--yes" not in args:
        print("maisecrets wipe deletes every stored value, the index, the audit, event and hook logs and the "
              "pending prompts of this user. Run `wipe --yes` to do it.")
        return 2
    from .hooks import _run_dir
    from .vault import wipe_everything
    try:
        run_dir = _run_dir()
    except (OSError, RuntimeError):
        run_dir = None
    n, problems = wipe_everything(load_config(), run_dir)
    print(f"wiped: {n} stored value(s), index, logs. The config file stays.")
    if problems:
        print("NOT complete: " + "; ".join(problems) + ". A value may still be in the store; check it by hand.")
        return 1
    return 0


SHORTCUT_COMMAND = """---
description: Send the last blocked prompt as maisecrets rewrote it (short for /maisecrets:send).
allowed-tools: Bash(bash ~/.maisecrets/bin/ms.sh*)
---

!`bash ~/.maisecrets/bin/ms.sh`

The text above is the prompt the user sent through maisecrets, with placeholders instead of
values. Begin your reply with one line `Sent: ` followed by that text as it is (clients such as
Remote Control show neither the blocked prompt nor a slash command's expansion), then answer it.
"""


def install_shortcut(name: str = "ms", only_if_absent: bool = False) -> "tuple[str, str] | None":
    """Write the personal `/ms` command (`~/.claude/commands/ms.md`) and the stable wrapper
    `~/.maisecrets/bin/ms.sh`, which finds the newest installed plugin copy at run time (the
    plugin folder moves with every version). With ``only_if_absent`` an existing command file
    of that name is left alone (it may be the user's own). Returns (command file, wrapper) or
    None when nothing was written. Field request, 2026-09-26."""
    from pathlib import Path as _P
    from .vault import HOME
    root = _P(__file__).resolve().parent.parent
    commands = _P(os.environ.get("CLAUDE_CONFIG_DIR", _P.home() / ".claude")) / "commands"
    target = commands / f"{name}.md"
    if only_if_absent and target.exists():
        return None
    bin_dir = HOME / "bin"
    bin_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    wrapper = bin_dir / "ms.sh"
    wrapper.write_text((root / "hooks" / "ms.sh").read_text(encoding="utf-8"), encoding="utf-8")
    wrapper.chmod(0o700)
    commands.mkdir(parents=True, exist_ok=True)
    target.write_text(SHORTCUT_COMMAND, encoding="utf-8")
    return str(target), str(wrapper)


def remove_shortcut(name: str = "ms") -> list[str]:
    """Undo install_shortcut: delete the command file (only when it is ours), the wrapper, and
    leave a marker so the next session start does not install it again."""
    from pathlib import Path as _P
    from .vault import HOME
    removed: list[str] = []
    commands = _P(os.environ.get("CLAUDE_CONFIG_DIR", _P.home() / ".claude")) / "commands"
    target = commands / f"{name}.md"
    try:
        if target.exists() and "maisecrets/bin/ms.sh" in target.read_text(encoding="utf-8"):
            target.unlink()
            removed.append(str(target))
    except OSError:
        pass
    wrapper = HOME / "bin" / "ms.sh"
    if wrapper.exists():
        wrapper.unlink()
        removed.append(str(wrapper))
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    (HOME / ".shortcut").write_text("removed\n", encoding="utf-8")
    return removed


def cmd_shortcut(args: list[str]) -> int:
    if "--remove" in args:
        removed = remove_shortcut(next((a for a in args if a != "--remove" and a.isalnum()), "ms"))
        print("removed: " + (", ".join(removed) if removed else "nothing (no maisecrets shortcut found)"))
        print("The session start will not install it again; run `shortcut` to get it back.")
        return 0
    name = (args[0] if args and args[0].isalnum() else "ms")
    target, wrapper = install_shortcut(name)
    from .vault import HOME
    (HOME / ".shortcut").write_text("installed\n", encoding="utf-8")
    print(f"installed /{name}: {target} -> {wrapper}.")
    print("Start a new session (or /reload-plugins) to use it.")
    return 0


def cmd_repair(_: list[str]) -> int:
    """Rebuild a damaged index from the store; every stored value is deleted, the counters
    continue past the highest key seen, so no new value overwrites an old one."""
    from .vault import make_backend
    from .vault import HOME, _lock_for
    v = Vault.__new__(Vault)
    v.cfg = load_config()
    v.backend = make_backend(v.cfg)
    try:
        with _lock_for(HOME / ".lock"):
            info = v.repair()
    except RuntimeError as exc:
        print(f"repair refused: {exc}", file=sys.stderr)
        return 1
    print(f"repaired: {info['deleted']} stored value(s) deleted, counters {info['counters']}")
    return 0


COMMANDS = {"list": cmd_list, "get": cmd_get, "put": cmd_put, "resolve": cmd_resolve, "audit": cmd_audit,
            "report": cmd_report, "expire": cmd_expire, "scan": cmd_scan, "config": cmd_config,
            "status": cmd_status, "wipe": cmd_wipe, "repair": cmd_repair, "shortcut": cmd_shortcut,
            "forget": cmd_forget}


def _stdin_words() -> list[str]:
    """The words of the slash-command arguments on stdin. shlex only splits; a text that it
    cannot split (an apostrophe in a report) falls back to plain whitespace words."""
    import shlex
    text = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in {"-h", "--help"}:
        print("maisecrets status | list | get <KEY> | put [--clipboard] [--type=EMAIL] | audit [n]\n"
              "           | report [last|n|bug|feature] [text] | expire | scan [text] | config\n"
              "           | wipe --yes | repair | shortcut [name] | resolve <KEY> --grant <NONCE> | hook <event>")
        return 0
    if argv[0] == "hook":
        return hook_main(["hook"] + argv[1:])
    if "--args-stdin" in argv[1:]:
        # a slash command passes its arguments in a quoted heredoc: spliced into the bash line,
        # `$(…)` or a pipe in a report text ran as code (feedback on 0.5.2, 2026-09-28)
        argv = [a for a in argv if a != "--args-stdin"] + _stdin_words()
    fn = COMMANDS.get(argv[0])
    if fn is None:
        print(f"unknown command {argv[0]}", file=sys.stderr)
        return 2
    # a damaged index or a wrong policy printed a Python traceback to the person who ran
    # /maisecrets:list; the message of these two errors names the file and the fix, never a value
    try:
        return fn(argv[1:])
    except ConfigError as exc:
        print(f"maisecrets {argv[0]}: configuration error: {exc}. Fix the file named there.", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"maisecrets {argv[0]}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
