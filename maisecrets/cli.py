"""maisecrets command line: list, get, expire, scan, hook."""
from __future__ import annotations

import json
import sys
import time

from . import detect
from .hooks import main as hook_main
from .vault import Vault, load_config


def _age(ts: float) -> str:
    d = time.time() - ts
    if d < 3600:
        return f"{int(d // 60)}m"
    if d < 86400:
        return f"{int(d // 3600)}h"
    return f"{int(d // 86400)}d"


def cmd_list(_: list[str]) -> int:
    v = Vault()
    rows = v.list()
    if not rows:
        print("(vault is empty)")
        return 0
    print(f"{'key':<14} {'type':<7} {'kind':<18} {'age':>5} {'uses':>4} {'expires':>8}  display")
    for e in sorted(rows, key=lambda x: x.created):
        exp = "purged" if e.purged else f"{int(max(0, e.expires - time.time()) // 3600)}h"
        print(f"{e.key:<14} {e.type:<7} {e.kind:<18} {_age(e.created):>5} {e.uses:>4} {exp:>8}  {e.display or ''}")
    if v.backend.test_mode:
        print("\nbackend: jsonfile (TEST MODE, plaintext under ~/.maisecrets/)")
    return 0


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
    """`report` lists the last detections; `report last [note]` or `report <n> [note]` builds a
    prefilled GitHub issue link for one of them; `report bug <text>` and `report feature <text>`
    build one without an event. Every link opens in the browser; nothing in it is a value."""
    from . import events
    if args and args[0] in ("bug", "feature"):
        url = events.generic_issue_url(args[0], " ".join(args[1:]))
        opened = events.open_in_browser(url)
        print(("opened in the browser: " if opened else "open this link: ") + url)
        return 0
    evs = events.load(20)
    if not evs:
        print("(no detection recorded yet)")
        return 0
    if not args or args[0] not in ("last", *map(str, range(1, len(evs) + 1))):
        print("n   time                 hook              client  hits")
        for i, e in enumerate(evs, 1):
            hits = ", ".join(f"{h['type']}/{h['kind']}" for h in e.get("hits", []))
            print(f"{i:<3} {e.get('ts', ''):<20} {e.get('hook', ''):<17} {e.get('client', ''):<7} {hits}")
        print("\nmaisecrets report last [note] | report <n> [note] | report bug <text> | report feature <text>")
        return 0
    ev = evs[-1] if args[0] == "last" else evs[int(args[0]) - 1]
    url = events.issue_url(ev, " ".join(args[1:]))
    opened = events.open_in_browser(url)
    print(("opened in the browser: " if opened else "open this link: ") + url)
    return 0


def cmd_expire(_: list[str]) -> int:
    print(f"purged {Vault().expire(limit=None)} expired value(s)")
    return 0


def cmd_scan(args: list[str]) -> int:
    text = " ".join(args) if args else sys.stdin.read()
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
    print(f"rules: {len(detect.rules())} (gitleaks {open(detect.RULES_DIR / 'GITLEAKS_VERSION').read().strip()}, "
          f"presidio {open(detect.RULES_DIR / 'PRESIDIO_VERSION').read().strip()}, "
          f"detect-secrets {open(detect.RULES_DIR / 'DETECT_SECRETS_VERSION').read().strip()}); "
          f"regions {v.cfg.get('pii_regions')}")
    for name in ("events.log", "audit.log", "hooks.log"):
        p = HOME / name
        try:
            n = sum(1 for _ in open(p, encoding="utf-8")) if p.exists() else 0
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
    print(f"repaired: {info['keys_seen']} stored key(s) deleted, counters {info['counters']}")
    return 0


COMMANDS = {"list": cmd_list, "get": cmd_get, "put": cmd_put, "resolve": cmd_resolve, "audit": cmd_audit,
            "report": cmd_report, "expire": cmd_expire, "scan": cmd_scan, "config": cmd_config,
            "status": cmd_status, "wipe": cmd_wipe, "repair": cmd_repair}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in {"-h", "--help"}:
        print("maisecrets status | list | get <KEY> | put [--clipboard] [--type=EMAIL] | audit [n]\n"
              "           | report [last|n|bug|feature] [text] | expire | scan [text] | config\n"
              "           | wipe --yes | repair | resolve <KEY> --grant <NONCE> | hook <event>")
        return 0
    if argv[0] == "hook":
        return hook_main(["hook"] + argv[1:])
    fn = COMMANDS.get(argv[0])
    if fn is None:
        print(f"unknown command {argv[0]}", file=sys.stderr)
        return 2
    return fn(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
