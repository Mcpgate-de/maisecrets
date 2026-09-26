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
    value, status = Vault().get(args[0])
    if status != "ok":
        print(f"{args[0]}: {status}", file=sys.stderr)
        return 1
    print(value)
    return 0


def cmd_expire(_: list[str]) -> int:
    print(f"purged {Vault().expire()} expired value(s)")
    return 0


def cmd_scan(args: list[str]) -> int:
    text = " ".join(args) if args else sys.stdin.read()
    for m in detect.scan(text):
        print(f"{m.type:<7} {m.kind:<18} at {m.start}-{m.end} (len {len(m.value)})")
    return 0


def cmd_config(_: list[str]) -> int:
    print(json.dumps(load_config(), indent=2))
    return 0


COMMANDS = {"list": cmd_list, "get": cmd_get, "expire": cmd_expire, "scan": cmd_scan, "config": cmd_config}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in {"-h", "--help"}:
        print("maisecrets list | get <KEY> | expire | scan [text] | config | hook <event>")
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
