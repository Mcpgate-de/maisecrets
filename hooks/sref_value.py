#!/usr/bin/env python3
"""The value of one Sensitive Reference, read by a Bash command when it starts: the Bash hook gave the command a
one-time grant instead of the value (maisecrets/sref_hooks.py, grant and redeem). Prints the value to stdout, which
the command substitution puts into a shell variable; on any failure it prints a fixed reason to stderr and exits 1."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from maisecrets import sref_hooks
    from maisecrets.vault_refs import Refused
    try:
        value = sref_hooks.redeem(sys.argv[1] if len(sys.argv) > 1 else "")
    except Refused as exc:
        print(f"maisecrets: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - a fixed text, never a value
        print(f"maisecrets: the reference could not be resolved ({type(exc).__name__})", file=sys.stderr)
        return 1
    sys.stdout.write(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
