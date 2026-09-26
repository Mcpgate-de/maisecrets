#!/usr/bin/env python3
"""Refresh the vendored detect-secrets keyword and basic-auth regexes to a pinned tag.

Usage: scripts/sync_detect_secrets.py v1.5.0
Fetches keyword.py and basic_auth.py from Yelp/detect-secrets at that tag,
executes them with stubbed imports to harvest the compiled regexes and their
secret group numbers, and writes maisecrets/rules/detect_secrets.json,
LICENSE-detect-secrets and DETECT_SECRETS_VERSION. Only the "config" and
"quotes required" regex sets are kept; the other sets are file-type specific.
"""
import enum
import json
import re
import sys
import urllib.request
from pathlib import Path

tag = sys.argv[1] if len(sys.argv) > 1 else None
if not tag or not tag.startswith("v"):
    print("usage: sync_detect_secrets.py vX.Y.Z")
    sys.exit(2)
base = f"https://raw.githubusercontent.com/Yelp/detect-secrets/{tag}/"


def fetch(path: str) -> str:
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return r.read().decode()


src = fetch("detect_secrets/plugins/keyword.py")
src = re.sub(r"^from .*$", "", src, flags=re.M).replace("class KeywordDetector(BasePlugin):", "class KeywordDetector:")


class FileType(enum.Enum):
    GO = 1; OBJECTIVE_C = 2; C_SHARP = 3; C = 4; C_PLUS_PLUS = 5; CLS = 6; JAVA = 7; JAVASCRIPT = 8  # noqa: E702
    PYTHON = 9; SWIFT = 10; TERRAFORM = 11; YAML = 12; CONFIG = 13; INI = 14; PROPERTIES = 15; TOML = 16; PHP = 17  # noqa: E702


ns = {"re": re, "FileType": FileType, "Optional": object, "Dict": dict, "Pattern": object, "Generator": object}
try:
    exec(src, ns)  # noqa: S102 - vendored upstream source, executed to harvest constants
except Exception:  # noqa: BLE001 - the class body may reference stubs; the constants are defined by then
    pass
names = {v: k for k, v in ns.items() if isinstance(v, re.Pattern)}
rules, seen = [], set()
for setname in ("CONFIG_DENYLIST_REGEX_TO_GROUP", "QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP"):
    for rx, group in ns[setname].items():
        rid = "ds-keyword-" + names[rx].replace("_REGEX", "").replace("FOLLOWED_BY_", "").replace("_", "-").lower()
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({"id": rid, "regex": rx.pattern, "ignorecase": bool(rx.flags & re.IGNORECASE),
                      "group": group, "set": setname.split("_DENYLIST")[0].lower()})
reserved, sub = ":/?#[]@", "!$&'()*+,;="
rules.append({"id": "ds-basic-auth", "regex": r"://[^{}\s]+:([^{}\s]+)@".format(re.escape(reserved + sub), re.escape(reserved + sub)),
              "ignorecase": False, "group": 1, "set": "basic_auth"})
dst = Path(__file__).resolve().parent.parent / "maisecrets" / "rules"
json.dump({"detect_secrets_version": tag, "denylist": list(ns["DENYLIST"]), "rules": rules},
          open(dst / "detect_secrets.json", "w"), indent=1)
(dst / "DETECT_SECRETS_VERSION").write_text(tag + "\n")
(dst / "LICENSE-detect-secrets").write_text(fetch("LICENSE"))
print(f"vendored {len(rules)} detect-secrets rules, {tag}")
