#!/usr/bin/env python3
"""Refresh the vendored Presidio pattern recognizers (regexes, scores, context words).

Presidio ships its recognizers as Python classes, so this script needs a Python
that has presidio-analyzer installed. It does NOT run inside the plugin; the
plugin reads the resulting maisecrets/rules/presidio.json as data.

Usage:
  python3 -m venv /tmp/presidio-venv && /tmp/presidio-venv/bin/pip install presidio-analyzer==2.2.364
  /tmp/presidio-venv/bin/python scripts/sync_presidio.py

Checksum validators are NOT exported (they are code); maisecrets/detect.py
ports the ones it needs (generic + DE) and marks the rest as "context only".
"""
import importlib
import inspect
import json
import pkgutil
import re
import sys
import urllib.request
from importlib.metadata import version
from pathlib import Path

from presidio_analyzer import PatternRecognizer
import presidio_analyzer.predefined_recognizers as pr

dst = Path(__file__).resolve().parent.parent / "maisecrets" / "rules"
out = []
for mod in pkgutil.walk_packages(pr.__path__, pr.__name__ + "."):
    try:
        m = importlib.import_module(mod.name)
    except Exception:
        continue
    for name, cls in inspect.getmembers(m, inspect.isclass):
        if issubclass(cls, PatternRecognizer) and cls is not PatternRecognizer and cls.__module__ == m.__name__:
            inst = cls()
            rid = re.sub(r"(?<!^)(?=[A-Z])", "-", name.replace("Recognizer", "")).lower()
            out.append({
                "id": rid, "class": name, "entity": inst.supported_entities[0],
                "language": inst.supported_language,
                "patterns": [{"name": p.name, "score": p.score, "regex": p.regex} for p in inst.patterns],
                "context": list(inst.context or []),
                "validator": type(inst).validate_result is not PatternRecognizer.validate_result,
            })
ver = version("presidio-analyzer")
json.dump({"presidio_version": ver, "recognizers": out}, open(dst / "presidio.json", "w"), indent=1)
(dst / "PRESIDIO_VERSION").write_text(ver + "\n")
with urllib.request.urlopen("https://raw.githubusercontent.com/microsoft/presidio/main/LICENSE", timeout=30) as r:
    (dst / "LICENSE-presidio").write_bytes(r.read())
print(f"vendored {len(out)} presidio pattern recognizers, version {ver}")
sys.exit(0)
