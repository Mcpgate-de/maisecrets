#!/usr/bin/env python3
"""Refresh the vendored Presidio pattern recognizers (regexes, scores, context words).

Usage: scripts/sync_presidio.py 2.2.364

Presidio ships its recognizers as Python classes. This script reads them from the source of the
presidio-analyzer wheel as data (scripts/_static_python.py) and executes none of it: the wheel is
downloaded from PyPI, checked against the sha256 PyPI lists, and opened as a zip. The plugin reads
the resulting maisecrets/rules/presidio.json as data.

Checksum validators are NOT exported (they are code); maisecrets/detect.py
ports the ones it needs (generic + DE) and marks the rest as "context only".
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _static_python import bind  # noqa: E402

PACKAGE = "presidio_analyzer/predefined_recognizers"
BASE = "PatternRecognizer"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def wheel(ver: str) -> zipfile.ZipFile:
    meta = json.loads(fetch(f"https://pypi.org/pypi/presidio-analyzer/{ver}/json"))
    files = [u for u in meta["urls"] if u["packagetype"] == "bdist_wheel" and u["filename"].endswith("-none-any.whl")]
    if len(files) != 1:
        sys.exit(f"expected one pure-Python wheel for {ver}, found {len(files)}")
    data = fetch(files[0]["url"])
    if hashlib.sha256(data).hexdigest() != files[0]["digests"]["sha256"]:
        sys.exit("the wheel does not match the sha256 PyPI lists")
    return zipfile.ZipFile(io.BytesIO(data))


def walk(names: set[str], pkg: str) -> list[str]:
    """The module order of pkgutil.walk_packages: a sorted directory listing, a package before its
    modules (the order the vendored JSON had when the recognizers were imported)."""
    prefix = pkg + "/"
    entries = sorted({n[len(prefix):].split("/")[0] for n in names if n.startswith(prefix)})
    order = []
    for fn in entries:
        if fn.endswith(".py") and fn != "__init__.py" and "." not in fn[:-3]:
            order.append(prefix + fn)
        elif "." not in fn and prefix + fn + "/__init__.py" in names:
            order.append(prefix + fn + "/__init__.py")
            order += walk(names, prefix + fn)
    return order


def init_default(cls: ast.ClassDef, arg: str):
    for f in cls.body:
        if isinstance(f, ast.FunctionDef) and f.name == "__init__":
            a = f.args
            pos = a.posonlyargs + a.args
            for p, d in zip(pos[len(pos) - len(a.defaults):], a.defaults):
                if p.arg == arg and isinstance(d, ast.Constant):
                    return d.value
            for p, d in zip(a.kwonlyargs, a.kw_defaults):
                if p.arg == arg and isinstance(d, ast.Constant):
                    return d.value
    return None


def main(argv: list[str]) -> int:
    ver = argv[0] if argv else ""
    if not re.fullmatch(r"\d+\.\d+\.\d+", ver):
        print("usage: sync_presidio.py X.Y.Z")
        return 2
    z = wheel(ver)
    names = set(z.namelist())
    classes: dict[str, tuple[ast.ClassDef, dict]] = {}
    per_module: list[tuple[str, list[str]]] = []
    for mod in walk(names, PACKAGE):
        tree = ast.parse(z.read(mod))
        env: dict = {}
        bind(tree.body, env)
        here = []
        for c in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            body_env = dict(env)
            bind(c.body, body_env, {"Pattern": lambda name, regex, score: {"name": name, "score": score,
                                                                             "regex": regex}})
            classes[c.name] = (c, body_env)
            here.append(c.name)
        per_module.append((mod, sorted(here)))       # inspect.getmembers sorts by name

    def chain(name: str) -> list[str]:
        out, seen = [], set()
        while name in classes and name not in seen:
            seen.add(name)
            out.append(name)
            bases = [b.id for b in classes[name][0].bases if isinstance(b, ast.Name)]
            name = bases[0] if bases else ""
        return out + ([BASE] if name == BASE else [])

    def attr(c: list[str], key: str):
        for n in c[:-1]:                              # the nearest class that assigns it in its own body
            node, body_env = classes[n]
            own = {t.id for s in node.body if isinstance(s, ast.Assign) for t in s.targets if isinstance(t, ast.Name)}
            own |= {s.target.id for s in node.body if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)}
            if key in own:
                return body_env.get(key)
        return None

    out = []
    for _, here in per_module:
        for name in here:
            c = chain(name)
            if not c or c[-1] != BASE or name == BASE:
                continue
            nodes = [classes[n][0] for n in c[:-1]]
            entity = next((v for v in (init_default(n, "supported_entity") for n in nodes) if v is not None), None)
            language = next((v for v in (init_default(n, "supported_language") for n in nodes) if v is not None),
                            "en")
            patterns = attr(c, "PATTERNS")
            if entity is None or not patterns:
                print(f"skipped {name}: no entity or patterns as data", file=sys.stderr)
                continue
            rid = re.sub(r"(?<!^)(?=[A-Z])", "-", name.replace("Recognizer", "")).lower()
            out.append({
                "id": rid, "class": name, "entity": entity, "language": language,
                "patterns": patterns,
                "context": list(attr(c, "CONTEXT") or []),
                "validator": any(isinstance(f, ast.FunctionDef) and f.name == "validate_result"
                                 for n in nodes for f in n.body),
            })
    dst = Path(__file__).resolve().parent.parent / "maisecrets" / "rules"
    json.dump({"presidio_version": ver, "recognizers": out}, open(dst / "presidio.json", "w"), indent=1)
    (dst / "PRESIDIO_VERSION").write_text(ver + "\n")
    (dst / "LICENSE-presidio").write_bytes(fetch("https://raw.githubusercontent.com/microsoft/presidio/main/LICENSE"))
    print(f"vendored {len(out)} presidio pattern recognizers, version {ver}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
