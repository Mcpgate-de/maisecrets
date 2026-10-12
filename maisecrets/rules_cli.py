"""`maisecrets rules`: show, check, test, start and import the rules of your own (maisecrets/user_rules.py).

Every line names a folder, a file, a rule id, a reason, a count or a time. None prints a regex match, a sample text
or a value: the output goes to the model when the agent runs the command.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

from . import detect, user_rules

USAGE = ("maisecrets rules                       the folders, their rules and what was left out\n"
         "maisecrets rules check [DIR]           check a folder (or every active one) and its samples.txt\n"
         "maisecrets rules test [text]           what the rules find in the text (or stdin); never the value\n"
         "maisecrets rules init DIR              start a rule folder for a team\n"
         "maisecrets rules import FILE.toml      a gitleaks or betterleaks config in the JSON form (Python 3.11+)")

# the text a rule runs over in `rules check`: prose, numbers, paths and a long run of one letter, which a regex that
# backtracks pays for. The rule's own keywords are added, so its regex really runs
_PROBE = ("The build 20261012 ran in 3.2 s on host build-07; path=/usr/lib/python3/site.py mode=0644 key=value "
          + "abcdefghij0123456789" * 3 + " " + "a" * 200 + "\n") * 60


def _q(q: "user_rules.Quarantined") -> str:
    where = f"{q.folder}/{q.file}" if q.file else q.folder
    return f"{where} · {q.rule or '(whole file)' if q.file else '(folder)'} · {q.reason}"


def show() -> int:
    loaded = user_rules.load()
    values, ids = detect.allow_list()
    print("maisecrets rules of your own\n")
    for f in loaded.folders:
        extra = (f" · {f.rules} rule(s) · hash {f.digest}" + (f" · commit {f.commit}" if f.commit else "")
                 if f.state == "ok" else f" · {f.state}")
        print(f"  {f.shown} ({f.source}){extra}")
    print(f"\nRules of your own loaded: {len(loaded.rules)}; all rules: {len(detect.rules())}")
    if loaded.quarantined:
        print(f"\nLeft out ({len(loaded.quarantined)}), each with the check it failed:")
        for q in loaded.quarantined:
            print(f"  {_q(q)}")
    print(f"\nAllow list: {len(values)} exact value(s), {len(ids)} rule id(s) switched off"
          + (f" ({', '.join(sorted(ids))})" if ids else ""))
    print("\nAdd a folder: /maisecrets:settings rule_dirs add DIR (type it as your own prompt)\n"
          "Check a folder: maisecrets rules check DIR")
    return 0


def _rule_folder(target: Path) -> tuple[Path, Path | None]:
    """The rule folder and the samples file of a check target: a team repository keeps its rules in `rules/` and
    samples.txt at its top; a plain folder holds both."""
    folder = target / "rules" if (target / "rules").is_dir() else target
    for cand in (target / "samples.txt", folder / "samples.txt"):
        if cand.is_file():
            return folder, cand
    return folder, None


def _samples(path: Path, rules: list) -> list[str]:
    """The failures of samples.txt: `hit <rule-id> <text>` must be found by that rule, `miss <text>` by no rule of
    the folder. A failure names the line, never its text."""
    failed = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        verb, _, rest = line.strip().partition(" ")
        if verb == "hit":
            rid, _, text = rest.strip().partition(" ")
            kind = rid if rid.startswith(user_rules.ID_PREFIX) else user_rules.ID_PREFIX + rid
            kinds = {m.kind for m in detect.scan(text, rule_list=rules)}
            if kind not in kinds:
                failed.append(f"samples.txt line {n}: no hit of {rid}"
                              + (f" (found: {', '.join(sorted(kinds))})" if kinds else ""))
        elif verb == "miss":
            kinds = {m.kind for m in detect.scan(rest, rule_list=rules)}
            if kinds:
                failed.append(f"samples.txt line {n}: a hit of {', '.join(sorted(kinds))} where none belongs")
        else:
            failed.append(f"samples.txt line {n}: neither `hit <rule-id> <text>` nor `miss <text>`")
    return failed


def check(args: list[str]) -> int:
    if args:
        target = Path(args[0]).expanduser()
        if not target.is_dir():
            print(f"maisecrets rules check: {args[0]} is no folder", file=sys.stderr)
            return 2
        folder, samples = _rule_folder(target)
        todo = [(str(folder), folder, samples)]
    else:
        todo = [(f.shown, f.path, None) for f in user_rules.load().folders if f.state == "ok"]
    bad = 0
    for shown, folder, samples in todo:
        rules, quarantined, digest = user_rules.load_folder(folder, shown)
        print(f"{shown}: {len(rules)} rule(s), {len(quarantined)} refused, hash {digest}")
        for rule in rules:
            t = time.perf_counter()
            detect.scan(_PROBE + " ".join(rule.keywords), rule_list=[rule])
            print(f"  ok      {rule.id[len(user_rules.ID_PREFIX):]}  {(time.perf_counter() - t) * 1000:.1f} ms")
        for q in quarantined:
            print(f"  refused {q.file}:{q.rule or '(whole file)'}  {q.reason}" if q.file else f"  refused {q.reason}")
        bad += len(quarantined)
        if samples is not None:
            failed = _samples(samples, rules)
            print(f"  samples: {'all pass' if not failed else f'{len(failed)} failed'}")
            for line in failed:
                print(f"  {line}")
            bad += len(failed)
    return 1 if bad else 0


_README = """# Detection rules for maisecrets

maisecrets reads the rules in `rules/` in addition to its own. To use them, clone this repository and type this as
your own prompt in Claude Code:

    /maisecrets:settings rule_dirs add {path}

In Codex, send this alone as your prompt: `maisecrets: set rule_dirs add {path}`

`/maisecrets:rules` then shows the folder and how many rules it loaded.

- `rules/*.json`: rules in the gitleaks form (`id`, `regex`, `keywords`, `entropy`, `secretGroup`, `allowlists`).
- `rules/*.prefixes`: one rule per line, `id  regex`; the whole match is the secret.
- `samples.txt`: `hit <rule-id> <text>` must be found by that rule, `miss <text>` by none.

Check a change before you commit it: `maisecrets rules check .` (the CI files here run the same).

A rule needs a keyword or a literal of 4 characters, at most 300 characters of regex, no repeat inside a repeat and
no quantifier at the start; a folder holds at most 500 rules, a file at most 64 KB. A rule that fails a check is left
out, not the folder.

No names, no customer data and no real values in here. A rule describes a shape; the samples use made-up values.
"""

_GITHUB = """name: rules
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: git clone --depth 1 --branch release https://github.com/Mcpgate-de/maisecrets.git "$RUNNER_TEMP/ms"
      - run: python3 -m maisecrets.cli rules check .
        env:
          PYTHONPATH: ${{ runner.temp }}/ms
          MAISECRETS_HOME: ${{ runner.temp }}/ms-home
"""

_GITLAB = """rules:
  image: python:3.12
  script:
    - git clone --depth 1 --branch release https://github.com/Mcpgate-de/maisecrets.git /tmp/ms
    - PYTHONPATH=/tmp/ms MAISECRETS_HOME=/tmp/ms-home python3 -m maisecrets.cli rules check .
"""


def init(args: list[str]) -> int:
    if len(args) != 1:
        print("maisecrets rules init: give one folder", file=sys.stderr)
        return 2
    top = Path(args[0]).expanduser()
    files = {
        "README.md": _README.format(path=f"~/src/{top.resolve().name}/rules"),
        "rules/example.json": json.dumps({"rules": [{
            "id": "example-internal-token", "description": "An example: a token of an internal service.",
            "regex": r"exmpl_[A-Za-z0-9]{24}", "keywords": ["exmpl_"], "entropy": 3.0}]}, indent=2) + "\n",
        "rules/example.prefixes": "# id                regex (the whole match is the secret)\n"
                                  "example-build-key   exbk-[0-9a-f]{32}\n",
        # made-up values, built here so that no value is written in this source file
        "samples.txt": ("hit example-internal-token token exmpl_" + "abcdefghijklmnopqrstuvwx" + "\n"
                        "miss exmpl_short\n"
                        "hit example-build-key exbk-" + "0123456789abcdef" * 2 + "\n"),
        ".github/workflows/rules.yml": _GITHUB,
        ".gitlab-ci.yml": _GITLAB,
    }
    there = [name for name in files if (top / name).exists()]
    if there:
        print(f"maisecrets rules init: {', '.join(there)} exist(s) in {top}; nothing was written", file=sys.stderr)
        return 1
    for name, text in files.items():
        path = top / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


# betterleaks writes a pure entropy floor as an Expr filter; that one form is read, every other filter is refused
_ENTROPY_FILTER_RE = re.compile(r'\s*entropy\(\s*finding\["secret"\]\s*\)\s*(?:<|<=)\s*([0-9]+(?:\.[0-9]+)?)\s*')


def convert(cfg: dict) -> tuple[list, list[str]]:
    """The rules of a gitleaks or betterleaks config in the JSON form, and one note per rule or part left out."""
    rules, notes = [], []
    if cfg.get("allowlist") or cfg.get("allowlists"):
        notes.append("the global allowlist is not taken over (a rule folder loosens only its own rules)")
    for r in cfg.get("rules") or []:
        rid = r.get("id", "?")
        if "regex" not in r:
            notes.append(f"refused {rid}: a rule by file path only")
            continue
        out = {"id": rid, "regex": r["regex"]}
        for key in ("description", "keywords", "entropy", "secretGroup"):
            if key in r:
                out[key] = r[key]
        if r.get("filter"):
            m = _ENTROPY_FILTER_RE.fullmatch(r["filter"])
            if not m:
                notes.append(f"refused {rid}: a filter maisecrets cannot read")
                continue
            out["entropy"] = float(m.group(1))
        lists = r.get("allowlists") or ([r["allowlist"]] if isinstance(r.get("allowlist"), dict) else [])
        kept = []
        for al in lists:
            parts = [k for k in ("regexes", "stopwords") if al.get(k)]
            if al.get("condition", "OR").upper() == "AND" and len(parts) + bool(al.get("paths")) > 1:
                notes.append(f"note {rid}: an allowlist with condition AND was dropped (stricter)")
                continue
            if not parts:
                if al.get("paths"):
                    notes.append(f"note {rid}: an allowlist by file path was dropped (stricter)")
                continue
            kept.append({k: al[k] for k in ("regexes", "regexTarget", "stopwords") if al.get(k)})
        if kept:
            out["allowlists"] = kept
        rules.append(out)
    return rules, notes


def import_toml(args: list[str]) -> int:
    if len(args) != 1:
        print("maisecrets rules import: give one .toml file", file=sys.stderr)
        return 2
    try:
        import tomllib
    except ImportError:
        print("maisecrets rules import: needs Python 3.11 or later (tomllib)", file=sys.stderr)
        return 2
    try:
        cfg = tomllib.loads(Path(args[0]).expanduser().read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"maisecrets rules import: {args[0]} cannot be read ({type(exc).__name__})", file=sys.stderr)
        return 2
    rules, notes = convert(cfg)
    loadable = []
    for r in rules:
        why, _, _ = user_rules.check_regex(r["regex"], tuple(r.get("keywords") or ()))
        if why:
            notes.append(f"refused {r['id']}: {why}")
        else:
            loadable.append(r)
    print(json.dumps({"rules": loadable}, indent=2))
    for note in notes:
        print(note, file=sys.stderr)
    print(f"{len(loadable)} rule(s) converted, {sum(n.startswith('refused') for n in notes)} refused",
          file=sys.stderr)
    return 1 if any(n.startswith("refused") for n in notes) else 0


def main(args: list[str], scan) -> int:
    if not args:
        return show()
    sub, rest = args[0], args[1:]
    if sub == "check":
        return check(rest)
    if sub == "test":
        return scan(rest)
    if sub == "init":
        return init(rest)
    if sub == "import":
        return import_toml(rest)
    print(USAGE, file=sys.stderr)
    return 2
