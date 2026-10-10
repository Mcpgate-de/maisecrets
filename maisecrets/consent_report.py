"""`maisecrets consent-report ssh`: what the ssh consent check (C21) would ask for the Bash commands of earlier
Claude Code sessions on this computer, so that a person can check the check on their own work before or after
turning it on (#15: the rules were tuned on one person's sessions).

It reads the local transcripts, classifies each Bash command that names an ssh-family word with the check of this
version, and prints counts per verdict and per reason. A reason names no host, no command and no value. It runs
nothing, changes no setting or consent, and sends nothing. With --excerpts FILE it writes a short window around
each question into a new file of the person's own, for a look by hand: the values the detectors find are masked,
hosts and commands stay in it, and the person decides what to share.
"""
from __future__ import annotations

import collections
import json
import os
import re
import time
from pathlib import Path

from . import detect, hooks, ssh_consent

USAGE = "maisecrets consent-report ssh [--last 30d | --last N] [--json] [--excerpts FILE]"


def _parse(text: str):
    ctxs = hooks._shell_contexts(text)
    return hooks._segments(text, ctxs), ctxs


def _sessions(base: Path, last: str) -> list[Path]:
    """The transcripts of the last N days (30d) or the N newest ones (200), oldest first."""
    found = []
    for p in base.glob("*/*.jsonl"):
        try:
            found.append((p.stat().st_mtime, p))
        except OSError:
            continue                         # a dangling link or a file that went away
    found.sort()
    if last.endswith("d"):
        cutoff = time.time() - int(last[:-1]) * 86400
        return [p for t, p in found if t >= cutoff]
    return [p for _t, p in found[-int(last):]]


def _commands(path: Path) -> list[str]:
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"Bash"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                msg = rec.get("message") if isinstance(rec, dict) else None
                content = msg.get("content") if isinstance(msg, dict) else None
                for block in content if isinstance(content, list) else []:
                    if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Bash":
                        tool_input = block.get("input")
                        cmd = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
                        if isinstance(cmd, str) and ssh_consent._TOKEN_RE.search(cmd):
                            out.append(cmd)
    except OSError:
        pass
    return out


_VOCABULARY: set = set()
# the slot of a reason that names the program the check saw: `argument of X`, `started by X`, `URL for X`, …
_PROGRAM_SLOT = re.compile(r"(argument of|started by|URL for|piped into|pipes text into|code that) ([^\s,]+)|"
                           r"(in a) ([^\s,]+)(?= command that runs)")


def _known_programs() -> set:
    return (ssh_consent._LAUNCHERS | ssh_consent._SHELLS | ssh_consent._URL_CLIENTS | ssh_consent._CONTAINER_EXEC
            | ssh_consent._RUN_TEXT | {"gh", "glab", "git", "find", "xargs", "parallel", "crontab", "at", "batch"})


def _reason(why: str) -> str:
    """The reason with no host, command or value of the person's: the program slot keeps a name only from a closed
    list of program names (./acme-billing-prod, root@web1:~# are the person's); a quoted part goes; and, as a second
    layer, a word that holds a host character (@ : ~ / #) or that the check's own source does not hold goes too
    (codex and Opus, review of #15)."""
    if not _VOCABULARY:
        _VOCABULARY.update(w.lower() for w in re.findall(r"[A-Za-z][\w.-]*", Path(ssh_consent.__file__).read_text(
            encoding="utf-8")))
    known = _known_programs()
    def slot(m: re.Match) -> str:
        verb, name = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        return f"{verb} {name if name.lower() in known else '…'}"
    text = _PROGRAM_SLOT.sub(slot, why or "")
    text = re.sub(r"'[^']*'|\"[^\"]*\"", "'…'", text)
    def word(w: re.Match) -> str:
        x = w.group(0)
        kept = x in ("~/.ssh", "~/.ssh,") or x.isdigit() or re.fullmatch(r"[A-Za-z][A-Za-z-]*\.?", x) \
            and x.rstrip(".").lower() in _VOCABULARY
        return x if kept else "…"
    return re.sub(r"[^\s,'…]+", word, text)


def _excerpt(cmd: str, why: str) -> str:
    """A short window around the word the verdict names, with every value the detectors find masked."""
    word = re.search(r"'([^']*)'", why or "")
    m = re.search(re.escape(word.group(1)), cmd) if word else ssh_consent._TOKEN_RE.search(cmd)
    lo, hi = (max(0, m.start() - 60), min(len(cmd), m.end() + 60)) if m else (0, 120)
    text = cmd[lo:hi]
    for hit in sorted(detect.scan(text), key=lambda h: -len(h.value)):
        text = text.replace(hit.value, "<value>")
    return text.replace("\n", "\\n")


def _write_new(path: str, lines: list[str]) -> None:
    """A new file for the person only: no symlink followed, no file of another name replaced."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(line + "\n" for line in lines)


def run(args: list[str]) -> int:
    if not args or args[0] != "ssh":
        print(USAGE)
        return 2
    args = args[1:]
    last, as_json, excerpts = "30d", False, ""
    while args:
        a = args.pop(0)
        if a == "--json":
            as_json = True
        elif a == "--last" and args and re.fullmatch(r"[1-9]\d*d?", args[0]):
            last = args.pop(0)
        elif a == "--excerpts" and args:
            excerpts = args.pop(0)
        else:
            print(USAGE)
            return 2
    base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
    kinds: collections.Counter = collections.Counter()
    reasons: collections.Counter = collections.Counter()
    sessions = commands = write_hosts = 0
    windows: list[str] = []
    for path in _sessions(base, last) if base.is_dir() else []:
        cmds = _commands(path)
        if not cmds:
            continue
        sessions += 1
        seen: set[str] = set()
        for cmd in cmds:
            commands += 1
            v = ssh_consent.classify(cmd, _parse)
            kinds[v.kind] += 1
            if v.kind == "write":
                new = set(v.hosts) - seen
                write_hosts += len(new)      # without a consent, a write asks once per host and session
                seen |= set(v.hosts)
            elif v.kind in ("unknown", "deny"):
                reasons[(v.kind, _reason(v.why))] += 1
                if excerpts:
                    windows.append(json.dumps({"kind": v.kind, "why": _reason(v.why), "excerpt": _excerpt(cmd, v.why)},
                                              ensure_ascii=False))
    if excerpts:
        try:
            _write_new(excerpts, windows)
        except OSError as exc:
            print(f"maisecrets consent-report: cannot write {excerpts}: {exc.strerror}. Name a new file.")
            return 1
    result = {"sessions": sessions, "commands": commands, "kinds": dict(kinds), "write_hosts": write_hosts,
              "questions": [{"kind": k, "why": w, "n": n} for (k, w), n in reasons.most_common()], "last": last}
    if as_json:
        print(json.dumps(result, ensure_ascii=False))
        return 0
    print(f"ssh consent report, sessions of the last {last if last.endswith('d') else last + ' sessions'} "
          f"(Claude Code, {base}):")
    print(f"  {sessions} sessions, {commands} Bash commands that name an ssh-family word")
    print(f"  none {kinds['none']}, read {kinds['read']} (no question), write {kinds['write']} "
          f"({write_hosts} questions without a consent: one per host and session), "
          f"unknown {kinds['unknown']} (a question each), refused {kinds['deny']}")
    if reasons:
        print("  questions and refusals per reason:")
        for (k, w), n in reasons.most_common():
            print(f"    {n:5}  {k:7}  {w}")
    if excerpts:
        print(f"  {len(windows)} masked windows in {excerpts}, for a look by hand; share only what you may share.")
    print("  Nothing ran and nothing was sent; Codex sessions are not read.")
    return 0
