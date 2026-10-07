"""Which ssh-family calls a shell command makes, and of what kind (opt-in: config `ssh_consent: true`).

An agent with the user's SSH keys can run any command on any host it reaches. Claude Code's own
`permissions.ask: ["Bash(ssh:*)"]` matches only the start of a command, so `cd x && ssh …`, `bash -c
"ssh …"` and `timeout 30 ssh …` pass it (Mcpgate-de/maisecrets#8). This module decides, for one
command line, whether it starts ssh and what the remote side does:

- ``none``: no ssh-family call.
- ``read``: every call runs a remote command from a small allowlist of named commands with named
  options and literal absolute paths. It runs without a question.
- ``write``: any other remote command, a login shell, a copy (scp, sftp, rsync), local data on
  stdin. It needs the person's consent for its host.
- ``unknown``: the command names ssh where this module cannot read the call (a wrapper it does not
  know, a command word built at run time, a nested shell, an option that changes the target). It is
  treated like a write that no approval covers.
- ``deny``: a short list of destructive remote commands. Always refused; an airbag, not the model:
  destructive shell has unlimited spellings.

The module imports nothing of maisecrets: the caller passes its shell parser, so the ssh part can
leave as its own plugin later (issue #8). A hook sees only the command text: a script file, an alias
or a variable that holds "ssh" and is set elsewhere is not seen (docs/THREAT-MODEL.md C21).
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Callable

# the parser of the caller: (command) -> (segments, contexts), as maisecrets.hooks._segments reads them
Parser = Callable[[str], "tuple[list[dict], list[str]]"]

SSH_CMDS = {"ssh", "autossh", "mosh", "scp", "sftp", "sshfs", "ssh-copy-id", "rsync"}

# a mention of ssh that this module must have read as a call, or the command is not understood.
# `.ssh/` paths are not a call (the lookbehind skips `~/.ssh`), except the config that retargets a host.
_TOKEN_RE = re.compile(
    r"(?<![\w./])(?:ssh|autossh|mosh|scp|sftp|sshfs|ssh-copy-id|sshpass|pssh|parallel-ssh|pscp|"
    r"pssh\.\w+|tsh|kitten|rsync)(?![\w-])"
    r"|ssh://|rsync://|GIT_SSH|sshCommand|RSYNC_RSH|DOCKER_HOST|\.ssh/config\b")

# ssh options that take an argument (ssh(1)); the first word that is no option is the host
_SSH_ARG_OPTS = set("BbcDEeFIiJLlmOoPpQRSWw")
# options that send the connection elsewhere than the host on the command line, or run a local command
_RETARGET_FLAGS = set("JWSOFM")
_RETARGET_O = re.compile(r"^(?:proxyjump|proxycommand|hostname|remotecommand|controlpath|controlmaster|"
                         r"localcommand|permitlocalcommand|match|include|knownhostscommand|"
                         r"canonicalizehostname|canonicaldomains)\b", re.I)
# commands whose quoted arguments are data, never run: a mention of ssh there is no call (`grep "ssh" log`)
_DATA_CMDS = {"grep", "egrep", "fgrep", "rg", "ag", "echo", "printf", "cut", "tr", "wc", "sort", "uniq", "head",
              "tail", "diff", "test", "[", "pgrep", "pkill"}
# a heredoc to these is text, not a script: a commit message or a file that mentions ssh
_HEREDOC_DATA = {"cat", "tee", "git", "gh", "glab", "grep", "echo", "printf", "wc", "head", "tail", "jq", "less"}
# stderr or all output to /dev/null, or stderr to stdout: no file is written
_HARMLESS_REDIRECT = re.compile(r"\s*(?:[12]?>\s*/dev/null|2>&1|&>\s*/dev/null)(?=\s|$|;|\|)")
# the timeout a macOS agent builds without timeout(1): perl -e 'alarm N; exec @ARGV' CMD ARGS
_PERL_ALARM = re.compile(r"^alarm\s+\d+\s*;\s*exec\s+@ARGV\s*;?$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# destructive remote commands, refused even with consent; each spelled loosely on purpose
_DENY = [
    ("mkfs", re.compile(r"(?<![\w-])mkfs(?:\.\w+)?(?![\w-])")),
    ("wipefs", re.compile(r"(?<![\w-])wipefs(?![\w-])")),
    ("dd to a device", re.compile(r"(?<![\w-])dd\b[^\n;|&]*\bof=/dev/")),
    ("rm -rf /", re.compile(r"(?<![\w-])rm\s+(?:-{1,2}[\w-]+\s+)*(?:/|/\*|--no-preserve-root)(?:\s|$|;)")),
    ("a fork bomb", re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
]

# read: commands that print metadata about the host, never the content of a file, a log or a process command
# line (those can carry a credential; Codex review of #8, 2026-10-06). The real ops commands of the corpus use
# sudo or docker almost always, so this list carries few calls and the consent per host carries the rest.
# Each command: its allowed options, and how its other words are checked ("none", "paths", "systemctl").
_READ: dict[str, tuple[set[str], str]] = {
    "uptime": (set(), "none"),
    "whoami": (set(), "none"),
    "id": (set(), "none"),
    "nproc": (set(), "none"),
    "hostname": ({"-f", "-s", "-I", "-i"}, "none"),
    "uname": ({"-a", "-r", "-s", "-n", "-m", "-v", "-o"}, "none"),
    "df": ({"-h", "-H", "-T", "-i", "-l", "-k", "-P"}, "paths"),
    "free": ({"-h", "-m", "-g", "-k", "-b", "-t", "-w"}, "none"),
    "w": ({"-h", "-s"}, "none"),
    "who": ({"-b", "-r", "-q", "-H"}, "none"),
    "ls": ({"-l", "-a", "-A", "-h", "-t", "-r", "-S", "-1", "-d", "-la", "-lh", "-lah", "-alh", "-ltr", "-lt"},
           "paths"),
    "wc": ({"-l", "-c", "-w", "-m"}, "paths"),
    "du": ({"-s", "-h", "-sh", "-c"}, "paths"),
    "systemctl": ({"--no-pager"}, "systemctl"),
}
_SYSTEMCTL_VERBS = {"is-active", "is-enabled", "is-failed", "list-units", "list-timers"}
_UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]+$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._/+@-]*$")
# a read of these prints a credential or a device; the output does reach the model
_SENSITIVE = re.compile(r"^/(?:proc|dev|sys|root|run/secrets)(?:/|$)|/etc/(?:g?shadow|sudoers|ssl/private)|"
                        r"(?:^|/)\.(?:ssh|aws|kube|docker|gnupg|netrc|pgpass|git-credentials|npmrc|pypirc)(?:/|$)|"
                        r"(?:^|/)\.env(?:\.[\w-]+)?$|(?:^|/)id_[\w-]+$|\.(?:pem|key|p12|pfx|jks|kdbx)$|"
                        r"(?:secret|credential|password|passwd|token)", re.I)


@dataclass
class Call:
    tool: str
    host: str          # the approval key: [user@]alias[:port], as written
    kind: str          # read | write | unknown | deny
    why: str


@dataclass
class Verdict:
    kind: str                                   # none | read | write | unknown | deny
    calls: list[Call] = field(default_factory=list)
    why: str = ""

    @property
    def hosts(self) -> list[str]:
        return sorted({c.host for c in self.calls if c.host})


_RANK = {"none": 0, "read": 1, "write": 2, "unknown": 3, "deny": 4}


def _deny_hit(text: str) -> str | None:
    for name, rx in _DENY:
        if rx.search(text):
            return name
    return None


def _path_ok(p: str) -> bool:
    return bool(_PATH_RE.match(p)) and ".." not in p.split("/") and not _SENSITIVE.search(p)


def _read_only(remote: str, parse: Parser) -> bool:
    """Whether every part of a remote command line is on the read list: no expansion, no redirection,
    no subshell; named options only; literal absolute paths that are not sensitive. sudo is a write."""
    remote = _HARMLESS_REDIRECT.sub("", remote)
    segs, ctxs = parse(remote)
    unquoted = "".join(ch if ctx == "" else " " for ch, ctx in zip(remote, ctxs))
    if any(c in unquoted for c in "><()&`$*?[]{}~") or "`" in remote or "$" in remote:
        return False
    if not segs:
        return False
    for sg in segs:
        try:
            words = shlex.split(remote[sg["start"]:sg["end"]])
        except ValueError:
            return False
        if not words or words[0] not in _READ:
            return False             # sudo, a path, an assignment, a wrapper or another command
        cmd, args = words[0], words[1:]
        opts, mode = _READ[cmd]
        if not _args_ok(cmd, args, opts, mode):
            return False
    return True


def _args_ok(cmd: str, args: list[str], opts: set[str], mode: str) -> bool:
    rest: list[str] = []
    for a in args:
        if a in opts:                        # a named option, also BSD style without a dash
            continue
        if a.startswith("-") and a != "-":
            return False
        rest.append(a)
    if mode == "none":
        return not rest
    if mode == "paths":
        return all(_path_ok(p) for p in rest)
    if mode == "systemctl":
        return bool(rest) and rest[0] in _SYSTEMCTL_VERBS and all(_UNIT_RE.match(u) for u in rest[1:])
    return False


_FORWARD_FLAGS = set("LRDw")
_FORWARD_O = re.compile(r"^(?:localforward|remoteforward|dynamicforward|tunnel|tunneldevice)$", re.I)


def _o_option(val: str, opt: dict) -> str:
    """One -o Name=value: a reason when it sends the connection elsewhere; the user, port or a forward into opt."""
    name, _, value = val.replace(" ", "=", 1).partition("=")
    if _RETARGET_O.match(name):
        return f"the option -o {val} changes the target or runs a command"
    low = name.lower()
    if low == "user":
        opt["l"] = value
    elif low == "port":
        opt["p"] = value
    elif _FORWARD_O.match(name):
        opt["fwd"] = f"-o {name}"
    return ""


def _ssh_options(words: list[str], i: int, opt: dict) -> "tuple[int, str]":
    """Read ssh options from words[i] on; returns the index of the first other word, or a reason when an
    option sends the connection elsewhere. OpenSSH reads options after the host too (`ssh h -p 2222 cmd`)."""
    while i < len(words) and words[i].startswith("-") and words[i] != "-":
        w = words[i]
        if w == "--":
            return i + 1, ""
        flags = w[1:]
        for k, f in enumerate(flags):
            if f in _RETARGET_FLAGS:
                return i, f"the option -{f} sends the connection elsewhere"
            if f in _FORWARD_FLAGS:
                opt["fwd"] = f"-{f}"
            if f in _SSH_ARG_OPTS:
                val = flags[k + 1:] or (words[i + 1] if i + 1 < len(words) else "")
                if f == "o":
                    why = _o_option(val, opt)
                    if why:
                        return i, why
                if f in "lp":
                    opt[f] = val
                i += 1 if flags[k + 1:] else 2
                break
        else:
            i += 1
    return i, ""


def _ssh_call(words: list[str], fed: bool, parse: Parser) -> Call:
    opt: dict = {}
    i, why = _ssh_options(words, 1, opt)
    if why:
        return Call("ssh", "", "unknown", why)
    if i >= len(words):
        return Call("ssh", "", "unknown", "no host")
    dest = words[i]
    i, why = _ssh_options(words, i + 1, opt)
    if why:
        return Call("ssh", "", "unknown", why)
    i -= 1                                   # words[i + 1:] is the remote command below
    user, port = opt.get("l", ""), opt.get("p", "")
    if dest.startswith("ssh://"):
        m = re.match(r"^ssh://(?:([^@/]+)@)?([^:/]+)(?::(\d+))?/?$", dest)
        if not m:
            return Call("ssh", "", "unknown", "an ssh:// target this hook cannot read")
        user, dest, port = m.group(1) or user, m.group(2), m.group(3) or port
    elif "@" in dest:
        user, dest = dest.rsplit("@", 1)
    if not _HOST_RE.match(dest) or (user and not _USER_RE.match(user)) or (port and not port.isdigit()):
        return Call("ssh", "", "unknown", "a host or user built at run time or with odd characters")
    host = f"{user + '@' if user else ''}{dest}{':' + port if port else ''}"
    if opt.get("fwd"):
        return Call("ssh", host, "write", f"the option {opt['fwd']} opens a port forward or a tunnel")
    remote = " ".join(words[i + 1:])
    if not remote.strip():
        return Call("ssh", host, "write", "an interactive login")
    hit = _deny_hit(remote)
    if hit:
        return Call("ssh", host, "deny", f"the remote command matches {hit}")
    if fed:
        return Call("ssh", host, "write", "local data goes to the remote command on stdin")
    if _read_only(remote, parse):
        return Call("ssh", host, "read", "a read-only remote command")
    return Call("ssh", host, "write", "a remote command that is not on the read list")


# options that take an argument, per copy tool; the ones that send the connection elsewhere or run a program
_COPY_ARG = {"scp": set("cDFiJloPSX"), "sftp": set("BbcDFiJloPRSs"), "sshfs": set("op"), "ssh-copy-id": set("iFJop"),
             "rsync": set()}
_COPY_RETARGET = {"scp": set("JFS"), "sftp": set("JFSDs"), "sshfs": set(), "ssh-copy-id": set("JF"), "rsync": set()}
_COPY_PORT = {"scp": "P", "sftp": "P", "sshfs": "p", "ssh-copy-id": "p"}
_URI_RE = re.compile(r"^(?:scp|sftp|rsync|ssh)://(?:([^@/:]+)@)?([^@/:]+)(?::(\d+))?(?:/.*)?$")
_SPEC_RE = re.compile(r"^(?:([^@/:]+)@)?([A-Za-z0-9][A-Za-z0-9._-]*):{1,2}(?!//)")


def _copy_call(cmd: str, words: list[str]) -> "tuple[list[str], str]":
    """The host keys ([user@]host[:port]) of an scp/sftp/rsync/sshfs/ssh-copy-id call, or a reason it cannot be
    read. A URI host and a colon host are parsed apart, so scp://web1/ and scp://db1/ never share a key."""
    opt: dict = {}
    targets: list[str] = []
    i = 1
    while i < len(words):
        w = words[i]
        if w.startswith("--"):
            if cmd == "rsync" and w.startswith("--port="):
                opt["p"] = w.split("=", 1)[1]
            i += 1
            continue
        if w.startswith("-") and w != "-":
            flags = w[1:]
            for k, f in enumerate(flags):
                if f in _COPY_RETARGET.get(cmd, set()):
                    return [], f"the option -{f} sends the connection elsewhere or runs a program"
                if f in _COPY_ARG.get(cmd, set()):
                    val = flags[k + 1:] or (words[i + 1] if i + 1 < len(words) else "")
                    if f == "o":
                        why = _o_option(val, opt)
                        if why:
                            return [], why
                    if f == _COPY_PORT.get(cmd):
                        opt["p"] = val
                    if f == "l":
                        opt["l"] = val
                    i += 1 if flags[k + 1:] else 2
                    break
            else:
                i += 1
            continue
        targets.append(w)
        i += 1
    hosts = []
    for w in targets:
        m = _URI_RE.match(w)
        if m:
            user, host, port = m.group(1) or opt.get("l", ""), m.group(2), m.group(3) or opt.get("p", "")
        elif cmd in ("sftp", "ssh-copy-id") and w is targets[-1] and not _SPEC_RE.match(w) and "/" not in w:
            user, _, host = w.rpartition("@")
            user, port = user or opt.get("l", ""), opt.get("p", "")
        else:
            m = _SPEC_RE.match(w)
            if not m:
                continue                     # a local path
            user, host, port = m.group(1) or opt.get("l", ""), m.group(2), opt.get("p", "")
        if not _HOST_RE.match(host) or (user and not _USER_RE.match(user)) or (port and not str(port).isdigit()):
            return [], "a host or user built at run time or with odd characters"
        hosts.append(f"{user + '@' if user else ''}{host}{':' + port if port else ''}")
    return hosts, ""


def classify(command: str, parse: Parser) -> Verdict:
    segs, ctxs = parse(command)
    calls: list[Call] = []
    spans: list[tuple[int, int]] = []
    for sg in segs:
        words = sg.get("words") or []
        cmd = sg.get("cmd", "")
        if cmd == "perl" and len(words) > 3 and words[1] == "-e" and _PERL_ALARM.match(words[2].strip()):
            words = words[3:]
            cmd = words[0].rsplit("/", 1)[-1]
        if cmd not in SSH_CMDS:
            continue
        text = command[sg["start"]:sg["end"]]
        # stdin from the local side: a pipe into ssh, a redirect, a here-string or a heredoc
        masked = "".join(ch if ctx == "" else " " for ch, ctx in
                         zip(text, ctxs[sg["start"]:sg["end"]]))
        fed = bool(sg.get("piped") or sg.get("heredoc") or re.search(r"(?<![<>&\d])<(?!\()", masked))
        if cmd == "ssh":
            call = _ssh_call(words, fed, parse)
        elif cmd == "autossh":
            # a connection that restarts itself, for tunnels: always a write, its host as ssh reads it
            call = _ssh_call(words, fed, parse)
            call.tool = cmd
            if call.kind == "read":
                call.kind, call.why = "write", "autossh keeps a connection and its tunnels open"
        elif cmd == "mosh":
            dest = next((w for w in words[1:] if not w.startswith("-")), "")
            call = Call(cmd, dest, "write" if _HOST_RE.match(dest.split("@")[-1] or "-") else "unknown",
                        "an interactive login")
        else:
            if cmd == "rsync" and (any(w in ("-e", "--rsh") or w.startswith(("--rsh=", "-e")) for w in words)
                                   or "RSYNC_RSH" in text):
                call = Call(cmd, "", "unknown", "rsync with its own remote shell")
            else:
                hosts, why = _copy_call(cmd, words)
                spans.append((sg["start"], sg["end"]))
                if why:
                    calls.append(Call(cmd, "", "unknown", why))
                elif hosts:
                    calls.extend(Call(cmd, h, "write", "a copy to or from the host") for h in hosts)
                elif cmd != "rsync":
                    calls.append(Call(cmd, "", "unknown", "a host this hook cannot read"))
                continue                         # rsync with no host is a local copy
        calls.append(call)
        spans.append((sg["start"], sg["end"]))
    # every mention of ssh outside a call read above: a wrapper this hook does not know (sshpass,
    # setsid, flock …), a word built at run time ($(which ssh), S=ssh; $S), a nested shell, git's ssh
    def piped_on(sg: dict) -> bool:
        k = segs.index(sg)
        return k + 1 < len(segs) and bool(segs[k + 1].get("piped"))

    fed_by_heredoc = any(c.kind != "unknown" for c in calls) and any(
        sg.get("heredoc") and sg.get("cmd") in SSH_CMDS for sg in segs)
    for m in _TOKEN_RE.finditer(command):
        ctx = ctxs[m.start()] if m.start() < len(ctxs) else ""
        if ctx == "comment":
            continue
        seg = next((sg for sg in segs if sg["start"] <= m.start() < sg["end"]), None)
        if seg and ctx in ("sq", "dq") and seg.get("cmd") in _DATA_CMDS and not piped_on(seg):
            continue                         # a mention in data: grep "ssh" log, echo "use ssh" (not | bash)
        if seg and seg.get("cmd") == "git" and m.group(0) in ("ssh", "ssh://") \
                and not re.search(r"(?:^|\s)-c(?:\s|$)|!", command[seg["start"]:seg["end"]]):
            continue                         # git over ssh is out of scope (C21); -c and a ! alias run commands
        if m.group(0) == ".ssh/config" and seg and not re.search(r">\s*\S*$", command[seg["start"]:m.start()]) \
                and seg.get("cmd") in _DATA_CMDS | {"cat", "less", "ls", "stat"}:
            continue                         # reading the config; a redirect into it is a change
        if ctx in ("hd", "hdq"):
            announcer = None
            for sg in segs:
                if sg.get("heredoc") and sg["start"] < m.start():
                    announcer = sg
            if announcer and announcer.get("cmd") in _HEREDOC_DATA and not piped_on(announcer):
                continue                     # a heredoc that is text for a command that runs nothing
        if ctx in ("hd", "hdq") and fed_by_heredoc:
            continue                         # the heredoc of a call read above, already a write
        if not any(a <= m.start() < b for a, b in spans):
            calls.append(Call(m.group(0), "", "unknown", f"'{m.group(0)}' where this hook cannot read the call"))
            break
    if not calls:
        return Verdict("none")
    worst = max(calls, key=lambda c: _RANK[c.kind])
    return Verdict(worst.kind, calls, worst.why)
