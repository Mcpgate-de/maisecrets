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
    r"|ssh://|rsync://|GIT_SSH|sshCommand|RSYNC_RSH|DOCKER_HOST|\.ssh/+(?:\./+)*config\b",
    re.I)                                    # SSH is ssh on macOS (APFS) and in PowerShell (opus round 3)
# a command line longer than this is not read at all when it names ssh: it asks (on Codex it is refused). Every
# pattern below is linear or bounded, but the shell parser and a few lazy patterns are not; the client's 10 s
# timeout lets a command run, so the answer must come first (opus round 3: 80 KB took 12 s)
MAX_READ = 8192

# ssh options that take an argument (ssh(1)); the first word that is no option is the host
_SSH_ARG_OPTS = set("BbcDEeFIiJLlmOoPpQRSWw")
# options that send the connection elsewhere than the host on the command line, or run a local command
_RETARGET_FLAGS = set("JWSOFMP")       # -P: a tag that selects a Match block of the user's config
_RETARGET_O = re.compile(r"^(?:proxyjump|proxycommand|hostname|remotecommand|controlpath|controlmaster|"
                         r"localcommand|permitlocalcommand|match|include|knownhostscommand|"
                         r"canonicalizehostname|canonicaldomains|tag)\b", re.I)
# commands whose quoted arguments are data, never run: a mention of ssh there is no call (`grep "ssh" log`)
_DATA_CMDS = {"grep", "egrep", "fgrep", "rg", "ag", "echo", "printf", "cut", "tr", "wc", "sort", "uniq", "head",
              "tail", "diff", "test", "[", "pgrep", "pkill"}
# options that make a data command start a program (rg --pre ssh . host ran ssh; sort --compress-program likewise):
# with one of them a data command is no data (Opus review of 0.6.7)
_EXEC_OPTION = re.compile(r"(?:^|\s)(?:--pre(?:-glob)?|--compress-program|--use-compress-program)(?:[=\s]|$)")
# the text fields of gh and glab subcommands that only post text: a quoted value of one of these flags that names ssh
# is the text of an issue, not a call (0.6.6 asked for `gh issue create --body "… an ssh host …"`)
_TEXT_FLAG = re.compile(r"(?:^|\s)(?:--body|-b|--title|-t|--description|-d|--message|-m|--notes|-n)[=\s]*$")
_TEXT_SUBCOMMANDS = {"issue", "pr", "mr", "release"}
# a heredoc to these is text, not a script: a commit message or a file that mentions ssh
_HEREDOC_DATA = {"cat", "tee", "git", "gh", "glab", "grep", "echo", "printf", "wc", "head", "tail", "jq", "less"}
# stderr or all output to /dev/null, or stderr to stdout: no file is written
_HARMLESS_REDIRECT = re.compile(r"\s*(?:[12]?>\s*/dev/null|2>&1|&>\s*/dev/null)(?=\s|$|;|\|)")
# the timeout a macOS agent builds without timeout(1): perl -e 'alarm N; exec @ARGV' CMD ARGS
_PERL_ALARM = re.compile(r"^alarm\s+\d+\s*;\s*exec\s+@ARGV\s*;?$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# destructive remote commands, refused even with consent; each spelled loosely on purpose
# a command word (at the start, after a separator or a wrapper), never part of a file name or an option value
_CMD_POS = r"(?:^|[\s;|&(`=])"
_DENY = [
    # the command word, then a device anywhere in the same simple command (options may take arguments: -t ext4)
    ("mkfs", re.compile(_CMD_POS + r"mkfs(?:\.\w+)?\s[^\n;|&]*?/dev/")),
    ("wipefs", re.compile(_CMD_POS + r"wipefs\s[^\n;|&]*?/dev/")),
    # /dev/null and the like are no device: `dd if=/dev/vda of=/dev/null` is a read benchmark (corpus, 2026-10-07)
    ("dd to a device", re.compile(_CMD_POS + r"dd\s[^\n;|&]*\bof=/dev/(?!(?:null|zero|stdout|stderr)\b)")),
    ("rm -rf /", re.compile(_CMD_POS + r"rm\s+(?:-{1,2}[\w-]+\s+)*(?:/|/\*|--no-preserve-root)(?:\s|$|;)")),
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


# a port forward, a tunnel, the agent or X11 forwarded, an environment sent: state on the other side
_FORWARD_FLAGS = set("LRDwAXYE")        # -E: a log file appended on this side
_FORWARD_O = re.compile(r"^(?:localforward|remoteforward|dynamicforward|tunnel|tunneldevice|forwardagent|forwardx11|"
                        r"forwardx11trusted|setenv|sendenv|streamlocalbindunlink)$", re.I)
# ssh_config(5) reads "Name value" and "Name=value" with blanks around both; a leading blank hid HostName (Gate B)
_O_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*(?:=\s*|\s+)(.*)$", re.S)


def _o_option(val: str, opt: dict) -> str:
    """One -o Name=value: a reason when it sends the connection elsewhere or cannot be read; the user, port or a
    forward into opt. Users and ports are lists: OpenSSH takes the first value, and two different ones are unknown."""
    m = _O_RE.match(val)
    if not m:
        return f"the option -o {val!r} cannot be read"
    name, value = m.group(1), m.group(2).strip()
    if _RETARGET_O.match(name):
        return f"the option -o {name} changes the target or runs a command"
    low = name.lower()
    if low == "user":
        opt.setdefault("users", []).append(value)
    elif low == "port":
        opt.setdefault("ports", []).append(value)
    elif _FORWARD_O.match(name):
        opt["fwd"] = f"-o {name}"
    return ""


def _one(values: list[str]) -> "tuple[str, bool]":
    """The single user or port that several sources name, and whether they disagree."""
    vals = [v for v in values if v]
    return (vals[0] if vals else ""), len(set(vals)) > 1


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
                if f == "l":
                    opt.setdefault("users", []).append(val)
                if f == "p":
                    opt.setdefault("ports", []).append(val)
                i += 1 if flags[k + 1:] else 2
                break
        else:
            i += 1
    return i, ""


# local redirections that change nothing on either side; stripped only when the raw text has them unquoted, so a
# quoted ">" that ssh hands to the remote shell stays part of the remote command (codex review of the repair)
_HARMLESS_WORDS = {"2>&1", "1>&2", ">&2", ">/dev/null", "1>/dev/null", "2>/dev/null", "&>/dev/null", "</dev/null"}


def _strip_harmless(words: list[str], unquoted: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if w in _HARMLESS_WORDS and w in unquoted.replace(" ", ""):
            i += 1
            continue
        if w in (">", "2>", "1>", "&>", "<") and i + 1 < len(words) and words[i + 1] == "/dev/null" \
                and re.search(re.escape(w) + r"\s*/dev/null", unquoted):
            i += 2
            continue
        out.append(w)
        i += 1
    return out


def _ssh_call(words: list[str], fed: bool, parse: Parser, unquoted: str = "") -> Call:
    words = _strip_harmless(words, unquoted)
    opt: dict = {}
    i, why = _ssh_options(words, 1, opt)
    if why:
        return Call("ssh", "", "unknown", why)
    if i >= len(words):
        return Call("ssh", "", "unknown", "no host")
    dest = words[i]
    if words[i - 1] != "--":
        # OpenSSH reads options after the host too, unless -- ended them before the host (Gate B round 2)
        i, why = _ssh_options(words, i + 1, opt)
        if why:
            return Call("ssh", "", "unknown", why)
    else:
        i += 1
    i -= 1                                   # words[i + 1:] is the remote command below
    users, ports = list(opt.get("users", [])), list(opt.get("ports", []))
    if dest.startswith("ssh://"):
        m = re.match(r"^ssh://(?:([^@/]+)@)?([^:/]+)(?::(\d+))?/?$", dest)
        if not m:
            return Call("ssh", "", "unknown", "an ssh:// target this hook cannot read")
        users.append(m.group(1) or "")
        ports.append(m.group(3) or "")
        dest = m.group(2)
    elif "@" in dest:
        u, dest = dest.rsplit("@", 1)
        users.append(u)
    (user, two_users), (port, two_ports) = _one(users), _one(ports)
    if two_users or two_ports:
        return Call("ssh", "", "unknown", "two users or two ports for one connection; ssh takes the first one")
    if not _HOST_RE.match(dest) or (user and not _USER_RE.match(user)) or (port and not port.isdigit()):
        return Call("ssh", "", "unknown", "a host or user built at run time or with odd characters")
    host = f"{user + '@' if user else ''}{dest}{':' + port if port else ''}"
    if opt.get("fwd"):
        return Call("ssh", host, "write", f"the option {opt['fwd']} forwards a port, a tunnel, the agent or X11, or "
                                          "sends the environment")
    remote = " ".join(words[i + 1:])
    if not remote.strip():
        return Call("ssh", host, "write", "an interactive login")
    hit = _deny_hit(remote.replace('"', "").replace("'", ""))
    if hit:
        return Call("ssh", host, "deny", f"the remote command matches {hit}")
    if fed:
        return Call("ssh", host, "write", "local data goes to the remote command on stdin")
    if _read_only(remote, parse):
        return Call("ssh", host, "read", "a read-only remote command")
    return Call("ssh", host, "write", "a remote command that is not on the read list")


# options that take an argument, per copy tool; the ones that send the connection elsewhere or run a program
_COPY_ARG = {"scp": set("cDFiJloPSX"), "sftp": set("BbcDFiJloPRSs"), "sshfs": set("opF"), "ssh-copy-id": set("iFJop"),
             "rsync": set()}
# rsync's daemon syntax: `::` right after [user@]host, not inside the remote path (codex review of the repair)
_DAEMON_RE = re.compile(r"^(?:[^@/:]+@)?[A-Za-z0-9][A-Za-z0-9._-]*::")
# local commands that only read: a mention of ~/.ssh in any other command, or a redirect into it, asks
_READ_LOCAL = {"cat", "less", "more", "head", "tail", "ls", "grep", "egrep", "fgrep", "rg", "stat", "wc", "file",
               "diff", "cmp", "md5sum", "sha256sum", "shasum"}
def _mosh_program(word: str) -> bool:
    """mosh --ssh/--server/--client, also abbreviated: mosh's Getopt::Long takes --se=… for --server (Gate B)."""
    name = word.split("=")[0].lstrip("-")
    return word.startswith("-") and len(name) >= 2 and not word.startswith(("-p", "-a", "-n")) \
        and any(o.startswith(name) for o in ("server", "client", "ssh"))


_MOSH_ARG = {"-p", "--port", "--predict", "--family", "--bind-server", "--experimental-remote-ip"}
# sshfs passes ssh options in a comma list and can run another ssh program
_SSHFS_PROGRAM = re.compile(r"^(?:ssh_command|ssh_protocol|sftp_server|directport|passive|slave)\b", re.I)
_COPY_RETARGET = {"scp": set("JFS"), "sftp": set("JFSDs"), "sshfs": set("F"), "ssh-copy-id": set("JF"), "rsync": set()}
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
            if cmd == "rsync" and w.startswith("--port"):
                if w.startswith("--port="):
                    opt.setdefault("ports", []).append(w.split("=", 1)[1])
                elif i + 1 < len(words):
                    opt.setdefault("ports", []).append(words[i + 1])
                    i += 1
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
                        for item in (val.split(",") if cmd == "sshfs" else [val]):
                            if cmd == "sshfs" and _SSHFS_PROGRAM.match(item.strip()):
                                return [], f"the sshfs option {item.strip()} runs another ssh program"
                            if cmd == "sshfs" and "=" not in item and " " not in item.strip():
                                continue     # an sshfs flag such as reconnect
                            why = _o_option(item, opt)
                            if why:
                                return [], why
                    if f == _COPY_PORT.get(cmd):
                        opt.setdefault("ports", []).append(val)
                    i += 1 if flags[k + 1:] else 2
                    break
            else:
                i += 1
            continue
        targets.append(w)
        i += 1
    if opt.get("fwd"):
        return [], f"the option {opt['fwd']} forwards or sends the environment"
    hosts = []
    for w in targets:
        if "[" in w and "]:" in w:
            return [], "a bracketed (IPv6) host this hook does not read"
        users, ports = list(opt.get("users", [])), list(opt.get("ports", []))
        m = _URI_RE.match(w)
        daemon = bool(m and w.startswith("rsync://")) or (cmd == "rsync" and bool(_DAEMON_RE.match(w)))
        if cmd == "rsync" and not daemon:
            ports = []                       # --port is the daemon's; host:path goes over ssh, port 22 (Gate B)
        if m:
            users.append(m.group(1) or "")
            ports.append(m.group(3) or "")
            host = m.group(2)
        elif cmd in ("sftp", "ssh-copy-id") and w is targets[-1] and not _SPEC_RE.match(w) and "/" not in w:
            u, _, host = w.rpartition("@")
            users.append(u)
        else:
            m = _SPEC_RE.match(w)
            if not m:
                continue                     # a local path
            users.append(m.group(1) or "")
            host = m.group(2)
        (user, two_users), (port, two_ports) = _one(users), _one(ports)
        if two_users or two_ports:
            return [], "two users or two ports for one connection"
        if not _HOST_RE.match(host) or (user and not _USER_RE.match(user)) or (port and not str(port).isdigit()):
            return [], "a host or user built at run time or with odd characters"
        hosts.append(f"{user + '@' if user else ''}{host}{':' + port if port else ''}")
    return hosts, ""


def classify(command: str, parse: Parser) -> Verdict:
    if len(command) > MAX_READ:
        low = command.lower()
        if _TOKEN_RE.search(command) or ".ss" in low:
            return Verdict("unknown", [Call("ssh", "", "unknown", f"a command over {MAX_READ} characters that names "
                                                               "ssh; maisecrets does not read it")],
                           f"a command over {MAX_READ} characters that names ssh")
        return Verdict("none")
    segs, ctxs = parse(command)
    calls: list[Call] = []
    spans: list[tuple[int, int]] = []
    for sg in segs:
        words = sg.get("words") or []
        cmd = sg.get("cmd", "").lower()      # SSH, Scp: the same program on a case-insensitive file system
        if cmd == "perl" and len(words) > 3 and words[1] == "-e" and _PERL_ALARM.match(words[2].strip()):
            words = words[3:]
            cmd = words[0].rsplit("/", 1)[-1]
        if cmd not in SSH_CMDS:
            continue
        text = command[sg["start"]:sg["end"]]
        # stdin from the local side: a pipe into ssh, a redirect, a here-string or a heredoc
        masked = "".join(ch if ctx == "" else " " for ch, ctx in
                         zip(text, ctxs[sg["start"]:sg["end"]]))
        fed = bool(sg.get("piped") or sg.get("heredoc")
                   or re.search(r"(?<![<>&\d])<(?!\(|\s*/dev/null\b)", masked))
        if re.match(r"\s*(?:\S+=\S*\s+)*(?:sudo|doas)\b[^;|&]*\s-(?:u|-user|i|s|-login|-shell)\b", masked):
            # another user's ssh config and keys: its aliases are not this user's (Gate B of #8)
            calls.append(Call(cmd, "", "unknown", "ssh as another local user, with that user's ssh config"))
            spans.append((sg["start"], sg["end"]))
            continue
        if cmd == "autossh":
            # -M is autossh's monitor port, not ssh's -M (Gate B: `autossh -M 0` asked every time)
            words = [w for k, w in enumerate(words) if not (w.startswith("-M") or (k and words[k - 1] == "-M"))]
        if cmd == "ssh":
            call = _ssh_call(words, fed, parse, masked)
        elif cmd == "autossh":
            # a connection that restarts itself, for tunnels: always a write, its host as ssh reads it
            call = _ssh_call(words, fed, parse, masked)
            call.tool = cmd
            if call.kind == "read":
                call.kind, call.why = "write", "autossh keeps a connection and its tunnels open"
        elif cmd == "mosh" and any(_mosh_program(w) for w in words):
            call = Call(cmd, "", "unknown", "mosh with its own ssh, server or client program")
        elif cmd == "mosh":
            # -p/--port is mosh's UDP port, not part of the host; skip the arguments of options (codex review)
            dest, k = "", 1
            while k < len(words):
                w = words[k]
                if w == "--":
                    k += 1
                    continue
                if w in _MOSH_ARG:
                    k += 2
                    continue
                if w.startswith("-"):
                    k += 1
                    continue
                dest = w
                break
            user, _, bare = dest.rpartition("@")
            ok = bool(dest) and _HOST_RE.match(bare) and (not user or _USER_RE.match(user))
            call = Call(cmd, dest if ok else "", "write" if ok else "unknown", "an interactive login")
        else:
            if cmd == "rsync" and (any(w in ("-e", "--rsh") or w.startswith("--rsh=") or re.match(r"^-[A-Za-z]*e", w)
                                       for w in words) or "RSYNC_RSH" in text):
                call = Call(cmd, "", "unknown", "rsync with its own remote shell")
            else:
                hosts, why = _copy_call(cmd, words)
                spans.append((sg["start"], sg["end"]))
                if why:
                    calls.append(Call(cmd, "", "unknown", why))
                elif hosts:
                    calls.extend(Call(cmd, h, "write", "a copy to or from the host") for h in hosts)
                elif cmd != "rsync" or any("[" in w and "]:" in w for w in words):
                    calls.append(Call(cmd, "", "unknown", "a host this hook cannot read"))
                continue                         # rsync with no host is a local copy
        calls.append(call)
        spans.append((sg["start"], sg["end"]))
    # every mention of ssh outside a call read above: a wrapper this hook does not know (sshpass,
    # setsid, flock …), a word built at run time ($(which ssh), S=ssh; $S), a nested shell, git's ssh
    def piped_on(sg: dict) -> bool:
        k = segs.index(sg)
        return k + 1 < len(segs) and bool(segs[k + 1].get("piped"))

    def quoted_start(pos: int) -> int:
        """Where the quoted string that holds pos begins (the index of its opening quote)."""
        k = pos
        while k > 0 and ctxs[k - 1] == ctxs[pos]:
            k -= 1
        return k - 1 if k > 0 else 0

    def gh_text_field(sg: dict, pos: int) -> bool:
        """pos is inside the quoted value of a text flag of `gh|glab issue|pr|mr|release …`: the text of an issue."""
        words = sg.get("words") or []
        if sg.get("cmd") not in ("gh", "glab") or len(words) < 2 or words[1] not in _TEXT_SUBCOMMANDS:
            return False
        return bool(_TEXT_FLAG.search(command[sg["start"]:quoted_start(pos)]))

    def data_only(sg: dict) -> bool:
        text = command[sg["start"]:sg["end"]]
        unq = "".join(ch if cx == "" else " " for ch, cx in zip(text, ctxs[sg["start"]:sg["end"]]))
        return sg.get("cmd") in _DATA_CMDS and not piped_on(sg) and ">" not in unq and not _EXEC_OPTION.search(text)

    # the airbag: when a command names an ssh-family call, every part of it that is not plain data is checked,
    # quotes removed (`echo '… mkfs …'` alone is data; `echo … | bash` is not). A narrower scan of "remote fields"
    # missed forms twice (Gate B rounds 1 and 2); the patterns match a command word on a device
    if _TOKEN_RE.search(command):
        for sg in (segs or [{"start": 0, "end": len(command), "cmd": ""}]):
            if data_only(sg):
                continue
            hit = _deny_hit(command[sg["start"]:sg["end"]].replace('"', "").replace("'", "").replace("\\", ""))
            if hit:
                calls.append(Call("ssh", "", "deny", f"the command matches {hit}"))
                break
    # a change that can reach ~/.ssh (its config retargets every alias): a mention of .ss… outside an ssh, autossh or
    # mosh call is allowed only in a command that only reads, and no redirect may point into it. A list of writers
    # was never complete (rsync, tar -C, patch …; codex review of the repair), so the reads are listed instead
    for m in re.finditer(r"\.ss", command, re.I):
        sg = next((x for x in segs if x["start"] <= m.start() < x["end"]), None)
        if sg and sg.get("cmd", "").lower() in ("ssh", "autossh", "mosh") and any(a <= m.start() < b for a, b in spans):
            continue                         # an option value (-i ~/.ssh/key) or a path on the remote side
        if not sg or sg.get("cmd", "").lower() not in _READ_LOCAL:
            calls.append(Call("ssh", "", "unknown", "a command that can change ~/.ssh, where ssh looks up hosts"))
            break
    flat = command.replace('"', "").replace("'", "").replace("\\", "")
    if any(".ss" in t.lower() for t in re.findall(r"(?:\d?>>?|&>>?|>\|)[ \t]*([^\s]+)", flat)):
        calls.append(Call("ssh", "", "unknown", "a write into ~/.ssh, which decides where ssh connects"))
    fed_by_heredoc = any(c.kind != "unknown" for c in calls) and any(
        sg.get("heredoc") and sg.get("cmd") in SSH_CMDS for sg in segs)
    for m in _TOKEN_RE.finditer(command):
        ctx = ctxs[m.start()] if m.start() < len(ctxs) else ""
        if ctx == "comment":
            continue
        seg = next((sg for sg in segs if sg["start"] <= m.start() < sg["end"]), None)
        if seg and ctx in ("sq", "dq") and data_only(seg):
            continue                         # quoted text a data command prints: echo "use ssh" (no > file, no pipe)
        if seg and ctx in ("sq", "dq") and gh_text_field(seg, m.start()):
            continue                         # the quoted body of an issue: gh issue create --body "… ssh …"
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
