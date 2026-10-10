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

def _hooks():
    from . import hooks              # the caller's module; imported late, since hooks imports this one
    return hooks


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
# the data commands with no option that starts a program; only in these is a quoted mention text. Not rg (--pre), ag
# (--pager) or sort (--compress-program): a list of such options was never complete (codex review of 0.6.7)
_TEXT_SAFE_CMDS = _DATA_CMDS - {"rg", "ag", "sort"}
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
        return "an option -o that cannot be read"     # never the value: it reaches the ask and the report
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
                                return [], "an sshfs option runs another ssh program"
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


# The mention rule (#15): an ssh-family word asks only where the shell starts it as a program. C21 reads the command
# line the agent sends, not what a program in it does: python, node, a script or make that starts ssh is outside it,
# and so is a word built at run time ("s" "sh"). An unknown program that gets the word as an argument of its own is
# taken for one that may start it (gcloud compute ssh, uv run ssh); only the commands that search, show or look up
# are known to start nothing.
_PROGRAM_WORDS = SSH_CMDS | {"sshpass", "pssh", "parallel-ssh", "pscp", "tsh", "kitten"}
_CONFIG_WORD_RE = re.compile(r"GIT_SSH|sshCommand|RSYNC_RSH|DOCKER_HOST", re.I)
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh"}
# a program that starts the program named in its arguments (sudo and doas the parser strips itself)
_LAUNCHERS = {"env", "xargs", "timeout", "nohup", "exec", "nice", "ionice", "chrt", "setsid", "stdbuf", "command",
              "builtin", "time", "watch", "caffeinate", "flock", "sshpass", "script", "tmux", "screen", "parallel",
              "su", "runuser", "unbuffer", "torsocks", "proxychains", "proxychains4", "tsocks", "strace", "nsenter",
              "chroot", "firejail", "unshare", "systemd-run", "expect", "sudo", "doas", "pkexec", "open", "xterm",
              "gtimeout", "hyperfine", "entr", "sg", "nix-shell", "gnome-terminal", "konsole", "alacritty", "wezterm",
              "kitty", "ssh-agent", "rlwrap", "noglob", "coproc"}
_CONTAINER_EXEC = {"docker", "podman", "nerdctl", "kubectl", "lxc"}
# commands that search, show, list or look up: an ssh word as their argument is data (grep ssh README.md, which ssh)
_LOOKS_UP = {"cd", "ls", "cat", "less", "more", "head", "tail", "which", "whereis", "type", "hash", "man", "info",
             "apropos", "tldr", "file", "stat", "ps", "pgrep", "pkill", "killall", "lsof", "git", "gh", "glab", "pip",
             "pip3", "brew", "apt", "apt-get", "apk", "dnf", "yum", "port", "npm", "pnpm", "yarn", "cargo", "rustup",
             "find", "locate", "mdfind", "jq", "yq", "diff", "cp", "mv", "rm", "touch", "mkdir", "chmod", "chown",
             "ln", "tar", "zip", "unzip", "sed", "systemctl", "service", "ufw", "vim", "vi", "nano", "emacs", "code",
             "subl", "helm"} | _CONTAINER_EXEC
# interpreters: their code is outside C21 (docs/THREAT-MODEL.md), so a word in it is no start this check reads
_INTERPRETERS = {"python", "python3", "node", "nodejs", "ruby", "perl", "php", "lua", "rscript", "julia", "deno", "bun",
                 "awk", "gawk", "osascript", "java", "groovy", "tclsh", "pwsh"}
# a verb before the word that names something to manage, not a program to start: systemctl restart ssh, npm i ssh
_MANAGE_VERBS = {"install", "add", "i", "view", "show", "info", "logs", "log", "status", "restart", "stop", "start",
                 "reload", "enable", "disable", "get", "describe", "delete", "rm", "tag", "allow", "deny", "remove",
                 "uninstall", "search", "list", "ls", "inspect", "pull", "top", "kill", "test", "upgrade"}
# a verb after which the next word is the program to run, also past its flags: uv run --no-sync ssh, gcloud compute
_RUN_VERBS = {"run", "exec", "x", "compute", "enter", "shell", "dlx"}
# options after which a quoted word is code that the command runs (sg docker -c '…', nix-shell --run "…")
_CODE_OPTIONS = {"-c", "--run", "--command", "-e", "--exec", "-x", "--"}
_FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
# an option whose value is a program the command starts (rg --pre, sort --compress-program, git difftool --extcmd)
_PROGRAM_OPTION = re.compile(r"(?:^|\s)(?:--(?:pre|hostname-bin|compress-prog\w*|use-compress-program|pager|extcmd|"
                             r"\w+-filter|exec|rsh|command|editor|program|ssh)|-[xI])(?:=|\s+)[\"']?$")
_ALIAS_RE = re.compile(r"(?:^|[\s;&|(])alias\s+([\w.-]+)=(\"[^\"]*\"|'[^']*'|[^\s;&|)]*)")
_HEAD_ASSIGN = re.compile(r"\s*(?:[A-Za-z_]\w*=(?:\"[^\"]*\"|'[^']*'|[^\s;&|)]*)\s+)+")
# a part that runs text it did not write itself: a word the shell builds at run time, the last argument, history,
# eval; a shell or source that runs a file or its input
_RUN_TEXT = {"eval", "fc", "source", "."}
# a file a shell, git or direnv reads as settings or runs later: ~/.bashrc, .envrc, .git/hooks/pre-commit
_STARTUP_FILE = re.compile(r"(?:^|/)\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|"
                           r"zlogin|zlogout|kshrc|mkshrc|envrc|tmux\.conf|gitconfig|config/git/|git/(?:config|hooks/)|"
                           r"config/fish/)")
# git -c keys whose value is a program git runs (codex, review of #15: git -c color.ui=never commit asked)
_GIT_PROGRAM_KEY = re.compile(r"(?i)^(?:alias\.|core\.(?:editor|pager|hookspath|fsmonitor|sshcommand|askpass)|"
                              r"sequence\.editor|gpg\.|credential\.|.*\.(?:command|cmd|textconv|clean|smudge|process|"
                              r"driver|program|helper|tool)(?:=|$))")
_GH_RUNS = {"codespace", "extension", "alias"}
# programs that connect to an scp://, sftp:// or ssh:// URL themselves (git over ssh is outside C21)
_URL_CLIENTS = {"curl", "docker", "podman", "nerdctl", "lftp", "rclone", "duplicity", "restic", "borg", "kubectl",
                "helm", "ansible", "ansible-playbook", "virsh", "ncftp", "gio"}


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def _first_word(value: str) -> str:
    words = value.strip("\"'").split()
    return _base(words[0]) if words else ""


def _plain(command: str, ctxs: list[str], sg: dict) -> str:
    span = zip(command[sg["start"]:sg["end"]], ctxs[sg["start"]:sg["end"]])
    return "".join(ch if cx == "" else " " for ch, cx in span)


def _git_runs(words: list[str]) -> bool:
    """git runs a program from its parsed words: -c before the subcommand (it can set an ssh command), rebase --exec,
    filter-branch, bisect run, submodule foreach, difftool --extcmd, a `!` alias. The words of a message (commit -m
    "feat(ssh)!: …") are not looked at (codex and Opus, review of #15)."""
    ws, k = words[1:], 0
    while k < len(ws) and ws[k].startswith("-"):
        if ws[k] == "-c" and k + 1 < len(ws) and _GIT_PROGRAM_KEY.match(ws[k + 1]):
            return True
        k += 2 if ws[k] in ("-C", "--git-dir", "--work-tree", "--namespace") else 1
    sub, rest = (ws[k], ws[k + 1:]) if k < len(ws) else ("", [])
    return sub == "filter-branch" or sub == "rebase" and any(w in ("--exec", "-x") or w.startswith("--exec=")
                                                              for w in rest) \
        or sub == "bisect" and rest[:1] == ["run"] or sub == "submodule" and "foreach" in rest \
        or sub == "difftool" and any(w.startswith("--extcmd") for w in rest) \
        or sub == "config" and any(w.startswith("!") for w in rest)


def _shell_code(words: list[str]) -> str:
    """The code of `sh -c CODE`, `bash -lc -- CODE`: the first word after the options, when one of them holds c."""
    k, has_c = 1, False
    while k < len(words) and words[k].startswith(("-", "+")) and len(words[k]) > 1:
        if not words[k].startswith("--") and "c" in words[k][1:]:
            has_c = True
        k += 2 if words[k] in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file") else 1
    return words[k] if has_c and k < len(words) else ""


def _runs_its_input(sg: dict) -> bool:
    """A part that runs the text piped into it: a shell, source or eval; xargs whose program is a shell or a launcher;
    parallel with no program of its own (it runs each line). Not `xargs -0 echo`."""
    name = _base(sg.get("cmd", ""))
    if name in _SHELLS | _RUN_TEXT | {"crontab", "at", "batch"}:
        return True                          # crontab - and at run the text later (Opus, review of #15)
    if name not in ("xargs", "parallel"):
        return False
    program = _program_of(sg)
    return program in _SHELLS | _RUN_TEXT | _LAUNCHERS or name == "parallel" and not program


def _program_of(sg: dict) -> str:
    """The program xargs or parallel starts: the first word that is no option, no option value and no number
    (xargs --max-args 1 -0 sh -c; codex, review of #15)."""
    words, k = sg.get("words") or [], 1
    while k < len(words):
        w = words[k]
        if w in ("-I", "-n", "-L", "-P", "-d", "-E", "-s", "-a", "-j", "-S", "-R"):
            k += 2
        elif w.startswith("-") or w.isdigit() or w == "{}" or w == ":::":
            k += 1
        else:
            return _base(w)
    return ""


def _writes_of(command: str, ctxs: list[str], sg: dict) -> list[str]:
    """The files the part writes, with the quotes taken off: a redirect target, tee's arguments, -o FILE."""
    text = command[sg["start"]:sg["end"]]
    plain = _HARMLESS_REDIRECT.sub(lambda h: " " * len(h.group(0)), _plain(command, ctxs, sg))
    out = []
    for r in list(re.finditer(r"(?<![<\d&])>>?\|?", plain)) + list(re.finditer(r"(?:^|\s)-o(?=\s)", plain)):
        rest = text[r.end():].lstrip()
        if rest[:1] in ("'", '"'):
            end = rest.find(rest[0], 1)
            out.append(rest[1:end] if end > 0 else rest[1:])
        elif rest:
            out.append(re.split(r"[\s;&|)]", rest, 1)[0])
    if _base(sg.get("cmd", "")) == "tee":
        out += [w for w in (sg.get("words") or [])[1:] if not w.startswith("-")]
    return [w for w in out if w]


def _write_runs(command: str, ctxs: list[str], segs: list[dict], writers: list[dict], after: int, raw: str) -> str:
    """The word goes into a file a later part runs, or into a startup file (the writers: the part itself, a tee it is
    piped into, the command that owns its heredoc)."""
    wrote = [w for sg in writers for w in _writes_of(command, ctxs, sg)]
    names = {_base(w) for w in wrote}
    later = [sg for sg in segs if sg["start"] > after and not sg.get("cmd", "").startswith("QQQ")]
    if names and any(_base(w) in names for sg in later for w in (sg.get("words") or [])[:1] + [
            x for x in (sg.get("words") or [])[1:] if _base(sg.get("cmd", "")) in _SHELLS | _RUN_TEXT]):
        return f"'{raw}' written to a file that a later part runs"
    if any(_STARTUP_FILE.search(w) for w in wrote):
        return f"'{raw}' written into a startup file, which a shell or a tool runs later"
    return ""


def _dynamic_word(command: str, sg: dict) -> bool:
    """The part's command word is built at run time: $x, ${…}, $_, `…`, $(…) (the parser's command word)."""
    return sg.get("cmd", "").lstrip('"').startswith(("$", "`"))


def _starts_here(command: str, segs: list[dict], ctxs: list[str], m: "re.Match", parse: Parser, fed: bool,
                 piped_on, data_only) -> str:
    """Why the word at m starts an ssh-family program, or "" when it is a mention that starts nothing."""
    pos, raw = m.start(), m.group(0)
    word = raw.lower()
    ctx = ctxs[pos] if pos < len(ctxs) else ""
    seg = next((sg for sg in segs if sg["start"] <= pos < sg["end"]), None)
    cmd = _base(seg.get("cmd", "")) if seg else ""
    words = (seg.get("words") or []) if seg else []
    if _CONFIG_WORD_RE.match(raw):
        if seg and data_only(seg) and cmd in _TEXT_SAFE_CMDS and ctx != "hd":
            return ""                        # grep sshCommand docs: a search, not a setting
        return f"'{raw}' sets the command that ssh or git runs"
    if ctx in ("hd", "hdq", "hdx"):
        if not _hooks().heredoc_is_sure(command, ctxs, pos):
            return f"'{raw}' in a heredoc whose end this hook cannot be sure of"
        owner = None
        for sg in segs:
            if sg.get("heredoc") and sg["start"] < pos:
                owner = sg
        name = _base(owner.get("cmd", "")) if owner else ""
        if fed and name in SSH_CMDS:
            return ""                        # the remote commands of a call read above
        if name in _SHELLS | _RUN_TEXT | {"xargs", "parallel"} or owner and piped_on(owner) and any(
                _base(x.get("cmd", "")) in _SHELLS for x in segs if x["start"] > owner["start"]):
            return f"'{raw}' in the heredoc of a shell"
        if owner:                            # cat > run.sh <<'EOF' … EOF; bash run.sh (Opus, review of #15)
            return _write_runs(command, ctxs, segs, [owner], pos, raw)
        return ""                            # the text of another program: python, cat, git commit -F -
    if ctx == "comment":
        return "" if _hooks().comment_is_sure(command, ctxs, pos) else \
            f"'{raw}' in a comment whose end this hook cannot be sure of"
    # 1. a command substitution starts it, also in double quotes, in zsh's ${(e)…} and in a -v array subscript
    before = re.sub(r"[\s\"']", "", command[max(0, pos - 16):pos])
    if "${(e)" not in command:
        before = re.sub(r"\\[`$]", "", before)        # "use \`ssh\` config": an escaped backtick is text
    before = before.replace("\\", "")
    if word in _PROGRAM_WORDS and before.endswith(("$(", "`")):
        return f"'{raw}' in a command substitution"
    opener = max(command.rfind("$(", 0, pos), command.rfind("`", 0, pos))
    if opener >= 0 and ctxs[opener] != "sq":     # a substitution the parser keeps whole: "$(sh -c 'ssh …')"
        close = command.find(")" if command[opener] == "$" else "`", pos)
        inner = command[opener + (2 if command[opener] == "$" else 1):close if close > 0 else len(command)]
        if raw in inner and inner != command and classify(inner, parse).kind != "none":
            return f"'{raw}' in a command substitution"
    if word not in _PROGRAM_WORDS and word != "ssh://":
        return ""                            # rsync:// is rsync's own protocol; .ssh/config: the ~/.ssh rules
    if command[m.end():m.end() + 3] == "://" or word == "ssh://":
        # 4. a URL a program connects to itself (curl scp://, docker -H ssh://), as an argument of its own; in git, sed,
        # or a data value (url=ssh://…) it is text
        own = pos == 0 or command[pos - 1] in " \t\n" or command[pos - 1] in "\"'" and (
            pos == 1 or command[pos - 2] in " \t\n=")
        return f"'{raw}' URL for {cmd}" if seg and own and cmd in _URL_CLIENTS else ""
    k = segs.index(seg) if seg else -1
    later = segs[k + 1:] if seg else segs
    # 2. another part runs text: a command word built at run time, $_, fc, eval (also in a function the line calls).
    # The line names the word, and no parser can tell which text that part runs (S=ssh; $S, x=$(echo …); $x, … ; $_)
    if any(_dynamic_word(command, sg) or _base(sg.get("cmd", "")) in {"eval", "fc"} for sg in segs if sg is not seg):
        return f"'{raw}' in a line that runs a command word it builds at run time"
    if not seg:
        return f"'{raw}' where this hook cannot read the call"
    if _dynamic_word(command, seg):
        return f"'{raw}' in a command word built at run time"
    if re.match(r"\s*command\s+-[vV]\b", command[seg["start"]:seg["end"]]):
        return ""                            # command -v ssh: a lookup
    # a search program that xargs or parallel runs takes the word as its argument: xargs -I{} grep ssh {}. Only
    # there: tmux new -s cat ssh … starts ssh (Opus, review of #15)
    searched = cmd in ("xargs", "parallel") and _program_of(seg) in _DATA_CMDS | _LOOKS_UP
    if words and (_base(words[0]) == word or _base(words[0]).startswith(word + ".")):
        return f"'{raw}' started as a program this hook cannot read"
    # 5. a variable before the command or an option names the program: BROWSER="ssh web1" gh …, rg --pre ssh
    head = _HEAD_ASSIGN.match(command, seg["start"])
    if head and pos < head.end():
        return f"'{raw}' in a variable the command reads as a program"
    if _PROGRAM_OPTION.search(command[seg["start"]:pos]):
        return f"'{raw}' as the program of an option"
    if cmd in _LAUNCHERS and not searched:
        return f"'{raw}' started by {cmd}"
    if cmd == "find" and any(w in _FIND_EXEC for w in words) and \
            min((command.find(w, seg["start"]) for w in _FIND_EXEC if w in words), default=pos) < pos:
        return f"'{raw}' started by find"
    if cmd in _CONTAINER_EXEC and any(w in ("exec", "run", "debug") for w in words[1:3]):
        return f"'{raw}' started in a container"
    if cmd == "git" and _git_runs(words):
        return f"'{raw}' in a git command that runs a program"
    if cmd in ("gh", "glab") and len(words) > 1 and words[1] in _GH_RUNS:
        return f"'{raw}' in a {cmd} command that runs a program"    # 6. gh codespace ssh, gh alias set x '!…'
    if cmd in _SHELLS | {"eval"}:
        code = " ".join(words[1:]) if cmd == "eval" else _shell_code(words)
        if code and raw in code and classify(code, parse).kind != "none":
            return f"'{raw}' in the code of a nested shell"
    elif cmd not in _DATA_CMDS | _LOOKS_UP | _INTERPRETERS:
        # quoted code that another program runs: sg docker -c '…', nix-shell --run "…", op run -- '…'. A word with no
        # space is a name, not code (tox -e ssh); an interpreter's code is outside C21 (python3 -c 'ssh = 1')
        for j, w in enumerate(words[1:-1], 1):
            if w in _CODE_OPTIONS and raw in words[j + 1] and " " in words[j + 1] and words[j + 1] != command \
                    and classify(words[j + 1], parse).kind != "none":
                return f"'{raw}' in the code that {cmd} runs"
    # 3. a shell runs the text: a pipe into it, a file this line wrote, a process substitution it reads
    j = k
    while j + 1 < len(segs) and segs[j + 1].get("piped"):
        j += 1
        if _runs_its_input(segs[j]):
            return f"'{raw}' piped into {_base(segs[j].get('cmd', ''))}"
    runs_input = [sg for sg in later if sg.get("piped") and _runs_its_input(sg)]
    if runs_input:
        return f"'{raw}' in a line that pipes text into {_base(runs_input[0].get('cmd', ''))}"
    writers = [seg]
    j = k
    while j + 1 < len(segs) and segs[j + 1].get("piped"):
        j += 1
        writers.append(segs[j])              # echo 'alias w="ssh …"' | tee -a ~/.zshrc
    why = _write_runs(command, ctxs, segs, writers, seg["start"], raw)
    if why:
        return why                           # 7. a file a later part runs, or a startup file (~/.bashrc)
    opener = command.rfind("<(", 0, pos)
    if opener >= 0 and command.find(")", opener) > pos and any(
            _base(sg.get("cmd", "")) in _SHELLS | _RUN_TEXT for sg in segs if sg["start"] < opener):
        return f"'{raw}' in a process substitution that a shell runs"
    # an unknown program that gets the word as an argument of its own: a launcher not on the list (gtimeout 10 ssh, uv
    # run ssh, op run -- ssh) or a subcommand (gcloud compute ssh, vagrant ssh). Not after an option, whose value it
    # can be (pytest -k ssh), and not for a command that searches, shows or looks up (Opus, review of #15)
    q = 1 if ctx in ("sq", "dq") else 0      # 'ssh' as a word of its own is the same argument (codex, review of #15)
    left = pos - q
    alone = (left <= 0 or command[left - 1] in " \t\n{(") and (q == 0 or command[pos - 1] in "'\"") and \
        (m.end() + q >= len(command) or command[m.end() + q] in " \t\n;&|)}") and \
        (q == 0 or command[m.end():m.end() + 1] in ("'", '"'))
    if alone and cmd not in _DATA_CMDS | _LOOKS_UP | _INTERPRETERS and not searched:
        k_word = next((j for j, w in enumerate(words) if w.lower() == word), -1)
        before_word = [w.lower() for w in words[1:k_word]] if k_word > 0 else []
        prev = words[k_word - 1] if k_word > 0 else ""
        after_option = len(prev) == 2 and prev.startswith("-") and prev != "--" and not set(before_word) & _RUN_VERBS
        if k_word > 0 and not after_option and not set(before_word) & _MANAGE_VERBS:
            return f"'{raw}' as an argument of {cmd}, which can start it"
    # an alias of the word that the same line starts: alias go=ssh; go host
    for a in _ALIAS_RE.finditer(command):
        if a.start(2) <= pos < a.end(2) and _first_word(a.group(2)) in _PROGRAM_WORDS and any(
                _base(sg.get("cmd", "")) == a.group(1).lower() for sg in segs if sg["start"] >= a.end(2)):
            return f"'{raw}' in an alias that the line starts"
    return ""


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
        if re.match(r"\s*command\s+-[vV]\b", command[sg["start"]:sg["end"]]):
            continue                         # command -v ssh: a lookup, the program does not start
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

    def data_only(sg: dict) -> bool:
        text = command[sg["start"]:sg["end"]]
        unq = "".join(ch if cx == "" else " " for ch, cx in zip(text, ctxs[sg["start"]:sg["end"]]))
        return sg.get("cmd") in _DATA_CMDS and not piped_on(sg) and ">" not in _HARMLESS_REDIRECT.sub(" ", unq)

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
        if any(a <= m.start() < b for a, b in spans):
            continue                         # a call read above
        why = _starts_here(command, segs, ctxs, m, parse, fed_by_heredoc, piped_on, data_only)
        if why:
            calls.append(Call(m.group(0), "", "unknown", why))
            break
    if not calls:
        return Verdict("none")
    worst = max(calls, key=lambda c: _RANK[c.kind])
    return Verdict(worst.kind, calls, worst.why)
