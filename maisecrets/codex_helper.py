"""The Client-Vault header for Codex: the `http_headers_helper` of a user-scope MCP server entry.

Codex runs this command when it connects to the server, in the folder of the session, with a cleared environment,
and sends the JSON object it prints as HTTP headers to the origin of the server's URL (codex-cli 0.162.0, measured:
MCP requests and the authorization-code token request; never the browser leg). A static `http_headers` entry would
not be safe: a repository's `.codex/config.toml` merges over the user's config and can set another URL for the same
entry, and the static header then goes to that URL (measured). This helper prints the header only when:

- the state file of maisecrets names this entry of this config file, with this URL, and a header;
- the user's config.toml still has this entry with this URL, and no profile of the user can change it;
- no project layer of the session folder (`<folder>/.codex/config.toml`, from the folder up to the root) has any
  `mcp_servers` table, and every such file parses;
- this Codex process gave the header at its first run, in this same folder. Codex fixes the server URLs when a
  session starts and runs the helper again later (a reconnect after the folder of the session changed, a retry after
  401 or 403), so only the first answer of a process sees the project layers that Codex used (Gate B review).

In every other case it prints `{}`. It never exits with an error and ends within 3 s: a helper that fails or takes
longer than 10 s stops Codex from connecting to the server (measured), and the command line in config.toml also ends
in `|| echo '{}'`. Standard library only, Python 3.11 or later (tomllib); the hooks import the same checks.

Usage (Codex runs it): python3 -I codex_helper.py <state file> <CODEX_HOME> <server name> <server URL>
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import time

HEADER = "Client-Vault"
_HEADER_RE = re.compile(r"v=1, kid=:[A-Za-z0-9+/]{43}=:")
MAX_FILE = 4 * 1024 * 1024            # a config file larger than this is not read: no header
DEADLINE = 3                          # seconds; Codex stops a helper after 10
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "busybox"}
RUN_TTL = 30 * 24 * 3600              # the record of a Codex process is kept this long
FIRST_WINDOW = 120                    # seconds: only a Codex process this young can make its first run
LOCK_STALE = 2                        # seconds, below DEADLINE: a lock of a helper the alarm ended goes in time


def _toml():
    try:
        import tomllib
    except ImportError:               # Python before 3.11
        return None
    return tomllib


def load(path: str) -> dict | None:
    """The parsed TOML file, or None when it is missing, no regular file, too large, unreadable or not TOML. The open
    does not block: a FIFO at the path would hold the helper past the deadline of Codex (Gate A and Gate B review)."""
    toml = _toml()
    if toml is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as f:
                raw = f.read(MAX_FILE + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_FILE:
            return None
        data = toml.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _mentions_servers(node: object, depth: int = 0) -> bool:
    """Any key `mcp_servers` at any depth: a project layer can also carry servers inside a profile table."""
    if depth > 64:
        return True
    if isinstance(node, dict):
        return any(k == "mcp_servers" or _mentions_servers(v, depth + 1) for k, v in node.items())
    if isinstance(node, list):
        return any(_mentions_servers(v, depth + 1) for v in node)
    return False


def _ancestors(folder: str) -> list[str]:
    out: list[str] = []
    for start in (os.path.abspath(folder), os.path.realpath(folder)):
        d = start
        while True:
            if d not in out:
                out.append(d)
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    return out


def _is_codex_home(dot: str, codex_home: str) -> bool:
    return os.path.abspath(dot) == os.path.abspath(codex_home) or os.path.realpath(dot) == os.path.realpath(codex_home)


def project_brings_servers(folder: object, codex_home: str) -> bool:
    """True when a project layer of this session folder has an `mcp_servers` table, when such a file cannot be read
    or parsed, or when the folder is unknown. Codex reads `<dir>/.codex/config.toml` from the project root down to the
    folder; this looks from the folder up to the file system root, which is the same set or more. The `.codex`
    folder that is the user's CODEX_HOME is the user layer, not a project layer (Codex skips it too); it is compared
    as given and resolved, because a linked config.toml says nothing about where CODEX_HOME is (Gate B review)."""
    if not isinstance(folder, str) or not folder or not os.path.isabs(folder) or _toml() is None:
        return True
    for d in _ancestors(folder):
        dot = os.path.join(d, ".codex")
        if _is_codex_home(dot, codex_home):
            continue
        path = os.path.join(dot, "config.toml")
        if not os.path.lexists(path):
            continue
        data = load(path)
        if data is None or _mentions_servers(data):
            return True
    return False


def user_entry_is_plain(data: dict | None, name: str, url: str) -> bool:
    """The user's config has this entry with this URL as its own, and no profile of the user can replace it: a top
    level `profile` key, or `mcp_servers` inside `profiles`, could give the entry another URL."""
    if not isinstance(data, dict) or "profile" in data or _mentions_servers(data.get("profiles")):
        return False
    servers = data.get("mcp_servers")
    spec = servers.get(name) if isinstance(servers, dict) else None
    return isinstance(spec, dict) and spec.get("url") == url and "command" not in spec


def profile_files_bring_servers(codex_home: str) -> bool:
    """A profile file `<CODEX_HOME>/<name>.config.toml` (selected with --profile) that has servers, or that does not
    parse."""
    try:
        names = os.listdir(codex_home)
    except OSError:
        return True
    for n in names:
        if n.endswith(".config.toml"):
            data = load(os.path.join(codex_home, n))
            if data is None or _mentions_servers(data):
                return True
    return False


# ------------------------------------------------------- the Codex process --
def _proc_linux(pid: int) -> tuple[int, str, str, float] | None:
    """(parent pid, command name, start time, age in seconds) from /proc."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    left, right = text.find("("), text.rfind(")")
    if left < 0 or right < left:
        return None
    rest = text[right + 2:].split()
    try:
        with open("/proc/stat", encoding="ascii", errors="replace") as f:
            boot = next(int(ln.split()[1]) for ln in f if ln.startswith("btime "))
        started = boot + int(rest[19]) / os.sysconf("SC_CLK_TCK")
        return int(rest[1]), text[left + 1:right], rest[19], time.time() - started
    except (IndexError, ValueError, StopIteration, OSError):
        return None


def _proc_ps(pid: int) -> tuple[int, str, str, float] | None:
    """(parent pid, command name, start time, age in seconds) from ps (macOS and other systems without /proc)."""
    import subprocess
    try:
        out = subprocess.run(["ps", "-o", "ppid=,lstart=,comm=", "-p", str(pid)], capture_output=True, text=True,
                             timeout=1.5, env={"PATH": "/bin:/usr/bin", "LC_ALL": "C"}).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None
    if len(out) < 7:
        return None
    try:
        start = " ".join(out[1:6])
        age = time.time() - time.mktime(time.strptime(start, "%a %b %d %H:%M:%S %Y"))
        return int(out[0]), " ".join(out[6:]), start, age
    except (ValueError, OverflowError):
        return None


def codex_process() -> tuple[str, float] | None:
    """(`<pid>:<start time>`, age in seconds) of the process that started this helper: the nearest ancestor that is no
    shell (Codex runs the command with `sh -c`). None when it cannot be told."""
    read = _proc_linux if os.path.isdir("/proc/self") else _proc_ps
    pid = os.getppid()
    for _ in range(4):
        info = read(pid)
        if info is None:
            return None
        parent, name, start, age = info
        if os.path.basename(name).lstrip("-") not in SHELLS:
            return f"{pid}:{start}", age
        pid = parent
    return None


def first_answer(runs_file: str, proc: str, folder: str, fresh: bool, age: float) -> bool:
    """The answer of this Codex process for this entry: the first run records its folder and its answer; a later run
    gives the header only when the first one did, in the same folder, and this one would too. Any `{}` stays. Deny by
    default: a run with no record counts as the first only while the process is younger than FIRST_WINDOW, so a first
    run that failed (a busy lock, the alarm) never lets a later run in another folder count as first, and neither
    does a record that expired (Gate A and Gate B review, round 2). A file that cannot be read or written gives no
    header."""
    lock = runs_file + ".lock"
    deadline = time.time() + 1.0
    while True:
        try:
            os.mkdir(lock, 0o700)
            break
        except FileExistsError:
            try:
                if time.time() - os.stat(lock).st_mtime > LOCK_STALE:
                    os.rmdir(lock)
                    continue
            except OSError:
                continue
            if time.time() > deadline:
                return False
            time.sleep(0.02)
        except OSError:
            return False
    try:
        try:
            with open(runs_file, encoding="utf-8") as f:
                runs = json.load(f)
        except FileNotFoundError:
            runs = {}
        except (OSError, ValueError, RecursionError):
            return False
        runs = runs if isinstance(runs, dict) else {}
        now = time.time()
        rec = runs.get(proc)
        runs = {k: v for k, v in runs.items() if isinstance(v, dict) and isinstance(v.get("t"), (int, float))
                and now - v["t"] < RUN_TTL}
        if not isinstance(rec, dict) or not isinstance(rec.get("t"), (int, float)):
            ok = fresh and 0 <= age < FIRST_WINDOW
            runs[proc] = {"cwd": folder, "ok": ok, "t": now}
        else:
            ok = bool(rec.get("ok")) and rec.get("cwd") == folder and fresh
            runs[proc] = {"cwd": rec.get("cwd"), "ok": ok, "t": rec["t"]}
        tmp = f"{runs_file}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(runs, f)
        os.replace(tmp, runs_file)
        return ok
    except OSError:
        return False
    finally:
        try:
            os.rmdir(lock)
        except OSError:
            pass


def entry_header(state_file: str, codex_home: str, name: str, url: str, folder: str) -> str | None:
    """The header value when every check of this run holds, without the record of the process; or None."""
    try:
        with open(state_file, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError, RecursionError):
        return None
    profile = os.path.realpath(os.path.join(codex_home, "config.toml"))
    mine = state.get(profile) if isinstance(state, dict) else None
    rec = mine.get(name) if isinstance(mine, dict) else None
    if not isinstance(rec, dict) or rec.get("url") != url:
        return None
    header = rec.get("header")
    if not isinstance(header, str) or not _HEADER_RE.fullmatch(header):
        return None
    if not user_entry_is_plain(load(profile), name, url) or profile_files_bring_servers(codex_home):
        return None
    if project_brings_servers(folder, codex_home):
        return None
    return header


def header_for(state_file: str, codex_home: str, name: str, url: str, folder: str) -> str | None:
    """The header for this entry in this run, or None."""
    header = entry_header(state_file, codex_home, name, url, folder)
    found = codex_process()
    if found is None:
        return None
    proc, age = found
    runs = os.path.join(os.path.dirname(state_file), "codex-helper-runs.json")
    key = f"{proc}\0{os.path.realpath(os.path.join(codex_home, 'config.toml'))}\0{name}"
    return header if first_answer(runs, key, folder, header is not None, age) else None


def _answer(header: str | None) -> None:
    os.write(1, json.dumps({HEADER: header} if header else {}).encode())


def main(argv: list[str]) -> int:
    if hasattr(os, "fork"):
        import signal

        def late(*_a) -> None:
            _answer(None)
            os._exit(0)
        signal.signal(signal.SIGALRM, late)
        signal.alarm(DEADLINE)
    header = None
    try:
        if len(argv) == 4:
            header = header_for(argv[0], argv[1], argv[2], argv[3], os.getcwd())
    except Exception:  # noqa: BLE001 - a helper that fails stops the server: never
        header = None
    if hasattr(os, "fork"):
        import signal
        signal.alarm(0)
    _answer(header)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
