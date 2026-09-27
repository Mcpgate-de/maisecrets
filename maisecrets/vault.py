"""The local vault: put, get, list, expire.

Values live in a backend. Metadata (type, fingerprint, created, last used,
expiry, display) lives in an index file under ``~/.maisecrets/`` that never
holds a value. When an entry expires, the value is deleted and the metadata
stays as a record of what went through.

Backends:
  * ``JsonFileBackend`` -- Day-1 test mode. Plaintext JSON, mode 0600, under
    ``~/.maisecrets/``. Never in a project directory. Marked ``test_mode``.
  * ``KeychainBackend`` -- macOS ``security`` CLI, generic passwords under one
    service name, no ``synchronizable`` flag, so nothing reaches iCloud.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import platform
import subprocess
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .placeholder import display_for

HOME = Path(os.environ.get("MAISECRETS_HOME", Path.home() / ".maisecrets"))
INDEX = HOME / "index.json"
CONFIG = HOME / "config.json"
# The keychain namespace is per service name, not per vault home. A second home
# (tests, the harness, a latency run) minted SECRET_c1 too and a cleanup deleted
# the real SECRET_c1 (2026-09-26). So every home other than the default gets its
# own service name.
_DEFAULT_HOME = Path.home() / ".maisecrets"
SERVICE = "maisecrets" if HOME == _DEFAULT_HOME else "maisecrets@" + hashlib.sha256(str(HOME).encode()).hexdigest()[:8]

DEFAULT_CONFIG = {
    "backend": "keychain",          # keychain (macOS) | windows-vault | encrypted-file (Linux) | jsonfile (test)
    "report_url": "https://github.com/Mcpgate-de/maisecrets/issues",   # shown in the block notice
    "ttl_seconds": {"default": 86400, "CARD": 3600},
    "max_ttl_seconds": 30 * 86400,
    "renew_on_use": True,
    "scrub_transcript": True,
    "block_at_mentions": True,
    "gateway_servers": [],           # MCP servers that resolve placeholders themselves (PROTOCOL §4); none by default
    "pii_regions": ["generic", "de"],
    "max_new_entries_per_result": 100,   # above this, a tool result is masked without storing more values
    "resolve_in_files": True,        # Write/Edit content resolves a placeholder like an MCP argument
    "shortcut": True,                # the first SessionStart names /maisecrets:shortcut once; it installs nothing
    "keep_purged_days": 30,          # metadata of an expired entry is deleted after this many days
    "audit_max_lines": 2000,
}

# a machine-wide policy the administrator writes; its keys win over the user file and the
# environment and cannot be changed from ~/.maisecrets (operator review, 2026-09-26)
POLICY_PATHS = {
    "Darwin": Path("/Library/Application Support/maisecrets/policy.json"),
    "Windows": Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "maisecrets" / "policy.json",
    "Linux": Path("/etc/maisecrets/policy.json"),
}
_CONFIG_TYPES = {
    "backend": str, "report_url": (str, type(None)), "ttl_seconds": dict, "max_ttl_seconds": int,
    "renew_on_use": bool, "scrub_transcript": bool, "block_at_mentions": bool, "gateway_servers": list,
    "pii_regions": list, "max_keys_per_session": int, "max_resolves_per_hour": int, "tips": bool,
    "max_new_entries_per_result": int, "keep_purged_days": int, "audit_max_lines": int,
    "allow_plaintext_store": bool, "resolve_in_files": bool, "shortcut": bool,
}


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write via a per-process temp file and an atomic rename. A shared temp name
    (``index.tmp``) let two hook processes running at once replace each other's file; the
    second one then failed with FileNotFoundError and the hook blocked the tool call
    (Codex with two plugin copies, 2026-09-26)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        # Windows refuses to replace a file another process has open for reading (WinError 5
        # in the 12-process test on windows-latest, 2026-09-26); a reader holds it for
        # milliseconds, so retry briefly instead of failing the hook
        for attempt in range(40):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 39:
                    raise
                time.sleep(0.05)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def read_text_retry(path: Path, attempts: int = 40) -> str:
    """Read a file that another hook process may be replacing right now. Windows raises
    PermissionError for the reader while os.replace runs on the same name (the 12-process test
    on windows-latest, 2026-09-27; the writer side got its retry on 2026-09-26). The window is
    milliseconds, so retry briefly; the last attempt raises."""
    for attempt in range(attempts):
        try:
            return path.read_text(encoding="utf-8")
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)
    raise AssertionError("unreachable")


_LOCKS: dict = {}


def _lock_for(path: Path) -> "_Lock":
    """One lock object per path and process, shared by every Vault in the process: a second
    flock on a second descriptor would wait for the first (measured: two Vault objects in one
    process deadlocked)."""
    key = str(path)
    if key not in _LOCKS:
        _LOCKS[key] = _Lock(path)
    return _LOCKS[key]


class LockTimeout(RuntimeError):
    pass


class _Lock:
    """An exclusive lock per vault home, taken around each read-modify-write of the index and
    released right after. Not held for a process's lifetime: a long-lived holder starved every
    hook, and a Codex hook that times out is fail-OPEN (measured 2026-09-26). Re-entrant within
    the process. A lock that cannot be taken within ``LOCK_DEADLINE`` raises, so the hook fails
    closed with a reason instead of hanging into the client's timeout, which fails open."""
    LOCK_DEADLINE = 6.0

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd = None
        self.depth = 0

    def __enter__(self):
        self.depth += 1
        if self.depth > 1:
            return self
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.time() + self.LOCK_DEADLINE
        try:
            while True:
                try:
                    try:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except ImportError:
                        import msvcrt
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise LockTimeout(f"vault lock busy for {self.LOCK_DEADLINE:.0f}s ({self.path})")
                    time.sleep(0.02)
        except BaseException:
            os.close(fd)
            self.depth -= 1
            raise
        self.fd = fd
        return self

    def __exit__(self, *exc) -> None:
        self.depth -= 1
        if self.depth > 0 or self.fd is None:
            return
        try:
            try:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except ImportError:
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            os.close(self.fd)
            self.fd = None


class ConfigError(RuntimeError):
    """A config value of the wrong type; the message names the key, never a value."""


def _check_types(cfg: dict, source: str) -> None:
    for key, want in _CONFIG_TYPES.items():
        if key in cfg and (not isinstance(cfg[key], want) or (want is int and isinstance(cfg[key], bool))):
            raise ConfigError(f"{source}: {key} has the wrong type")
    ttl = cfg.get("ttl_seconds")
    if isinstance(ttl, dict) and not all(isinstance(v, int) for v in ttl.values()):
        raise ConfigError(f"{source}: ttl_seconds values must be integers")


def load_config() -> dict:
    """Defaults, then ~/.maisecrets/config.json, then CLAUDE_PLUGIN_OPTION_<KEY> if a client passes
    plugin options that way, then the machine policy file, whose keys win. The manifest declares
    no `userConfig`: Claude Code 2.1.223 rejects a manifest with that key as invalid and then
    loads NO hook at all (measured on Debian, 2026-09-26), and a guard that silently vanishes
    on an older client is worse than a guard without a settings dialog. A wrong type raises
    ConfigError with the key name: a silent AttributeError later locked the user out with no
    hint at the config (review, 2026-09-26)."""
    import copy
    import platform as _platform
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["config_warning"] = ""
    try:
        user = json.loads(CONFIG.read_text(encoding="utf-8"))
        if not isinstance(user, dict):
            raise ConfigError(f"{CONFIG.name} must hold one JSON object")
        _check_types(user, CONFIG.name)
    except OSError:
        user = {}
    except ValueError:
        # the user file is advisory: a typo must not lock the user out of the client (review,
        # 2026-09-26). The defaults are the strict values, so the fallback loosens nothing; the
        # warning is shown at session start and in the block notice.
        user = {}
        cfg["config_warning"] = f"{CONFIG.name} is not valid JSON and was ignored"
    except ConfigError as exc:
        user = {}
        cfg["config_warning"] = f"{exc}; the file was ignored"
    unknown = sorted(k for k in user if k not in _CONFIG_TYPES)
    if unknown:
        cfg["config_warning"] = (cfg["config_warning"] + "; " if cfg["config_warning"] else "") + \
            f"{CONFIG.name}: unknown key(s) {', '.join(unknown)} ignored"
        user = {k: v for k, v in user.items() if k in _CONFIG_TYPES}
    cfg.update(user)
    env = os.environ
    backend = env.get("CLAUDE_PLUGIN_OPTION_BACKEND", "").strip()
    if backend and backend != "auto":
        cfg["backend"] = backend
    regions = env.get("CLAUDE_PLUGIN_OPTION_PII_REGIONS", "").strip()
    if regions:
        cfg["pii_regions"] = ["generic"] + [r.strip().lower() for r in regions.split(",") if r.strip()]
    ttl = env.get("CLAUDE_PLUGIN_OPTION_TTL_HOURS", "").strip()
    if ttl:
        try:
            cfg.setdefault("ttl_seconds", {})["default"] = int(float(ttl) * 3600)
        except ValueError:
            pass
    if env.get("CLAUDE_PLUGIN_OPTION_REPORT_URL", "").strip():
        cfg["report_url"] = env["CLAUDE_PLUGIN_OPTION_REPORT_URL"].strip()
    policy_path = POLICY_PATHS.get(_platform.system())
    cfg["policy_keys"] = []
    if policy_path is not None:
        try:
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
        except OSError:
            policy = {}
        except ValueError as exc:
            raise ConfigError(f"{policy_path} is not valid JSON") from exc
        if not isinstance(policy, dict):
            # valid JSON of another shape was skipped silently: no policy applied at all
            raise ConfigError(f"{policy_path} must hold one JSON object")
        _check_types(policy, policy_path.name)
        cfg.update(policy)
        cfg["policy_keys"] = sorted(policy)
    cfg["max_ttl_seconds"] = min(int(cfg.get("max_ttl_seconds", 30 * 86400)), 30 * 86400)
    if cfg.get("backend") == "jsonfile" and not cfg.get("allow_plaintext_store", False):
        # the plaintext store is for tests and the harness, which say so in their own config
        raise ConfigError("backend jsonfile is the TEST store; set allow_plaintext_store to use it")
    return cfg


def describe_backend(backend) -> str:
    """One line for a human: which store, where, and how to change it."""
    name = type(backend).__name__
    where = {
        "KeychainBackend": f"macOS login keychain, service '{SERVICE}' (Keychain Access shows the entries)",
        "WindowsVaultBackend": f"Windows Credential Locker, resource '{SERVICE}' (Settings > Credential Manager)",
        "EncryptedFileBackend": f"encrypted file {HOME / 'vault.enc.json'} (openssl, key file {HOME / 'key'})",
        "JsonFileBackend": f"PLAINTEXT file {HOME / 'vault.json'} - TEST MODE, not for real secrets",
    }.get(name, name)
    return (f"maisecrets vault: {where}. Metadata: {INDEX}. "
            f"To change it: write {{\"backend\": \"encrypted-file\"}} to {CONFIG} (takes effect on the next call). "
            "Free and open source, by mcpgate.de.")


def intro_line(backend) -> str:
    """The first session start, for a person: what maisecrets does and where values stay. The
    paths, the backend switch and the file names are in /maisecrets:status (UX review,
    2026-09-27: JSON and file paths at the first start told a non-developer to change a setting
    their IT owns)."""
    where = {
        "KeychainBackend": "in the macOS Keychain",
        "WindowsVaultBackend": "in the Windows Credential Locker",
        "EncryptedFileBackend": "in an encrypted file",
        "JsonFileBackend": "in a PLAIN TEXT test file (test mode, not for real secrets)",
    }.get(type(backend).__name__, "in the local store")
    return (f"It keeps passwords, keys and personal data out of the AI: a prompt that holds one is "
            f"stopped, and the value stays on this computer, {where}.")


FP_KEY_ENTRY = "_maisecrets_fpkey"   # backend key that holds the fingerprint key (32 random bytes, hex)


def fingerprint(value: str, key: bytes) -> str:
    """Keyed fingerprint. An unkeyed hash of a short value (a phone number, a PIN) can
    be reversed by trying every candidate against the index file; the key lives in the
    backend, so the index alone gives nothing to try against."""
    import hmac
    return hmac.new(key, value.encode(), "sha256").hexdigest()[:16]


@dataclass
class Entry:
    key: str            # EMAIL_c1
    type: str           # EMAIL
    kind: str           # pattern name that found it
    fingerprint: str
    display: str | None
    created: float
    last_used: float
    expires: float
    max_expires: float
    session: str | None = None          # the session that created the entry
    uses: int = 0
    purged: bool = False
    counters: dict = field(default_factory=dict)  # unused on entries; kept for schema stability
    sessions: list = field(default_factory=list)  # sessions allowed to resolve the entry (see Vault.get)
    # no purged_at field: from_meta drops it, so the proof below can remove the filter and
    # the owning test sees the TypeError of the field report again

    @classmethod
    def from_meta(cls, meta: dict) -> "Entry":
        """An Entry from an index record, ignoring fields this version does not know. expire wrote
        `purged_at` into the index while Entry had no such field, so every read of an expired
        entry raised TypeError: /maisecrets:status and list failed, and a value pasted again after
        it expired blocked the prompt (field report, 2026-09-27). A record written by a newer
        version must not break an older one either."""
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in meta.items() if k in names})

    @property
    def ref(self) -> str:
        from .placeholder import CLOSE, OPEN
        return f"{OPEN}{self.key}:{self.display}{CLOSE}" if self.display else f"{OPEN}{self.key}{CLOSE}"


# ---------------------------------------------------------------- backends --
class JsonFileBackend:
    test_mode = True

    def __init__(self) -> None:
        self.path = HOME / "vault.json"

    def _load(self, for_write: bool = False) -> dict:
        try:
            return json.loads(read_text_retry(self.path))
        except OSError:
            return {}
        except ValueError:
            if for_write:
                raise RuntimeError("vault store file unreadable; not overwritten")
            return {}

    def _save(self, data: dict) -> None:
        atomic_write(self.path, json.dumps(data))

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        d = self._load(for_write=True)
        d[key] = value
        self._save(d)

    def get(self, key: str) -> str | None:
        return self._load().get(key)

    def delete(self, key: str) -> None:
        d = self._load(for_write=True)
        d.pop(key, None)
        self._save(d)

    def keys(self) -> list[str]:
        return list(self._load())


def parse_keychain_dump(text: str, service: str) -> list[str]:
    """The account names of every item of ``service`` in a `security dump-keychain` listing
    (attributes only). An item starts at a `keychain:` line; inside it the attributes are
    alphabetical, so "acct" comes before "svce"."""
    out: list[str] = []
    acct = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("keychain:"):
            acct = None
        elif line.startswith('"acct"<blob>='):
            acct = line.split("=", 1)[1].strip('"')
        elif line.startswith('"svce"<blob>=') and line.split("=", 1)[1].strip('"') == service and acct:
            out.append(acct)
    return out


def _run_store(what: str, args: list[str], **kw) -> subprocess.CompletedProcess:
    """subprocess.run for a store call. A call that hits its timeout raised TimeoutExpired, which
    passed every `except RuntimeError` of the sweep, forget and wipe, and whose text lists the
    argv, the value included on the keychain's long-value path (CLI test agent, 2026-09-27)."""
    try:
        return subprocess.run(args, **kw)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{what} call timed out") from None


class KeychainBackend:
    """macOS login keychain via the ``security`` CLI. No sync flag is set."""
    test_mode = False

    MAX_LINE = 3900   # `security -i` line limit is 4096 bytes; the rest would run as a command

    @staticmethod
    def _q(s: str) -> str:
        """Quote one argument for the `security -i` command reader (double quotes, backslash escapes)."""
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _interactive(self, line: str) -> subprocess.CompletedProcess:
        # `security -i` reads commands from stdin, so the value never sits on a command line where
        # `ps` of any local user shows it during the call (review, 2026-09-26)
        return _run_store("keychain", ["security", "-i"], input=(line + "\n").encode("utf-8"),
                              capture_output=True, timeout=5)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        # -l is the "Name" column in Keychain Access, -j the comment shown in the item's info.
        # The item's ACL trusts /usr/bin/security, the tool that created it, so ANY process of
        # this user that runs `security find-generic-password` reads the value without a dialog
        # (review 2026-09-26, docs/reviews). The keychain protects the value at rest and from
        # other users, not from this user's other processes. The gates are in the hooks.
        # No synchronizable flag: the item never joins iCloud Keychain or the Passwords app.
        # the value is stored base64-encoded with a marker: `find-generic-password -w` prints a
        # non-ASCII value as hex, so an umlaut never came back equal (measured 2026-09-26)
        import base64
        stored = "b64:" + base64.b64encode(value.encode("utf-8")).decode("ascii")
        parts = ["add-generic-password", "-U", "-s", self._q(SERVICE), "-a", self._q(key),
                 "-l", self._q(label or f"maisecrets {key}"), "-D", self._q("maisecrets placeholder"),
                 "-w", self._q(stored)]
        if comment:
            parts += ["-j", self._q(comment)]
        # no check=True: CalledProcessError prints the argument list, and an error text can reach
        # the model as a block reason (Codex review, 2026-09-26)
        line = " ".join(parts)
        if len(line.encode("utf-8")) <= self.MAX_LINE:
            r = self._interactive(line)
        else:
            # `security -i` reads at most 4096 bytes per line and runs the rest as a second
            # command (review, 2026-09-26: a 4096-bit PEM key). A long value goes on the
            # command line instead: the value is then visible to `ps` of any local user for the
            # milliseconds of the call, the trade documented in the README
            r = _run_store("keychain", ["security", "add-generic-password", "-U", "-s", SERVICE, "-a", key,
                                "-l", label or f"maisecrets {key}", "-D", "maisecrets placeholder",
                                "-w", stored] + (["-j", comment] if comment else []),
                               capture_output=True, timeout=5)
        if r.returncode != 0:
            raise RuntimeError(f"keychain add failed (rc {r.returncode})")
        if self.get(key) != value:
            raise RuntimeError("keychain add failed (read-back differs)")

    def get(self, key: str) -> str | None:
        r = _run_store(
            "keychain",
            ["security", "find-generic-password", "-s", SERVICE, "-a", key, "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return None
        raw = r.stdout.rstrip("\n")
        if raw.startswith("b64:"):
            import base64
            try:
                return base64.b64decode(raw[4:]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None
        return raw   # an entry written before 0.3.22

    def delete(self, key: str) -> None:
        r = _run_store(
            "keychain",
            ["security", "delete-generic-password", "-s", SERVICE, "-a", key],
            capture_output=True, timeout=5,
        )
        # rc 44: no such item, which is the wanted end state; anything else keeps the entry
        # unpurged so the next sweep tries again (review, 2026-09-26)
        if r.returncode not in (0, 44):
            raise RuntimeError(f"keychain delete failed (rc {r.returncode})")

    def keys(self) -> list[str]:
        """Every account of the service, from the attribute dump (no secrets are printed without
        -d), so a damaged index can be rebuilt and an orphan item found (review, 2026-09-26)."""
        r = _run_store("keychain", ["security", "dump-keychain"], capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return []
        return parse_keychain_dump(r.stdout, SERVICE)

    def wipe(self) -> int:
        """Delete every item of the service, one call per item until none is left: the store is
        enumerated by deleting, so an item whose index entry is gone goes too. Raises when an
        item refuses to go (a locked keychain), so the caller never reports a wipe that did not
        happen."""
        n = 0
        for _ in range(10000):
            r = _run_store("keychain", ["security", "delete-generic-password", "-s", SERVICE],
                               capture_output=True, timeout=5)
            if r.returncode == 44:
                break
            if r.returncode != 0:
                raise RuntimeError(f"keychain delete failed (rc {r.returncode})")
            n += 1
        return n


class EncryptedFileBackend:
    """Linux servers and anywhere without a keychain: values encrypted at rest with
    ``openssl enc`` (AES-256-CBC, PBKDF2) plus an HMAC-SHA256 tag, key in a 0600 file.

    The key file is ``~/.maisecrets/key`` or ``$MAISECRETS_KEY_FILE`` (a root-managed
    path on a server). Without the key the vault file is noise. This is not a
    hardware-backed store: a process running as the same user can read the key,
    exactly as it could read the keychain on a Mac.
    """
    test_mode = False

    def __init__(self) -> None:
        self.path = HOME / "vault.enc.json"
        self.key_file = Path(os.environ.get("MAISECRETS_KEY_FILE", HOME / "key"))

    def _key(self) -> bytes:
        if not self.key_file.exists():
            self.key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(os.urandom(32).hex() + "\n")
        return self.key_file.read_bytes().strip()

    def _openssl(self, args: list[str], data: bytes) -> bytes:
        r = _run_store("openssl", ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-salt",
                            "-pass", f"file:{self.key_file}", *args], input=data, capture_output=True, timeout=5)
        if r.returncode != 0:
            raise RuntimeError("openssl failed: " + r.stderr.decode(errors="ignore")[:200])
        return r.stdout

    def _tag(self, blob: bytes) -> str:
        import hmac
        return hmac.new(hashlib.sha256(b"maisecrets-mac:" + self._key()).digest(), blob, "sha256").hexdigest()

    def _load(self, for_write: bool = False) -> dict:
        try:
            return json.loads(read_text_retry(self.path))
        except OSError:
            return {}
        except ValueError:
            # a damaged vault file must not be replaced by one with a single new entry: every
            # other value would be lost without a message (review, 2026-09-26)
            if for_write:
                raise RuntimeError("vault store file unreadable; not overwritten")
            return {}

    def _save(self, data: dict) -> None:
        atomic_write(self.path, json.dumps(data))

    def keys(self) -> list[str]:
        return list(self._load())

    def wipe(self) -> int:
        n = len(self._load())
        for f in (self.path, self.key_file):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                # a file that stays holds the values: never count it as wiped
                raise RuntimeError(f"{f.name} not deleted ({type(exc).__name__})") from exc
        return n

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        import base64
        self._key()
        blob = self._openssl([], value.encode())
        d = self._load(for_write=True)
        d[key] = {"c": base64.b64encode(blob).decode(), "t": self._tag(blob)}
        self._save(d)

    def get(self, key: str) -> str | None:
        import base64
        import hmac
        entry = self._load().get(key)
        if not entry:
            return None
        blob = base64.b64decode(entry["c"])
        if not hmac.compare_digest(self._tag(blob), entry.get("t", "")):
            return None   # tampered or foreign key: fail closed
        try:
            return self._openssl(["-d"], blob).decode()
        except RuntimeError:
            return None

    def delete(self, key: str) -> None:
        d = self._load(for_write=True)
        d.pop(key, None)
        self._save(d)


class WindowsVaultBackend:
    """Windows: the per-user Credential Locker (``Windows.Security.Credentials.PasswordVault``),
    DPAPI-backed, reached through PowerShell. No module to install; the entries show up in
    Settings > Credential Manager under the resource name ``maisecrets``."""
    test_mode = False
    _PRELUDE = ("[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]"
                " | Out-Null; $v = New-Object Windows.Security.Credentials.PasswordVault; ")

    def _ps(self, script: str, stdin: str = "") -> subprocess.CompletedProcess:
        return _run_store("Credential Locker",
                          ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PRELUDE + script],
                          input=stdin, capture_output=True, text=True, timeout=15)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        # the value travels via stdin as base64, never as a command-line argument and never as
        # text the console code page could re-encode (review, 2026-09-26: Windows PowerShell 5.1
        # reads a redirected stdin in the OEM code page)
        import base64
        b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
        r = self._ps("$b = [Console]::In.ReadToEnd().Trim(); "
                     "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)); "
                     f"try {{ $old = $v.Retrieve('{SERVICE}', '{key}'); $v.Remove($old) }} catch {{}}; "
                     f"$v.Add((New-Object Windows.Security.Credentials.PasswordCredential('{SERVICE}', '{key}', $p)))",
                     stdin=b64)
        if r.returncode != 0:
            raise RuntimeError(f"PasswordVault add failed (rc {r.returncode})")

    def get(self, key: str) -> str | None:
        import base64
        r = self._ps(f"try {{ $c = $v.Retrieve('{SERVICE}', '{key}'); $c.RetrievePassword(); "
                     "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($c.Password))) } "
                     "catch { exit 3 }")
        if r.returncode != 0:
            return None
        try:
            return base64.b64decode(r.stdout.strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def delete(self, key: str) -> None:
        self._ps(f"try {{ $v.Remove($v.Retrieve('{SERVICE}', '{key}')) }} catch {{}}")

    def keys(self) -> list[str]:
        r = self._ps(f"try {{ $v.FindAllByResource('{SERVICE}') | ForEach-Object {{ $_.UserName }} }} catch {{}}")
        return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()] if r.returncode == 0 else []

    def get_many(self, keys: list[str]) -> dict[str, str]:
        """All values in one PowerShell start (each start costs hundreds of milliseconds; one
        per key on every tool result reached the watchdog; review, 2026-09-26)."""
        import base64
        if not keys:
            return {}
        wanted = ",".join("'" + k + "'" for k in keys if re.fullmatch(r"[A-Z][A-Z_]*_c\d{1,9}", k))
        r = self._ps("foreach ($k in @(" + wanted + ")) { try { "
                     f"$c = $v.Retrieve('{SERVICE}', $k); $c.RetrievePassword(); "
                     "[Console]::Out.WriteLine($k + ' ' + "
                     "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($c.Password))) "
                     "} catch {} }")
        out: dict[str, str] = {}
        if r.returncode != 0:
            return out
        for ln in r.stdout.splitlines():
            k, _sp, b = ln.strip().partition(" ")
            try:
                out[k] = base64.b64decode(b).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
        return out

    def wipe(self) -> int:
        keys = self.keys()
        for k in keys:
            self.delete(k)
        return len(keys)


def make_backend(cfg: dict):
    """keychain on macOS; an openssl-encrypted file elsewhere; jsonfile only when asked (test mode)."""
    backend = cfg.get("backend", "keychain")
    if backend == "jsonfile":
        return JsonFileBackend()
    if backend == "encrypted-file":
        return EncryptedFileBackend()
    if backend == "windows-vault":
        return WindowsVaultBackend()
    if platform.system() == "Darwin":
        return KeychainBackend()
    if platform.system() == "Windows":
        return WindowsVaultBackend()
    return EncryptedFileBackend()


def _mutating(fn):
    """Run the method as one read-modify-write under the vault lock."""
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._exclusive():
            return fn(self, *args, **kwargs)
    return wrapper


class _Mutation:
    def __init__(self, vault: "Vault") -> None:
        self.vault = vault

    def __enter__(self):
        self.vault._lock.__enter__()
        if self.vault._lock.depth == 1:
            try:
                self.vault._index = self.vault._load_index()
            except BaseException:
                # `with` calls __exit__ only after __enter__ returned: a damaged index kept the lock
                self.vault._lock.__exit__(None, None, None)
                raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None and self.vault._lock.depth == 1:
                self.vault._save_index()
        finally:
            self.vault._lock.__exit__(exc_type, exc, tb)


# ------------------------------------------------------------------- vault --
class Vault:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or load_config()
        self.backend = make_backend(self.cfg)
        self._lock = _lock_for(HOME / ".lock")
        self._index = self._load_index()

    def _exclusive(self):
        """Lock, re-read the index (another process may have written it), and save on exit:
        every mutation is a read-modify-write under the lock, so no update is lost."""
        return _Mutation(self)

    # index -----------------------------------------------------------------
    def _load_index(self) -> dict:
        if not INDEX.exists():
            return {"entries": {}, "counters": {}, "by_fingerprint": {}}
        try:
            data = json.loads(read_text_retry(INDEX))
        except ValueError as exc:
            # a damaged index must not become an empty one: the counters would restart and the
            # next put would overwrite SECRET_c1 in the store. The file stays in place, so every
            # later call raises too (moving it away made the guard last one call; review,
            # 2026-09-26). `maisecrets repair` rebuilds the counters from the store.
            raise RuntimeError(f"vault index unreadable ({INDEX.name}); nothing is stored or resolved until "
                               f"`maisecrets repair` ran or the file was fixed by hand") from exc
        if not isinstance(data, dict) or "entries" not in data:
            raise RuntimeError("vault index has an unexpected shape")
        return data

    def _save_index(self) -> None:
        atomic_write(INDEX, json.dumps(self._index, indent=1))

    def _ttl_for(self, type_: str) -> int:
        ttls = self.cfg.get("ttl_seconds", {})
        return int(ttls.get(type_, ttls.get("default", 86400)))

    _fpkey_cache: bytes | None = None

    def fp_key(self) -> bytes:
        """The fingerprint key, created on first use and kept in the backend, never in the index."""
        if self._fpkey_cache is None:
            raw = self.backend.get(FP_KEY_ENTRY)
            if not raw:
                raw = os.urandom(32).hex()
                self.backend.put(FP_KEY_ENTRY, raw, label="maisecrets fingerprint key",
                                 comment="maisecrets: key for the fingerprints in index.json; not a placeholder value.")
            self._fpkey_cache = bytes.fromhex(raw.strip())
        return self._fpkey_cache

    def fingerprint(self, value: str) -> str:
        return fingerprint(value, self.fp_key())

    def live_fingerprints(self) -> dict[str, str]:
        """fingerprint -> key for every entry whose value is still stored."""
        return {m["fingerprint"]: k for k, m in self._index["entries"].items() if not m.get("purged")}

    # api -------------------------------------------------------------------
    @_mutating
    def put(self, value: str, type_: str, kind: str, session: str | None = None,
            ttl: int | None = None) -> Entry:
        """Store a value; the same live value yields the same reference."""
        self.expire()
        fp = self.fingerprint(value)
        existing = self._index["by_fingerprint"].get(fp)
        if existing and not self._index["entries"][existing].get("purged"):
            e = Entry.from_meta(self._index["entries"][existing])
            if session and session not in e.sessions:
                e.sessions.append(session)
            self._touch(e)
            return e
        e = self._put_new(value, type_, kind, session, ttl)
        self._save_index()
        return e

    def _put_new(self, value: str, type_: str, kind: str, session: str | None, ttl: int | None) -> "Entry":
        fp = self.fingerprint(value)
        n = self._index["counters"].get(type_, 0) + 1
        self._index["counters"][type_] = n
        key = f"{type_}_c{n}"
        now = time.time()
        ttl = min(ttl or self._ttl_for(type_), int(self.cfg.get("max_ttl_seconds", 30 * 86400)))
        e = Entry(key=key, type=type_, kind=kind, fingerprint=fp,
                  display=display_for(type_, value), created=now, last_used=now,
                  expires=now + ttl, max_expires=now + int(self.cfg.get("max_ttl_seconds", 30 * 86400)),
                  session=session, uses=0, sessions=[session] if session else [])
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(now))
        self.backend.put(
            key, value,
            label=f"maisecrets {key} ({kind})",
            comment=f"maisecrets placeholder {e.ref}. type={type_} kind={kind} created={created} "
                    f"ttl={ttl}s fingerprint={fp}. Value is inserted only into the real call.",
        )
        self._index["entries"][key] = asdict(e)
        self._index["by_fingerprint"][fp] = key
        return e

    @_mutating
    def put_many(self, items: list[tuple[str, str, str]], session: str | None = None) -> list["Entry | None"]:
        """Store many values in one lock, one sweep and one index save; a tool result with
        hundreds of addresses called put() per value and rewrote the growing index each time
        (measured: 1000 e-mails 8.7 s, above the watchdog; review, 2026-09-26). Above
        `max_new_entries_per_result` new values, the rest is not stored: None in the result,
        the caller masks the value without a key."""
        self.expire()
        cap = int(self.cfg.get("max_new_entries_per_result", 100))
        out: list[Entry | None] = []
        new = 0
        dirty = False
        for value, type_, kind in items:
            fp = self.fingerprint(value)
            existing = self._index["by_fingerprint"].get(fp)
            if existing and not self._index["entries"][existing].get("purged"):
                e = Entry.from_meta(self._index["entries"][existing])
                if session and session not in e.sessions:
                    e.sessions.append(session)
                self._touch(e, save=False)
                dirty = True
                out.append(e)
                continue
            if new >= cap:
                out.append(None)
                continue
            out.append(self._put_new(value, type_, kind, session, None))
            new += 1
            dirty = True
            if new % 10 == 0:
                self._save_index()   # a watchdog exit mid-way leaves at most ten unnamed store items
        if dirty:
            self._save_index()
        return out

    def status(self, key: str, session: str | None = None) -> str:
        """ok | unknown | expired | no-session | foreign-session, without reading the value.

        A reference resolves only in a session that saw it come in: the session that
        created the entry, or one where a human typed the reference into a prompt
        (``admit``). Keys are counters, so a reference an agent never saw is guessable;
        without this rule an injected instruction could name ``SECRET_c1`` and have it
        resolved (review 2026-09-26, docs/reviews/2026-09-26-agent-channel.md).
        """
        meta = self._index["entries"].get(key)
        if meta is None:
            return "unknown"
        if meta.get("purged") or meta["expires"] < time.time():
            return "expired"
        if session is None:
            return "no-session"
        # the creating session always counts; entries written before 0.3.0 have `session` but no
        # `sessions` list (a 0.2.0 entry was refused in its own session after the update, 2026-09-26)
        allowed = set(meta.get("sessions") or [])
        if meta.get("session"):
            allowed.add(meta["session"])
        if session not in allowed:
            return "foreign-session"
        return "ok"

    @_mutating
    def admit(self, key: str, session: str | None) -> None:
        """A human brought the reference into this session (it was in a prompt)."""
        meta = self._index["entries"].get(key)
        if meta is None or not session or session in meta.get("sessions", []):
            return
        meta.setdefault("sessions", []).append(session)
        self._save_index()

    @_mutating
    def get(self, key: str, session: str | None = None, human: bool = False) -> tuple[str | None, str]:
        """Return (value, status). ``human=True`` is the CLI path: no session rule."""
        self.expire()
        meta = self._index["entries"].get(key)
        if meta is None:
            return None, "unknown"
        # past its expiry but not purged: the store refused the delete, or the sweep cap left it
        # for the next call; the human path skips `status`, so it printed the value (suite
        # review, 2026-09-27)
        if meta.get("purged") or meta["expires"] < time.time():
            return None, "expired"
        if not human:
            st = self.status(key, session)
            if st != "ok":
                return None, st
        value = self.backend.get(key)
        if value is None:
            return None, "expired"
        e = Entry.from_meta(meta)
        self._touch(e)
        return value, "ok"

    # grants: one-time permission for a command to read one value ----------
    GRANT_TTL = 120
    GRANT_USES = 3      # the value is read once in the main shell before the command runs; a retry
                        # of the read itself is the only reason for a second use

    @_mutating
    def grant(self, key: str, session: str | None, tool: str, context: str) -> tuple[str | None, str]:
        """Mint a one-time grant for ``key`` after the session rule and the limiter passed.

        Returns (nonce, status). The Bash hook puts ``resolve KEY --grant NONCE`` into the
        command instead of the value, so the command the user approves and the transcript
        never carry the value. The limiter caps distinct keys per session and resolves per
        hour so many values cannot leave in one automated sweep.
        """
        st = self.status(key, session)
        if st != "ok":
            return None, st
        st = self._limit(key, session)
        if st != "ok":
            return None, st
        import secrets as _secrets
        nonce = _secrets.token_urlsafe(16)
        now = time.time()
        grants = self._index.setdefault("grants", {})
        for n in [n for n, g in grants.items() if g["expires"] < now or g.get("uses", 0) >= self.GRANT_USES]:
            del grants[n]
        grants[nonce] = {"key": key, "session": session, "expires": now + self.GRANT_TTL, "uses": 0}
        if not self._record(key, session, tool, context):
            del grants[nonce]
            return None, "audit log not writable"
        self._save_index()
        return nonce, "ok"

    @_mutating
    def redeem(self, key: str, nonce: str) -> tuple[str | None, str]:
        g = self._index.get("grants", {}).get(nonce)
        if g is None or g["key"] != key:
            return None, "no-grant"
        if g.get("used") or g.get("uses", 0) >= self.GRANT_USES:
            return None, "grant-used"
        if g["expires"] < time.time():
            return None, "grant-expired"
        g["uses"] = g.get("uses", 0) + 1
        self._save_index()
        return self.get(key, human=True)

    def _limit(self, key: str, session: str | None) -> str:
        now = time.time()
        rec = [r for r in self._index.get("resolves", []) if r["ts"] > now - 3600]
        self._index["resolves"] = rec
        per_session = int(self.cfg.get("max_keys_per_session", 25))
        per_hour = int(self.cfg.get("max_resolves_per_hour", 60))
        keys_in_session = {r["key"] for r in rec if r["session"] == session}
        if key not in keys_in_session and len(keys_in_session) >= per_session:
            return f"limit: {per_session} distinct keys in this session this hour (max_keys_per_session)"
        if len(rec) >= per_hour:
            return f"limit: {per_hour} resolves in the last hour (max_resolves_per_hour)"
        return "ok"

    def _record(self, key: str, session: str | None, tool: str, context: str) -> bool:
        """One audit line per resolve. False when the line could not be written: the README
        promises the line, so a resolve without it does not happen (review, 2026-09-26)."""
        now = time.time()
        self._index.setdefault("resolves", []).append({"ts": now, "session": session, "key": key})
        try:
            HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = HOME / "audit.log"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
                ctx = context.replace("\n", " ").replace("\t", " ")[:160]
                f.write(f"{stamp}\t{(session or '-')[:8]}\t{key}\t{tool}\t{ctx}\n")
            self._rotate_audit(path)
            return True
        except OSError:
            return False

    def _rotate_audit(self, path: Path) -> None:
        """Keep the newest `audit_max_lines` lines (retention; operator review, 2026-09-26)."""
        cap = int(self.cfg.get("audit_max_lines", 2000))
        try:
            if path.stat().st_size < cap * 120:
                return
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > cap:
                atomic_write(path, "\n".join(lines[-cap:]) + "\n")
        except OSError:
            pass

    @_mutating
    def record_resolve(self, key: str, session: str | None, tool: str, context: str) -> str:
        """For tools that need the value inline (MCP arguments): session rule + limiter + audit."""
        st = self.status(key, session)
        if st != "ok":
            return st
        st = self._limit(key, session)
        if st != "ok":
            return st
        if not self._record(key, session, tool, context):
            return "audit log not writable"
        self._save_index()
        return "ok"

    @_mutating
    def _touch(self, e: Entry, save: bool = True) -> None:
        now = time.time()
        e.last_used = now
        e.uses += 1
        if self.cfg.get("renew_on_use", True):
            e.expires = min(now + self._ttl_for(e.type), e.max_expires)
        self._index["entries"][e.key] = asdict(e)
        if save:
            self._save_index()

    def list(self) -> list[Entry]:
        self.expire()
        return [Entry.from_meta(m) for m in self._index["entries"].values()]

    @_mutating
    def forget(self, key: str) -> str:
        """Delete one entry at the user's request: the value from the store and the metadata
        from the index, fingerprint included. "ok", "unknown", or "store" when the store refused
        (the entry then stays, so nothing looks deleted that is not)."""
        meta = self._index["entries"].get(key)
        if meta is None:
            return "unknown"
        if not meta.get("purged"):
            try:
                self.backend.delete(key)
            except RuntimeError:
                return "store"
        fp = meta.get("fingerprint")
        del self._index["entries"][key]
        if fp and self._index["by_fingerprint"].get(fp) == key:
            del self._index["by_fingerprint"][fp]
        self._save_index()
        return "ok"

    @_mutating
    def expire(self, limit: int | None = 25) -> int:
        """Delete expired values; keep their metadata. Returns the count.

        Runs on every put/get/list, so every hook call sweeps. A keychain
        delete costs ~10 ms (measured 2026-09-26), so a sweep is capped at
        `limit` deletes per call; the rest go on the next call. `limit=None`
        sweeps everything (SessionStart, `maisecrets expire`).
        """
        now = time.time()
        n = 0
        for key, meta in self._index["entries"].items():
            if limit is not None and n >= limit:
                break
            if not meta.get("purged") and meta["expires"] < now:
                try:
                    self.backend.delete(key)
                except RuntimeError:
                    # one item that refuses to go (a locked keychain over SSH) must not block
                    # every hook; the entry stays unpurged and the next sweep tries again
                    n += 1
                    continue
                meta["purged"] = True
                meta["purged_at"] = now
                n += 1
        # metadata of a purged entry (masked display, session ids) is retention too: gone after
        # keep_purged_days; the fingerprint map goes with it (operator review, 2026-09-26)
        keep = int(self.cfg.get("keep_purged_days", 30)) * 86400
        old = [k for k, m in self._index["entries"].items()
               if m.get("purged") and now - float(m.get("purged_at") or m.get("expires") or now) > keep]
        for k in old:
            fp = self._index["entries"][k].get("fingerprint")
            del self._index["entries"][k]
            if fp and self._index["by_fingerprint"].get(fp) == k:
                del self._index["by_fingerprint"][fp]
        if n or old:
            self._save_index()
        return n

    def repair(self) -> dict:
        """Rebuild a damaged index from the store: every stored value is deleted (nothing
        resolves), and the counters are set past every key seen so no new entry can overwrite
        an old value. Refused on a backend that cannot enumerate itself."""
        if not hasattr(self.backend, "keys"):
            raise RuntimeError("this store cannot be enumerated; repair is not possible here")
        keys = self.backend.keys()
        counters: dict[str, int] = {}
        for key in keys:
            if "_c" not in key:
                continue
            type_, _c, num = key.rpartition("_c")
            if num.isdigit():
                counters[type_] = max(counters.get(type_, 0), int(num))
        for key in keys:
            if key != FP_KEY_ENTRY:
                try:
                    self.backend.delete(key)
                except RuntimeError:
                    pass
        idx = {"entries": {}, "counters": counters, "by_fingerprint": {}}
        atomic_write(INDEX, json.dumps(idx, indent=1))
        return {"keys_seen": len(keys), "counters": counters}


def wipe_everything(cfg: dict, run_dir: str | None = None) -> tuple[int, list[str]]:
    """Delete every stored value of this vault's service, the metadata, the logs and the waiting
    prompts: the offboarding step. Works without a readable index (a damaged index is the case
    where it is needed most). Returns (values deleted, problems); a problem means a value may
    still be in the store, and the caller must say so (review, 2026-09-26)."""
    backend = make_backend(cfg)
    problems: list[str] = []
    n = 0
    with _lock_for(HOME / ".lock"):
        # a file store raises OSError (a folder that is not writable), the platform stores
        # RuntimeError; either one is a problem to report, never a traceback (2026-09-27)
        try:
            n = backend.wipe() if hasattr(backend, "wipe") else 0
        except (RuntimeError, OSError) as exc:
            problems.append(f"store: {type(exc).__name__}")
        try:
            keys = backend.keys() if hasattr(backend, "keys") else []
        except (RuntimeError, OSError):
            keys = []
        for key in keys:
            try:
                backend.delete(key)
                n += 1
            except (RuntimeError, OSError):
                problems.append(f"store item {key} not deleted")
        for name in ("index.json", "audit.log", "events.log", "hooks.log", ".announced"):
            try:
                (HOME / name).unlink()
            except FileNotFoundError:
                pass
            except OSError:
                problems.append(f"{name} not deleted")
        dirs = [HOME / "pending", HOME / "run"] + ([Path(run_dir)] if run_dir else [])
        for d in dirs:
            if d.is_dir():
                for f in d.iterdir():
                    try:
                        f.unlink()
                    except OSError:
                        problems.append(f"{f.name} not deleted")
    return n, problems
