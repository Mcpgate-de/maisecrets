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
import platform
import subprocess
import time
from dataclasses import asdict, dataclass, field
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
    "gateway_servers": ["phase6-ai-gateway", "ai-gateway-local", "ai-gateway-devops"],
    "pii_regions": ["generic", "de"],
}


def load_config() -> dict:
    """Defaults, then ~/.maisecrets/config.json, then CLAUDE_PLUGIN_OPTION_<KEY> if a client passes
    plugin options that way. The manifest declares no `userConfig`: Claude Code 2.1.223 rejects a
    manifest with that key as invalid and then loads NO hook at all (measured on Debian,
    2026-09-26), and a guard that silently vanishes on an older client is worse than a guard
    without a settings dialog. The env path stays for clients that know the key."""
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(CONFIG.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
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
            "maisecrets is free and open source, brought to you by mcpgate.de - "
            "connecting your company with its tools.")


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

    @property
    def ref(self) -> str:
        from .placeholder import CLOSE, OPEN
        return f"{OPEN}{self.key}:{self.display}{CLOSE}" if self.display else f"{OPEN}{self.key}{CLOSE}"


# ---------------------------------------------------------------- backends --
class JsonFileBackend:
    test_mode = True

    def __init__(self) -> None:
        self.path = HOME / "vault.json"

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        d = self._load()
        d[key] = value
        self._save(d)

    def get(self, key: str) -> str | None:
        return self._load().get(key)

    def delete(self, key: str) -> None:
        d = self._load()
        d.pop(key, None)
        self._save(d)


class KeychainBackend:
    """macOS login keychain via the ``security`` CLI. No sync flag is set."""
    test_mode = False

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        # -l is the "Name" column in Keychain Access, -j the comment shown in the item's info.
        # The item's ACL trusts /usr/bin/security, the tool that created it, so ANY process of
        # this user that runs `security find-generic-password` reads the value without a dialog
        # (review 2026-09-26, docs/reviews). The keychain protects the value at rest and from
        # other users, not from this user's other processes. The gates are in the hooks.
        # No synchronizable flag: the item never joins iCloud Keychain or the Passwords app.
        cmd = ["security", "add-generic-password", "-U", "-s", SERVICE, "-a", key,
               "-l", label or f"maisecrets {key}", "-D", "maisecrets placeholder", "-w", value]
        if comment:
            cmd += ["-j", comment]
        subprocess.run(cmd, check=True, capture_output=True)

    def get(self, key: str) -> str | None:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", SERVICE, "-a", key, "-w"],
            capture_output=True, text=True,
        )
        return r.stdout.rstrip("\n") if r.returncode == 0 else None

    def delete(self, key: str) -> None:
        subprocess.run(
            ["security", "delete-generic-password", "-s", SERVICE, "-a", key],
            capture_output=True,
        )


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
        r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-salt",
                            "-pass", f"file:{self.key_file}", *args], input=data, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError("openssl failed: " + r.stderr.decode(errors="ignore")[:200])
        return r.stdout

    def _tag(self, blob: bytes) -> str:
        import hmac
        return hmac.new(hashlib.sha256(b"maisecrets-mac:" + self._key()).digest(), blob, "sha256").hexdigest()

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        import base64
        self._key()
        blob = self._openssl([], value.encode())
        d = self._load()
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
        d = self._load()
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
        return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", self._PRELUDE + script],
                              input=stdin, capture_output=True, text=True, timeout=15)

    def put(self, key: str, value: str, label: str | None = None, comment: str | None = None) -> None:
        # the value travels via stdin, never as a command-line argument
        r = self._ps("$p = [Console]::In.ReadToEnd().TrimEnd(\"`r\", \"`n\"); "
                     f"try {{ $old = $v.Retrieve('{SERVICE}', '{key}'); $v.Remove($old) }} catch {{}}; "
                     f"$v.Add((New-Object Windows.Security.Credentials.PasswordCredential('{SERVICE}', '{key}', $p)))",
                     stdin=value)
        if r.returncode != 0:
            raise RuntimeError("PasswordVault add failed: " + r.stderr[:200])

    def get(self, key: str) -> str | None:
        r = self._ps(f"try {{ $c = $v.Retrieve('{SERVICE}', '{key}'); $c.RetrievePassword(); "
                     "[Console]::Out.Write($c.Password) } catch { exit 3 }")
        return r.stdout if r.returncode == 0 else None

    def delete(self, key: str) -> None:
        self._ps(f"try {{ $v.Remove($v.Retrieve('{SERVICE}', '{key}')) }} catch {{}}")


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


# ------------------------------------------------------------------- vault --
class Vault:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or load_config()
        self.backend = make_backend(self.cfg)
        self._index = self._load_index()

    # index -----------------------------------------------------------------
    def _load_index(self) -> dict:
        try:
            return json.loads(INDEX.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"entries": {}, "counters": {}, "by_fingerprint": {}}

    def _save_index(self) -> None:
        HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = INDEX.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._index, f, indent=1)
        os.replace(tmp, INDEX)

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
    def put(self, value: str, type_: str, kind: str, session: str | None = None,
            ttl: int | None = None) -> Entry:
        """Store a value; the same live value yields the same reference."""
        self.expire()
        fp = self.fingerprint(value)
        existing = self._index["by_fingerprint"].get(fp)
        if existing and not self._index["entries"][existing].get("purged"):
            e = Entry(**self._index["entries"][existing])
            if session and session not in e.sessions:
                e.sessions.append(session)
            self._touch(e)
            return e
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
        self._save_index()
        return e

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

    def admit(self, key: str, session: str | None) -> None:
        """A human brought the reference into this session (it was in a prompt)."""
        meta = self._index["entries"].get(key)
        if meta is None or not session or session in meta.get("sessions", []):
            return
        meta.setdefault("sessions", []).append(session)
        self._save_index()

    def get(self, key: str, session: str | None = None, human: bool = False) -> tuple[str | None, str]:
        """Return (value, status). ``human=True`` is the CLI path: no session rule."""
        self.expire()
        meta = self._index["entries"].get(key)
        if meta is None:
            return None, "unknown"
        if meta.get("purged"):
            return None, "expired"
        if not human:
            st = self.status(key, session)
            if st != "ok":
                return None, st
        value = self.backend.get(key)
        if value is None:
            return None, "expired"
        e = Entry(**meta)
        self._touch(e)
        return value, "ok"

    # grants: one-time permission for a command to read one value ----------
    GRANT_TTL = 120
    GRANT_USES = 20     # a retry loop or two references to one key redeem the same nonce; a command
                        # that needs more is not a command, it is a sweep

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
        self._record(key, session, tool, context)
        self._save_index()
        return nonce, "ok"

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

    def _record(self, key: str, session: str | None, tool: str, context: str) -> None:
        now = time.time()
        self._index.setdefault("resolves", []).append({"ts": now, "session": session, "key": key})
        try:
            HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(HOME / "audit.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
                ctx = context.replace("\n", " ").replace("\t", " ")[:160]
                f.write(f"{stamp}\t{(session or '-')[:8]}\t{key}\t{tool}\t{ctx}\n")
        except OSError:
            pass

    def record_resolve(self, key: str, session: str | None, tool: str, context: str) -> str:
        """For tools that need the value inline (MCP arguments): session rule + limiter + audit."""
        st = self.status(key, session)
        if st != "ok":
            return st
        st = self._limit(key, session)
        if st != "ok":
            return st
        self._record(key, session, tool, context)
        self._save_index()
        return "ok"

    def _touch(self, e: Entry) -> None:
        now = time.time()
        e.last_used = now
        e.uses += 1
        if self.cfg.get("renew_on_use", True):
            e.expires = min(now + self._ttl_for(e.type), e.max_expires)
        self._index["entries"][e.key] = asdict(e)
        self._save_index()

    def list(self) -> list[Entry]:
        self.expire()
        return [Entry(**m) for m in self._index["entries"].values()]

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
                self.backend.delete(key)
                meta["purged"] = True
                n += 1
        if n:
            self._save_index()
        return n
