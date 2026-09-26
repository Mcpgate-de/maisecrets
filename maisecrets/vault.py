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
SERVICE = "maisecrets"

DEFAULT_CONFIG = {
    "backend": "keychain",          # keychain (macOS) | jsonfile (test mode, any OS)
    "ttl_seconds": {"default": 86400, "CARD": 3600},
    "max_ttl_seconds": 30 * 86400,
    "renew_on_use": True,
    "scrub_transcript": True,
    "block_at_mentions": True,
    "gateway_servers": ["phase6-ai-gateway", "ai-gateway-local", "ai-gateway-devops"],
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(CONFIG.read_text()))
    except (OSError, ValueError):
        pass
    return cfg


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


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
    session: str | None = None
    uses: int = 0
    purged: bool = False
    counters: dict = field(default_factory=dict)  # unused on entries; kept for schema stability

    @property
    def ref(self) -> str:
        t, _, _ = self.key.rpartition("_")
        return f"<{self.key}:{self.display}>" if self.display else f"<{self.key}>"


# ---------------------------------------------------------------- backends --
class JsonFileBackend:
    test_mode = True

    def __init__(self) -> None:
        self.path = HOME / "vault.json"

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
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
        # No -A / -T: the default ACL stays (the creating tool may read it, others are asked).
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


def make_backend(cfg: dict):
    """keychain on macOS; elsewhere the jsonfile test backend until the Windows store exists."""
    if cfg.get("backend") == "keychain" and platform.system() == "Darwin":
        return KeychainBackend()
    return JsonFileBackend()


# ------------------------------------------------------------------- vault --
class Vault:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or load_config()
        self.backend = make_backend(self.cfg)
        self._index = self._load_index()

    # index -----------------------------------------------------------------
    def _load_index(self) -> dict:
        try:
            return json.loads(INDEX.read_text())
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

    # api -------------------------------------------------------------------
    def put(self, value: str, type_: str, kind: str, session: str | None = None,
            ttl: int | None = None) -> Entry:
        """Store a value; the same live value yields the same reference."""
        self.expire()
        fp = fingerprint(value)
        existing = self._index["by_fingerprint"].get(fp)
        if existing and not self._index["entries"][existing].get("purged"):
            e = Entry(**self._index["entries"][existing])
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
                  session=session, uses=0)
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

    def get(self, key: str) -> tuple[str | None, str]:
        """Return (value, status). status: ok | expired | unknown."""
        self.expire()
        meta = self._index["entries"].get(key)
        if meta is None:
            return None, "unknown"
        if meta.get("purged"):
            return None, "expired"
        value = self.backend.get(key)
        if value is None:
            return None, "expired"
        e = Entry(**meta)
        self._touch(e)
        return value, "ok"

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

    def expire(self) -> int:
        """Delete expired values; keep their metadata. Returns the count."""
        now = time.time()
        n = 0
        for key, meta in self._index["entries"].items():
            if not meta.get("purged") and meta["expires"] < now:
                self.backend.delete(key)
                meta["purged"] = True
                n += 1
        if n:
            self._save_index()
        return n
