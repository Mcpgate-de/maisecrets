#!/usr/bin/env python3
"""Exit 0 only inside the Claude Code sandbox. The first step of a command that sends a value over ssh.

Four signals, all needed (measured 2026-09-27 and 2026-09-28, Claude Code 2.1.283, macOS and Debian 13):
1. SANDBOX_RUNTIME=1;
2. HTTPS_PROXY is a proxy on this machine with a login of the sandbox runtime's form, srt or srt.…;
3. three direct TCP connections fail (no command reaches the network directly in the sandbox);
4. the proxy refuses a wrong login with 407.
One failed connection proved little: a company firewall blocks 1.1.1.1, an offline laptop fails every
connection, and a copied environment on such a machine with a local proxy passed signals 1 to 3.
"""
from __future__ import annotations

import base64
import os
import socket
import sys
from urllib.parse import urlsplit

TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443))
LOCAL = ("localhost", "127.0.0.1", "::1")


def inside(env: dict | None = None) -> bool:
    env = os.environ if env is None else env
    if env.get("SANDBOX_RUNTIME") != "1":
        return False
    try:
        u = urlsplit(env.get("HTTPS_PROXY") or "")
        port = u.port
    except ValueError:
        return False
    # the sandbox runtime's login: `srt.<…>` on macOS, `srt` alone on Linux (Claude Code 2.1.283,
    # measured on Debian 13, 2026-09-28: the guard refused every ssh in the Linux sandbox)
    user = u.username or ""
    if u.hostname not in LOCAL or not port or not (user == "srt" or user.startswith("srt.")):
        return False
    for target in TARGETS:
        s = socket.socket()
        s.settimeout(2)
        try:
            if s.connect_ex(target) == 0:
                return False
        finally:
            s.close()
    wrong = base64.b64encode(b"srt.maisecrets:" + b"wrong")
    try:
        s = socket.create_connection((u.hostname, port), 5)
        s.sendall(b"CONNECT maisecrets-probe.invalid:9 HTTP/1.1\r\nHost: maisecrets-probe.invalid:9\r\n"
                  b"Proxy-Authorization: Basic " + wrong + b"\r\n\r\n")
        reply = s.recv(64)
        s.close()
    except OSError:
        return False
    return reply.split(b" ")[1:2] == [b"407"]


if __name__ == "__main__":
    sys.exit(0 if inside() else 1)
