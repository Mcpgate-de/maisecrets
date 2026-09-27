#!/usr/bin/env python3
"""An ssh ProxyCommand for the Claude Code sandbox: one CONNECT through the sandbox proxy.

Inside the sandbox no command reaches the network directly; everything goes through Claude Code's
proxy, which admits only the hosts in `sandbox.network.allowedDomains` (measured 2026-09-27,
Claude Code 2.1.283 on macOS and Debian 13: an allowed host answers `200 Connection Established`,
another one `403 Forbidden`). Claude Code's own GIT_SSH_COMMAND uses `nc -X 5`, which cannot send
the proxy login, so the proxy refuses it. This helper sends the login from HTTPS_PROXY.

    ssh -o ProxyCommand='python3 proxy_connect.py %h %p' host …

It talks only to a proxy on this machine (localhost, 127.0.0.1, ::1): the login of the sandbox
proxy never goes to another host. Exit 1 with the proxy's status line when the proxy refuses.
"""
from __future__ import annotations

import base64
import os
import select
import socket
import sys
from urllib.parse import unquote, urlsplit

LOCAL = {"localhost", "127.0.0.1", "::1"}


def proxy() -> tuple[str, int, str | None]:
    url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    u = urlsplit(url)
    if u.scheme != "http" or u.hostname not in LOCAL or not u.port:
        raise SystemExit("maisecrets proxy_connect: no local sandbox proxy in HTTPS_PROXY; "
                         "this ssh route works only inside the Claude Code sandbox")
    auth = None
    if u.username is not None:
        auth = base64.b64encode(f"{unquote(u.username)}:{unquote(u.password or '')}".encode()).decode()
    return u.hostname, u.port, auth


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: proxy_connect.py <host> <port>", file=sys.stderr)
        return 2
    host, port = argv[1], argv[2]
    if not port.isdigit() or not host or any(c in host for c in " \r\n/@"):
        print("maisecrets proxy_connect: bad host or port", file=sys.stderr)
        return 2
    phost, pport, auth = proxy()
    s = socket.create_connection((phost, pport), timeout=15)
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    head = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if auth:
        head += f"Proxy-Authorization: Basic {auth}\r\n"
    s.sendall((head + "\r\n").encode())
    reply = b""
    while b"\r\n\r\n" not in reply:
        chunk = s.recv(1)
        if not chunk or len(reply) > 8192:
            break
        reply += chunk
    status = reply.split(b"\r\n", 1)[0].decode(errors="replace")
    if status.split(" ")[1:2] != ["200"]:
        print(f"maisecrets proxy_connect: the sandbox proxy refused {target}: {status}", file=sys.stderr)
        return 1
    s.settimeout(None)
    stdin, stdout = sys.stdin.fileno(), sys.stdout.fileno()
    open_in = True
    while True:
        rlist = [s] + ([stdin] if open_in else [])
        ready, _, _ = select.select(rlist, [], [])
        if stdin in ready:
            data = os.read(stdin, 65536)
            if data:
                s.sendall(data)
            else:
                open_in = False
                try:
                    s.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        if s in ready:
            data = s.recv(65536)
            if not data:
                return 0
            os.write(stdout, data)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
