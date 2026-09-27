"""DNS utilities built on the standard library (no external deps)."""

from __future__ import annotations

import socket

__all__ = ["resolve_host", "reverse_lookup"]


def resolve_host(hostname: str) -> dict:
    """Forward DNS resolution with all addresses."""
    out = {"hostname": hostname, "addresses": [], "error": None}
    try:
        infos = socket.getaddrinfo(hostname, None)
        addrs = []
        for family, _type, _proto, _canonname, sockaddr in infos:
            addr = sockaddr[0]
            if addr not in addrs:
                addrs.append(addr)
        out["addresses"] = addrs
    except socket.gaierror as exc:
        out["error"] = str(exc)
    return out


def reverse_lookup(ip: str) -> dict:
    """Reverse DNS (PTR) lookup."""
    out = {"ip": ip, "hostnames": [], "error": None}
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        hosts = [name] + [a for a in aliases if a != name]
        out["hostnames"] = hosts
    except (socket.herror, socket.gaierror, OSError) as exc:
        out["error"] = str(exc)
    return out
