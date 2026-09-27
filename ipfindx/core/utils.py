"""Shared utilities: IP validation, CIDR/target expansion, rate limiting."""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Callable, Iterator, List, Optional

__all__ = [
    "is_public_ip",
    "normalize_ip",
    "expand_targets",
    "expand_targets_limited",
    "TargetLimitError",
    "parse_ports",
    "RateLimiter",
    "MultiRateLimiter",
    "read_ip_file",
]

# IPv4 host:port only — never strip hextets from bare IPv6 literals.
_IPV4_PORT_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})$"
)
# Bracketed IPv6 with optional port: [2001:db8::1]:443
_IPV6_BRACKET_RE = re.compile(
    r"^\[(?P<ip>[^\]]+)\](?::(?P<port>\d{1,5}))?$"
)

# Soft safety ceiling for the uncapped expand_targets() API only.
_EXPAND_HARD_CAP = 65536


def is_public_ip(ip_str: str) -> bool:
    """True when *ip_str* parses to a global (routable) IP address."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def normalize_ip(ip_str: str) -> str:
    """Return the canonical string form of an IP, or the input if unparseable."""
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        return ip_str.strip()


class TargetLimitError(ValueError):
    """Raised when target expansion would exceed the configured maximum."""

    def __init__(self, message: str, requested: int):
        super().__init__(message)
        self.requested = requested


def _looks_like_ipv6(spec: str) -> bool:
    return ":" in spec and "." not in spec.split("/")[0].split("-")[0]


def _host_from_spec(spec: str) -> str:
    """Extract the host from a target, never mistaking IPv6 hextets for :port.

    Supported forms:
      - bare IPv4 / IPv6 literals (unchanged)
      - IPv4:port  (e.g. 8.8.8.8:53)
      - [IPv6]:port / [IPv6]  (bracket syntax required for IPv6+port)
    """
    m = _IPV6_BRACKET_RE.match(spec)
    if m:
        return m.group("ip")
    m = _IPV4_PORT_RE.match(spec)
    if m:
        return m.group("ip")
    return spec


def _hosts_count(net) -> int:
    """Count of addresses yielded by ``net.hosts()`` without materialising them.

    Matches ``ipaddress`` semantics:
      - IPv4 /31 and /32: all addresses are usable hosts
      - IPv4 otherwise: num_addresses - 2 (exclude network + broadcast)
      - IPv6 /127 and /128: all addresses
      - IPv6 otherwise: num_addresses - 1 (exclude subnet-router anycast)
    """
    n = int(net.num_addresses)
    if net.version == 4:
        return n if net.prefixlen >= 31 else max(0, n - 2)
    return n if net.prefixlen >= 127 else max(0, n - 1)


def expand_targets(spec: str, *, max_addresses: Optional[int] = _EXPAND_HARD_CAP) -> Iterator[str]:
    """Expand a target spec into individual public IP addresses.

    Supported forms::

        8.8.8.8                  single IP
        8.8.8.0/24               CIDR network
        8.8.8.1-8.8.8.10         inclusive range
        2001:4860:4860::8888     bare IPv6
        [2001:4860:4860::8888]:443   bracketed IPv6 with port

    When *max_addresses* is set and a range/CIDR requests more than that many
    addresses, raises :class:`TargetLimitError` instead of silently truncating.
    Pass ``max_addresses=None`` to disable the safety ceiling (used by
    :func:`expand_targets_limited` after its own limit check).
    """
    spec = spec.strip()
    if not spec:
        return

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return
        requested = _hosts_count(net)
        if max_addresses is not None and requested > max_addresses:
            raise TargetLimitError(
                f"target '{spec}' requests {requested} addresses which exceeds "
                f"the limit of {max_addresses}",
                requested,
            )
        for host in net.hosts():
            if ipaddress.ip_address(host).is_global:
                yield str(host)
        return

    if "-" in spec and spec.count("-") == 1 and not _looks_like_ipv6(spec):
        left, _, right = spec.partition("-")
        try:
            start = ipaddress.ip_address(left.strip())
            end = ipaddress.ip_address(right.strip())
        except ValueError:
            return
        if start.version != end.version or int(end) < int(start):
            return
        requested = int(end) - int(start) + 1
        if max_addresses is not None and requested > max_addresses:
            raise TargetLimitError(
                f"target '{spec}' requests {requested} addresses which exceeds "
                f"the limit of {max_addresses}",
                requested,
            )
        current = int(start)
        stop = int(end)
        while current <= stop:
            ip = ipaddress.ip_address(current)
            if ip.is_global:
                yield str(ip)
            current += 1
        return

    candidate = _host_from_spec(spec)
    if is_public_ip(candidate):
        yield normalize_ip(candidate)


def _count_requested(spec: str) -> Optional[int]:
    """How many addresses the spec *requests* (public or not), or None if unknown."""
    spec = spec.strip()
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return None
        return _hosts_count(net)
    if "-" in spec and spec.count("-") == 1 and not _looks_like_ipv6(spec):
        left, _, right = spec.partition("-")
        try:
            start = ipaddress.ip_address(left.strip())
            end = ipaddress.ip_address(right.strip())
        except ValueError:
            return None
        if start.version != end.version or int(end) < int(start):
            return None
        return int(end) - int(start) + 1
    # single host (possibly with port suffix)
    candidate = _host_from_spec(spec)
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return 1  # hostname / unknown — treat as one
    return 1


def expand_targets_limited(
    spec: str,
    max_targets: int,
    on_truncate: Optional[Callable[[str, int], None]] = None,
) -> List[str]:
    """Expand *spec* with a hard limit — never silently truncates.

    Raises :class:`TargetLimitError` when the spec requests more than
    *max_targets* addresses (checked before materialising the iterator).
    Expansion itself uses ``max_addresses=None`` so the internal safety
    ceiling cannot quietly shorten a range that already passed the check.
    """
    requested = _count_requested(spec)
    if requested is not None and requested > max_targets:
        raise TargetLimitError(
            f"target '{spec}' requests {requested} addresses which exceeds "
            f"the limit of {max_targets} (raise max_targets in the config "
            f"or narrow the target)",
            requested,
        )
    # Fully expand — no silent internal cap. Public-IP filtering may still
    # yield fewer addresses than *requested*; that is not truncation.
    try:
        hits = list(expand_targets(spec, max_addresses=None))
    except TargetLimitError:
        raise
    if on_truncate and requested is not None and len(hits) < requested:
        # Only fire when something unexpected shortened the set beyond
        # public-IP filtering of a fully-walked range (kept for API compat).
        on_truncate(spec, requested)
    return hits


def parse_ports(spec: str) -> List[int]:
    """Parse a port spec like ``80,443,1000-1010`` into a sorted list."""
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                a, b = int(lo), int(hi)
            except ValueError:
                continue
            if 1 <= a <= 65535 and 1 <= b <= 65535 and a <= b:
                ports.update(range(a, b + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def read_ip_file(path: str) -> List[str]:
    """Read a file of targets (one per line, ``#`` comments ignored)."""
    targets: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


class RateLimiter:
    """Thread-safe pacing limiter enforcing a minimum interval between calls.

    Each ``wait()`` blocks until at least ``1 / calls_per_second`` seconds
    have passed since the previous wait returned, so concurrent callers are
    evenly spaced instead of bursting.
    """

    def __init__(self, calls_per_second: float = 4.0):
        self._interval = 1.0 / max(calls_per_second, 0.01)
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self._next_slot - now
            if delay > 0:
                self._next_slot += self._interval
            else:
                # we are behind schedule: don't accumulate debt, reset the slot
                self._next_slot = now + self._interval
                delay = 0
        if delay > 0:
            time.sleep(delay)

    def penalize(self, seconds: float) -> None:
        """Push the next allowed slot out by *seconds* (used on HTTP 429)."""
        if seconds <= 0:
            return
        with self._lock:
            now = time.monotonic()
            candidate = now + seconds
            if candidate > self._next_slot:
                self._next_slot = candidate


class MultiRateLimiter:
    """One independent :class:`RateLimiter` per named provider.

    Unrelated providers never block each other; each provider's calls are
    paced according to its own configured rate.
    """

    def __init__(self, calls_per_second: float = 4.0):
        self._rate = calls_per_second
        self._limiters: dict = {}
        self._lock = threading.Lock()

    def limiter(self, name: str) -> RateLimiter:
        with self._lock:
            lim = self._limiters.get(name)
            if lim is None:
                lim = RateLimiter(self._rate)
                self._limiters[name] = lim
            return lim

    def wait(self, name: str) -> None:
        self.limiter(name).wait()

    def penalize(self, name: str, seconds: float) -> None:
        self.limiter(name).penalize(seconds)
