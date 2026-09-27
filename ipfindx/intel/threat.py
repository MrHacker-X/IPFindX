"""Threat-intelligence assessment and risk scoring.

Signals combined (no paid API required):

- Tor exit node membership (bulk list, cached locally)
- Datacenter/hosting ASN classification
- Open administrative ports (from recon, when available)
- Reverse-DNS naming heuristics (static.*, mail.*, etc.)
- Optional AbuseIPDB confidence score when an API key is configured
"""

from __future__ import annotations

import threading
import time
from typing import List, Optional, Set

import requests

from ipfindx.core.models import IPRecord, ThreatReport

__all__ = ["assess_threat", "fetch_tor_exits", "load_tor_exits", "reset_tor_cache"]

_TOR_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_TTL = 6 * 3600       # successful list lives 6h in memory / SQLite
_TOR_FAIL_TTL = 60.0      # empty/failed fetch — short cooldown, not per-target retry
_TOR_CACHE_KEY = "tor_exits"
_TOR_FAIL_KEY = "tor_exits_fail"

_tor_lock = threading.Lock()
_tor_cache: Optional[Set[str]] = None
_tor_fetched_at: float = 0.0
_tor_failed: bool = False


def reset_tor_cache() -> None:
    """Drop in-memory Tor list state (used by tests)."""
    global _tor_cache, _tor_fetched_at, _tor_failed
    with _tor_lock:
        _tor_cache = None
        _tor_fetched_at = 0.0
        _tor_failed = False


def fetch_tor_exits(timeout: float = 10.0) -> set:
    """Fetch the current Tor exit node list (empty set on failure)."""
    try:
        resp = requests.get(_TOR_URL, timeout=timeout, headers={"User-Agent": "IPFindX/4.0"})
        resp.raise_for_status()
        return {line.strip() for line in resp.text.splitlines() if line.strip()}
    except requests.exceptions.RequestException:
        return set()


def load_tor_exits(cache=None, timeout: float = 10.0) -> set:
    """Thread-safe single-flight Tor exit list loader.

    * Only one worker performs the HTTP fetch; others wait and reuse the result.
    * Successful results are memoized for ``_TOR_TTL`` (6 h) and, when *cache*
      (a :class:`~ipfindx.core.cache.TTLCache`) is provided, persisted so the
      TTL survives separate CLI invocations.
    * Failed / empty fetches are memoized for ``_TOR_FAIL_TTL`` so an outage
      cannot trigger one HTTP request per target.
    * When *cache* is ``None`` (``--no-cache`` / cache disabled) no SQLite
      reads or writes occur.
    """
    global _tor_cache, _tor_fetched_at, _tor_failed

    # Fast path: durable cache hit (no lock needed for a read-only get)
    if cache is not None:
        cached = cache.get(_TOR_CACHE_KEY)
        if cached is not None:
            return set(cached)
        if cache.get(_TOR_FAIL_KEY) is not None:
            return set()

    now = time.monotonic()
    with _tor_lock:
        # Re-check durable cache inside the lock (another worker may have filled it)
        if cache is not None:
            cached = cache.get(_TOR_CACHE_KEY)
            if cached is not None:
                _tor_cache = set(cached)
                _tor_failed = False
                _tor_fetched_at = now
                return _tor_cache
            if cache.get(_TOR_FAIL_KEY) is not None:
                _tor_cache = set()
                _tor_failed = True
                _tor_fetched_at = now
                return _tor_cache

        if _tor_cache is not None and _tor_fetched_at > 0:
            ttl = _TOR_FAIL_TTL if _tor_failed else _TOR_TTL
            if now - _tor_fetched_at < ttl:
                return _tor_cache

        # Single-flight: only the lock holder fetches
        exits = fetch_tor_exits(timeout=timeout)
        _tor_fetched_at = time.monotonic()
        if exits:
            _tor_cache = exits
            _tor_failed = False
            if cache is not None:
                cache.set(_TOR_CACHE_KEY, sorted(exits), ttl=_TOR_TTL)
        else:
            _tor_cache = set()
            _tor_failed = True
            if cache is not None:
                cache.set(_TOR_FAIL_KEY, True, ttl=int(_TOR_FAIL_TTL))
        return _tor_cache


_DATACENTER_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "ovh", "hetzner", "vultr", "contabo", "oracle", "cloud", "hosting", "server",
    "datacamp", "choopa", "packethub", "leaseweb", "m247",
)

_SUSPICIOUS_RDNS = ("static.", "mail.", "smtp.", "vpn.", "proxy.", "tor.")


def _classify_datacenter(rec: IPRecord) -> bool:
    if rec.is_hosting:
        return True
    hay = f"{rec.isp or ''} {rec.org or ''} {rec.as_name or ''}".lower()
    return any(kw in hay for kw in _DATACENTER_KEYWORDS)


def assess_threat(
    record: IPRecord,
    open_ports: Optional[List[int]] = None,
    abuseipdb_key: Optional[str] = None,
    tor_cache=None,
    timeout: float = 10.0,
) -> ThreatReport:
    """Build a ThreatReport with a 0-100 risk score from available signals."""
    report = ThreatReport(ip=record.ip)
    score = 0

    if record.ip and record.ip in load_tor_exits(cache=tor_cache, timeout=timeout):
        report.tor_exit = True
        report.signals.append("Tor exit node")
        score += 40

    report.is_datacenter = _classify_datacenter(record)
    if report.is_datacenter:
        report.signals.append("Datacenter/hosting infrastructure")
        score += 15

    if record.is_proxy:
        report.signals.append("Flagged as proxy/VPN by geo provider")
        score += 30

    suspicious_rdns = record.reverse_dns and record.reverse_dns.lower().startswith(_SUSPICIOUS_RDNS)
    if suspicious_rdns:
        report.signals.append(f"Suspicious reverse DNS pattern ({record.reverse_dns})")
        score += 10

    if open_ports:
        admin_ports = {22, 23, 3389, 5900, 5901}
        hits = sorted(set(open_ports) & admin_ports)
        if hits:
            report.signals.append(f"Administrative ports exposed: {', '.join(map(str, hits))}")
            score += min(20, 5 * len(hits))
        if 23 in open_ports:
            report.signals.append("Telnet (23) open — plaintext remote admin")
            score += 10
    report.open_ports = list(open_ports or [])

    if abuseipdb_key:
        conf = _abuseipdb_check(record.ip, abuseipdb_key, timeout)
        if conf is not None:
            report.abuse_confidence = conf
            report.details["abuseipdb"] = conf
            if conf >= 50:
                report.signals.append(f"AbuseIPDB confidence {conf}%")
                score = max(score, conf)

    score = max(0, min(100, score))
    report.score = score
    report.level = _level_for(score)
    return report


def _level_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "elevated"
    if score >= 20:
        return "moderate"
    if score >= 5:
        return "low"
    return "minimal"


def _abuseipdb_check(ip: str, key: str, timeout: float) -> Optional[int]:
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json", "User-Agent": "IPFindX/4.0"},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            return None
        score = data.get("abuseConfidenceScore")
        return int(score) if isinstance(score, (int, float)) else None
    except (requests.exceptions.RequestException, ValueError, TypeError, KeyError):
        return None
