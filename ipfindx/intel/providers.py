"""Geolocation providers with automatic failover, per-provider rate limiting
and correct request timing.

Rate limiting
-------------
Each provider has its own :class:`RateLimiter` (see ``MultiRateLimiter``), so
concurrent batch workers are paced per provider and unrelated providers never
block each other. HTTP 429 responses are honoured: the ``Retry-After`` header
(value in seconds) pushes the provider's next allowed slot into the future.

Timing
------
``lookup_ms`` measures the actual HTTP request for every provider.
"""

from __future__ import annotations

import datetime
import threading
import time
from typing import Any, Optional, Tuple

import requests

from ipfindx.core.models import IPRecord
from ipfindx.core.utils import MultiRateLimiter

__all__ = ["PROVIDERS", "fetch_from_provider", "fetch_geo", "set_rate_limit",
           "reset_rate_limiters"]

_UA = "IPFindX/4.0 (+https://github.com/MrHacker-X/IPFindX)"

_limiters_lock = threading.Lock()
_limiters: Optional[MultiRateLimiter] = None
_limiters_rate: Optional[float] = None


def _get_limiters(rate_limit: Optional[float]) -> MultiRateLimiter:
    """Return the shared per-provider limiter set, (re)built for *rate_limit*.

    The limiter set is cached per rate so batch workers share pacing state;
    it is only rebuilt when the configured rate actually changes.
    """
    global _limiters, _limiters_rate
    with _limiters_lock:
        if _limiters is None or _limiters_rate != rate_limit:
            _limiters = MultiRateLimiter(rate_limit if rate_limit and rate_limit > 0 else 4.0)
            _limiters_rate = rate_limit
        return _limiters


def set_rate_limit(rate_limit: float) -> None:
    """Explicitly (re)configure the per-provider rate limit."""
    global _limiters, _limiters_rate
    with _limiters_lock:
        _limiters = MultiRateLimiter(rate_limit)
        _limiters_rate = rate_limit


def reset_rate_limiters() -> None:
    """Drop all limiter state (used by tests)."""
    global _limiters, _limiters_rate
    with _limiters_lock:
        _limiters = None
        _limiters_rate = None


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _retry_after_seconds(resp: requests.Response) -> Optional[float]:
    """Parse a Retry-After header expressed in seconds (HTTP-date not handled)."""
    raw = resp.headers.get("Retry-After") if resp.headers is not None else None
    if not raw:
        return None
    try:
        val = float(raw.strip())
        return val if val >= 0 else None
    except (ValueError, AttributeError):
        return None


def _require_object(data: Any, provider: str) -> dict:
    """Ensure top-level JSON is a dict; raise ValueError otherwise."""
    if not isinstance(data, dict):
        raise ValueError(
            f"{provider}: expected JSON object, got {type(data).__name__}"
        )
    return data


def _mapping(value: Any) -> dict:
    """Return *value* if it is a dict, else an empty dict (soft nested validate)."""
    return value if isinstance(value, dict) else {}


def _request_json(provider: str, url: str, timeout: float,
                  params: Optional[dict] = None) -> Tuple[dict, int]:
    """Rate-limited GET returning ``(parsed_json_object, elapsed_ms)``.

    Waits for the provider's rate slot *before* the request; on HTTP 429 the
    provider's limiter is penalised by ``Retry-After`` (default 1 s) before
    the HTTPError propagates to the failover logic. Non-object JSON bodies
    raise ``ValueError`` so callers fail soft via :func:`fetch_from_provider`.
    """
    # Reuse the limiter set configured via fetch_geo()/set_rate_limit().
    # Passing None here would rebuild it with the 4 req/s default and
    # silently discard the configured rate.
    limiters = _get_limiters(_limiters_rate)
    limiters.wait(provider)
    start = time.monotonic()
    resp = requests.get(url, params=params, timeout=timeout, headers={"User-Agent": _UA})
    elapsed = int((time.monotonic() - start) * 1000)
    if resp.status_code == 429:
        penalty = _retry_after_seconds(resp)
        limiters.penalize(provider, penalty if penalty is not None else 1.0)
    resp.raise_for_status()
    try:
        data = resp.json()
    except ValueError as exc:
        raise ValueError(f"{provider}: invalid JSON ({exc})") from exc
    return _require_object(data, provider), elapsed


# ---------------------------------------------------------------- providers


def _provider_ipapi(ip: str, timeout: float, **kw) -> IPRecord:
    url = f"http://ip-api.com/json/{ip}"
    params = (
        "status,message,continent,continentCode,country,countryCode,region,"
        "regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,"
        "org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    data, elapsed = _request_json("ip-api", f"{url}?fields={params}", timeout)
    rec = IPRecord(ip=ip, source="ip-api.com", lookup_ms=elapsed)
    if data.get("status") == "fail":
        rec.status = "fail"
        msg = data.get("message", "lookup failed")
        rec.message = msg if isinstance(msg, str) else "lookup failed"
        return rec
    rec.status = "success"
    rec.continent = data.get("continent")
    rec.continent_code = data.get("continentCode")
    rec.country = data.get("country")
    rec.country_code = data.get("countryCode")
    rec.region = data.get("region")
    rec.region_name = data.get("regionName")
    rec.city = data.get("city")
    rec.district = data.get("district")
    rec.zip = str(data.get("zip") or "") or None
    lat, lon = data.get("lat"), data.get("lon")
    rec.lat = lat if isinstance(lat, (int, float)) else None
    rec.lon = lon if isinstance(lon, (int, float)) else None
    rec.timezone = data.get("timezone")
    rec.offset = data.get("offset")
    rec.currency = data.get("currency")
    rec.isp = data.get("isp")
    rec.org = data.get("org")
    rec.asn = data.get("as")
    rec.as_name = data.get("asname")
    rec.reverse_dns = data.get("reverse") or None
    rec.is_mobile = data.get("mobile")
    rec.is_proxy = data.get("proxy")
    rec.is_hosting = data.get("hosting")
    rec.fetched_at = _now_iso()
    return rec


def _provider_ipwhois(ip: str, timeout: float, **kw) -> IPRecord:
    data, elapsed = _request_json("ipwhois", f"https://ipwho.is/{ip}", timeout)
    rec = IPRecord(ip=ip, source="ipwho.is", lookup_ms=elapsed)
    if not data.get("success", False):
        rec.status = "fail"
        msg = data.get("message", "lookup failed")
        rec.message = msg if isinstance(msg, str) else "lookup failed"
        return rec
    rec.status = "success"
    rec.continent = data.get("continent")
    rec.continent_code = data.get("continent_code")
    rec.country = data.get("country")
    rec.country_code = data.get("country_code")
    rec.region = data.get("region")
    rec.region_name = data.get("region")
    rec.city = data.get("city")
    rec.zip = str(data.get("postal") or "") or None
    lat, lon = data.get("latitude"), data.get("longitude")
    rec.lat = lat if isinstance(lat, (int, float)) else None
    rec.lon = lon if isinstance(lon, (int, float)) else None
    timezone = _mapping(data.get("timezone"))
    rec.timezone = timezone.get("id")
    flag = _mapping(data.get("flag"))
    conn = _mapping(data.get("connection"))
    rec.isp = conn.get("isp")
    rec.org = conn.get("org")
    asn = conn.get("asn")
    rec.asn = f"AS{asn}" if isinstance(asn, int) else (asn and f"AS{asn}")
    rec.as_name = conn.get("domain")
    security = _mapping(data.get("security"))
    if security:
        rec.is_proxy = security.get("proxy")
        rec.is_hosting = security.get("hosting")
    rec.fetched_at = _now_iso()
    rec.extra["flag"] = {"emoji": flag.get("emoji"), "img": flag.get("img")}
    return rec


def _provider_ipinfo(ip: str, timeout: float, token: Optional[str] = None, **kw) -> IPRecord:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else None
    data, elapsed = _request_json("ipinfo", url, timeout, params=params)
    rec = IPRecord(ip=ip, source="ipinfo.io", lookup_ms=elapsed)
    if "error" in data:
        rec.status = "fail"
        rec.message = str(data["error"])
        return rec
    rec.status = "success"
    hostname = data.get("hostname")
    rec.reverse_dns = hostname if isinstance(hostname, str) else None
    rec.city = data.get("city")
    rec.region_name = data.get("region")
    rec.country_code = data.get("country")
    rec.zip = data.get("postal")
    loc = data.get("loc") if isinstance(data.get("loc"), str) else ""
    parts = loc.split(",")
    if len(parts) == 2:
        try:
            rec.lat = float(parts[0])
            rec.lon = float(parts[1])
        except ValueError:
            pass
    rec.timezone = data.get("timezone")
    org = data.get("org", "")
    if not isinstance(org, str):
        org = ""
    if org:
        # format: "AS15169 Google LLC"
        bits = org.split(" ", 1)
        if bits[0].upper().startswith("AS"):
            rec.asn = bits[0]
            rec.as_name = bits[1] if len(bits) > 1 else None
            rec.isp = bits[1] if len(bits) > 1 else None
        else:
            rec.isp = org
    rec.fetched_at = _now_iso()
    privacy = _mapping(data.get("privacy"))
    if privacy:
        rec.is_proxy = privacy.get("vpn") or privacy.get("proxy")
        rec.is_hosting = privacy.get("hosting")
        if "residential" in privacy:
            rec.is_mobile = not (privacy.get("residential") is False)
    rec.extra["raw_org"] = org
    return rec


PROVIDERS = {
    "ip-api": _provider_ipapi,
    "ipwhois": _provider_ipwhois,
    "ipinfo": _provider_ipinfo,
}


def fetch_from_provider(name: str, ip: str, timeout: float = 10.0, **kwargs) -> IPRecord:
    fn = PROVIDERS.get(name)
    if fn is None:
        rec = IPRecord(ip=ip, status="fail", message=f"unknown provider '{name}'")
        return rec
    try:
        return fn(ip, timeout=timeout, **kwargs)
    except requests.exceptions.RequestException as exc:
        return IPRecord(ip=ip, status="fail", message=f"{name}: {exc}", source=name)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        # Malformed / unexpected JSON schemas fail soft — not a programming bug
        # in our code when the provider returns [], null, a string, etc.
        return IPRecord(ip=ip, status="fail", message=f"{name}: bad response ({exc})", source=name)


def fetch_geo(ip: str, providers: list, timeout: float = 10.0,
              rate_limit: Optional[float] = None, **kwargs) -> IPRecord:
    """Try each provider in order until one succeeds.

    ``rate_limit`` (calls/second per provider) comes from the config; when
    given it (re)configures the shared per-provider limiter set.
    """
    if rate_limit is not None and _limiters_rate != rate_limit:
        # Only (re)build when the rate actually changed, so repeated calls
        # (e.g. one per batch worker) keep the shared pacing state intact.
        set_rate_limit(rate_limit)
    last: Optional[IPRecord] = None
    for name in providers:
        rec = fetch_from_provider(name, ip, timeout=timeout, **kwargs)
        if rec.ok:
            return rec
        last = rec
    return last or IPRecord(ip=ip, status="fail", message="no providers configured")
