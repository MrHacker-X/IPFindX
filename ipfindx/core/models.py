"""Core data models for IPFindX v4."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = ["IPRecord", "ThreatReport", "ReconResult", "LookupReport"]


@dataclass
class IPRecord:
    """Geolocation + network intelligence for a single IP address."""

    ip: str
    status: str = "fail"
    message: Optional[str] = None
    continent: Optional[str] = None
    continent_code: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    region_name: Optional[str] = None
    city: Optional[str] = None
    district: Optional[str] = None
    zip: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    timezone: Optional[str] = None
    offset: Optional[int] = None
    currency: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    as_name: Optional[str] = None
    reverse_dns: Optional[str] = None
    is_mobile: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None
    # enrichment
    source: str = "unknown"
    lookup_ms: Optional[int] = None
    fetched_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "success"

    @property
    def maps_url(self) -> Optional[str]:
        if self.lat is None or self.lon is None:
            return None
        return f"https://www.google.com/maps/search/?api=1&query={self.lat},{self.lon}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "status": self.status,
            "message": self.message,
            "continent": self.continent,
            "continentCode": self.continent_code,
            "country": self.country,
            "countryCode": self.country_code,
            "region": self.region,
            "regionName": self.region_name,
            "city": self.city,
            "district": self.district,
            "zip": self.zip,
            "lat": self.lat,
            "lon": self.lon,
            "timezone": self.timezone,
            "offset": self.offset,
            "currency": self.currency,
            "isp": self.isp,
            "org": self.org,
            "as": self.asn,
            "asname": self.as_name,
            "reverse": self.reverse_dns,
            "mobile": self.is_mobile,
            "proxy": self.is_proxy,
            "hosting": self.is_hosting,
            "source": self.source,
            "lookupMs": self.lookup_ms,
            "fetchedAt": self.fetched_at,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IPRecord":
        return cls(
            ip=d.get("ip") or d.get("query", ""),
            status=d.get("status", "fail"),
            message=d.get("message"),
            continent=d.get("continent"),
            continent_code=d.get("continentCode"),
            country=d.get("country"),
            country_code=d.get("countryCode"),
            region=d.get("region"),
            region_name=d.get("regionName"),
            city=d.get("city"),
            district=d.get("district"),
            zip=d.get("zip"),
            lat=d.get("lat"),
            lon=d.get("lon"),
            timezone=d.get("timezone"),
            offset=d.get("offset"),
            currency=d.get("currency"),
            isp=d.get("isp"),
            org=d.get("org"),
            asn=d.get("as"),
            as_name=d.get("asname"),
            reverse_dns=d.get("reverse"),
            is_mobile=d.get("mobile"),
            is_proxy=d.get("proxy"),
            is_hosting=d.get("hosting"),
            source=d.get("source", "unknown"),
            lookup_ms=d.get("lookupMs"),
            fetched_at=d.get("fetchedAt", ""),
            extra=d.get("extra", {}) or {},
        )


@dataclass
class ThreatReport:
    """Threat-intelligence assessment for a single IP address."""

    ip: str
    score: int = 0  # 0 (safe) .. 100 (critical)
    level: str = "minimal"
    signals: List[str] = field(default_factory=list)
    tor_exit: bool = False
    is_datacenter: bool = False
    open_ports: List[int] = field(default_factory=list)
    abuse_confidence: Optional[int] = None  # AbuseIPDB 0-100, if API key set
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "score": self.score,
            "level": self.level,
            "signals": self.signals,
            "torExit": self.tor_exit,
            "datacenter": self.is_datacenter,
            "openPorts": self.open_ports,
            "abuseConfidence": self.abuse_confidence,
            "details": self.details,
        }


@dataclass
class ReconResult:
    """Results of local network reconnaissance probes against a target."""

    target: str
    dns: Dict[str, Any] = field(default_factory=dict)
    ping: Dict[str, Any] = field(default_factory=dict)
    traceroute: List[Dict[str, Any]] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    whois: Optional[str] = None
    tls: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "dns": self.dns,
            "ping": self.ping,
            "traceroute": self.traceroute,
            "ports": self.ports,
            "whois": self.whois,
            "tls": self.tls,
        }


@dataclass
class LookupReport:
    """Everything IPFindX knows about one target, ready for export."""

    record: IPRecord
    threat: Optional[ThreatReport] = None
    recon: Optional[ReconResult] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"record": self.record.to_dict()}
        if self.threat:
            out["threat"] = self.threat.to_dict()
        if self.recon:
            out["recon"] = self.recon.to_dict()
        return out
