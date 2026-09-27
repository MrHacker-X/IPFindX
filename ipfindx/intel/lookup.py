"""High-level lookup orchestration: cache, geo failover, threat, recon, history."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional, Tuple

from ipfindx.core.cache import TTLCache
from ipfindx.core.config import Config, load_config
from ipfindx.core.models import IPRecord, LookupReport
from ipfindx.core.utils import (
    TargetLimitError,
    expand_targets,
    expand_targets_limited,
    is_public_ip,
    normalize_ip,
)
from ipfindx.intel.providers import fetch_geo
from ipfindx.intel.threat import assess_threat

__all__ = ["lookup", "scan_batch", "_lookup_one", "resolve_target"]


def _cache_key(ip: str) -> str:
    return f"geo:{ip}"


def resolve_target(target: str) -> Optional[str]:
    """Resolve any target spec (IP literal, CIDR, range or hostname) to an IP.

    Returns None when the target is invalid, private, or unresolvable.
    """
    import ipaddress

    t = target.strip()
    try:
        literal = ipaddress.ip_address(t)
    except ValueError:
        literal = None

    if literal is not None:
        if is_public_ip(t):
            return normalize_ip(t)
        return None  # private / reserved / loopback literal

    # hostname: forward-resolve; prefer public IPv4, fall back to IPv6
    from ipfindx.recon.dns import resolve_host

    dns = resolve_host(t)
    addrs = dns.get("addresses", [])
    for addr in addrs:
        if is_public_ip(addr) and ":" not in addr:
            return addr
    for addr in addrs:
        if is_public_ip(addr):
            return addr
    return None


def _open_geo_cache(cfg: Config, no_cache: bool) -> Optional[TTLCache]:
    """Open the geo cache unless disabled by config or --no-cache."""
    if not cfg.cache_enabled or no_cache:
        return None
    try:
        return TTLCache(cfg.cache_db, ttl=cfg.cache_ttl)
    except Exception:
        return None


def lookup(
    target: str,
    config: Optional[Config] = None,
    threat: bool = False,
    recon: bool = False,
    no_cache: bool = False,
    ports: Optional[str] = None,
) -> LookupReport:
    """Full intelligence report for a single target (IP, CIDR or range).

    When the target expands to multiple IPs, the *first* is used (lazily —
    nothing is materialised); prefer :func:`scan_batch` for multi-target work.
    """
    cfg = config or load_config()
    ip = next(iter(expand_targets(target)), None)
    if ip is None:
        ip = resolve_target(target)
    if ip is None:
        rec = IPRecord(
            ip=target,
            status="fail",
            message="invalid, private, reserved or unresolvable target",
        )
        return LookupReport(record=rec)

    cache = _open_geo_cache(cfg, no_cache)
    try:
        return _lookup_one(
            ip,
            cfg,
            cache=cache,
            threat=threat,
            recon=recon,
            ports=ports,
            orig_target=target,
        )
    finally:
        if cache is not None:
            cache.close()


def _lookup_one(
    ip: str,
    cfg: Config,
    cache: Optional[TTLCache] = None,
    threat: bool = False,
    recon: bool = False,
    ports: Optional[str] = None,
    orig_target: Optional[str] = None,
) -> LookupReport:
    """Run one lookup. Recon and threat are independently controlled.

    When both are requested the recon result feeds the threat scorer
    (open ports) instead of probing twice.
    """
    ip = normalize_ip(ip)
    rec: Optional[IPRecord] = None

    if cache is not None:
        cached = cache.get(_cache_key(ip))
        if cached is not None:
            rec = IPRecord.from_dict(cached)
            rec.extra["cached"] = True

    if rec is None:
        rec = fetch_geo(ip, cfg.providers, timeout=cfg.timeout,
                        rate_limit=cfg.rate_limit, token=cfg.ipinfo_token)
        if rec.ok and cache is not None:
            cache.set(_cache_key(ip), rec.to_dict())

    report = LookupReport(record=rec)
    if not rec.ok:
        return report

    # --- recon (independent of threat) -----------------------------------
    open_ports: Optional[List[int]] = None
    if recon:
        from ipfindx.recon.engine import run_recon

        port_spec = ports or ",".join(map(str, cfg.top_ports))
        report.recon = run_recon(orig_target or ip, cfg, port_spec=port_spec)
        open_ports = [p["port"] for p in report.recon.ports if p.get("state") == "open"]

    # --- threat (reuses recon's open ports when available) ----------------
    if threat:
        report.threat = assess_threat(
            rec,
            open_ports=open_ports,
            abuseipdb_key=cfg.abuseipdb_key,
            tor_cache=cache,  # durable Tor TTL when caching is on; None for --no-cache
            timeout=cfg.timeout,
        )

    return report


def scan_batch(
    targets: Iterable[str],
    config: Optional[Config] = None,
    threat: bool = False,
    recon: bool = False,
    ports: Optional[str] = None,
    no_cache: bool = False,
    progress: Optional[Callable[[int, int, str], None]] = None,
) -> List[LookupReport]:
    """Scan many targets concurrently, preserving input order in results.

    Invalid or over-limit specs produce explicit failed ``LookupReport``
    entries instead of disappearing silently. The batch-wide total of
    expanded targets never exceeds ``cfg.max_targets``, no matter how many
    CIDRs/ranges are combined. ``progress(done, total, current_target)`` is
    invoked after each completion.
    """
    cfg = config or load_config()

    # ---- expansion phase: (spec, ip) tasks + explicit failures -----------
    # max_targets is enforced AGGREGATELY across the whole batch: every spec
    # expands only against the remaining budget, so several CIDRs/ranges
    # cannot collectively bypass the configured safety limit, and the tasks
    # list is never built beyond it.
    tasks: List[Tuple[str, Optional[str], Optional[str]]] = []
    budget = cfg.max_targets
    for spec in targets:
        if budget <= 0:
            tasks.append(
                (spec, None,
                 f"batch target limit reached ({cfg.max_targets} max per scan)")
            )
            continue
        try:
            hits = expand_targets_limited(spec, budget)
        except TargetLimitError as exc:
            tasks.append((spec, None, str(exc)))
            continue
        if hits:
            budget -= len(hits)
            for hit in hits:
                tasks.append((spec, hit, None))
            continue
        resolved = resolve_target(spec)  # hostname support
        if resolved:
            budget -= 1
            tasks.append((spec, resolved, None))
        else:
            tasks.append(
                (spec, None, "invalid, private, reserved or unresolvable target")
            )

    # de-duplicate valid IPs while preserving order
    seen: set = set()
    ips: List[str] = []
    specs: List[str] = []
    valid_positions: List[int] = []
    for pos, (spec, ip, err) in enumerate(tasks):
        if err is not None:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)
        specs.append(spec)
        valid_positions.append(pos)

    # ---- concurrent lookups over the valid targets -----------------------
    cache = _open_geo_cache(cfg, no_cache)
    results: List[Optional[LookupReport]] = [None] * len(ips)
    done = 0
    workers = max(1, min(cfg.batch_workers, len(ips) or 1))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_lookup_one, ip, cfg, cache, threat, recon, ports, spec): idx
                for idx, (ip, spec) in enumerate(zip(ips, specs))
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # keep the batch alive
                    results[idx] = LookupReport(
                        record=IPRecord(ip=ips[idx], status="fail", message=str(exc))
                    )
                done += 1
                if progress:
                    progress(done, len(ips), ips[idx])
    finally:
        if cache is not None:
            cache.close()

    # ---- assemble: valid results in order, failures in their own order ---
    # (duplicate IPs were de-duplicated before scanning; they are skipped here
    # so each valid result maps back to exactly one task position)
    valid_set = set(valid_positions)
    final: List[LookupReport] = []
    viter = iter(results)
    for pos, (spec, ip, err) in enumerate(tasks):
        if err is not None:
            final.append(
                LookupReport(record=IPRecord(ip=spec, status="fail", message=err))
            )
        elif pos in valid_set:
            report = next(viter)
            if report is not None:
                final.append(report)
    return final
