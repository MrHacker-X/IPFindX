# Changelog

All notable changes to IPFindX are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/) (adapted) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [4.0.0] — 2026-09-27

The single-file scanner became a full intelligence platform.

### Added
- **Multi-provider geolocation** (ip-api → ipwho.is → ipinfo) with automatic
  failover and per-provider rate limiting (HTTP 429 `Retry-After` honoured).
- **Threat scoring (0–100)**: Tor exit lists, datacenter/proxy flags, exposed
  admin ports, rDNS heuristics, optional AbuseIPDB enrichment.
- **Network recon**: DNS, ping (ICMP with TCP fallback), traceroute, concurrent
  TCP port scan, RIR-routed WHOIS, TLS certificate inspection (raw DER parser).
- **Target expansion**: CIDR, ranges, hostnames, `--myip`.
- **SQLite TTL cache** — thread-safe (per-thread connections, WAL mode) with
  `--no-cache` bypass.
- **Persistent history + `--diff`** change detection.
- **Interactive shell** (`--interactive`) and clean `--json` stdout mode.
- **Exports**: JSON (object/array semantics), NDJSON, CSV (formula-injection
  guarded), self-contained offline HTML report.

### Changed
- CLI exit code is non-zero when every target fails.
- `lookup_ms` measures the actual provider request for every provider.
- Batch scans enforce `max_targets` **aggregate across all specs** and preserve
  invalid targets as explicit failed reports.

### Security
- CSV export sanitizes formula-injection prefixes (`= + - @ \t \r`).
- Rate limiting is on by default (4 req/s per provider, configurable).

## [3.0.1] — 2022

Last release of the classic single-file tool: one API source, JSON export only.

## [3.0.0] — 2021

Initial PyPI release of IPFindX.
