<div align="center">

# 🌐 IPFindX v4 — Advanced IP Intelligence & Reconnaissance Toolkit

<p>
<img src="https://img.shields.io/badge/💎-Premium%20OSINT%20Tool-blueviolet?style=for-the-badge" alt="Premium Tool">
<img src="https://img.shields.io/badge/🛡-Threat%20Scoring-red?style=for-the-badge" alt="Threat Scoring">
<img src="https://img.shields.io/badge/⚡-Multi--Provider%20Failover-yellow?style=for-the-badge" alt="Failover">
</p>

### 🚀 *Geolocation • Threat Intelligence • Network Recon • Interactive Shell — one toolkit*

**The successor to the classic single-file scanner: a full intelligence platform with multi-provider failover, 0–100 risk scoring, live network reconnaissance, SQLite history with change detection, and self-contained HTML reports.**

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.0.0-brightgreen.svg)](#-whats-new-in-v4)
[![Tests](https://img.shields.io/badge/tests-122%20passing-success.svg)](#-development)

</div>

---

## 📋 Table of Contents

- [What's New in v4](#-whats-new-in-v4)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [CLI Reference](#-cli-reference)
- [Threat Scoring](#-threat-scoring)
- [Network Recon](#-network-recon)
- [Interactive Shell](#-interactive-shell)
- [Python Library API](#-python-library-api)
- [Configuration](#-configuration)
- [Exports](#-exports)
- [Docker](#-docker)
- [Architecture](#-architecture)
- [Development](#-development)
- [Compatibility](#-compatibility)
- [Security Considerations](#-security-considerations)
- [License](#-license)

## 🆕 What's New in v4

| Feature | v3 | v4 |
|---|---|---|
| Data sources | single API | **3 providers with automatic failover** (ip-api → ipwho.is → ipinfo) |
| Threat intel | ❌ | **0–100 risk scoring**: Tor exit lists, datacenter ASNs, proxy flags, exposed admin ports, rDNS heuristics, optional AbuseIPDB |
| Network recon | ❌ | **DNS, ping, traceroute, TCP port scan, whois, TLS certificate inspection** — all stdlib |
| Target types | single IPs | **CIDR (`8.8.8.0/24`), ranges (`1.1.1.1-1.1.1.9`), hostnames (`example.com`), your own IP (`--myip`)** |
| Batch mode | sequential | **concurrent with live progress bar**, per-provider rate limiting |
| Caching | ❌ | **SQLite TTL cache** — instant repeat lookups, quota saved |
| History | ❌ | **persistent history + `--diff`** shows exactly what changed since last lookup |
| Interactive mode | ❌ | **full shell**: `lookup`, `threat`, `recon`, `batch`, `history`, `diff`… |
| Exports | JSON | **JSON, NDJSON, CSV, self-contained HTML report** |
| Library use | ❌ | clean **Python API**: `from ipfindx import lookup` |
| Tests / packaging | ❌ | **122+ unit tests, pyproject.toml, `pip install ipfindx`, Docker image** |

## 🚀 Installation

```bash
# From source (this repo)
git clone https://github.com/MrHacker-X/IPFindX.git
cd IPFindX
pip install -r requirements.txt

# Run
python ipfindx.py --help        # classic entry point still works
ipfindx --help                  # after `pip install .`
python -m ipfindx --help        # module style
```

## ⚡ Quick Start

```bash
ipfindx -i 8.8.8.8                    # geolocation + network intelligence
ipfindx -i 8.8.8.8 -t                 # + threat scoring (0-100)
ipfindx -i example.com -r             # hostname + full recon + threat
ipfindx --myip -t                     # intelligence on your own public IP
ipfindx -i 8.8.8.0/28 -t              # scan a CIDR block
ipfindx -i 8.8.8.1-8.8.8.9            # scan a range
ipfindx -l targets.txt -t -f all      # batch + every export format
ipfindx --diff 1.1.1.1                # what changed since last lookup?
ipfindx --history                     # recent lookups
ipfindx --interactive                 # recon shell
```

## 🎛 CLI Reference

```
targets:
  -i, --ip TARGET       IP, CIDR (8.8.8.0/24), range (8.8.8.1-8.8.8.9) or hostname
  -l, --list FILE       file with one target per line (# comments allowed)
  -m, --myip            run intelligence on your own public IP

modes:
  --about / --connect   info + community links
  --interactive         interactive shell
  --history [IP]        show lookup history
  --diff IP             fresh lookup diffed against the previous one
  --clear-cache         purge the lookup cache

enrichment:
  -t, --threat          threat assessment and risk score
  -r, --recon           DNS, ping, traceroute, ports, whois, TLS
  -p, --ports SPEC      port spec for recon (e.g. 80,443,1000-2000)

output:
  -o, --output DIR      output directory (default: output-ipfindx)
  -f, --format FMT      json,csv,html,ndjson,all (comma separated)
  --json                clean JSON on stdout (UI goes to stderr)
  --no-save             don't write any files (exports and history)
  -q, --quiet           suppress banner/progress

configuration:
  -c, --config FILE     JSON config file
  --workers N           concurrent workers for batch scans
  --timeout S           network timeout in seconds
  --no-cache            bypass the lookup cache
```

## 🛡 Threat Scoring

`-t` produces a 0–100 risk score from layered signals:

| Signal | Weight |
|---|---|
| Tor exit node (live bulk list, cached 6 h) | +40 |
| Flagged as proxy/VPN by geo provider | +30 |
| Datacenter/hosting infrastructure | +15 |
| Exposed admin ports (SSH, Telnet, RDP, VNC — from recon) | up to +20 |
| Suspicious reverse-DNS patterns (`static.*`, `mail.*`, `tor.*`…) | +10 |
| AbuseIPDB confidence ≥ 50 (optional API key) | floors the score |

Levels: `minimal` → `low` → `moderate` → `elevated` → `high` → `critical`.

Enable AbuseIPDB enrichment without any code changes:

```bash
export IPFINDX_ABUSEIPDB_KEY="your_key"
ipfindx -i 185.220.101.1 -t -r
```

## 🛰 Network Recon

`-r` runs the full suite (stdlib only — no nmap needed):

- **DNS** — forward resolution, all A/AAAA records
- **Ping** — ICMP with automatic TCP-latency fallback when the binary is missing or returns no replies (works on Termux/containers)
- **Traceroute** — hop-by-hop via the OS binary (`traceroute` on Unix, `tracert` on Windows); no TCP traceroute fallback
- **Port scan** — concurrent TCP connect scan over 18 common ports (or `-p` custom spec)
- **WHOIS** — direct RIR queries (ARIN/RIPE/APNIC/LACNIC/AFRINIC) with smart server routing
- **TLS** — certificate subject/issuer/validity + SHA-256 fingerprint, parsed from raw DER with verified-then-insecure SNI fallback

```bash
ipfindx -i 8.8.8.8 -r -p 53,80,443
```

## 🐚 Interactive Shell

```bash
$ ipfindx --interactive
ipfindx> recon example.com --ports 80,443
ipfindx> threat 185.220.101.1
ipfindx> batch suspects.txt
ipfindx> history
ipfindx> diff 8.8.8.8
ipfindx> config
ipfindx> exit
```

## 🐍 Python Library API

```python
from ipfindx import lookup, scan_batch, is_public_ip, expand_targets

# one report: geo + threat
report = lookup("8.8.8.8", threat=True)
print(report.record.city, report.threat.score)
print(report.to_dict())

# concurrent batch with progress
reports = scan_batch(
    ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    threat=True,
    progress=lambda done, total, cur: print(f"{done}/{total} {cur}"),
)

# target expansion utilities
print(list(expand_targets("8.8.8.0/30")))   # ['8.8.8.1', '8.8.8.2']
```

## ⚙️ Configuration

Optional `ipfindx.json` (or `~/.config/ipfindx/config.json`):

```json
{
  "timeout": 10.0,
  "rate_limit": 4.0,
  "batch_workers": 8,
  "providers": ["ip-api", "ipwhois", "ipinfo"],
  "abuseipdb_key": null,
  "top_ports": [22, 80, 443, 3306],
  "cache_ttl": 3600
}
```

Environment overrides: `IPFINDX_ABUSEIPDB_KEY`, `IPFINDX_IPINFO_TOKEN`, `IPFINDX_TIMEOUT`.

## 📦 Exports

```bash
ipfindx -i 8.8.8.8 -t -r -f all        # JSON + NDJSON + CSV + HTML
```

- **JSON** — full nested report (record / threat / recon)
- **NDJSON** — one report per line, ideal for log pipelines
- **CSV** — flat spreadsheet view with risk columns
- **HTML** — self-contained dark-theme dashboard with risk gauge, signal chips, port table and TLS details; **works fully offline**, open it anywhere

All files land in `output-ipfindx/` (or `-o DIR`) with UTC-style timestamps.

## 🐳 Docker

```bash
docker build -t ipfindx .
docker run --rm ipfindx -i 8.8.8.8 -t
docker run --rm --cap-add=NET_RAW ipfindx -i 8.8.8.8 -r   # + ICMP/traceroute
```

## 🏗 Architecture

```
IPFindX/
├── ipfindx.py               # legacy entry point → package shim
├── pyproject.toml           # packaging (pip install .)
├── CHANGELOG.md             # release history
├── Dockerfile
├── ipfindx/
│   ├── core/                # models, validation, CIDR expansion, config, TTL cache
│   ├── intel/
│   │   ├── providers.py     # 3 geo providers + failover
│   │   ├── threat.py        # risk scoring engine
│   │   └── lookup.py        # orchestration + concurrent batch
│   ├── recon/               # DNS, ping, traceroute, ports, whois, TLS (DER parser)
│   ├── exporters/           # JSON, NDJSON, CSV, self-contained HTML
│   ├── storage/             # SQLite history + diff engine
│   ├── ui/                  # rich terminal rendering
│   ├── cli.py               # argument parsing + flows
│   └── shell.py             # interactive console
└── tests/                   # 122+ offline unit / regression tests
```

Every probe fails soft: provider outages, unreachable hosts and missing binaries degrade gracefully, never crash a scan.

## 🧪 Development

```bash
pip install -r requirements.txt
pip install -e ".[dev]"
python -m pytest tests/ -v          # full suite, fully offline
python -m pytest tests/ --cov=ipfindx --cov-report=term-missing
```

### Building & publishing to PyPI

```bash
python -m build                     # wheel + sdist into dist/
twine check dist/*                  # validate metadata
python -m twine upload dist/*       # publish (needs a PyPI token)
```

Release checklist before uploading:

1. Bump `__version__` in `ipfindx/__init__.py` (single source of truth — the
   package build reads it dynamically) and add a `CHANGELOG.md` entry.
2. `python -m pytest tests/ -v` — green suite.
3. Install the built wheel in a fresh venv and run one smoke lookup.
4. `twine check dist/*` — clean, then upload.

## 🖥 Compatibility

Linux · macOS · Windows · Android (Termux). ICMP ping falls back to a TCP connect probe when the OS `ping` binary is missing or returns no usable RTTs. Traceroute uses `traceroute` on Unix and `tracert` on Windows; there is no automatic TCP traceroute fallback. Python 3.9+.

## 🔒 Security Considerations

- Recon probes are lightweight TCP connects — use only on assets you're authorised to assess
- No data leaves your machine except the geo/threat API queries themselves
- Cache and history live locally in `~/.cache/ipfindx/` and `~/.local/share/ipfindx/`
- Private, reserved and loopback ranges are always rejected
- API keys are read from the environment, never stored in output files
- CSV export guards against spreadsheet formula injection
- Provider requests are rate-limited by default (4 req/s per provider)

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👨‍💻 Developer

**Alex Butler** · Vritra Security Organization
[GitHub](https://github.com/MrHacker-X) · [Website](https://vritrasec.com) · [Telegram](https://t.me/VritraSec)

---

<div align="center">

**Made with ❤️ by the <a href="https://vritrasec.com">Vritra Security Organization</a>**

</div>
