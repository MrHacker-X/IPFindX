"""IPFindX v4 — Advanced IP Intelligence & Network Reconnaissance Toolkit.

Public library API::

    from ipfindx import lookup, scan_batch

    report = lookup("8.8.8.8", threat=True)
    print(report.record.city, report.threat.score)

    data = report.to_dict()   # plain dict — persist it however you like

    reports = scan_batch(["8.8.8.8", "1.1.1.1"], threat=True)

Related modules you may want to import directly:

- ``ipfindx.core.cache.TTLCache``       — thread-safe SQLite TTL cache
- ``ipfindx.storage.history.HistoryDB`` — lookup history + diffing
- ``ipfindx.exporters``                 — export_json / export_ndjson /
                                          export_csv / export_html

Submodules:

- ``ipfindx.core``       — models, validation, config, cache
- ``ipfindx.intel``      — multi-provider geolocation + threat intelligence
- ``ipfindx.recon``      — DNS, ping, traceroute, port, whois, TLS probes
- ``ipfindx.exporters``  — JSON / NDJSON / CSV / self-contained HTML reports
- ``ipfindx.storage``    — SQLite history database + diff engine
- ``ipfindx.ui``         — rich terminal rendering
- ``ipfindx.cli``        — command-line interface
- ``ipfindx.shell``      — interactive shell mode
"""

from ipfindx.core.config import Config, load_config
from ipfindx.core.models import IPRecord, ReconResult, ThreatReport
from ipfindx.core.utils import expand_targets, is_public_ip, normalize_ip
from ipfindx.intel.lookup import lookup, scan_batch

__version__ = "4.0.0"

__all__ = [
    "Config",
    "load_config",
    "IPRecord",
    "ReconResult",
    "ThreatReport",
    "expand_targets",
    "is_public_ip",
    "normalize_ip",
    "lookup",
    "scan_batch",
    "__version__",
]
