"""CSV export for batch scans, hardened against spreadsheet formula injection.

Values beginning with ``=``, ``+``, ``-``, ``@``, tab or carriage return are
prefixed with a single quote (the standard mitigation used by major
spreadsheets' own escape paths) so Excel/LibreOffice/Google Sheets do not
interpret them as formulas. Numeric values and normal strings are untouched.
"""

from __future__ import annotations

import csv
import os
from typing import TYPE_CHECKING, Any, List

from ipfindx.exporters.stamp import export_stamp

if TYPE_CHECKING:  # pragma: no cover
    from ipfindx.core.models import LookupReport

__all__ = ["export_csv", "sanitize_csv_value"]

_FIELDS = [
    "ip", "status", "country", "country_code", "region_name", "city", "zip",
    "lat", "lon", "timezone", "isp", "org", "asn", "reverse_dns",
    "is_mobile", "is_proxy", "is_hosting", "source",
    "risk_score", "risk_level", "tor_exit", "open_ports",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_value(value: Any) -> Any:
    """Return *value* safe for CSV emission.

    Strings starting with a formula trigger character (``=``, ``+``, ``-``,
    ``@``, tab, CR) get a leading ``'`` guard. Non-string values (ints,
    floats, bools, None) pass through unchanged.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def export_csv(reports: List["LookupReport"], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"scan-{export_stamp()}.csv")
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDS)
        writer.writeheader()
        for report in reports:
            rec = report.record
            threat = report.threat
            row = {
                "ip": rec.ip,
                "status": rec.status,
                "country": rec.country,
                "country_code": rec.country_code,
                "region_name": rec.region_name,
                "city": rec.city,
                "zip": rec.zip,
                "lat": rec.lat,
                "lon": rec.lon,
                "timezone": rec.timezone,
                "isp": rec.isp,
                "org": rec.org,
                "asn": rec.asn,
                "reverse_dns": rec.reverse_dns,
                "is_mobile": rec.is_mobile,
                "is_proxy": rec.is_proxy,
                "is_hosting": rec.is_hosting,
                "source": rec.source,
                "risk_score": threat.score if threat else "",
                "risk_level": threat.level if threat else "",
                "tor_exit": threat.tor_exit if threat else "",
                "open_ports": ",".join(map(str, threat.open_ports)) if threat else "",
            }
            writer.writerow({k: sanitize_csv_value(v) for k, v in row.items()})
    return path
