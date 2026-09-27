"""JSON export: single-object or JSON-array for batches, plus streaming NDJSON."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, List

from ipfindx.exporters.stamp import export_stamp

if TYPE_CHECKING:  # pragma: no cover
    from ipfindx.core.models import LookupReport

__all__ = ["export_json", "export_ndjson"]


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def export_json(reports: List["LookupReport"], output_dir: str) -> str:
    """Write reports as timestamped JSON, returning the file path.

    A single report produces a JSON object; multiple reports produce a JSON
    **array** — always one valid JSON document.
    """
    _ensure_dir(output_dir)
    stamp = export_stamp()
    if len(reports) == 1:
        ip = reports[0].record.ip.replace(":", "_")
        path = os.path.join(output_dir, f"{ip}-{stamp}.json")
        payload = reports[0].to_dict()
    else:
        path = os.path.join(output_dir, f"batch-{stamp}.json")
        payload = [r.to_dict() for r in reports]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def export_ndjson(reports: List["LookupReport"], output_dir: str) -> str:
    """Write a batch as newline-delimited JSON (one report per line)."""
    _ensure_dir(output_dir)
    path = os.path.join(output_dir, f"batch-{export_stamp()}.ndjson")
    with open(path, "w", encoding="utf-8") as fh:
        for report in reports:
            fh.write(json.dumps(report.to_dict()) + "\n")
    return path
