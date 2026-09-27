"""Collision-safe UTC export filename stamps."""

from __future__ import annotations

import datetime
import threading

__all__ = ["export_stamp"]

_lock = threading.Lock()
_last_stamp = ""
_seq = 0


def export_stamp() -> str:
    """Return a UTC stamp unique even for back-to-back exports in the same second.

    Format: ``YYYYMMDD-HHMMSS-ffffff`` with an optional ``-N`` suffix when the
    same microsecond stamp would otherwise collide.
    """
    global _last_stamp, _seq
    base = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    with _lock:
        if base == _last_stamp:
            _seq += 1
            return f"{base}-{_seq}"
        _last_stamp = base
        _seq = 0
        return base
