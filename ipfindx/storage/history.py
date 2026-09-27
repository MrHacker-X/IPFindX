"""SQLite-backed lookup history with change detection and diffing."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

__all__ = ["HistoryDB"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lookups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ts TEXT NOT NULL,
    source TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookups_ip ON lookups(ip, ts);
"""


class HistoryDB:
    """Persistent lookup history stored at ~/.local/share/ipfindx/history.sqlite3."""

    def __init__(self, db_path: str):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._closed = False
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        except Exception:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            raise
        self._conn: Optional[sqlite3.Connection] = conn

    # ---------------------------------------------------------------- write

    def record(self, ip: str, payload: dict, source: str = "", ts: str = "") -> int:
        import datetime

        if self._conn is None:
            raise RuntimeError("history database is closed")
        ts = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()
        cur = self._conn.execute(
            "INSERT INTO lookups(ip, ts, source, payload) VALUES(?,?,?,?)",
            (ip, ts, source, json.dumps(payload)),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    # ----------------------------------------------------------------- read

    def last_snapshot(self, ip: str) -> Optional[dict]:
        """Most recent stored payload for *ip*, or None."""
        if self._conn is None:
            raise RuntimeError("history database is closed")
        cur = self._conn.execute(
            "SELECT payload FROM lookups WHERE ip = ? ORDER BY id DESC LIMIT 1", (ip,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def entries(self, ip: Optional[str] = None, limit: int = 50) -> List[dict]:
        """Recent lookups, newest first, optionally filtered by IP."""
        if self._conn is None:
            raise RuntimeError("history database is closed")
        if ip:
            cur = self._conn.execute(
                "SELECT ip, ts, source FROM lookups WHERE ip = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            )
        else:
            cur = self._conn.execute(
                "SELECT ip, ts, source FROM lookups ORDER BY id DESC LIMIT ?", (limit,)
            )
        return [{"ip": r[0], "ts": r[1], "source": r[2]} for r in cur.fetchall()]

    def seen_ips(self) -> List[str]:
        if self._conn is None:
            raise RuntimeError("history database is closed")
        cur = self._conn.execute("SELECT DISTINCT ip FROM lookups ORDER BY ip")
        return [r[0] for r in cur.fetchall()]

    # ---------------------------------------------------------------- diff

    # Volatile metadata that changes on every lookup and is not intelligence.
    _VOLATILE_KEYS = frozenset({"fetchedAt", "lookupMs"})
    _VOLATILE_EXTRA_KEYS = frozenset({"cached"})

    def diff_fields(self, ip: str, current_payload: dict) -> Dict[str, tuple]:
        """Compare *current_payload* to the last stored snapshot.

        Returns ``{field: (old, new)}`` for every changed field. Timing and
        cache-only metadata (``fetchedAt``, ``lookupMs``, ``extra.cached``)
        are ignored so ``--diff`` reports meaningful intelligence changes.
        """
        prev = self.last_snapshot(ip)
        if prev is None:
            return {}
        prev_rec = (prev or {}).get("record", prev or {})
        cur_rec = (current_payload or {}).get("record", current_payload or {})
        if not isinstance(prev_rec, dict):
            prev_rec = {}
        if not isinstance(cur_rec, dict):
            cur_rec = {}
        diffs: Dict[str, tuple] = {}
        for key in sorted(set(prev_rec) | set(cur_rec)):
            if key in self._VOLATILE_KEYS:
                continue
            old, new = prev_rec.get(key), cur_rec.get(key)
            if key == "extra":
                old = self._stable_extra(old)
                new = self._stable_extra(new)
            if old != new:
                diffs[key] = (old, new)
        return diffs

    @classmethod
    def _stable_extra(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        return {k: v for k, v in value.items() if k not in cls._VOLATILE_EXTRA_KEYS}

    def close(self) -> None:
        """Close the underlying SQLite connection (idempotent)."""
        if self._closed:
            return
        self._closed = True
        conn = self._conn
        self._conn = None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "HistoryDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
