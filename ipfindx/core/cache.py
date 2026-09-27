"""SQLite-backed TTL cache, safe for concurrent use across threads.

Concurrency design
------------------
* Every thread gets its **own** ``sqlite3.Connection`` (thread-local), so no
  handle is ever shared between threads for queries — sharing a handle is not
  safe and produces sqlite3 misuse errors under load.
* Connections are created with ``check_same_thread=False`` solely so
  :meth:`close` can deterministically shut down every connection owned by the
  cache (including ones created on worker threads) from the closing thread.
  Operational use still goes only through the thread-local handle.
* WAL journal mode + ``busy_timeout`` let concurrent readers/writers proceed
  without spurious "database is locked" failures.
* Writes use short implicit transactions (autocommit); ``close()`` is
  idempotent and closes **all** connections owned by this cache instance.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional, Set

__all__ = ["TTLCache"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at);
"""

_BUSY_TIMEOUT_MS = 5000


class TTLCache:
    """TTL cache safe for use from multiple threads.

    Each thread talks to SQLite over its own connection. WAL mode allows
    one writer and many readers to proceed concurrently; ``busy_timeout``
    absorbs remaining contention. ``close()`` closes every connection this
    instance created, not only the caller's thread-local one.
    """

    def __init__(self, db_path: str, ttl: int = 3600):
        self.ttl = ttl
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._closed = threading.Event()
        self._conns_lock = threading.Lock()
        self._conns: Set[sqlite3.Connection] = set()
        # one init connection to create schema / enable WAL
        conn = self._new_connection()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            self._discard_connection(conn)

    # ------------------------------------------------------- connections

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self._path), timeout=_BUSY_TIMEOUT_MS / 1000.0,
            # False so close() can shut down worker-thread connections from
            # the owning/closing thread. Ops still use thread-local only.
            check_same_thread=False,
        )
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=%d" % _BUSY_TIMEOUT_MS)
            conn.execute("PRAGMA synchronous=NORMAL")
            with self._conns_lock:
                if self._closed.is_set():
                    raise RuntimeError("cache is closed")
                self._conns.add(conn)
        except Exception:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            raise
        return conn

    def _discard_connection(self, conn: sqlite3.Connection) -> None:
        """Close *conn* and drop it from the owned-connection registry."""
        with self._conns_lock:
            self._conns.discard(conn)
        try:
            conn.close()
        except sqlite3.Error:
            pass

    def _connection(self) -> sqlite3.Connection:
        """Return this thread's connection, creating it on first use."""
        if self._closed.is_set():
            raise RuntimeError("cache is closed")
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_connection()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close every connection owned by this cache (idempotent).

        Thread-local / per-worker connections are closed here as well as the
        caller's, so batch workers cannot leave open handles behind.
        """
        self._closed.set()
        with self._conns_lock:
            conns = list(self._conns)
            self._conns.clear()
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local.conn = None

    def __enter__(self) -> "TTLCache":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ ops

    def get(self, key: str) -> Optional[Any]:
        try:
            conn = self._connection()
        except RuntimeError:
            return None
        try:
            cur = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            )
            row = cur.fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        value, expires_at = row
        if expires_at < time.time():
            self.delete(key)
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires = time.time() + (ttl if ttl is not None else self.ttl)
        try:
            conn = self._connection()
        except RuntimeError:
            return
        try:
            conn.execute(
                "INSERT INTO cache(key, value, expires_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at",
                (key, json.dumps(value), expires),
            )
            conn.commit()
        except sqlite3.Error:
            pass  # cache must never break the tool

    def delete(self, key: str) -> None:
        try:
            conn = self._connection()
        except RuntimeError:
            return
        try:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()
        except sqlite3.Error:
            pass

    def purge_expired(self) -> int:
        try:
            conn = self._connection()
        except RuntimeError:
            return 0
        cur = conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
        conn.commit()
        return cur.rowcount or 0

    def clear(self) -> int:
        try:
            conn = self._connection()
            cur = conn.execute("DELETE FROM cache")
            conn.commit()
            return cur.rowcount or 0
        except (sqlite3.Error, RuntimeError):
            return 0

    def __len__(self) -> int:
        try:
            conn = self._connection()
            cur = conn.execute("SELECT COUNT(*) FROM cache")
            return int(cur.fetchone()[0])
        except (sqlite3.Error, RuntimeError):
            return 0
