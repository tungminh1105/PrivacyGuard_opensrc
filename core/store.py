"""SQLite storage module for PrivacyGuard events, processes, and alerts.

Implements the data schema specified in SPEC Section 4 with WAL mode and batching.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  pid INTEGER NOT NULL,
  ppid INTEGER,
  proc_key TEXT NOT NULL,
  type TEXT NOT NULL,
  path TEXT,
  dest_ip TEXT,
  dest_port INTEGER,
  proto TEXT,
  nbytes INTEGER DEFAULT 0,
  extra_json TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_pk ON events(proc_key, ts);

CREATE TABLE IF NOT EXISTS processes (
  proc_key TEXT PRIMARY KEY,
  pid INTEGER,
  ppid INTEGER,
  name TEXT,
  exe_path TEXT,
  signed INTEGER,
  publisher TEXT,
  start_ts REAL,
  end_ts REAL
);

CREATE TABLE IF NOT EXISTS windows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proc_key TEXT,
  t_start REAL,
  t_end REAL,
  features_json TEXT,
  label INTEGER,
  scenario TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL,
  proc_key TEXT,
  window_id INTEGER,
  detector TEXT,
  score REAL,
  severity TEXT,
  evidence TEXT,
  status TEXT DEFAULT 'new'
);

CREATE TABLE IF NOT EXISTS file_zones (
  path TEXT PRIMARY KEY,
  host_domain TEXT,
  referrer_domain TEXT,
  zone_id TEXT,
  proc_key TEXT,
  ts REAL
);

CREATE TABLE IF NOT EXISTS receiver_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc REAL NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER NOT NULL,
  dest_port INTEGER NOT NULL,
  bytes_received INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receiver_ts ON receiver_logs(ts_utc);
"""


class EventStore:
    """Manages SQLite storage for PrivacyGuard with WAL mode and bulk write capability."""

    def __init__(self, db_path: str = "data/privacyguard.db", wal_mode: bool = True):
        self.db_path = db_path
        self._ensure_dir()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db(wal_mode=wal_mode)
        self.existing_record_ids: Set[int] = self._load_existing_record_ids()

    def _ensure_dir(self) -> None:
        """Create parent directory for the database file if not present."""
        dirname = os.path.dirname(self.db_path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname, exist_ok=True)

    def _init_db(self, wal_mode: bool = True) -> None:
        """Initialize database tables, indexes, and journal mode."""
        cur = self.conn.cursor()
        if wal_mode:
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
        cur.executescript(SCHEMA_SQL)
        self.conn.commit()

    def _load_existing_record_ids(self) -> Set[int]:
        """Load set of existing event_record_ids from extra_json column."""
        cur = self.conn.cursor()
        try:
            cur.execute("SELECT json_extract(extra_json, '$.event_record_id') FROM events WHERE extra_json IS NOT NULL")
            return {int(row[0]) for row in cur.fetchall() if row[0] is not None}
        except Exception:
            return set()

    def insert_events_batch(self, events: List[Dict[str, Any]]) -> int:
        """Insert a batch of event dictionaries into the events table.

        Automatically deduplicates events that share an already recorded event_record_id.

        Args:
            events: List of event dicts containing fields matching the schema.

        Returns:
            Number of inserted rows.
        """
        if not events:
            return 0

        # Filter out events whose event_record_id has already been recorded
        to_insert = []
        for e in events:
            rec_id = None
            extra = e.get("extra_json")
            if isinstance(extra, dict):
                rec_id = extra.get("event_record_id")
            elif isinstance(extra, str):
                try:
                    rec_id = json.loads(extra).get("event_record_id")
                except Exception:
                    pass

            if rec_id is not None:
                try:
                    rec_id = int(rec_id)
                    if rec_id in self.existing_record_ids:
                        continue
                    self.existing_record_ids.add(rec_id)
                except (ValueError, TypeError):
                    pass

            to_insert.append(e)

        if not to_insert:
            return 0

        sql = """
        INSERT INTO events (ts, pid, ppid, proc_key, type, path, dest_ip, dest_port, proto, nbytes, extra_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = []
        for e in to_insert:
            extra = e.get("extra_json")
            if isinstance(extra, dict):
                extra = json.dumps(extra, ensure_ascii=False)
            rows.append((
                float(e["ts"]),
                int(e["pid"]),
                int(e["ppid"]) if e.get("ppid") is not None else None,
                str(e["proc_key"]),
                str(e["type"]),
                e.get("path"),
                e.get("dest_ip"),
                int(e["dest_port"]) if e.get("dest_port") is not None else None,
                e.get("proto"),
                int(e.get("nbytes", 0)),
                extra,
            ))

        with self.conn:
            self.conn.executemany(sql, rows)
        return len(rows)

    def upsert_process(self, proc: Dict[str, Any]) -> None:
        """Insert or update process metadata in the processes table."""
        sql = """
        INSERT INTO processes (proc_key, pid, ppid, name, exe_path, signed, publisher, start_ts, end_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(proc_key) DO UPDATE SET
            pid=COALESCE(excluded.pid, processes.pid),
            ppid=COALESCE(excluded.ppid, processes.ppid),
            name=COALESCE(excluded.name, processes.name),
            exe_path=COALESCE(excluded.exe_path, processes.exe_path),
            signed=COALESCE(excluded.signed, processes.signed),
            publisher=COALESCE(excluded.publisher, processes.publisher),
            start_ts=COALESCE(excluded.start_ts, processes.start_ts),
            end_ts=COALESCE(excluded.end_ts, processes.end_ts)
        """
        with self.conn:
            self.conn.execute(sql, (
                str(proc["proc_key"]),
                int(proc["pid"]) if proc.get("pid") is not None else None,
                int(proc["ppid"]) if proc.get("ppid") is not None else None,
                proc.get("name"),
                proc.get("exe_path"),
                int(proc["signed"]) if proc.get("signed") is not None else None,
                proc.get("publisher"),
                float(proc["start_ts"]) if proc.get("start_ts") is not None else None,
                float(proc["end_ts"]) if proc.get("end_ts") is not None else None,
            ))

    def update_process_end(self, proc_key: str, end_ts: float) -> None:
        """Update end timestamp for a terminated process."""
        sql = "UPDATE processes SET end_ts = ? WHERE proc_key = ?"
        with self.conn:
            self.conn.execute(sql, (float(end_ts), str(proc_key)))

    def upsert_file_zone(self, zone: Dict[str, Any]) -> None:
        """Insert or replace Zone.Identifier information for a downloaded file."""
        sql = """
        INSERT INTO file_zones (path, host_domain, referrer_domain, zone_id, proc_key, ts)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            host_domain=excluded.host_domain,
            referrer_domain=excluded.referrer_domain,
            zone_id=excluded.zone_id,
            proc_key=excluded.proc_key,
            ts=excluded.ts
        """
        with self.conn:
            self.conn.execute(sql, (
                str(zone["path"]),
                zone.get("host_domain", "unknown"),
                zone.get("referrer_domain", "unknown"),
                str(zone.get("zone_id", "unknown")),
                zone.get("proc_key"),
                float(zone["ts"]) if zone.get("ts") is not None else None,
            ))

    def get_event_count(self) -> int:
        """Return total row count in events table."""
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events")
        return cur.fetchone()[0]

    def get_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve events ordered by id ascending."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM events ORDER BY id ASC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(row) for row in cur.fetchall()]

    def get_processes(self) -> List[Dict[str, Any]]:
        """Retrieve all recorded processes."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM processes")
        return [dict(row) for row in cur.fetchall()]

    def get_file_zones(self) -> List[Dict[str, Any]]:
        """Retrieve all recorded file zone info."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM file_zones")
        return [dict(row) for row in cur.fetchall()]

    def log_receiver_bytes(
        self, ts_utc: float, src_ip: str, src_port: int, dest_port: int, bytes_received: int
    ) -> None:
        """Record received network bytes and UTC timestamp into receiver_logs without payload."""
        sql = """
        INSERT INTO receiver_logs (ts_utc, src_ip, src_port, dest_port, bytes_received)
        VALUES (?, ?, ?, ?, ?)
        """
        with self.conn:
            self.conn.execute(sql, (float(ts_utc), str(src_ip), int(src_port), int(dest_port), int(bytes_received)))

    def get_receiver_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve recorded receiver logs ordered by id ASC."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM receiver_logs ORDER BY id ASC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(row) for row in cur.fetchall()]

    def get_total_receiver_bytes(self, dest_port: Optional[int] = None) -> int:
        """Calculate total bytes received across all logged connections."""
        cur = self.conn.cursor()
        if dest_port is not None:
            cur.execute("SELECT COALESCE(SUM(bytes_received), 0) FROM receiver_logs WHERE dest_port = ?", (int(dest_port),))
        else:
            cur.execute("SELECT COALESCE(SUM(bytes_received), 0) FROM receiver_logs")
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def close(self) -> None:
        """Close database connection."""
        try:
            self.conn.close()
        except Exception:
            pass

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
