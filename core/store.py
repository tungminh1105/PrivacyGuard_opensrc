"""SQLite storage module for PrivacyGuard events, processes, and alerts.

Implements the data schema specified in SPEC Section 4 with WAL mode and batching.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set

from core.paths import resolve_path

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
  bytes_received INTEGER NOT NULL,
  matched_event_id INTEGER DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_receiver_ts ON receiver_logs(ts_utc);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS scan_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  events_loaded INTEGER DEFAULT 0,
  windows_created INTEGER DEFAULT 0,
  no_proc_key INTEGER DEFAULT 0,
  not_direct_actor INTEGER DEFAULT 0,
  ignored_process INTEGER DEFAULT 0,
  no_causal INTEGER DEFAULT 0,
  bytes_below_min INTEGER DEFAULT 0,
  no_sensitive_file INTEGER DEFAULT 0,
  score_below_threshold INTEGER DEFAULT 0,
  duplicate INTEGER DEFAULT 0,
  alerts_created INTEGER DEFAULT 0,
  not_ready INTEGER DEFAULT 0,
  details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_stats_ts ON scan_stats(ts);
"""


class EventStore:
    """Manages SQLite storage for PrivacyGuard with WAL mode and bulk write capability."""

    def __init__(self, db_path: str = "data/privacyguard.db", wal_mode: bool = True):
        if db_path == ":memory:" or db_path.startswith("file:"):
            self.db_path = db_path
        else:
            self.db_path = resolve_path(db_path)
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

        # Schema migrations for existing databases
        try:
            cur.execute("PRAGMA table_info(receiver_logs)")
            cols = [col[1] for col in cur.fetchall()]
            if "matched_event_id" not in cols and cols:
                cur.execute("ALTER TABLE receiver_logs ADD COLUMN matched_event_id INTEGER DEFAULT NULL")
                self.conn.commit()
            cur.execute("CREATE INDEX IF NOT EXISTS idx_receiver_matched ON receiver_logs(matched_event_id)")
            self.conn.commit()
        except Exception as e:
            logger.debug("Migration check on receiver_logs failed: %s", e)

        try:
            cur.execute("PRAGMA table_info(scan_stats)")
            cols = [col[1] for col in cur.fetchall()]
            for c in ["no_proc_key", "not_direct_actor", "not_ready"]:
                if c not in cols and cols:
                    cur.execute(f"ALTER TABLE scan_stats ADD COLUMN {c} INTEGER DEFAULT 0")
            self.conn.commit()
        except Exception as e:
            logger.debug("Migration check on scan_stats failed: %s", e)

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

    def get_receiver_logs(
        self,
        t_start: Optional[float] = None,
        t_end: Optional[float] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        unmatched_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Retrieve recorded receiver logs ordered by ts_utc / id ASC."""
        cur = self.conn.cursor()
        unmatched_clause = "matched_event_id IS NULL" if unmatched_only else "1=1"
        if t_start is not None and t_end is not None:
            cur.execute(
                f"SELECT * FROM receiver_logs WHERE {unmatched_clause} AND ts_utc >= ? AND ts_utc <= ? ORDER BY ts_utc ASC",
                (float(t_start), float(t_end)),
            )
        elif t_start is not None:
            cur.execute(
                f"SELECT * FROM receiver_logs WHERE {unmatched_clause} AND ts_utc >= ? ORDER BY ts_utc ASC",
                (float(t_start),),
            )
        elif limit is not None:
            cur.execute(
                f"SELECT * FROM receiver_logs WHERE {unmatched_clause} ORDER BY id ASC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            cur.execute(f"SELECT * FROM receiver_logs WHERE {unmatched_clause} ORDER BY id ASC")
        return [dict(row) for row in cur.fetchall()]

    def set_receiver_log_matched_event_id(self, rx_id: int, event_id: int) -> bool:
        """Mark a receiver_logs entry as matched with an event_id. Returns True if updated."""
        with self.conn:
            cur = self.conn.execute(
                "UPDATE receiver_logs SET matched_event_id = ? WHERE id = ? AND matched_event_id IS NULL",
                (int(event_id), int(rx_id)),
            )
            return cur.rowcount > 0

    def get_total_receiver_bytes(self, dest_port: Optional[int] = None) -> int:
        """Calculate total bytes received across all logged connections."""
        cur = self.conn.cursor()
        if dest_port is not None:
            cur.execute("SELECT COALESCE(SUM(bytes_received), 0) FROM receiver_logs WHERE dest_port = ?", (int(dest_port),))
        else:
            cur.execute("SELECT COALESCE(SUM(bytes_received), 0) FROM receiver_logs")
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def insert_alert(
        self,
        ts: float,
        proc_key: str,
        detector: str,
        score: float,
        severity: str,
        evidence: str,
        window_id: Optional[int] = None,
        status: str = "new",
    ) -> int:
        """Insert a detected anomaly alert into the alerts table."""
        sql = """
        INSERT INTO alerts (ts, proc_key, window_id, detector, score, severity, evidence, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.conn:
            cur = self.conn.execute(
                sql,
                (
                    float(ts),
                    str(proc_key),
                    window_id,
                    str(detector),
                    float(score),
                    str(severity),
                    str(evidence),
                    str(status),
                ),
            )
            return int(cur.lastrowid or 0)

    def get_alerts(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve recorded alerts ordered by timestamp descending."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT ? OFFSET ?", (limit, offset))
        return [dict(row) for row in cur.fetchall()]

    def count_alerts(self) -> int:
        """Return total count of recorded alerts."""
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Fetch metadata value by key."""
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return str(row[0]) if row and row[0] is not None else default

    def set_meta(self, key: str, value: str) -> None:
        """Insert or update metadata key-value pair."""
        with self.conn:
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )

    def get_last_scanned_event_id(self) -> int:
        """Get the highest event ID that has already been scanned."""
        val = self.get_meta("last_scanned_event_id", "0")
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    def set_last_scanned_event_id(self, event_id: int) -> None:
        """Persist the highest event ID that has been scanned."""
        self.set_meta("last_scanned_event_id", str(event_id))

    def reset_alerts(self) -> int:
        """Delete all alert records while preserving events and processes.

        Returns:
            Number of deleted alert records.
        """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts")
            count = int(cur.fetchone()[0])
            cur.execute("DELETE FROM alerts")
            return count

    def has_recent_similar_alert(
        self,
        proc_key: str,
        dest_str: str,
        sample_files: List[str],
        cooldown_sec: float = 600.0,
        now: Optional[float] = None,
    ) -> bool:
        """Check if an identical or highly similar alert was persisted within cooldown_sec.

        Matches on:
        - Same proc_key
        - Within [now - cooldown_sec, now]
        - Same destination string or IP
        - Overlapping sensitive files
        """
        cur_ts = now if now is not None else time.time()
        t_cutoff = cur_ts - float(cooldown_sec)

        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, ts, evidence FROM alerts WHERE proc_key = ? AND ts >= ? ORDER BY ts DESC",
            (str(proc_key), t_cutoff),
        )
        rows = cur.fetchall()
        if not rows:
            return False

        norm_dest = dest_str.strip().lower()
        norm_files = {os.path.basename(f).strip().lower() for f in sample_files if f}

        for row in rows:
            try:
                ev = json.loads(row[2]) if isinstance(row[2], str) else (row[2] or {})
            except Exception:
                continue

            # Check destination match
            prev_dest = str(ev.get("dest_str") or ev.get("dest_ip") or "").strip().lower()
            dest_matches = (
                norm_dest == prev_dest
                or (norm_dest.split(":")[0] == prev_dest.split(":")[0] and norm_dest.split(":")[0] != "")
            )

            # Check file match
            prev_file_summary = str(ev.get("sample_files_summary") or "").lower()
            prev_files = ev.get("sensitive_files") or []
            prev_file_set = {os.path.basename(f).strip().lower() for f in prev_files if f}

            file_matches = False
            if norm_files and prev_file_set:
                file_matches = bool(norm_files & prev_file_set)
            elif norm_files and prev_file_summary:
                file_matches = any(fn in prev_file_summary for fn in norm_files)
            elif not norm_files:
                file_matches = True

            if dest_matches and file_matches:
                return True

        return False

    def get_max_receiver_log_id(self) -> int:
        """Get the highest ID in receiver_logs."""
        cur = self.conn.cursor()
        cur.execute("SELECT MAX(id) FROM receiver_logs")
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def update_event_nbytes(self, event_id: int, nbytes: int) -> None:
        """Update the nbytes field for an event record."""
        with self.conn:
            self.conn.execute("UPDATE events SET nbytes = ? WHERE id = ?", (int(nbytes), int(event_id)))

    def insert_scan_stats(self, stats: Dict[str, Any]) -> int:
        """Record diagnostic statistics for a scan cycle."""
        ts = float(stats.get("ts", time.time()))
        details = stats.get("details_json")
        if isinstance(details, dict):
            details_str = json.dumps(details, ensure_ascii=False)
        else:
            details_str = str(details) if details is not None else None

        sql = """
        INSERT INTO scan_stats (
            ts, events_loaded, windows_created, no_proc_key, not_direct_actor,
            ignored_process, no_causal, bytes_below_min, no_sensitive_file,
            score_below_threshold, duplicate, alerts_created, not_ready, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.conn:
            cur = self.conn.execute(sql, (
                ts,
                int(stats.get("events_loaded", 0)),
                int(stats.get("windows_created", 0)),
                int(stats.get("no_proc_key", 0)),
                int(stats.get("not_direct_actor", 0)),
                int(stats.get("ignored_process", 0)),
                int(stats.get("no_causal", 0)),
                int(stats.get("bytes_below_min", 0)),
                int(stats.get("no_sensitive_file", 0)),
                int(stats.get("score_below_threshold", 0)),
                int(stats.get("duplicate", 0)),
                int(stats.get("alerts_created", 0)),
                int(stats.get("not_ready", 0)),
                details_str,
            ))
            stats_id = cur.lastrowid or 0

        try:
            self.set_meta("latest_scan_stats", json.dumps(stats, ensure_ascii=False))
        except Exception:
            pass

        return stats_id

    def get_recent_scan_stats(self, seconds: float = 60.0) -> List[Dict[str, Any]]:
        """Retrieve scan stats recorded in the last N seconds."""
        t_cutoff = time.time() - float(seconds)
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM scan_stats WHERE ts >= ? ORDER BY ts DESC", (t_cutoff,))
        return [dict(r) for r in cur.fetchall()]

    def get_recent_event_counts_by_type(self, seconds: float = 60.0) -> Dict[str, int]:
        """Aggregate event counts by type for recent activity."""
        t_cutoff = time.time() - float(seconds)
        cur = self.conn.cursor()
        cur.execute("SELECT type, COUNT(*) FROM events WHERE ts >= ? GROUP BY type", (t_cutoff,))
        return {str(row[0]): int(row[1]) for row in cur.fetchall()}

    def get_recent_receiver_stats(self, seconds: float = 60.0) -> Dict[str, Any]:
        """Aggregate receiver logs in the last N seconds."""
        t_cutoff = time.time() - float(seconds)
        cur = self.conn.cursor()
        cur.execute(
            "SELECT COUNT(*), COALESCE(SUM(bytes_received), 0) FROM receiver_logs WHERE ts_utc >= ?",
            (t_cutoff,),
        )
        row = cur.fetchone()
        return {
            "count": int(row[0]) if row else 0,
            "total_bytes": int(row[1]) if row else 0,
        }

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
