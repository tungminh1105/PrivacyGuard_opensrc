"""Unit tests for EventStore SQLite storage module."""

import os
import sqlite3
import pytest
from core.store import EventStore


@pytest.fixture
def temp_db(tmp_path):
    db_file = str(tmp_path / "test_store.db")
    store = EventStore(db_path=db_file, wal_mode=True)
    yield store
    store.close()


def test_schema_initialization(temp_db):
    """Verify all tables and indexes are initialized correctly."""
    cur = temp_db.conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cur.fetchall()}
    assert "events" in tables
    assert "processes" in tables
    assert "windows" in tables
    assert "alerts" in tables
    assert "file_zones" in tables

    cur.execute("PRAGMA journal_mode;")
    mode = cur.fetchone()[0]
    assert mode.lower() == "wal"


def test_insert_events_batch(temp_db):
    """Test batch inserting events and querying them back."""
    events = [
        {
            "ts": 1700000000.0,
            "pid": 1234,
            "ppid": 1000,
            "proc_key": "{guid-1234}",
            "type": "proc_start",
            "path": "C:\\Windows\\notepad.exe",
            "dest_ip": None,
            "dest_port": None,
            "proto": None,
            "nbytes": 0,
        },
        {
            "ts": 1700000005.0,
            "pid": 1234,
            "ppid": None,
            "proc_key": "{guid-1234}",
            "type": "net_connect",
            "path": None,
            "dest_ip": "1.1.1.1",
            "dest_port": 443,
            "proto": "tcp",
            "nbytes": 0,
        },
    ]

    inserted = temp_db.insert_events_batch(events)
    assert inserted == 2
    assert temp_db.get_event_count() == 2

    rows = temp_db.get_events(limit=10)
    assert len(rows) == 2
    assert rows[0]["type"] == "proc_start"
    assert rows[0]["proc_key"] == "{guid-1234}"
    assert rows[1]["type"] == "net_connect"
    assert rows[1]["dest_ip"] == "1.1.1.1"
    assert rows[1]["dest_port"] == 443


def test_upsert_process_and_update_end(temp_db):
    """Test process metadata insertion, upsert, and end_ts update."""
    proc = {
        "proc_key": "{guid-9999}",
        "pid": 5678,
        "ppid": 1234,
        "name": "chrome.exe",
        "exe_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
        "signed": 1,
        "publisher": "Google LLC",
        "start_ts": 1700000100.0,
        "end_ts": None,
    }
    temp_db.upsert_process(proc)

    procs = temp_db.get_processes()
    assert len(procs) == 1
    assert procs[0]["proc_key"] == "{guid-9999}"
    assert procs[0]["name"] == "chrome.exe"
    assert procs[0]["end_ts"] is None

    # Process terminates
    temp_db.update_process_end("{guid-9999}", 1700000200.0)
    procs_updated = temp_db.get_processes()
    assert procs_updated[0]["end_ts"] == 1700000200.0


def test_upsert_file_zone(temp_db):
    """Test inserting and updating Zone.Identifier download info."""
    zone = {
        "path": "C:\\Users\\Test\\Downloads\\setup.exe",
        "host_domain": "download.example.com",
        "referrer_domain": "example.com",
        "zone_id": "3",
        "proc_key": "{guid-browser}",
        "ts": 1700000300.0,
    }
    temp_db.upsert_file_zone(zone)

    zones = temp_db.get_file_zones()
    assert len(zones) == 1
    assert zones[0]["path"] == "C:\\Users\\Test\\Downloads\\setup.exe"
    assert zones[0]["host_domain"] == "download.example.com"
    assert zones[0]["referrer_domain"] == "example.com"
    assert zones[0]["zone_id"] == "3"
