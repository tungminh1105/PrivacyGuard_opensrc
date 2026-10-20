"""Unit tests for live collection, backfill filtering, and event deduplication."""

import time
import pytest
from collector.sysmon_collector import LiveSysmonCollector, SysmonParser
from core.store import EventStore


def generate_mock_event(record_id: int, ts: float, is_file: bool = False):
    """Generate a valid mock Sysmon event dictionary with event_record_id."""
    return {
        "ts": ts,
        "pid": 1000 + record_id,
        "ppid": 500,
        "proc_key": f"{{guid-{record_id}}}",
        "type": "file_create" if is_file else "net_connect",
        "path": f"C:\\Users\\User\\Documents\\file_{record_id}.docx" if is_file else None,
        "dest_ip": "192.168.1.1" if not is_file else None,
        "dest_port": 443 if not is_file else None,
        "proto": "tcp" if not is_file else None,
        "nbytes": 0,
        "extra_json": {"event_record_id": record_id},
    }


def test_live_mode_filters_old_events(tmp_path):
    """Simulate 100 old events and 20 new events.

    In live mode (backfill=False), only the 20 new events must be recorded.
    """
    db_file = str(tmp_path / "test_live.db")
    collector = LiveSysmonCollector(db_path=db_file, backfill=False)
    collector.start_ts = 1700001000.0  # Collector simulated start time

    # Generate 100 old events (prior to start_ts)
    old_events = [
        generate_mock_event(record_id=i, ts=collector.start_ts - 500.0 + i)
        for i in range(1, 101)
    ]

    # Generate 20 new events (after start_ts)
    new_events = [
        generate_mock_event(record_id=100 + i, ts=collector.start_ts + 10.0 + i)
        for i in range(1, 21)
    ]

    # Feed all 120 events to collector
    for ev in old_events + new_events:
        collector.process_event(ev, pr=None, zn=None)

    # Manually drain the queue to store (simulating writer worker)
    items = []
    while not collector.event_queue.empty():
        items.append(collector.event_queue.get_nowait()[0])
    collector.store.insert_events_batch(items)

    assert collector.total_received == 120
    assert collector.store.get_event_count() == 20

    # Verify that only record IDs 101-120 exist in DB
    rows = collector.store.get_events(limit=100)
    assert len(rows) == 20
    for r in rows:
        assert r["ts"] >= collector.start_ts
    collector.store.close()


def test_consecutive_runs_prevent_duplicate_records(tmp_path):
    """Verify that running insertion twice consecutively does not create duplicate records."""
    db_file = str(tmp_path / "test_dedup.db")
    store = EventStore(db_path=db_file)

    events = [
        generate_mock_event(record_id=i, ts=1700002000.0 + i)
        for i in range(1, 21)
    ]

    # First run: inserts 20 events
    first_inserted = store.insert_events_batch(events)
    assert first_inserted == 20
    assert store.get_event_count() == 20

    # Second run with exact same 20 events: must be deduplicated by event_record_id
    second_inserted = store.insert_events_batch(events)
    assert second_inserted == 0
    assert store.get_event_count() == 20

    store.close()

    # Re-open store (simulating process restart) and test again
    reopened_store = EventStore(db_path=db_file)
    third_inserted = reopened_store.insert_events_batch(events)
    assert third_inserted == 0
    assert reopened_store.get_event_count() == 20
    reopened_store.close()


def test_backfill_mode_ingests_history(tmp_path):
    """Verify that when backfill=True, historical events are recorded and counted."""
    db_file = str(tmp_path / "test_backfill.db")
    collector = LiveSysmonCollector(db_path=db_file, backfill=True)
    collector.start_ts = 1700005000.0

    old_events = [
        generate_mock_event(record_id=i, ts=collector.start_ts - 200.0 + i)
        for i in range(1, 11)
    ]
    new_events = [
        generate_mock_event(record_id=10 + i, ts=collector.start_ts + 10.0 + i)
        for i in range(1, 6)
    ]

    for ev in old_events + new_events:
        collector.process_event(ev, pr=None, zn=None)

    items = []
    while not collector.event_queue.empty():
        items.append(collector.event_queue.get_nowait()[0])
    collector.store.insert_events_batch(items)

    assert collector.historical_count == 10
    assert collector.store.get_event_count() == 15
    collector.store.close()


def test_queue_overflow_tracks_dropped_events(tmp_path):
    """Verify queue full drops events and calculates dropped_ratio accurately."""
    db_file = str(tmp_path / "test_overflow.db")
    # Small queue to trigger overflow
    collector = LiveSysmonCollector(db_path=db_file, max_queue_size=5)
    collector.start_ts = 1700000000.0

    events = [
        generate_mock_event(record_id=i, ts=collector.start_ts + 10.0 + i)
        for i in range(1, 16)
    ]

    for ev in events:
        collector.process_event(ev, pr=None, zn=None)

    assert collector.total_received == 15
    assert collector.dropped_events == 10  # 5 in queue, 10 dropped
    dropped_ratio = (collector.dropped_events / collector.total_received) * 100.0
    assert round(dropped_ratio, 2) == 66.67
    collector.store.close()
