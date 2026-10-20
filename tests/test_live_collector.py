"""Unit tests for live collection watermark polling, backfill filtering, and event deduplication."""

import os
import time
import pytest
from collector.sysmon_collector import LiveSysmonCollector, SysmonParser
from core.store import EventStore


def generate_mock_event(record_id: int, ts: float, is_file: bool = False, image_path: str = None):
    """Generate a valid mock Sysmon event dictionary with event_record_id."""
    default_path = (
        f"C:\\Users\\User\\Documents\\file_{record_id}.docx"
        if is_file
        else "C:\\Program Files\\App\\app.exe"
    )
    return {
        "ts": ts,
        "pid": 1000 + record_id,
        "ppid": 500,
        "proc_key": f"{{guid-{record_id}}}",
        "type": "file_create" if is_file else "net_connect",
        "path": image_path or default_path,
        "dest_ip": "192.168.1.1" if not is_file else None,
        "dest_port": 443 if not is_file else None,
        "proto": "tcp" if not is_file else None,
        "nbytes": 0,
        "extra_json": {"event_record_id": record_id},
    }


def test_simulated_watermark_polling_and_deduplication(tmp_path):
    """Simulate initial watermark=100 with 100 old records (1-100) and 20 new records (101-120).

    Verify collector only records 20 new records, updates watermark to 120,
    and running polling a second time does not record any duplicates.
    """
    db_file = str(tmp_path / "test_watermark_poll.db")
    collector = LiveSysmonCollector(db_path=db_file, backfill=False)
    collector.watermark = 100  # Initial watermark is 100

    # 100 old records (IDs 1-100) and 20 new records (IDs 101-120)
    old_records = [
        (generate_mock_event(record_id=i, ts=1700000000.0 + i), None, None)
        for i in range(1, 101)
    ]
    new_records = [
        (generate_mock_event(record_id=100 + i, ts=1700001000.0 + i), None, None)
        for i in range(1, 21)
    ]
    full_stream = old_records + new_records

    # First polling run: should only accept records with ID > 100
    accepted_first = collector.poll_once_from_events(full_stream)
    assert accepted_first == 20
    assert collector.watermark == 120

    # Drain queue to store
    items = []
    while not collector.event_queue.empty():
        items.append(collector.event_queue.get_nowait()[0])
    inserted = collector.store.insert_events_batch(items)
    assert inserted == 20
    assert collector.store.get_event_count() == 20

    # Verify only IDs 101-120 are in store
    rows = collector.store.get_events(limit=100)
    assert len(rows) == 20
    for r in rows:
        import json
        extra = json.loads(r["extra_json"])
        assert extra["event_record_id"] > 100

    # Second polling run on the same stream: must accept 0 records and insert 0 duplicates
    accepted_second = collector.poll_once_from_events(full_stream)
    assert accepted_second == 0
    assert collector.watermark == 120
    assert collector.store.get_event_count() == 20

    collector.store.close()


def test_filters_sysmon_and_collector_process():
    """Verify is_noise filters out Sysmon binaries and the collector's own process."""
    parser = SysmonParser()

    # Sysmon executable must be filtered
    sysmon_event_64 = {
        "type": "proc_start",
        "path": "C:\\Windows\\System32\\Sysmon64.exe",
        "pid": 9999,
    }
    assert parser.is_noise(sysmon_event_64) is True

    sysmon_event = {
        "type": "proc_start",
        "path": "C:\\Windows\\Sysmon.exe",
        "pid": 9998,
    }
    assert parser.is_noise(sysmon_event) is True

    # Collector's own process PID must be filtered
    collector_pid_event = {
        "type": "file_create",
        "path": "D:\\KERNAL PROTECT\\privacyguard\\data\\privacyguard.db",
        "pid": os.getpid(),
    }
    assert parser.is_noise(collector_pid_event) is True

    # Cached collector GUID must be filtered
    parser.collector_guid = "{collector-guid-12345}"
    collector_guid_event = {
        "type": "net_connect",
        "proc_key": "{collector-guid-12345}",
        "pid": 5555,
        "path": "C:\\Python314\\python.exe",
    }
    assert parser.is_noise(collector_guid_event) is True

    # Normal user application event must NOT be filtered
    normal_event = {
        "type": "file_create",
        "path": "C:\\Users\\User\\Downloads\\sample.docx",
        "pid": 1234,
        "proc_key": "{normal-user-app}",
    }
    assert parser.is_noise(normal_event) is False


def test_consecutive_runs_prevent_duplicate_records(tmp_path):
    """Verify that running insertion twice consecutively does not create duplicate records."""
    db_file = str(tmp_path / "test_dedup.db")
    store = EventStore(db_path=db_file)

    events = [
        generate_mock_event(record_id=i, ts=1700002000.0 + i)
        for i in range(1, 21)
    ]

    first_inserted = store.insert_events_batch(events)
    assert first_inserted == 20
    assert store.get_event_count() == 20

    second_inserted = store.insert_events_batch(events)
    assert second_inserted == 0
    assert store.get_event_count() == 20
    store.close()

    # Re-open store to ensure persistence of record id cache
    reopened = EventStore(db_path=db_file)
    third_inserted = reopened.insert_events_batch(events)
    assert third_inserted == 0
    assert reopened.get_event_count() == 20
    reopened.close()


def test_backfill_mode_ingests_history(tmp_path):
    """Verify that when backfill=True, historical events are recorded and counted."""
    db_file = str(tmp_path / "test_backfill.db")
    collector = LiveSysmonCollector(db_path=db_file, backfill=True)
    collector.start_ts = 1700005000.0
    collector.watermark = 0

    old_events = [
        (generate_mock_event(record_id=i, ts=collector.start_ts - 200.0 + i), None, None)
        for i in range(1, 11)
    ]
    new_events = [
        (generate_mock_event(record_id=10 + i, ts=collector.start_ts + 10.0 + i), None, None)
        for i in range(1, 6)
    ]

    accepted = collector.poll_once_from_events(old_events + new_events)
    assert accepted == 15
    assert collector.historical_count == 10
    assert collector.watermark == 15

    items = []
    while not collector.event_queue.empty():
        items.append(collector.event_queue.get_nowait()[0])
    collector.store.insert_events_batch(items)
    assert collector.store.get_event_count() == 15
    collector.store.close()


def test_queue_overflow_tracks_dropped_events(tmp_path):
    """Verify queue full drops events and calculates dropped_ratio accurately."""
    db_file = str(tmp_path / "test_overflow.db")
    collector = LiveSysmonCollector(db_path=db_file, max_queue_size=5)
    collector.start_ts = 1700000000.0

    events = [
        generate_mock_event(record_id=i, ts=collector.start_ts + 10.0 + i)
        for i in range(1, 16)
    ]

    for ev in events:
        collector.process_event(ev, pr=None, zn=None)

    assert collector.total_received == 15
    assert collector.dropped_events == 10
    dropped_ratio = (collector.dropped_events / collector.total_received) * 100.0
    assert round(dropped_ratio, 2) == 66.67
    collector.store.close()


def test_filter_breakdown_metrics(tmp_path):
    """Verify that filtered events are tracked by reason: sysmon, collector, noise pattern."""
    db_file = str(tmp_path / "test_breakdown.db")
    collector = LiveSysmonCollector(db_path=db_file)

    # 1. Event from sysmon binary
    sysmon_ev = generate_mock_event(record_id=1, ts=time.time(), image_path="C:\\Windows\\Sysmon64.exe")
    # 2. Event from collector's own PID
    collector_ev = generate_mock_event(record_id=2, ts=time.time())
    collector_ev["pid"] = os.getpid()
    # 3. Event from Recent shortcut noise pattern
    recent_ev = generate_mock_event(
        record_id=3,
        ts=time.time(),
        is_file=True,
        image_path="C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\document.lnk",
    )
    # 4. Valid normal event
    normal_ev = generate_mock_event(
        record_id=4,
        ts=time.time(),
        is_file=True,
        image_path="C:\\Users\\User\\Downloads\\sample.pdf",
    )

    audit_csv = str(tmp_path / "test_audit.csv")
    collector.audit_csv_path = audit_csv

    collector.process_event(sysmon_ev, None, None)
    collector.process_event(collector_ev, None, None)
    collector.process_event(recent_ev, None, None)
    collector.process_event(normal_ev, None, None)

    assert collector.total_received == 4
    assert collector.filtered_sysmon == 1
    assert collector.filtered_collector == 1
    assert collector.filtered_noise_pattern == 1
    assert not collector.event_queue.empty()
    item = collector.event_queue.get_nowait()
    assert item[0]["path"] == "C:\\Users\\User\\Downloads\\sample.pdf"
    collector.store.close()

    # Verify audit CSV was created and contains exactly 3 filtered events
    assert os.path.exists(audit_csv)
    with open(audit_csv, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 4  # Header + 3 filtered rows
    assert "filter_reason,matched_pattern" in lines[0]
    assert "sysmon" in lines[1]
    assert "collector" in lines[2]
    assert "drop_pattern" in lines[3]


def test_claude_telemetry_tagged_not_dropped(tmp_path):
    """Test Claude sentry\\session.json is written to DB with noise_candidate=1,
    while Prefetch and collector events are dropped and not written to DB.
    """
    db_file = str(tmp_path / "test_claude_tag.db")
    audit_file = str(tmp_path / "test_claude_audit.csv")
    collector = LiveSysmonCollector(db_path=db_file, backfill=False)
    collector.audit_csv_path = audit_file

    claude_path = r"C:\Users\User\AppData\Local\Packages\Claude_xyz123\LocalCache\Roaming\Claude\sentry\session.json"
    prefetch_path = r"C:\Windows\Prefetch\CLAUDE.EXE-A1B2C3D4.pf"
    collector_path = r"D:\KERNAL PROTECT\privacyguard\data\privacyguard.db"

    claude_ev = generate_mock_event(record_id=201, ts=time.time(), is_file=True, image_path=claude_path)
    claude_ev["proc_key"] = "{claude-guid-1111}"
    claude_ev["image"] = r"C:\Users\User\AppData\Local\Programs\Claude\Claude.exe"

    prefetch_ev = generate_mock_event(record_id=202, ts=time.time(), is_file=True, image_path=prefetch_path)
    prefetch_ev["proc_key"] = "{system-prefetch-guid}"

    collector_ev = generate_mock_event(record_id=203, ts=time.time(), is_file=True, image_path=collector_path)
    collector_ev["pid"] = os.getpid()

    # Process all three events
    assert collector.process_event(claude_ev, None, None) is True
    assert collector.process_event(prefetch_ev, None, None) is False
    assert collector.process_event(collector_ev, None, None) is False

    assert collector.total_received == 3
    assert collector.tagged_count == 1
    assert collector.filtered_drop_patterns == 1
    assert collector.filtered_collector == 1

    # Drain event queue and write to store
    batch = []
    while not collector.event_queue.empty():
        batch.append(collector.event_queue.get_nowait()[0])
    inserted = collector.store.insert_events_batch(batch)
    assert inserted == 1

    # Verify database contents: exactly 1 event (Claude telemetry)
    assert collector.store.get_event_count() == 1
    rows = collector.store.get_events(limit=10)
    assert len(rows) == 1
    stored_ev = rows[0]
    assert stored_ev["path"] == claude_path

    # Verify noise_candidate=1 in extra_json
    import json
    extra = json.loads(stored_ev["extra_json"])
    assert extra.get("noise_candidate") == 1
    assert extra.get("event_record_id") == 201

    # Verify filtered audit log: Prefetch and collector are logged, Claude is NOT logged
    assert os.path.exists(audit_file)
    with open(audit_file, "r", encoding="utf-8") as f:
        audit_content = f.read()
    assert "CLAUDE.EXE" in audit_content or "Prefetch" in audit_content
    assert "collector" in audit_content
    assert "session.json" not in audit_content

    collector.store.close()



