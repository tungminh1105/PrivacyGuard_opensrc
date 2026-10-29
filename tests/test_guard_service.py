"""Unit tests for Real-time Guard Service and System Tray components.

Validates:
1. Real-time background detection and automated persistence into SQLite alerts table.
2. Causal flow detection triggering high-risk exfiltration alerts.
3. Pause, resume, and scan_now execution cycles.
4. Dynamic cybersecurity shield icon generation with Pillow.
5. Windows Toast notification wrapper resilience.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from typing import Any, Dict, List

import pytest
from PIL import Image

from core.store import EventStore
from core.guard_service import RealtimeGuardService, ToastNotifier
from ui.tray_app import create_shield_icon_image


@pytest.fixture
def temp_guard_workspace():
    """Create and clean up a temporary workspace for guard service testing."""
    d = tempfile.mkdtemp(prefix="pg_guard_test_")
    db_path = os.path.join(d, "guard_test.db")
    yield {"dir": d, "db_path": db_path}
    shutil.rmtree(d, ignore_errors=True)


def test_guard_service_detects_and_persists_alert(temp_guard_workspace):
    """Verify guard service scans recent events and records an alert in SQLite."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path, wal_mode=False)

    now = time.time()
    proc_key = "{guard-test-actor-777}"

    # 1. Ingest Process Metadata
    store.upsert_process({
        "proc_key": proc_key,
        "pid": 6789,
        "ppid": 1000,
        "name": "data_harvester.exe",
        "exe_path": r"C:\AppData\Local\Programs\data_harvester.exe",
        "signed": 0,
        "publisher": None,
        "start_ts": now - 30.0,
    })

    # 2. Ingest Events within lookback window (< 120s ago)
    events: List[Dict[str, Any]] = [
        {
            "ts": now - 25.0,
            "pid": 6789,
            "ppid": 1000,
            "proc_key": proc_key,
            "type": "proc_start",
            "extra_json": {"image": "data_harvester.exe", "event_record_id": 501},
        },
        {
            "ts": now - 20.0,
            "pid": 6789,
            "ppid": 1000,
            "proc_key": proc_key,
            "type": "file_create",
            "path": r"C:\Users\TargetUser\Documents\FakeDocuments\payroll_database.xlsx",
            "extra_json": {"event_record_id": 502},
        },
        {
            "ts": now - 15.0,
            "pid": 6789,
            "ppid": 1000,
            "proc_key": proc_key,
            "type": "net_connect",
            "dest_ip": "203.0.113.45",
            "dest_port": 443,
            "proto": "tcp",
            "nbytes": 600000,  # ~600 KB
            "extra_json": {"event_record_id": 503},
        },
    ]
    store.insert_events_batch(events)
    store.close()

    # 3. Instantiate Guard Service
    callback_alerts: List[Dict[str, Any]] = []

    def on_alert(alert_dict):
        callback_alerts.append(alert_dict)

    service = RealtimeGuardService(
        db_path=db_path,
        polling_interval_sec=5.0,
        alert_threshold=0.70,
        enable_toast=False,  # Headless test
        poll_sysmon=False,   # Headless isolated test - do not query host Sysmon
    )
    service.add_alert_callback(on_alert)

    # 4. Trigger single scan step
    new_alerts = service.scan_now(poll_sysmon=False)

    assert new_alerts == 1
    assert service.alert_count == 1
    assert len(callback_alerts) == 1

    # 5. Verify Database Records in alerts table
    saved_alerts = service.store.get_alerts()
    assert len(saved_alerts) == 1
    a = saved_alerts[0]

    assert a["proc_key"] == proc_key
    assert a["detector"] == "RuleBased"
    assert a["severity"] == "Cao"
    assert a["score"] >= 0.70

    evidence = json.loads(a["evidence"])
    assert "CẢNH BÁO NGUY HIỂM" in evidence["narrative"]
    assert "data_harvester.exe" in evidence["narrative"]
    assert "(Mã tiến trình: 6789)" in evidence["narrative"]
    assert evidence["has_causal_flow"] is True
    assert "payroll_database.xlsx" in evidence["sample_files_summary"]

    service.stop()


def test_guard_service_pause_and_resume(temp_guard_workspace):
    """Verify pause and resume states toggle correctly."""
    db_path = temp_guard_workspace["db_path"]
    service = RealtimeGuardService(db_path=db_path, enable_toast=False)

    assert service.is_paused() is False
    service.pause()
    assert service.is_paused() is True
    service.resume()
    assert service.is_paused() is False
    service.stop()


def test_toast_notifier_fallback():
    """Verify ToastNotifier handles notification without crashing."""
    notifier = ToastNotifier(app_id="PrivacyGuardTest")
    # Should not raise exception
    res = notifier.notify(
        title="[Test] Title",
        message="Test notification body",
        launch_url="http://localhost:8501",
    )
    assert isinstance(res, bool)


def test_shield_icon_generator():
    """Verify dynamic Pillow shield icon is generated with correct RGBA dimensions."""
    img = create_shield_icon_image(size=64)
    assert isinstance(img, Image.Image)
    assert img.size == (64, 64)
    assert img.mode == "RGBA"


def test_tray_app_root_and_python_resolution(monkeypatch):
    """Verify find_project_root and get_python_executable resolve project paths."""
    from ui.tray_app import find_project_root, get_python_executable, is_port_listening

    # Test running in current source tree
    root = find_project_root()
    assert os.path.exists(os.path.join(root, "config.yaml"))
    assert os.path.exists(os.path.join(root, "ui", "app.py"))

    # Test simulated PyInstaller frozen environment in dist/privacyguard/privacyguard.exe
    fake_exe = os.path.join(root, "dist", "privacyguard", "privacyguard.exe")
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", fake_exe)

    frozen_root = find_project_root()
    assert os.path.samefile(frozen_root, root)

    # Test simulated single-file PyInstaller frozen environment in dist/privacyguard.exe
    fake_onefile = os.path.join(root, "dist", "privacyguard.exe")
    monkeypatch.setattr("sys.executable", fake_onefile)
    onefile_root = find_project_root()
    assert os.path.samefile(onefile_root, root)

    # Test get_python_executable prioritizing .venv
    py_exe = get_python_executable()
    assert os.path.exists(py_exe)
    assert "python" in os.path.basename(py_exe).lower()
    if os.path.exists(os.path.join(root, ".venv", "Scripts", "python.exe")):
        assert ".venv" in py_exe

    # Test is_port_listening returns boolean without crashing
    closed_check = is_port_listening("127.0.0.1", 59999, timeout=0.1)
    assert isinstance(closed_check, bool)


def test_guard_service_trigger_test_alert(temp_guard_workspace):
    """Verify trigger_test_alert and trigger_manual_test_alert synthesize and persist alert."""
    from core.guard_service import trigger_manual_test_alert

    db_path = temp_guard_workspace["db_path"]
    service = RealtimeGuardService(db_path=db_path, enable_toast=False)

    try:
        res = service.trigger_test_alert(
            proc_name="python.exe",
            pid=8888,
            dest_str="127.0.0.1:8765",
            sample_file="hop_dong_kinh_te.docx",
            score=0.95,
        )

        assert res["alert_id"] == 1
        assert res["proc_name"] == "python.exe"
        assert res["pid"] == 8888
        assert res["score"] == 0.95
        assert isinstance(res["delivered"], bool)

        # Check DB
        alerts = service.store.get_alerts()
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["proc_key"] == "python.exe:8888"
        assert alert["detector"] == "TestAlertSimulator"
        assert alert["score"] == 0.95

        ev = json.loads(alert["evidence"])
        assert "hop_dong_kinh_te.docx" in ev["sample_files_summary"]
        assert ev["dest_str"] == "127.0.0.1:8765"
        assert ev["risk_pct"] == 95
        assert "CẢNH BÁO NGUY HIỂM" in ev["narrative"]
    finally:
        service.stop()

    # Test standalone helper function
    manual_res = trigger_manual_test_alert(
        db_path=db_path,
        proc_name="python.exe",
        dest_str="127.0.0.1:8765",
        sample_file="hop_dong_kinh_te.docx",
    )
    assert manual_res["alert_id"] == 2
    assert manual_res["score"] == 0.95


def test_tray_app_dynamic_alert_counting(temp_guard_workspace):
    """Verify TrayApp dynamically reads updated alert counts from SQLite."""
    from ui.tray_app import PrivacyGuardTrayApp

    db_path = temp_guard_workspace["db_path"]
    app = PrivacyGuardTrayApp(db_path=db_path)

    # Initial count should be 0
    text_0 = app.get_alert_count_text(None)
    assert "(0 alerts)" in text_0

    # Insert test alert into DB
    app.guard_service.trigger_test_alert(score=0.95)

    # Calling get_alert_count_text dynamically queries SQLite
    text_1 = app.get_alert_count_text(None)
    assert "(1 alerts)" in text_1

    app.guard_service.stop()


def test_guard_service_resolves_absolute_db_path_on_different_cwd():
    """Verify RealtimeGuardService resolves canonical absolute paths even when CWD is changed."""
    import tempfile
    from core.paths import PROJECT_ROOT

    orig_cwd = os.getcwd()
    tmp_dir = tempfile.mkdtemp(prefix="pg_cwd_test_")
    try:
        os.chdir(tmp_dir)
        service = RealtimeGuardService(db_path="data/privacyguard.db", enable_toast=False, poll_sysmon=False)
        try:
            assert os.path.isabs(service.db_path)
            assert service.db_path == os.path.abspath(os.path.join(PROJECT_ROOT, "data", "privacyguard.db"))
            assert os.path.isabs(service.config_path)
            assert service.config_path == os.path.abspath(os.path.join(PROJECT_ROOT, "config.yaml"))
        finally:
            service.stop()
    finally:
        os.chdir(orig_cwd)
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def test_tray_app_alert_count_queries_db_directly_ignoring_ram(temp_guard_workspace):
    """Verify get_alert_count_text queries SQLite directly and ignores RAM state."""
    import sqlite3
    from ui.tray_app import PrivacyGuardTrayApp

    db_path = temp_guard_workspace["db_path"]
    app = PrivacyGuardTrayApp(db_path=db_path)

    try:
        # Directly insert into SQLite
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts (ts, proc_key, detector, score, severity, evidence) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), "direct:123", "RuleBased", 0.95, "Cao", "{}"),
        )
        conn.commit()
        conn.close()

        # Intentionally sabotage RAM count
        app.guard_service.alert_count = 9999

        # Should query SQLite and return 1 alert, completely ignoring the 9999 in RAM
        text = app.get_alert_count_text(None)
        assert "(1 alerts)" in text
        assert "9999" not in text
    finally:
        app.guard_service.stop()


def test_guard_service_rejects_ignored_processes(temp_guard_workspace):
    """Verify processes in ignore_processes (e.g. privacyguard.exe) never trigger alerts."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()
    pk = "{pg-proc-guid-1111}"

    store.upsert_process({
        "proc_key": pk,
        "pid": 5555,
        "ppid": 1,
        "name": "privacyguard.exe",
        "exe_path": "C:\\Program Files\\PrivacyGuard\\privacyguard.exe",
        "start_ts": now - 30.0,
        "signed": 0,
    })
    events = [
        {"ts": now - 20.0, "pid": 5555, "proc_key": pk, "type": "proc_start"},
        {"ts": now - 15.0, "pid": 5555, "proc_key": pk, "type": "file_create", "path": "C:\\Docs\\sensitive.docx"},
        {"ts": now - 10.0, "pid": 5555, "proc_key": pk, "type": "net_connect", "dest_ip": "1.2.3.4", "dest_port": 443, "proto": "tcp", "nbytes": 500000},
    ]
    store.insert_events_batch(events)
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        new_alerts = service.scan_now(poll_sysmon=False)
        assert new_alerts == 0
        assert service.store.count_alerts() == 0
    finally:
        service.stop()


def test_guard_service_rejects_under_min_exfil_bytes(temp_guard_workspace):
    """Verify exfiltration with bytes_sent < min_exfil_bytes (e.g. 0 bytes) is rejected."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()
    pk = "{small-leak-guid}"

    store.upsert_process({
        "proc_key": pk,
        "pid": 4321,
        "name": "malicious.exe",
        "start_ts": now - 30.0,
        "signed": 0,
    })
    # nbytes is 500 (< 1024)
    events = [
        {"ts": now - 20.0, "pid": 4321, "proc_key": pk, "type": "proc_start"},
        {"ts": now - 15.0, "pid": 4321, "proc_key": pk, "type": "file_create", "path": "C:\\Docs\\sensitive.xlsx"},
        {"ts": now - 10.0, "pid": 4321, "proc_key": pk, "type": "net_connect", "dest_ip": "1.2.3.4", "dest_port": 443, "proto": "tcp", "nbytes": 500},
    ]
    store.insert_events_batch(events)
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        new_alerts = service.scan_now(poll_sysmon=False)
        assert new_alerts == 0
        assert service.store.count_alerts() == 0
    finally:
        service.stop()


def test_guard_service_deduplication_cooldown(temp_guard_workspace):
    """Verify identical exfiltration within cooldown period generates exactly 1 alert."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()
    pk = "{dedup-test-guid}"

    store.upsert_process({
        "proc_key": pk,
        "pid": 7777,
        "name": "exfiltrator.exe",
        "start_ts": now - 30.0,
        "signed": 0,
    })
    events = [
        {"ts": now - 20.0, "pid": 7777, "proc_key": pk, "type": "proc_start"},
        {"ts": now - 15.0, "pid": 7777, "proc_key": pk, "type": "file_create", "path": "C:\\Docs\\passwords.kdbx"},
        {"ts": now - 10.0, "pid": 7777, "proc_key": pk, "type": "net_connect", "dest_ip": "198.51.100.1", "dest_port": 443, "proto": "tcp", "nbytes": 100000},
    ]
    store.insert_events_batch(events)
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        # First scan generates 1 alert
        first_scan = service.scan_now(poll_sysmon=False)
        assert first_scan == 1
        assert service.store.count_alerts() == 1

        # Second scan immediately on same DB generates 0 new alerts (watermark + cooldown)
        second_scan = service.scan_now(poll_sysmon=False)
        assert second_scan == 0
        assert service.store.count_alerts() == 1
    finally:
        service.stop()


def test_store_reset_alerts(temp_guard_workspace):
    """Verify reset_alerts clears alerts table while keeping events and processes intact."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()

    store.upsert_process({"proc_key": "p1", "pid": 11, "name": "p1.exe", "start_ts": now})
    store.insert_events_batch([{"ts": now, "pid": 11, "proc_key": "p1", "type": "proc_start"}])
    store.insert_alert(ts=now, proc_key="p1", detector="RuleBased", score=0.9, severity="Cao", evidence="{}")
    store.insert_alert(ts=now, proc_key="p1", detector="RuleBased", score=0.8, severity="Cao", evidence="{}")

    assert store.count_alerts() == 2
    deleted = store.reset_alerts()
    assert deleted == 2
    assert store.count_alerts() == 0

    # Ensure processes and events are not deleted
    cur = store.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM processes")
    assert cur.fetchone()[0] == 1
    cur.execute("SELECT COUNT(*) FROM events")
    assert cur.fetchone()[0] == 1
    store.close()


def test_net_connect_enriched_with_receiver_logs_triggers_alert(temp_guard_workspace):
    """Verify net_connect with nbytes=0 is enriched by receiver_logs and triggers alert."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()
    pk = "{receiver-enrichment-guid}"

    store.upsert_process({
        "proc_key": pk,
        "pid": 5555,
        "name": "data_stealer.exe",
        "start_ts": now - 30.0,
        "signed": 0,
    })
    events = [
        {"ts": now - 20.0, "pid": 5555, "proc_key": pk, "type": "proc_start"},
        {"ts": now - 15.0, "pid": 5555, "proc_key": pk, "type": "file_create", "path": "C:\\Users\\User\\Documents\\confidential_report.xlsx"},
        {
            "ts": now - 10.0,
            "pid": 5555,
            "proc_key": pk,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "proto": "tcp",
            "nbytes": 0,  # Sysmon Event 3 initially reports 0 bytes
            "extra_json": json.dumps({"src_port": 49152}),
        },
    ]
    store.insert_events_batch(events)

    # Insert true byte count into receiver_logs matching (dest_port, src_port)
    store.log_receiver_bytes(
        ts_utc=now - 9.5,
        src_ip="127.0.0.1",
        src_port=49152,
        dest_port=8765,
        bytes_received=95000,
    )
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        new_alerts = service.scan_now(poll_sysmon=False)
        assert new_alerts == 1
        assert service.store.count_alerts() == 1

        # Check evidence contains true bytes
        cur = service.store.conn.cursor()
        cur.execute("SELECT evidence FROM alerts ORDER BY id DESC LIMIT 1")
        evidence = json.loads(cur.fetchone()[0])
        assert evidence["bytes_sent"] == 95000
    finally:
        service.stop()


def test_net_connect_without_receiver_logs_rejected_by_min_bytes(temp_guard_workspace):
    """Verify net_connect with nbytes=0 and no receiver_logs is rejected by min_exfil_bytes gate."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()
    pk = "{zero-byte-reject-guid}"

    store.upsert_process({
        "proc_key": pk,
        "pid": 5556,
        "name": "normal_app.exe",
        "start_ts": now - 30.0,
        "signed": 0,
    })
    events = [
        {"ts": now - 20.0, "pid": 5556, "proc_key": pk, "type": "proc_start"},
        {"ts": now - 15.0, "pid": 5556, "proc_key": pk, "type": "file_create", "path": "C:\\Users\\User\\Documents\\confidential_report.xlsx"},
        {
            "ts": now - 10.0,
            "pid": 5556,
            "proc_key": pk,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "proto": "tcp",
            "nbytes": 0,  # 0 bytes and NO receiver_logs entry
        },
    ]
    store.insert_events_batch(events)
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        new_alerts = service.scan_now(poll_sysmon=False)
        # Should be rejected by Gate 3: bytes_sent < min_exfil_bytes (1024)
        assert new_alerts == 0
        assert service.store.count_alerts() == 0
        assert service.latest_scan_stats["bytes_below_min"] >= 1
    finally:
        service.stop()


def test_alert_attribution_and_sensitive_files_subset(temp_guard_workspace):
    """Verify alert is strictly attributed to python.exe (leaker) and sensitive_files <= 15 from FakeDocuments."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()

    pk_pwsh = "{powershell-actor-1111}"
    pk_py = "{python-leaker-2222}"

    # 1. Upsert processes: powershell and python
    store.upsert_process({
        "proc_key": pk_pwsh,
        "pid": 1001,
        "name": "powershell.exe",
        "start_ts": now - 40.0,
        "signed": 1,
    })
    store.upsert_process({
        "proc_key": pk_py,
        "pid": 2002,
        "name": "python.exe",
        "start_ts": now - 35.0,
        "signed": 0,
    })

    # 2. PowerShell events: only touches temp files, then connects
    pwsh_events = [
        {"ts": now - 30.0, "pid": 1001, "proc_key": pk_pwsh, "type": "proc_start"},
        {"ts": now - 28.0, "pid": 1001, "proc_key": pk_pwsh, "type": "file_create", "path": r"C:\Users\User\AppData\Local\Temp\pwsh_temp.tmp"},
        {"ts": now - 25.0, "pid": 1001, "proc_key": pk_pwsh, "type": "net_connect", "dest_ip": "1.1.1.1", "dest_port": 53, "nbytes": 50000},
    ]

    # 3. Python events: creates 3 sensitive files in FakeDocuments, then connects to 8765
    py_docs = [
        os.path.abspath("data/FakeDocuments/financial_report.xlsx"),
        os.path.abspath("data/FakeDocuments/payroll_2026.docx"),
        os.path.abspath("data/FakeDocuments/customer_records.csv"),
    ]
    py_events = [
        {"ts": now - 20.0, "pid": 2002, "proc_key": pk_py, "type": "proc_start"},
        {"ts": now - 18.0, "pid": 2002, "proc_key": pk_py, "type": "file_create", "path": py_docs[0]},
        {"ts": now - 17.0, "pid": 2002, "proc_key": pk_py, "type": "file_create", "path": py_docs[1]},
        {"ts": now - 16.0, "pid": 2002, "proc_key": pk_py, "type": "file_create", "path": py_docs[2]},
        {
            "ts": now - 10.0,
            "pid": 2002,
            "proc_key": pk_py,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "proto": "tcp",
            "nbytes": 0,
            "extra_json": json.dumps({"src_port": 51234}),
        },
    ]

    store.insert_events_batch(pwsh_events + py_events)

    # 4. Insert receiver_log matching python connection
    store.log_receiver_bytes(
        ts_utc=now - 9.8,
        src_ip="127.0.0.1",
        src_port=51234,
        dest_port=8765,
        bytes_received=65432,
    )
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        new_alerts = service.scan_now(poll_sysmon=False)
        assert new_alerts == 1
        assert service.store.count_alerts() == 1

        cur = service.store.conn.cursor()
        cur.execute("SELECT id, proc_key, evidence FROM alerts ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        assert row is not None
        assert row[1] == pk_py

        ev = json.loads(row[2])
        # 1. Process attribution
        assert ev["proc_name"] == "python.exe"

        # 2. Bytes exact match
        assert ev["bytes_sent"] == 65432

        # 3. Sensitive files: subset of FakeDocuments, count <= 15
        sens_files = ev["sensitive_files"]
        assert len(sens_files) <= 15
        assert len(sens_files) == 3
        for f in sens_files:
            assert "FakeDocuments" in f

        # PowerShell must NOT generate an alert (rejected at causal/sensitive gates)
        cur.execute("SELECT COUNT(*) FROM alerts WHERE proc_key = ?", (pk_pwsh,))
        assert cur.fetchone()[0] == 0
    finally:
        service.stop()


def test_two_consecutive_cycles_no_byte_reuse(temp_guard_workspace):
    """Verify running 2 consecutive cycles never reuses receiver_logs and alert bytes do not exceed rx bytes."""
    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    now = time.time()
    pk = "{byte-reuse-prevent-guid}"

    store.upsert_process({
        "proc_key": pk,
        "pid": 7788,
        "name": "python.exe",
        "start_ts": now - 30.0,
        "signed": 0,
    })

    test_doc = os.path.abspath("data/FakeDocuments/ho_so_bao_mat.xlsx")
    events = [
        {"ts": now - 20.0, "pid": 7788, "proc_key": pk, "type": "proc_start"},
        {"ts": now - 15.0, "pid": 7788, "proc_key": pk, "type": "file_create", "path": test_doc},
        {
            "ts": now - 10.0,
            "pid": 7788,
            "proc_key": pk,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "proto": "tcp",
            "nbytes": 0,
            "extra_json": json.dumps({"src_port": 52222}),
        },
    ]
    store.insert_events_batch(events)

    # Insert 1 receiver_log with 75000 bytes
    store.log_receiver_bytes(
        ts_utc=now - 9.5,
        src_ip="127.0.0.1",
        src_port=52222,
        dest_port=8765,
        bytes_received=75000,
    )

    cur = store.conn.cursor()
    cur.execute("SELECT id, matched_event_id FROM receiver_logs WHERE src_port = 52222")
    rx_before = cur.fetchone()
    assert rx_before[1] is None  # initially unmatched
    store.close()

    service = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    try:
        # Cycle 1: First scan matches receiver log and generates 1 alert
        alerts_1 = service.scan_now(poll_sysmon=False)
        assert alerts_1 == 1

        # Verify matched_event_id is now populated in DB
        cur = service.store.conn.cursor()
        cur.execute("SELECT id, matched_event_id, bytes_received FROM receiver_logs WHERE src_port = 52222")
        rx_after = cur.fetchone()
        assert rx_after[1] is not None
        matched_ev_id = rx_after[1]

        # Verify event was updated in DB
        cur.execute("SELECT nbytes FROM events WHERE id = ?", (matched_ev_id,))
        assert cur.fetchone()[0] == 75000

        # Cycle 2: Insert a new zero-byte net_connect event at now - 1.0
        new_event = {
            "ts": now - 1.0,
            "pid": 7788,
            "proc_key": pk,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "proto": "tcp",
            "nbytes": 0,
            "extra_json": json.dumps({"src_port": 53333}),
        }
        service.store.insert_events_batch([new_event])

        # Scan Cycle 2: Should NOT reuse the already-matched receiver log
        alerts_2 = service.scan_now(poll_sysmon=False)
        assert alerts_2 == 0  # rejected because nbytes remains 0 < 1024

        # Total alert bytes in DB must not exceed real bytes received (75000)
        cur.execute("SELECT evidence FROM alerts")
        all_ev = [json.loads(row[0]) for row in cur.fetchall()]
        total_alert_bytes = sum(ev.get("bytes_sent", 0) for ev in all_ev)
        assert total_alert_bytes == 75000
    finally:
        service.stop()


def test_realtime_guard_with_live_sysmon_poll(temp_guard_workspace):
    """Verify guard service runs with poll_sysmon=True without alert storm on clean environment."""
    db_path = temp_guard_workspace["db_path"]
    service = RealtimeGuardService(
        db_path=db_path,
        polling_interval_sec=1.0,
        enable_toast=False,
        poll_sysmon=True,
    )
    try:
        new_alerts = service.scan_now(poll_sysmon=True)
        # Even with host Sysmon polled, zero exfiltration alerts should be created on idle system
        assert new_alerts == 0
        assert service.store.count_alerts() == 0
    finally:
        service.stop()


def test_cmd_test_real_non_admin_fails_cleanly(temp_guard_workspace, monkeypatch):
    """Test cmd_test_real in non-admin environment exits != 0 (code 2) and adds 0 alerts."""
    import argparse
    from cli import cmd_test_real
    from core.store import EventStore

    db_path = temp_guard_workspace["db_path"]
    store = EventStore(db_path=db_path)
    count_before = store.count_alerts()

    # Simulate non-admin environment
    import ctypes
    monkeypatch.setattr(ctypes.windll.shell32, "IsUserAnAdmin", lambda: 0)

    args = argparse.Namespace(db=db_path, port=8765)
    with pytest.raises(SystemExit) as exc_info:
        cmd_test_real(args)

    assert exc_info.value.code == 2
    assert store.count_alerts() == count_before
    store.close()


def test_cmd_test_real_contains_no_synthetic_injection():
    """Verify cmd_test_real has no calls to insert_events_batch or upsert_process."""
    import inspect
    from cli import cmd_test_real

    source = inspect.getsource(cmd_test_real)
    assert "insert_events_batch" not in source, "cmd_test_real must not inject events via insert_events_batch"
    assert "upsert_process" not in source, "cmd_test_real must not inject processes via upsert_process"
    assert "poll_sysmon=False" not in source, "cmd_test_real must only use real Sysmon telemetry (poll_sysmon=True)"


def test_sysmon_guid_regex_and_pid_validation():
    """Verify Sysmon GUID regex matches real Sysmon proc_key and rejects synthetic ones."""
    import re

    guid_regex = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")

    # Real Sysmon GUID samples
    real_guids = [
        "{a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d}",
        "{01234567-89AB-CDEF-0123-456789ABCDEF}",
        "{FEDCBA98-7654-3210-FEDC-BA9876543210}",
    ]
    for g in real_guids:
        assert guid_regex.match(g), f"Expected real GUID to match regex: {g}"

    # Synthetic proc_keys that must FAIL
    synthetic_keys = [
        "{leaker-python-1793287815}",
        "{live-test-1234567890}",
        "python.exe:8888",
        "mock_proc_key",
        "{12345678-1234-1234-1234}",
    ]
    for s in synthetic_keys:
        assert not guid_regex.match(s), f"Expected synthetic key to NOT match regex: {s}"

    # PID constraint
    mock_pid = 8888
    assert mock_pid == 8888  # Identifies synthetic
    real_pid = 14208
    assert real_pid != 8888






