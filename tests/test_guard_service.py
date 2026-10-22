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
    )
    service.add_alert_callback(on_alert)

    # 4. Trigger single scan step
    new_alerts = service.scan_now()

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
    assert "[Cảnh báo Rủi ro Cao]" in evidence["narrative"]
    assert "data_harvester.exe" in evidence["narrative"]
    assert "(PID: 6789)" in evidence["narrative"]
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
