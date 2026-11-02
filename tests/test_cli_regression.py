"""Regression tests for CLI test-real DB routing, receiver logging, and dashboard stability.

Ensures:
- ReceiverServer writes receiver_logs strictly to the specified target DB, not canonical DB.
- cmd_test_real rejects occupied ports safely without touching DBs.
- ui/app.py defines CANONICAL_DB without NameError.
- is_tray_running accurately detects active tray processes.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import socket
import sqlite3
import sys
import time
from types import SimpleNamespace

import psutil
import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.paths import get_default_db_path
from core.store import EventStore
from simulator.leaker import send_tcp_data
from simulator.receiver import ReceiverServer
import cli
from cli import is_tray_running


def test_receiver_server_writes_to_target_db_not_canonical(tmp_path):
    """ReceiverServer must log strictly to target db_path and never touch canonical DB."""
    canonical_path = get_default_db_path()
    assert os.path.exists(canonical_path)

    # Read initial state of canonical DB
    conn_canon = sqlite3.connect(f"file:{pathlib.Path(canonical_path).as_posix()}?mode=ro", uri=True)
    cur_canon = conn_canon.cursor()
    cur_canon.execute("SELECT COUNT(*), COALESCE(SUM(bytes_received), 0) FROM receiver_logs")
    canon_rx_count_before, canon_rx_bytes_before = cur_canon.fetchone()
    conn_canon.close()

    # Target test database
    target_db = tmp_path / "target_demo.db"
    test_port = 18765

    # Run ReceiverServer targeted at target_db
    rx = ReceiverServer(host="127.0.0.1", ports=[test_port], db_path=str(target_db))
    with rx:
        test_payload = b"TEST_BYTES_ROUTING_" * 100  # 1900 bytes
        send_tcp_data("127.0.0.1", test_port, test_payload)
        time.sleep(0.3)

    # Verify target DB recorded the connection
    store_target = EventStore(db_path=str(target_db))
    target_logs = store_target.get_receiver_logs()
    assert len(target_logs) == 1
    assert target_logs[0]["bytes_received"] == len(test_payload)
    assert target_logs[0]["dest_port"] == test_port
    store_target.close()

    # Verify canonical DB was COMPLETELY UNTOUCHED
    conn_canon2 = sqlite3.connect(f"file:{pathlib.Path(canonical_path).as_posix()}?mode=ro", uri=True)
    cur_canon2 = conn_canon2.cursor()
    cur_canon2.execute("SELECT COUNT(*), COALESCE(SUM(bytes_received), 0) FROM receiver_logs")
    canon_rx_count_after, canon_rx_bytes_after = cur_canon2.fetchone()
    conn_canon2.close()

    assert canon_rx_count_after == canon_rx_count_before
    assert canon_rx_bytes_after == canon_rx_bytes_before


def test_cmd_test_real_port_occupied_fails_early_without_running(tmp_path, monkeypatch, capsys):
    """An occupied port must fail before the target DB or guard is opened."""
    test_port = 18766
    target_db = tmp_path / "unused.db"

    # Occupy the port with a raw dummy socket.
    dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dummy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dummy_sock.bind(("127.0.0.1", test_port))
    dummy_sock.listen(5)

    try:
        # Make the test deterministic on machines where the real tray app is
        # running (or where the test is not elevated): the port gate must be
        # reached before the tray/admin/Sysmon gates.
        monkeypatch.setattr(cli, "is_tray_running", lambda: (False, None))

        args = argparse.Namespace(db=str(target_db), port=test_port)
        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_test_real(args)

        assert exc_info.value.code == 1
        output = capsys.readouterr().out
        assert f"Cổng {test_port} đang bị chiếm dụng" in output
        assert not target_db.exists(), "Port conflict must not create the target DB"
    finally:
        dummy_sock.close()


def test_dashboard_canonical_db_defined_and_importable():
    """ui/app.py must define CANONICAL_DB resolving to the canonical database without NameError."""
    from ui.app import CANONICAL_DB, load_db_statistics, load_all_alerts

    assert CANONICAL_DB is not None
    assert str(CANONICAL_DB).endswith("privacyguard.db")
    assert not isinstance(CANONICAL_DB, Exception)

    # Test stats and alerts loaders don't crash
    stats = load_db_statistics(CANONICAL_DB)
    assert isinstance(stats, dict)
    assert "event_count" in stats

    alerts = load_all_alerts(CANONICAL_DB)
    assert isinstance(alerts, list)


def test_is_tray_running_detects_cli_tray_cmdline(monkeypatch):
    """is_tray_running must detect a Python process whose argv contains tray."""
    fake_tray = SimpleNamespace(
        info={
            "pid": 987654,
            "name": "python.exe",
            "cmdline": ["python.exe", "cli.py", "tray"],
        }
    )
    fake_unrelated = SimpleNamespace(
        info={
            "pid": 987655,
            "name": "notepad.exe",
            "cmdline": ["notepad.exe", "notes.txt"],
        }
    )
    monkeypatch.setattr(
        psutil,
        "process_iter",
        lambda attrs=None: iter([fake_unrelated, fake_tray]),
    )

    running, pid = is_tray_running()
    assert running is True
    assert pid == 987654


def test_is_tray_running_ignores_unrelated_process(monkeypatch):
    """Unrelated processes must not be reported as the tray app."""
    fake_unrelated = SimpleNamespace(
        info={
            "pid": 987656,
            "name": "python.exe",
            "cmdline": ["python.exe", "some_worker.py"],
        }
    )
    monkeypatch.setattr(
        psutil,
        "process_iter",
        lambda attrs=None: iter([fake_unrelated]),
    )

    running, pid = is_tray_running()
    assert running is False
    assert pid is None
