"""Unit and integration tests for PrivacyGuard Phase B Simulator.

Validates:
- make_fake_docs safety and file count.
- leaker safety bounds (rejects non-FakeDocuments paths and non-127.0.0.1 hosts).
- receiver accurate byte counting and no-payload storage policy.
- ground_truth.csv formatting and row count tracking.
- receiver matches leaker sent byte count.
- all 9 scenarios execution and correct ground truth labels.
"""

from __future__ import annotations

import csv
import os
import socket
import sys
import time
import pytest

from simulator.make_fake_docs import create_fake_documents, validate_fake_docs_path
from simulator.receiver import ReceiverServer
from simulator.leaker import (
    GROUND_TRUTH_HEADER,
    run_leaker,
    send_tcp_data,
    validate_safe_environment,
)
from simulator.benign_sync import run_benign_sync, validate_sync_paths
from core.store import EventStore


def test_make_fake_docs_safety_rejection(tmp_path):
    """make_fake_docs must reject any directory path that does not contain 'FakeDocuments'."""
    unsafe_dir = str(tmp_path / "PersonalDocuments")
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_fake_docs_path(unsafe_dir)

    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        create_fake_documents(target_dir=unsafe_dir, count=50)


def test_make_fake_docs_file_count_and_naming(tmp_path):
    """make_fake_docs must create between 50 and 200 files with sensitive names and seed reproducibility."""
    safe_dir = str(tmp_path / "FakeDocuments")

    # Generate 60 files with seed 100
    files = create_fake_documents(target_dir=safe_dir, count=60, seed=100)
    assert len(files) == 60
    assert len(os.listdir(safe_dir)) == 60

    # Verify sensitive-sounding extensions and names
    names = [os.path.basename(f) for f in files]
    assert any("hop_dong" in n for n in names)
    assert any("bang_luong" in n for n in names)
    assert any("bao_cao" in n for n in names)
    assert any(n.endswith(".docx") for n in names)
    assert any(n.endswith(".xlsx") for n in names)
    assert any(n.endswith(".pdf") for n in names)

    # Verify seed reproducibility
    safe_dir_2 = str(tmp_path / "FakeDocuments_2")
    files_2 = create_fake_documents(target_dir=safe_dir_2, count=60, seed=100)
    names_2 = [os.path.basename(f) for f in files_2]
    assert names == names_2


def test_leaker_safety_constraints():
    """Leaker must strictly reject non-FakeDocuments directories and non-127.0.0.1 destinations."""
    # Reject unsafe directories
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_safe_environment("C:\\Users\\User\\Documents", "127.0.0.1")

    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_safe_environment("D:\\RealData", "127.0.0.1")

    # Reject non-loopback network destinations
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_safe_environment("data/FakeDocuments", "8.8.8.8")

    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_safe_environment("data/FakeDocuments", "192.168.1.1")

    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_safe_environment("data/FakeDocuments", "example.com")


def test_benign_sync_safety_constraints(tmp_path):
    """Benign sync must reject source outside FakeDocuments or dest outside fake_cloud."""
    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_sync_paths("data/RealDocs", "data/fake_cloud")

    with pytest.raises(ValueError, match="SAFETY VIOLATION"):
        validate_sync_paths("data/FakeDocuments", "data/real_cloud")


def test_receiver_byte_count_and_no_payload_stored(tmp_path):
    """Receiver must accurately count received bytes in SQLite and never store payloads."""
    db_file = str(tmp_path / "test_receiver.db")
    test_port = 18765

    server = ReceiverServer(host="127.0.0.1", ports=[test_port], db_path=db_file)
    with server:
        # Send 3 distinct payloads
        p1 = b"A" * 1024
        p2 = b"B" * 4096
        p3 = b"C" * 2048

        send_tcp_data("127.0.0.1", test_port, p1)
        send_tcp_data("127.0.0.1", test_port, p2)
        send_tcp_data("127.0.0.1", test_port, p3)

        time.sleep(0.2)

        store = EventStore(db_path=db_file)
        logs = store.get_receiver_logs()
        assert len(logs) == 3

        total_bytes = store.get_total_receiver_bytes()
        assert total_bytes == 1024 + 4096 + 2048

        # Check table schema: must contain only metadata, strictly NO payload columns
        cur = store.conn.cursor()
        cur.execute("PRAGMA table_info(receiver_logs)")
        cols = [col[1] for col in cur.fetchall()]
        assert "bytes_received" in cols
        assert "ts_utc" in cols
        assert "payload" not in cols
        assert "content" not in cols
        assert "data" not in cols

        store.close()


def test_ground_truth_format_and_row_count(tmp_path):
    """Verify ground_truth.csv has exact expected headers and row count."""
    fake_docs = str(tmp_path / "FakeDocuments")
    create_fake_documents(target_dir=fake_docs, count=50, seed=42)

    db_file = str(tmp_path / "test_gt.db")
    gt_file = str(tmp_path / "ground_truth.csv")
    test_port = 18766

    with ReceiverServer(host="127.0.0.1", ports=[test_port], db_path=db_file):
        # Run scenario 1 for 3 runs
        results = run_leaker(
            scenario=1,
            runs=3,
            seed=42,
            gt_path=gt_file,
            fake_docs_dir=fake_docs,
            host="127.0.0.1",
            port=test_port,
            db_path=db_file,
        )

        assert len(results) == 3
        assert os.path.exists(gt_file)

        with open(gt_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # 1 Header row + 3 data rows = 4 rows
        assert len(rows) == 4
        assert rows[0] == GROUND_TRUTH_HEADER

        for i, row in enumerate(rows[1:], start=1):
            run_id, scenario, label, proc_name, pid, proc_guid, t_start_utc, t_end_utc = row
            assert run_id == f"run_{i:04d}"
            assert scenario == "1"
            assert label == "1"
            assert int(pid) > 0
            assert proc_guid.startswith("{") and proc_guid.endswith("}")
            assert t_start_utc <= t_end_utc


def test_receiver_matches_leaker_sent_bytes(tmp_path):
    """Receiver received bytes must exactly equal the total bytes sent by leaker."""
    fake_docs = str(tmp_path / "FakeDocuments")
    create_fake_documents(target_dir=fake_docs, count=50, seed=123)

    db_file = str(tmp_path / "test_match.db")
    gt_file = str(tmp_path / "ground_truth.csv")
    test_port = 18767

    with ReceiverServer(host="127.0.0.1", ports=[test_port], db_path=db_file):
        # Run scenario 1 (bulk) and scenario 8 (network only)
        r1 = run_leaker(
            scenario=1,
            runs=1,
            seed=1,
            gt_path=gt_file,
            fake_docs_dir=fake_docs,
            host="127.0.0.1",
            port=test_port,
            db_path=db_file,
        )
        r8 = run_leaker(
            scenario=8,
            runs=1,
            seed=8,
            gt_path=gt_file,
            fake_docs_dir=fake_docs,
            host="127.0.0.1",
            port=test_port,
            db_path=db_file,
        )

        time.sleep(0.2)
        total_sent = r1[0]["bytes_sent"] + r8[0]["bytes_sent"]

        store = EventStore(db_path=db_file)
        total_received = store.get_total_receiver_bytes()
        store.close()

        assert total_sent > 0
        assert total_received == total_sent


def test_all_nine_scenarios(tmp_path):
    """Execute all 9 scenarios once: verify ground truth rows, labels, and specific controls."""
    fake_docs = str(tmp_path / "FakeDocuments")
    create_fake_documents(target_dir=fake_docs, count=50, seed=999)
    fake_cloud = str(tmp_path / "fake_cloud")

    db_file = str(tmp_path / "test_scenarios.db")
    gt_file = str(tmp_path / "ground_truth.csv")
    test_port = 18768
    test_port_443 = 18443  # Use test port for scenario 5 in isolated unit test

    with ReceiverServer(host="127.0.0.1", ports=[test_port, test_port_443], db_path=db_file):
        for s in range(1, 10):
            res = run_leaker(
                scenario=s,
                runs=1,
                seed=s,
                gt_path=gt_file,
                fake_docs_dir=fake_docs,
                fake_cloud_dir=fake_cloud,
                host="127.0.0.1",
                port=test_port,
                scenario5_port=test_port_443,
                db_path=db_file,
            )
            assert len(res) == 1
            if s <= 6:
                assert res[0]["label"] == 1
            else:
                assert res[0]["label"] == 0

        # Scenario 7 (benign cloud sync) must create files in fake_cloud
        assert os.path.exists(fake_cloud)
        assert len(os.listdir(fake_cloud)) > 0

        # Check ground_truth.csv contains exactly 9 rows
        with open(gt_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert len(rows) == 10  # 1 header + 9 data rows
