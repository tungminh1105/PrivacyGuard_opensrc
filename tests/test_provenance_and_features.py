"""Unit tests for PrivacyGuard Phase C: Provenance Engine and Feature Extraction.

Validates:
- Sensitive path detection, credential classification, and sensitivity scoring.
- Threat intelligence: local IP, tracker domains, first-seen destination tracking.
- Provenance graph construction: node types, edge relations (SPAWN, CREATE, CONNECT, CAUSAL_FLOW).
- Causal chain File -> Process -> Socket resolution for Phase B scenarios.
- Feature extraction: exact 17-dimensional vector, zero NaN/None values, sliding window slicing.
"""

from __future__ import annotations

import math
import os
import pytest

from core.sensitive import get_sensitivity_score, is_sensitive_path, sensitivity
from core.intel import (
    IntelTracker,
    get_country,
    is_local_ip,
    is_new_destination,
    is_tracker,
)
from core.provenance import (
    ProcessHierarchy,
    ProvenanceEngine,
    build_provenance_graph,
    normalize_file_node_id,
    normalize_proc_node_id,
    normalize_socket_node_id,
)
from core.features import (
    FEATURE_NAMES,
    SlidingWindowFeatureExtractor,
    compute_burstiness,
    extract_window_features,
    features_to_vector,
    sanitize_float,
)


def test_sensitive_path_and_scoring():
    """Verify sensitive path identification and score boundaries [0.0, 1.0]."""
    # 1. High secrets (1.0)
    assert get_sensitivity_score("C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data") == 1.0
    assert get_sensitivity_score("C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies") == 1.0
    assert get_sensitivity_score("C:\\Users\\User\\.ssh\\id_rsa") == 1.0
    assert get_sensitivity_score("C:\\Users\\User\\.aws\\credentials") == 1.0
    assert get_sensitivity_score("C:\\app\\secret_key.pem") == 1.0
    assert get_sensitivity_score("C:\\app\\db_password.kdbx") == 1.0

    # 2. Sensitive documents in user folders (0.8)
    assert get_sensitivity_score("D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\hop_dong_thue_nha.docx") == 0.8
    assert get_sensitivity_score("C:\\Users\\User\\Documents\\bang_luong_thang_10.xlsx") == 0.8
    assert get_sensitivity_score("C:\\Users\\User\\Desktop\\bao_cao_tai_chinh.pdf") == 0.8
    assert is_sensitive_path("D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\hop_dong_thue_nha.docx") is True

    # 3. Generic files in user folders (0.5)
    assert get_sensitivity_score("C:\\Users\\User\\Documents\\notes.log") == 0.5

    # 4. Sensitive extensions outside user folders (0.4)
    assert get_sensitivity_score("D:\\tools\\manual.pdf") == 0.4

    # 5. System binaries and noise (0.0)
    assert get_sensitivity_score("C:\\Windows\\System32\\cmd.exe") == 0.0
    assert get_sensitivity_score("C:\\Windows\\Prefetch\\CMD.EXE-A1B2C3D4.pf") == 0.0
    assert get_sensitivity_score("C:\\pagefile.sys") == 0.0
    assert is_sensitive_path("C:\\Windows\\System32\\notepad.exe") is False
    assert is_sensitive_path("") is False
    assert is_sensitive_path(None) is False


def test_intel_ip_and_tracker_classification():
    """Verify local IP detection, tracker domains, and destination history."""
    # Local IP tests
    assert is_local_ip("127.0.0.1") is True
    assert is_local_ip("127.0.0.1:8765") is True
    assert is_local_ip("localhost") is True
    assert is_local_ip("::1") is True
    assert is_local_ip("192.168.1.15") is True
    assert is_local_ip("10.0.0.1") is True
    assert is_local_ip("172.16.5.10") is True
    assert is_local_ip("8.8.8.8") is False
    assert is_local_ip("142.250.190.46") is False
    assert is_local_ip(None) is False

    assert get_country("127.0.0.1") == "LOCAL"
    assert get_country("8.8.8.8") == "UNKNOWN"

    # Tracker domain tests
    assert is_tracker("google-analytics.com") is True
    assert is_tracker("telemetry.microsoft.com") is True
    assert is_tracker("adservice.google.com") is True
    assert is_tracker("safe-api.internal.org") is False
    assert is_tracker("") is False

    # First-seen tracker tests
    tracker = IntelTracker()
    app = "{app-guid-1}"
    dest = "142.250.190.46"

    # First observation should be new
    assert tracker.is_new_destination(app, dest, ts=100.0) is True
    assert tracker.first_seen(app, dest) == 100.0

    # Second observation should NOT be new
    assert tracker.is_new_destination(app, dest, ts=110.0) is False
    assert tracker.first_seen(app, dest) == 100.0


def test_provenance_graph_causal_chain():
    """Verify provenance graph builds File -> Process -> Socket causal chain for Phase B scenario."""
    proc_key = "{leaker-guid-001}"
    doc_path = "D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\bang_luong.xlsx"
    dest_ip = "127.0.0.1"
    dest_port = 8765

    events = [
        {
            "ts": 1000.0,
            "pid": 5000,
            "ppid": None,
            "proc_key": proc_key,
            "type": "proc_start",
            "image": "C:\\Python314\\python.exe",
        },
        {
            "ts": 1005.0,
            "pid": 5000,
            "proc_key": proc_key,
            "type": "file_create",
            "path": doc_path,
        },
        {
            "ts": 1010.0,
            "pid": 5000,
            "proc_key": proc_key,
            "type": "net_connect",
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "nbytes": 68961,
        },
    ]

    engine = ProvenanceEngine(delta_t_sec=30.0)
    G = engine.build_graph(events)

    # 1. Verify node presence
    proc_node = normalize_proc_node_id(proc_key)
    file_node = normalize_file_node_id(doc_path)
    sock_node = normalize_socket_node_id(dest_ip, dest_port)

    assert G.has_node(proc_node)
    assert G.has_node(file_node)
    assert G.has_node(sock_node)

    assert G.nodes[proc_node]["node_type"] == "process"
    assert G.nodes[file_node]["node_type"] == "file"
    assert G.nodes[file_node]["is_sensitive"] is True
    assert G.nodes[sock_node]["node_type"] == "socket"
    assert G.nodes[sock_node]["is_local"] is True

    # 2. Verify edges
    # File touched by process
    assert G.has_edge(proc_node, file_node)
    assert G.get_edge_data(proc_node, file_node)["relation"] == "CREATE"
    assert G.has_edge(file_node, proc_node)
    assert G.get_edge_data(file_node, proc_node)["relation"] == "TOUCH"

    # Process connects to socket
    assert G.has_edge(proc_node, sock_node)
    assert G.get_edge_data(proc_node, sock_node)["relation"] == "CONNECT"

    # 3. Verify causal edge File -> Socket
    assert G.has_edge(file_node, sock_node)
    causal_edge = G.get_edge_data(file_node, sock_node)
    assert causal_edge["relation"] == "CAUSAL_FLOW"
    assert causal_edge["dt"] == 5.0
    assert causal_edge["weight"] > 0.8

    # 4. Verify path explanation
    explanations = engine.explain_paths(G)
    assert len(explanations) == 1
    exp = explanations[0]
    assert exp["file_path"] == doc_path
    assert exp["destination"] == "127.0.0.1:8765"
    assert exp["is_local"] is True
    assert exp["causal_dt"] == 5.0


def test_provenance_subprocess_spawning():
    """Verify ProcessHierarchy and provenance graph across parent-child subprocess execution."""
    parent_key = "{parent-proc-100}"
    child_key = "{child-proc-200}"
    doc_path = "D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\cmnd_can_cuoc.pdf"

    events = [
        # Parent starts
        {
            "ts": 100.0,
            "pid": 1000,
            "ppid": None,
            "proc_key": parent_key,
            "type": "proc_start",
        },
        # Parent touches sensitive document
        {
            "ts": 102.0,
            "pid": 1000,
            "proc_key": parent_key,
            "type": "file_create",
            "path": doc_path,
        },
        # Parent spawns child
        {
            "ts": 104.0,
            "pid": 2000,
            "ppid": 1000,
            "proc_key": child_key,
            "type": "proc_start",
        },
        # Child sends data to network socket
        {
            "ts": 106.0,
            "pid": 2000,
            "proc_key": child_key,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "nbytes": 75265,
        },
    ]

    G = build_provenance_graph(events, delta_t_sec=30.0)

    p_node = normalize_proc_node_id(parent_key)
    c_node = normalize_proc_node_id(child_key)
    f_node = normalize_file_node_id(doc_path)
    s_node = normalize_socket_node_id("127.0.0.1", 8765)

    # Parent spawns child edge
    assert G.has_edge(p_node, c_node)
    assert G.get_edge_data(p_node, c_node)["relation"] == "SPAWN"

    # Causal flow from parent's file to child's socket
    assert G.has_edge(f_node, s_node)
    assert G.get_edge_data(f_node, s_node)["relation"] == "CAUSAL_FLOW"


def test_feature_extraction_vector_dimension_and_no_nan():
    """Feature vector must have exact length 17, and contain NO NaN or None values."""
    proc_key = "{test-proc-guid}"
    events = [
        {
            "ts": 2000.0,
            "pid": 4000,
            "proc_key": proc_key,
            "type": "file_create",
            "path": "D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\hop_dong_thue_nha.docx",
        },
        {
            "ts": 2005.0,
            "pid": 4000,
            "proc_key": proc_key,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "nbytes": 142681,
        },
        {
            "ts": 2010.0,
            "pid": 4000,
            "proc_key": proc_key,
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "nbytes": 5000,
        },
    ]

    g = build_provenance_graph(events, delta_t_sec=30.0)
    features = extract_window_features(
        proc_key=proc_key,
        window_events=events,
        t_start=1990.0,
        t_end=2020.0,
        proc_info={"signed": 1, "start_ts": 1980.0},
        provenance_graph=g,
    )

    # 1. Verify all 17 feature keys exist
    for fname in FEATURE_NAMES:
        assert fname in features, f"Missing feature: {fname}"

    # 2. Check values
    assert features["n_file_create"] == 1.0
    assert features["n_sensitive_files"] == 1.0
    assert features["ratio_sensitive_events"] == 1.0
    assert features["n_net_connect"] == 2.0
    assert features["total_bytes_sent"] == 142681.0 + 5000.0
    assert features["is_local_dest_only"] == 1.0
    assert features["is_signed_process"] == 1.0
    assert features["process_lifetime"] == 40.0  # 2020.0 - 1980.0
    assert features["has_causal_flow"] == 1.0

    # 3. Vector conversion
    vec = features_to_vector(features)
    assert len(vec) == 17
    assert len(FEATURE_NAMES) == 17

    # Check for NaN / None
    for val in vec:
        assert val is not None
        assert not math.isnan(float(val))
        assert not math.isinf(float(val))


def test_sliding_window_extractor_execution():
    """Verify SlidingWindowFeatureExtractor generates windows over event sequence."""
    events = [
        {
            "ts": 100.0,
            "pid": 3000,
            "proc_key": "{proc-A}",
            "type": "file_create",
            "path": "D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\file_1.docx",
        },
        {
            "ts": 120.0,
            "pid": 3000,
            "proc_key": "{proc-A}",
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "nbytes": 4096,
        },
        {
            "ts": 180.0,
            "pid": 3000,
            "proc_key": "{proc-A}",
            "type": "net_connect",
            "dest_ip": "127.0.0.1",
            "dest_port": 8765,
            "nbytes": 8192,
        },
    ]

    extractor = SlidingWindowFeatureExtractor(window_sec=60.0, step_sec=15.0)
    windows = extractor.extract_windows(events)

    assert len(windows) > 0
    first_window = windows[0]
    assert "proc_key" in first_window
    assert "features" in first_window
    assert "vector" in first_window
    assert len(first_window["vector"]) == 17

    for w in windows:
        for val in w["vector"]:
            assert not math.isnan(float(val))


def test_sliding_window_extractor_from_db(tmp_path):
    """Verify extract_from_db properly reads from SQLite database and produces windows."""
    from core.store import EventStore

    db_file = str(tmp_path / "test_extract.db")
    store = EventStore(db_file)

    store.upsert_process({
        "proc_key": "{proc-db-test}",
        "pid": 5000,
        "name": "python.exe",
        "start_ts": 100.0,
        "signed": 0,
    })

    store.insert_events_batch([
        {
            "ts": 105.0,
            "pid": 5000,
            "proc_key": "{proc-db-test}",
            "type": "file_create",
            "path": "D:\\KERNAL PROTECT\\privacyguard\\data\\FakeDocuments\\passwords.txt",
        },
        {
            "ts": 115.0,
            "pid": 5000,
            "proc_key": "{proc-db-test}",
            "type": "net_connect",
            "dest_ip": "1.2.3.4",
            "dest_port": 443,
            "nbytes": 2048,
        },
    ])
    store.close()

    extractor = SlidingWindowFeatureExtractor(window_sec=30.0, step_sec=15.0)
    windows = extractor.extract_from_db(db_file)

    assert len(windows) > 0
    w = windows[0]
    assert w["proc_key"] == "{proc-db-test}"
    assert w["features"]["n_file_create"] == 1.0
    assert w["features"]["n_sensitive_files"] == 1.0
    assert w["features"]["n_net_connect"] == 1.0
    assert w["features"]["has_causal_flow"] == 1.0
    assert len(w["vector"]) == 17
