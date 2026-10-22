"""Full End-to-End Integration Tests for PrivacyGuard (Phase F).

Validates the complete closed-loop lifecycle:
1. EventStore initialization in temporary database.
2. Ingestion of realistic multi-event telemetry (Process -> Sensitive File -> Network Egress).
3. Provenance Graph generation linking File, Process, and Network Socket.
4. Feature extraction over sliding temporal windows producing valid 17D vectors.
5. Anomaly detection via RuleBased, IsolationForest, and Autoencoder models.
6. Evidence explanation narrative generation with privacy redaction and safe firewall proposal.
7. Verification that benign non-exfiltration workloads do not trigger false alarms.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from typing import Any, Dict, List

import numpy as np
import pytest

from core.store import EventStore
from core.provenance import ProcessHierarchy, build_provenance_graph
from core.features import SlidingWindowFeatureExtractor, extract_window_features, features_to_vector
from core.explain import EvidenceExplainer, explain_alert, sanitize_user_path
from models.rules import RuleBasedDetector
from models.iforest import IsolationForestDetector
from models.autoencoder import AutoencoderDetector
from eval.overhead import run_io_impact_benchmark, run_pipeline_inference_benchmark


@pytest.fixture
def temp_workspace():
    """Create and tear down a temporary workspace for integration testing."""
    d = tempfile.mkdtemp(prefix="pg_integ_")
    db_path = os.path.join(d, "test_integ.db")
    yield {"dir": d, "db_path": db_path}
    shutil.rmtree(d, ignore_errors=True)


def test_end_to_end_exfiltration_detection_and_explanation(temp_workspace):
    """Verify complete pipeline from DB ingestion to anomaly detection and explanation."""
    db_path = temp_workspace["db_path"]
    store = EventStore(db_path=db_path, wal_mode=False)

    base_ts = time.time() - 100.0
    proc_key = "{integ-proc-guid-999}"

    # 1. Ingest Process Metadata
    proc_record = {
        "proc_key": proc_key,
        "pid": 5432,
        "ppid": 1000,
        "name": "suspicious_exporter.exe",
        "exe_path": r"C:\AppData\Local\Programs\suspicious_exporter.exe",
        "signed": 0,
        "publisher": None,
        "start_ts": base_ts,
    }
    store.upsert_process(proc_record)

    # 2. Ingest Sequence of Events: Process Start -> File Create -> Network Connect
    events: List[Dict[str, Any]] = [
        {
            "ts": base_ts + 1.0,
            "pid": 5432,
            "ppid": 1000,
            "proc_key": proc_key,
            "type": "proc_start",
            "extra_json": {"image": "suspicious_exporter.exe", "event_record_id": 101},
        },
        {
            "ts": base_ts + 5.0,
            "pid": 5432,
            "ppid": 1000,
            "proc_key": proc_key,
            "type": "file_create",
            "path": r"C:\Users\TargetUser\Documents\FakeDocuments\confidential_financials.xlsx",
            "extra_json": {"event_record_id": 102},
        },
        {
            "ts": base_ts + 10.0,
            "pid": 5432,
            "ppid": 1000,
            "proc_key": proc_key,
            "type": "net_connect",
            "dest_ip": "198.51.100.88",
            "dest_port": 443,
            "proto": "tcp",
            "nbytes": 524288,  # 512 KB
            "extra_json": {"event_record_id": 103},
        },
    ]

    inserted = store.insert_events_batch(events)
    assert inserted == 3
    store.close()

    # 3. Extract Sliding Windows & Features
    extractor = SlidingWindowFeatureExtractor(window_sec=60.0, step_sec=15.0)
    windows = extractor.extract_from_db(db_path)
    assert len(windows) > 0

    target_window = windows[0]
    vector = target_window["vector"]
    features = target_window["features"]

    assert len(vector) == 17
    assert not np.isnan(vector).any()
    assert features["n_sensitive_files"] >= 1.0
    assert features["total_bytes_sent"] >= 500000.0

    # 4. Provenance Graph Construction
    G = build_provenance_graph(events, delta_t_sec=30.0)
    assert len(G.nodes) >= 3
    # Verify Causal Flow Edge exists
    causal_edges = [
        (u, v, d) for u, v, d in G.edges(data=True) if d.get("relation") == "CAUSAL_FLOW"
    ]
    assert len(causal_edges) > 0, "Expected at least one CAUSAL_FLOW edge connecting file to socket"

    # 5. Run Detectors
    X = np.array([vector], dtype=np.float32)

    # RuleBased Detector
    rule_detector = RuleBasedDetector()
    rule_score = float(rule_detector.score(X)[0])
    rule_alert = bool(rule_detector.predict(X)[0])
    assert rule_alert is True, "Rule detector should flag bulk sensitive egress"
    assert rule_score >= 0.7

    # Isolation Forest
    # Train on 20 benign synthetic records then predict
    rng = np.random.RandomState(42)
    benign_X = rng.normal(loc=0.1, scale=0.05, size=(30, 17)).astype(np.float32)
    benign_X[:, 1] = 0.0  # Zero sensitive files
    benign_X[:, 5] = 0.0  # Zero bytes sent

    iforest = IsolationForestDetector()
    iforest.fit(benign_X)
    iforest_score = float(iforest.score(X)[0])
    assert iforest_score > 0.0

    # Autoencoder
    ae = AutoencoderDetector(epochs=5, batch_size=16)
    ae.fit(benign_X)
    ae_score = float(ae.score(X)[0])
    assert ae_score > 0.0

    # 6. Generate Evidence Explanation
    explainer = EvidenceExplainer()
    window_for_alert = {
        "proc_key": proc_key,
        "proc_name": "suspicious_exporter.exe",
        "pid": 5432,
        "features": features,
        "sensitive_files": [r"C:\Users\TargetUser\Documents\FakeDocuments\confidential_financials.xlsx"],
        "dest_ip": "198.51.100.88",
        "dest_port": 443,
    }
    proc_info = {
        "name": "suspicious_exporter.exe",
        "pid": 5432,
        "exe_path": r"C:\AppData\Local\Programs\suspicious_exporter.exe",
    }

    explanation = explainer.explain(
        window=window_for_alert,
        detector_name="RuleBased",
        score=rule_score,
        proc_info=proc_info,
        provenance_graph=G,
    )

    # Verify Narrative
    narrative = explanation["narrative"]
    assert "CẢNH BÁO NGUY HIỂM" in narrative
    assert "suspicious_exporter.exe" in narrative
    assert "(Mã tiến trình: 5432)" in narrative
    assert "TargetUser" not in narrative, "Personal username should be redacted from narrative"
    assert "confidential_financials.xlsx" in narrative
    assert r"C:\Users\***\Documents" in explanation["sensitive_files"][0]

    # Verify Structured Explanation
    assert "Nguy hiểm cao" in explanation["headline"] or "Cao" in explanation["headline"]
    assert explanation["has_causal_flow"] is True
    assert len(explanation["sensitive_files"]) >= 1
    assert "198.51.100.88:443" in explanation["dest_str"]

    # Verify Safe Firewall Command Template (strictly no execution)
    fw_rule = explanation["suggested_firewall_rule"]
    assert "netsh advfirewall firewall add rule" in fw_rule
    assert "action=block" in fw_rule


def test_benign_workload_does_not_trigger_false_alarm(temp_workspace):
    """Verify standard benign activity produces clean non-alert scores."""
    db_path = temp_workspace["db_path"]
    store = EventStore(db_path=db_path, wal_mode=False)

    base_ts = time.time() - 50.0
    proc_key = "{benign-proc-guid-111}"

    store.upsert_process({
        "proc_key": proc_key,
        "pid": 1234,
        "name": "explorer.exe",
        "exe_path": r"C:\Windows\explorer.exe",
        "signed": 1,
        "publisher": "Microsoft Windows",
        "start_ts": base_ts,
    })

    # Non-sensitive file in temp directory, no network connections
    events = [
        {
            "ts": base_ts + 2.0,
            "pid": 1234,
            "proc_key": proc_key,
            "type": "file_create",
            "path": r"C:\Windows\Temp\temp_icon_cache.tmp",
            "extra_json": {"event_record_id": 201},
        }
    ]
    store.insert_events_batch(events)
    store.close()

    extractor = SlidingWindowFeatureExtractor(window_sec=60.0, step_sec=15.0)
    windows = extractor.extract_from_db(db_path)
    assert len(windows) > 0

    vector = windows[0]["vector"]
    X = np.array([vector], dtype=np.float32)

    rule_detector = RuleBasedDetector()
    assert bool(rule_detector.predict(X)[0]) is False
    assert float(rule_detector.score(X)[0]) < 0.3


def test_overhead_benchmark_components_run():
    """Verify overhead benchmark helper functions execute and pass criteria."""
    io_res = run_io_impact_benchmark(num_files=100)
    assert "overhead_percent" in io_res
    assert io_res["num_files"] == 100

    pipe_res = run_pipeline_inference_benchmark(num_windows=50)
    assert pipe_res["latency_rules_ms_per_window"] >= 0.0
    assert pipe_res["latency_iforest_ms_per_window"] >= 0.0
    assert pipe_res["latency_autoencoder_ms_per_window"] >= 0.0
