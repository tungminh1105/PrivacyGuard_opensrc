"""Unit tests for False Positive Rate (FPR) report generation and verdict evaluation.

Ensures strict integrity:
1. Duration < 120 minutes -> INCONCLUSIVE
2. New alerts > 0 -> FAIL / NEEDS CLASSIFICATION
3. Duration >= 120 minutes, windows > 0, events > 0, alerts == 0 -> PASS
4. Inconsistent metrics (e.g. timestamps vs duration) -> FAIL
"""

import datetime
import json
import os
import subprocess
import sys
import tempfile
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.monitor_fpr import (
    compute_evaluation_verdict,
    check_consistency,
    export_markdown_report,
)


def _build_mock_summary(
    duration_min: float = 120.0,
    events_ingested: int = 5000,
    windows_evaluated: int = 1500,
    alerts_new: int = 0,
    events_before: int = 10000,
    alerts_before: int = 5,
) -> dict:
    """Helper to build a self-consistent summary dictionary."""
    now = datetime.datetime.now()
    start_dt = now - datetime.timedelta(minutes=duration_min)
    end_dt = now
    events_after = events_before + events_ingested
    alerts_after = alerts_before + alerts_new
    fpr_per_1000 = (alerts_new / windows_evaluated * 1000.0) if windows_evaluated > 0 else 0.0
    alerts_per_hour = alerts_new / (duration_min / 60.0) if duration_min > 0 else 0.0

    return {
        "duration_min": duration_min,
        "interval_sec": 60.0,
        "db_path": "data/privacyguard.db",
        "start_time": start_dt.isoformat(),
        "end_time": end_dt.isoformat(),
        "watermark_start": 100,
        "watermark_end": 200,
        "events_before": events_before,
        "events_after": events_after,
        "events_ingested": events_ingested,
        "windows_before": 2000,
        "windows_after": 2000 + windows_evaluated,
        "windows_evaluated": windows_evaluated,
        "alerts_before": alerts_before,
        "alerts_after": alerts_after,
        "alerts_new": alerts_new,
        "fpr_per_1000_windows": round(fpr_per_1000, 6),
        "alerts_per_hour": round(alerts_per_hour, 6),
        "funnel_breakdown": {
            "windows_created": windows_evaluated,
            "no_proc_key": 0,
            "not_direct_actor": 0,
            "ignored_process": 0,
            "no_causal": 0,
            "bytes_below_min": 0,
            "no_sensitive_file": 0,
            "score_below_threshold": 0,
            "duplicate": 0,
            "alerts_created": alerts_new,
        },
    }


def test_fpr_report_duration_insufficient(tmp_path):
    """Case 1: duration < 120 minutes -> INCONCLUSIVE."""
    summary = _build_mock_summary(duration_min=30.0, windows_evaluated=300, alerts_new=0)
    eval_res = compute_evaluation_verdict(summary)

    assert eval_res["overall_verdict"] == "INCONCLUSIVE"
    assert eval_res["duration_ok"] is False
    assert any("30.0 phút" in r for r in eval_res["reasons"])

    report_path = str(tmp_path / "FPR_REPORT_30min.md")
    export_markdown_report(summary, [], [], {"total": 0, "by_type": {}}, report_path)

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "INCONCLUSIVE" in content
    assert "CHƯA ĐẠT" in content
    assert "PASS (ĐẠT CHUẨN NGHIỆM THU)" not in content


def test_fpr_report_alerts_detected(tmp_path):
    """Case 2: alerts_new > 0 -> FAIL."""
    summary = _build_mock_summary(duration_min=120.0, windows_evaluated=1200, alerts_new=2)
    eval_res = compute_evaluation_verdict(summary)

    assert eval_res["overall_verdict"] == "FAIL"
    assert eval_res["alerts_ok"] is False

    mock_alerts = [
        {
            "id": 180,
            "ts": datetime.datetime.now().isoformat(),
            "proc_key": "{test-guid-1}",
            "proc_name": "curl.exe",
            "pid": 5555,
            "bytes_sent": 4096,
            "dest": "1.2.3.4:443",
            "files": ["report.docx"],
            "verdict": "unclassified",
        }
    ]

    report_path = str(tmp_path / "FPR_REPORT_fail.md")
    export_markdown_report(summary, mock_alerts, [], {"total": 0, "by_type": {}}, report_path)

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "FAIL" in content
    assert "CẦN PHÂN LOẠI" in content
    assert "curl.exe" in content
    assert "0 False Alarms" not in content
    assert "PASS (ĐẠT CHUẨN NGHIỆM THU)" not in content


def test_fpr_report_full_pass(tmp_path):
    """Case 3: duration >= 120 min, windows > 0, events > 0, alerts_new == 0 -> PASS."""
    summary = _build_mock_summary(duration_min=120.0, windows_evaluated=1500, alerts_new=0)
    eval_res = compute_evaluation_verdict(summary)

    assert eval_res["overall_verdict"] == "PASS"
    assert eval_res["duration_ok"] is True
    assert eval_res["events_ok"] is True
    assert eval_res["windows_ok"] is True
    assert eval_res["alerts_ok"] is True

    report_path = str(tmp_path / "FPR_REPORT_pass.md")
    mock_tpr = [
        {
            "id": 170,
            "proc_key": "{guid-170}",
            "pid": 14916,
            "bytes_sent": 187814,
            "dest_str": "127.0.0.1:8765",
            "sensitive_files": ["secret.xlsx"],
        },
        {"id": 171, "proc_key": "{guid-171}", "pid": 11572, "bytes_sent": 150722, "dest_str": "127.0.0.1:8765", "sensitive_files": ["f.xlsx"]},
        {"id": 172, "proc_key": "{guid-172}", "pid": 3104, "bytes_sent": 153329, "dest_str": "127.0.0.1:8765", "sensitive_files": ["f.xlsx"]},
        {"id": 173, "proc_key": "{guid-173}", "pid": 9188, "bytes_sent": 210419, "dest_str": "127.0.0.1:8765", "sensitive_files": ["f.xlsx"]},
        {"id": 174, "proc_key": "{guid-174}", "pid": 16132, "bytes_sent": 164202, "dest_str": "127.0.0.1:8765", "sensitive_files": ["f.xlsx"]},
    ]
    export_markdown_report(summary, [], mock_tpr, {"total": 5, "by_type": {"doc": 5}}, report_path)

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "PASS (ĐẠT CHUẨN NGHIỆM THU)" in content
    assert "0 False Alarms" in content
    assert "5/5 (100%)" in content


def test_fpr_report_consistency_check():
    """Consistency check rejects manipulated metrics (>5% mismatch)."""
    summary = _build_mock_summary(duration_min=120.0, events_ingested=5000, alerts_new=0)

    # 1. Tamper with duration_min vs start/end timestamps
    bad_summary = dict(summary)
    bad_summary["duration_min"] = 300.0  # timestamps only 120m apart
    is_ok, errs = check_consistency(bad_summary)
    assert is_ok is False
    assert any("duration_min" in e for e in errs)

    # 2. Tamper with events_ingested
    bad_summary_ev = dict(summary)
    bad_summary_ev["events_ingested"] = 99999
    is_ok, errs = check_consistency(bad_summary_ev)
    assert is_ok is False
    assert any("events_ingested" in e for e in errs)


def test_fpr_report_tpr_less_than_5_does_not_claim_100(tmp_path):
    """When TPR reference alerts < 5, report must show N/A (x/5) and NOT claim 100%."""
    summary = _build_mock_summary(duration_min=120.0, windows_evaluated=1500, alerts_new=0)
    report_path = str(tmp_path / "FPR_REPORT_tpr_partial.md")
    partial_tpr = [
        {"id": 170, "proc_key": "{guid-170}", "pid": 14916, "bytes_sent": 187814, "dest_str": "127.0.0.1:8765", "sensitive_files": ["secret.xlsx"]},
        {"id": 171, "proc_key": "{guid-171}", "pid": 11572, "bytes_sent": 150722, "dest_str": "127.0.0.1:8765", "sensitive_files": ["f.xlsx"]},
    ]
    export_markdown_report(summary, [], partial_tpr, {"total": 0, "by_type": {}}, report_path)

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "N/A (2/5)" in content
    assert "(100%)" not in content
    assert "Phát hiện 100%" not in content


def test_fpr_report_consistency_windows_and_watermark():
    """Consistency check rejects mismatched windows_evaluated and regressing watermark."""
    summary = _build_mock_summary(duration_min=120.0, windows_evaluated=1500, alerts_new=0)

    # 1. Tamper with windows_evaluated vs windows_after - windows_before
    bad_win = dict(summary)
    bad_win["windows_evaluated"] = 9999
    is_ok, errs = check_consistency(bad_win)
    assert is_ok is False
    assert any("windows_evaluated" in e for e in errs)

    # 2. Tamper with watermark (end <= start)
    bad_wm = dict(summary)
    bad_wm["watermark_end"] = 50  # start is 100
    is_ok, errs = check_consistency(bad_wm)
    assert is_ok is False
    assert any("watermark_end" in e for e in errs)


def test_fpr_report_dynamic_fpr_calculation(tmp_path):
    """FPR display is computed from alerts_new / windows_evaluated if fpr_per_1000 is None."""
    summary = _build_mock_summary(duration_min=120.0, windows_evaluated=2000, alerts_new=4)
    summary["fpr_per_1000_windows"] = None  # None in summary
    summary["alerts_per_hour"] = None

    report_path = str(tmp_path / "FPR_REPORT_dynamic_fpr.md")
    export_markdown_report(summary, [], [], {"total": 0, "by_type": {}}, report_path)

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 4 alerts / 2000 windows * 1000 = 2.0000
    assert "2.0000" in content
    assert "Windows 11 Enterprise" not in content  # must not hardcode Windows 11 Enterprise


def test_report_only_without_summary_exits_code_3():
    """Verify monitor_fpr.py --report-only exits with code 3 if no summary exists."""
    py_exec = sys.executable
    non_existent = os.path.join(PROJECT_ROOT, "results", "non_existent_summary_test.json")
    if os.path.exists(non_existent):
        os.remove(non_existent)

    res = subprocess.run(
        [py_exec, "scripts/monitor_fpr.py", "--report-only", "--summary-out", non_existent],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 3
    assert "INCONCLUSIVE" in res.stdout
    assert "chưa có dữ liệu đo" in res.stdout
