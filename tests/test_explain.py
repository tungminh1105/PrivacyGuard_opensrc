"""Unit tests for Evidence Explanation module (Phase E).

Validates:
- Privacy-preserving path sanitization (user account name redaction).
- Narrative text generation adhering strictly to the required template format.
- Structured explanation dictionary generation with contributing factors and causal chains.
- Robustness against missing or empty telemetry attributes.
- Safe Windows Firewall rule template generation without auto-execution.
"""

from __future__ import annotations

import pytest
from core.explain import (
    EvidenceExplainer,
    explain_alert,
    format_bytes_human,
    get_severity_label,
    sanitize_user_path,
)


def test_sanitize_user_path_redacts_usernames():
    """Verify personal usernames are masked in both Windows and Unix path conventions."""
    win_path = r"C:\Users\Tungminh\Documents\FakeDocuments\hop_dong_thue_nha.docx"
    sanitized_win = sanitize_user_path(win_path)
    assert r"C:\Users\***\Documents\FakeDocuments\hop_dong_thue_nha.docx" == sanitized_win
    assert "Tungminh" not in sanitized_win

    unix_path = "/home/developer/workspace/privacyguard/data/passwords.txt"
    sanitized_unix = sanitize_user_path(unix_path)
    assert "/home/***/workspace/privacyguard/data/passwords.txt" == sanitized_unix
    assert "developer" not in sanitized_unix

    # System paths remain unchanged
    sys_path = r"C:\Windows\System32\svchost.exe"
    assert sanitize_user_path(sys_path) == sys_path


def test_format_bytes_human_units():
    """Verify byte formatting handles bytes, KB, and MB scales correctly."""
    assert format_bytes_human(500) == "500 bytes"
    assert format_bytes_human(2048) == "2.0 KB"
    assert format_bytes_human(1024 * 1024 * 2.5) == "2.50 MB"


def test_get_severity_label_thresholds():
    """Verify severity categories match anomaly score boundaries."""
    assert get_severity_label(0.95) == "Cao"
    assert get_severity_label(0.70) == "Cao"
    assert get_severity_label(0.55) == "Trung bình"
    assert get_severity_label(0.20) == "Thấp"


def test_explain_alert_narrative_and_structured_output():
    """Verify narrative matches the requested template string and causal chain is formed."""
    window = {
        "proc_key": "{proc-test-100}",
        "proc_name": "python.exe",
        "pid": 8000,
        "dest_ip": "127.0.0.1",
        "dest_port": 8765,
        "sensitive_files": [
            r"C:\Users\Victim\Documents\sao_ke_tai_khoan.xlsx",
            r"C:\Users\Victim\Documents\cmnd_can_cuoc.pdf",
        ],
        "features": {
            "n_file_create": 2,
            "n_sensitive_files": 2,
            "total_bytes_sent": 54321,
            "n_net_connect": 1,
            "n_new_dest": 1,
            "has_causal_flow": 1.0,
            "is_signed_process": 0.0,
        },
    }
    proc_info = {
        "name": "python.exe",
        "pid": 8000,
        "exe_path": r"C:\Users\Victim\AppData\Local\Programs\Python\Python314\python.exe",
    }

    res = explain_alert(
        window=window,
        detector_name="RuleBased",
        score=0.92,
        proc_info=proc_info,
    )

    # 1. Check severity and score
    assert res["severity"] == "Cao"
    assert res["score"] == 0.92
    assert res["detector"] == "RuleBased"

    # 2. Check storytelling narrative template requirements
    narrative = res["narrative"]
    assert "🔴 [CẢNH BÁO NGUY HIỂM: PHÁT HIỆN GỬI TRỘM DỮ LIỆU]" in narrative
    assert "python.exe (Mã tiến trình: 8000)" in narrative
    assert "53.0 KB" in narrative or "54321" in narrative
    assert "127.0.0.1:8765" in narrative
    assert "Điểm rủi ro 92/100" in narrative
    assert "Chặn ứng dụng này" in narrative

    # 3. Check privacy redaction in sensitive files and narrative
    assert "Victim" not in narrative
    assert all("Victim" not in f for f in res["sensitive_files"])

    # 4. Check causal chain structure
    assert res["has_causal_flow"] is True
    assert len(res["causal_chain"]) == 3
    assert "Tệp nhạy cảm" in res["causal_chain"][0]
    assert "python.exe" in res["causal_chain"][1]
    assert "127.0.0.1:8765" in res["causal_chain"][2]

    # 5. Check firewall command template
    assert "netsh advfirewall firewall add rule" in res["suggested_firewall_rule"]
    assert "PG_block_python" in res["suggested_firewall_rule"]
    assert "Victim" not in res["suggested_firewall_rule"]
    assert "CẢNH BÁO AN TOÀN" in res["safety_warning"]


def test_explain_alert_handles_missing_fields_gracefully():
    """Verify explain_alert does not crash on empty/minimal inputs."""
    minimal_window = {}
    res = explain_alert(minimal_window)

    assert isinstance(res, dict)
    assert "narrative" in res
    assert "severity" in res
    assert "suggested_firewall_rule" in res
    assert res["has_causal_flow"] is False
