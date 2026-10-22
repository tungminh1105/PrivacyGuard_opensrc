"""Evidence explanation module for PrivacyGuard (Phase E).

Converts raw anomaly detection scores and provenance graphs into human-readable,
auditable evidence narratives and structured explanation dictionaries for analysts and UI.
Strictly redacts sensitive user account names in paths to maintain privacy.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional
import networkx as nx

logger = logging.getLogger(__name__)


def sanitize_user_path(path: Optional[str]) -> str:
    """Redact personal username in Windows and Unix file paths for privacy."""
    if not path or not isinstance(path, str):
        return ""

    # Windows: C:\Users\<Username>\... -> C:\Users\***\...
    p_win = re.sub(
        r"([a-zA-Z]:\\Users\\)[^\\]+(\\.*)?",
        r"\1***\2",
        path,
        flags=re.IGNORECASE,
    )
    # Unix: /home/<username>/... -> /home/***/...
    p_unix = re.sub(
        r"(/home/)[^/]+(/.*)?",
        r"\1***\2",
        p_win,
        flags=re.IGNORECASE,
    )
    return p_unix


def format_bytes_human(nbytes: int | float) -> str:
    """Format byte integers into human-readable KB/MB strings."""
    b = float(nbytes)
    if b >= 1024 * 1024:
        return f"{b / (1024 * 1024):.2f} MB"
    elif b >= 1024:
        return f"{b / 1024:.1f} KB"
    else:
        return f"{int(b)} bytes"


def get_severity_label(score: float) -> str:
    """Map numeric anomaly score to categorical severity string."""
    s = float(score)
    if s >= 0.70:
        return "Cao"
    elif s >= 0.45:
        return "Trung bình"
    else:
        return "Thấp"


class EvidenceExplainer:
    """Generates structured and narrative explanations from detected anomaly windows."""

    def __init__(self):
        pass

    def explain(
        self,
        window: Dict[str, Any],
        detector_name: str = "RuleBased",
        score: Optional[float] = None,
        proc_info: Optional[Dict[str, Any]] = None,
        provenance_graph: Optional[nx.DiGraph] = None,
    ) -> Dict[str, Any]:
        """Generate human-readable and structured evidence explanation.

        Args:
            window: Dictionary with 'features', 'proc_key', 't_start', 't_end', etc.
            detector_name: Name of detecting model.
            score: Anomaly score in [0.0, 1.0]. If None, extracted from window or features.
            proc_info: Process metadata dict (name, pid, exe_path, signed, etc.).
            provenance_graph: Optional NetworkX DiGraph for causal path extraction.

        Returns:
            Structured explanation dictionary with narrative headline and action items.
        """
        feats = window.get("features", {})
        p_info = proc_info or {}

        # 1. Process identity
        proc_key = str(window.get("proc_key", p_info.get("proc_key", "unknown")))
        proc_name = str(p_info.get("name") or window.get("proc_name") or "python.exe")
        pid = p_info.get("pid") or window.get("pid", "N/A")
        exe_path = p_info.get("exe_path") or f"C:\\Program Files\\{proc_name}"

        # 2. Score & Severity
        sc_val = score
        if sc_val is None:
            sc_val = float(window.get("score", feats.get("score", 0.75)))
        sc_val = float(max(0.0, min(1.0, sc_val)))
        severity = get_severity_label(sc_val)

        # 3. Features extraction
        n_file_create = int(feats.get("n_file_create", 0))
        n_sensitive = int(feats.get("n_sensitive_files", 0))
        bytes_sent = int(feats.get("total_bytes_sent", 0))
        n_net = int(feats.get("n_net_connect", 0))
        n_new_dest = int(feats.get("n_new_dest", 0))
        has_causal = float(feats.get("has_causal_flow", 0.0)) > 0.5
        is_signed = float(feats.get("is_signed_process", 0.0)) > 0.5

        # 4. Sensitive files & network targets
        files_sample = window.get("sensitive_files") or []
        if not files_sample and provenance_graph is not None:
            files_sample = [
                data.get("path", node.replace("file:", ""))
                for node, data in provenance_graph.nodes(data=True)
                if data.get("type") == "File" or str(node).startswith("file:")
            ]

        # Sanitize file paths
        sanitized_files = [sanitize_user_path(f) for f in files_sample if f]
        sample_file_str = (
            ", ".join([os.path.basename(f) for f in sanitized_files[:3]])
            if sanitized_files
            else "dữ liệu bảo mật"
        )
        if len(sanitized_files) > 3:
            sample_file_str += f" và {len(sanitized_files) - 3} file khác"

        # Destination info
        dest_ip = window.get("dest_ip") or "127.0.0.1"
        dest_port = window.get("dest_port") or (443 if feats.get("dest_port") == 443 else 8765)
        country_or_domain = (
            "Local Loopback / Test Server"
            if dest_ip in ("127.0.0.1", "localhost")
            else "Đích đến ngoại mạng"
        )
        dest_str = f"{dest_ip}:{dest_port}"

        # 5. Build Causal Chain
        causal_chain = []
        if has_causal:
            causal_chain = [
                f"Tệp nhạy cảm ({sample_file_str})",
                f"Tiến trình {proc_name} (PID: {pid})",
                f"Kết nối mạng ({dest_str})",
            ]
            causal_flow_text = "File -> Process -> Network Socket"
        else:
            causal_flow_text = "Không phát hiện đường truyền trực tiếp"

        # 6. Format standard narrative string requested
        bytes_str = format_bytes_human(bytes_sent) if bytes_sent > 0 else "kết nối"
        narrative = (
            f"[Cảnh báo Rủi ro {severity}] Tiến trình {proc_name} (PID: {pid}) "
            f"đã đọc/tạo {max(1, n_sensitive if n_sensitive > 0 else n_file_create)} file nhạy cảm "
            f"({sample_file_str}) và gửi {bytes_str} tới {dest_str} ({country_or_domain}). "
            f"Điểm bất thường: {sc_val:.2f} (Mô hình: {detector_name}). "
            f"Đường dẫn nhân quả: {causal_flow_text}."
        )

        # 7. Contributing factors
        factors = []
        if has_causal:
            factors.append("Tồn tại chuỗi nhân quả trực tiếp từ tệp nhạy cảm đến cổng mạng (CAUSAL_FLOW).")
        if n_sensitive > 0:
            factors.append(f"Truy cập {n_sensitive} tệp nhạy cảm trong phân vùng tài liệu người dùng.")
        if bytes_sent > 1024:
            factors.append(f"Lưu lượng truyền tải lớn ra ngoài mạng ({bytes_str}).")
        if n_new_dest > 0:
            factors.append("Địa chỉ IP đích là máy chủ mới xuất hiện lần đầu trong hệ thống.")
        if not is_signed:
            factors.append("Tiến trình không có chữ ký số hợp lệ từ nhà phát triển tin cậy.")

        if not factors:
            factors.append("Hành vi tiến trình lệch khỏi phân phối thống kê thông thường.")

        # 8. Firewall suggestion command
        clean_app_name = re.sub(r"[^a-zA-Z0-9_]", "", proc_name.replace(".exe", ""))
        firewall_cmd = (
            f'netsh advfirewall firewall add rule name="PG_block_{clean_app_name}" '
            f'dir=out action=block program="{sanitize_user_path(exe_path)}"'
        )

        return {
            "severity": severity,
            "headline": f"[Cảnh báo Rủi ro {severity}] Nghi vấn rò rỉ dữ liệu từ {proc_name}",
            "narrative": narrative,
            "proc_name": proc_name,
            "pid": pid,
            "proc_key": proc_key,
            "exe_path": sanitize_user_path(exe_path),
            "score": sc_val,
            "detector": detector_name,
            "sensitive_files": sanitized_files,
            "sample_files_summary": sample_file_str,
            "bytes_sent": bytes_sent,
            "bytes_formatted": bytes_str,
            "dest_str": dest_str,
            "country_or_domain": country_or_domain,
            "has_causal_flow": has_causal,
            "causal_flow_text": causal_flow_text,
            "causal_chain": causal_chain,
            "contributing_factors": factors,
            "suggested_firewall_rule": firewall_cmd,
            "safety_warning": "CẢNH BÁO AN TOÀN: Hệ thống không tự ý thực thi chặn. Quản trị viên cần kiểm tra kỹ trước khi áp dụng luật tường lửa Windows Firewall.",
        }


def explain_alert(
    window: Dict[str, Any],
    detector_name: str = "RuleBased",
    score: Optional[float] = None,
    proc_info: Optional[Dict[str, Any]] = None,
    provenance_graph: Optional[nx.DiGraph] = None,
) -> Dict[str, Any]:
    """Functional convenience wrapper for EvidenceExplainer."""
    explainer = EvidenceExplainer()
    return explainer.explain(
        window=window,
        detector_name=detector_name,
        score=score,
        proc_info=proc_info,
        provenance_graph=provenance_graph,
    )
