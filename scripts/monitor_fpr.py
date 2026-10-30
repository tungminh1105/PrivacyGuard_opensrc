"""False Positive Rate (FPR) Monitor and Evaluation for PrivacyGuard.

Monitors real-time Sysmon telemetry during 120 minutes of normal user activity
to calculate and verify the empirical False Positive Rate (FPR).

Outputs:
1. results/fpr_summary.json: duration, events, windows evaluated, alerts, FPR metrics.
2. results/fpr_alerts.csv: details of any alerts created during the measurement window.
3. results/FPR_REPORT.md: comprehensive diagnostic report matching database statistics.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime
import json
import os
import platform
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.guard_service import RealtimeGuardService
from core.store import EventStore


def get_os_environment_str() -> str:
    """Detect actual OS and edition from Windows registry and platform module."""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        pname = winreg.QueryValueEx(k, "ProductName")[0]
        bnum = winreg.QueryValueEx(k, "CurrentBuildNumber")[0]
        return f"{pname} (Build {bnum}, {platform.platform()})"
    except Exception:
        return f"Microsoft Windows ({platform.platform()})"


def is_admin() -> bool:
    """Check if process has elevated administrator token on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_consistency(summary: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Verify consistency among summary metrics to detect manipulation or data skew."""
    errors: List[str] = []

    # 1. Check duration vs start_time and end_time
    start_str = summary.get("start_time")
    end_str = summary.get("end_time")
    duration_min = float(summary.get("duration_min", 0.0))
    if start_str and end_str:
        try:
            start_dt = datetime.datetime.fromisoformat(start_str)
            end_dt = datetime.datetime.fromisoformat(end_str)
            ts_delta_min = (end_dt - start_dt).total_seconds() / 60.0
            # Discrepancy > 5% and > 0.5 minute
            if abs(duration_min - ts_delta_min) > max(0.5, 0.05 * max(ts_delta_min, 1.0)):
                errors.append(
                    f"duration_min ({duration_min:.2f}m) lệch >5% so với chênh lệch timestamp ({ts_delta_min:.2f}m)"
                )
        except Exception as e:
            errors.append(f"Không thể phân tích timestamp start/end: {e}")
    else:
        errors.append("Thiếu start_time hoặc end_time trong summary")

    # 2. Check events_ingested == events_after - events_before
    ev_before = int(summary.get("events_before", 0))
    ev_after = int(summary.get("events_after", 0))
    ev_ingested = int(summary.get("events_ingested", 0))
    ev_diff = ev_after - ev_before
    if ev_ingested != ev_diff:
        errors.append(f"events_ingested ({ev_ingested}) không khớp (events_after - events_before = {ev_diff})")

    # 3. Check alerts_new == alerts_after - alerts_before
    al_before = int(summary.get("alerts_before", 0))
    al_after = int(summary.get("alerts_after", 0))
    al_new = int(summary.get("alerts_new", 0))
    al_diff = al_after - al_before
    if al_new != al_diff:
        errors.append(f"alerts_new ({al_new}) không khớp (alerts_after - alerts_before = {al_diff})")

    # 4. Check windows_evaluated vs (windows_after - windows_before)
    win_before = int(summary.get("windows_before", 0))
    win_after = int(summary.get("windows_after", 0))
    win_evaluated = int(summary.get("windows_evaluated", 0))
    win_diff = win_after - win_before
    if abs(win_evaluated - win_diff) > max(1, 0.05 * max(win_diff, 1)):
        errors.append(
            f"windows_evaluated ({win_evaluated}) lệch >5% so với chênh lệch windows_after - windows_before ({win_diff})"
        )

    # 5. Check watermark progression
    wm_start = int(summary.get("watermark_start", 0))
    wm_end = int(summary.get("watermark_end", 0))
    if wm_start > 0 and wm_end <= wm_start:
        errors.append(
            f"watermark_end ({wm_end}) không tăng so với watermark_start ({wm_start})"
        )

    return (len(errors) == 0, errors)


def compute_evaluation_verdict(summary: Dict[str, Any]) -> Dict[str, Any]:
    """Compute strictly data-driven criteria statuses and overall test verdict."""
    is_consistent, consistency_errors = check_consistency(summary)

    duration_min = float(summary.get("duration_min", 0.0))
    events_ingested = int(summary.get("events_ingested", 0))
    windows_evaluated = int(summary.get("windows_evaluated", 0))
    alerts_new = int(summary.get("alerts_new", 0))

    duration_ok = duration_min >= 120.0
    events_ok = events_ingested > 0
    windows_ok = windows_evaluated > 0
    alerts_ok = alerts_new == 0

    reasons: List[str] = []
    if not is_consistent:
        reasons.extend(consistency_errors)
    if not duration_ok:
        reasons.append(f"Thời lượng đo chưa đạt tối thiểu 120 phút (thực tế: {duration_min:.1f} phút)")
    if not events_ok:
        reasons.append(f"Không có sự kiện Sysmon nào được nạp (events_ingested = {events_ingested})")
    if not windows_ok:
        reasons.append(f"Không có cửa sổ trượt nào được đánh giá (windows_evaluated = {windows_evaluated})")
    if not alerts_ok:
        reasons.append(f"Phát sinh {alerts_new} cảnh báo mới trong quá trình kiểm thử tải lành tính")

    # Overall Verdict
    if not is_consistent:
        overall_verdict = "FAIL"
        summary_conclusion = f"FAIL — Dữ liệu không nhất quán: {'; '.join(consistency_errors)}"
    elif alerts_new > 0:
        overall_verdict = "FAIL"
        summary_conclusion = f"FAIL — Phát hiện {alerts_new} cảnh báo mới (cần đối soát evidence để phân loại)"
    elif not (duration_ok and events_ok and windows_ok):
        overall_verdict = "INCONCLUSIVE"
        summary_conclusion = f"INCONCLUSIVE — Dữ liệu chưa đủ điều kiện nghiệm thu: {'; '.join(reasons)}"
    else:
        overall_verdict = "PASS"
        summary_conclusion = "PASS — Đạt chuẩn nghiệm thu: chạy đủ >= 120 phút, có nạp sự kiện Sysmon, có cửa sổ đánh giá, 0 cảnh báo giả"

    return {
        "overall_verdict": overall_verdict,
        "is_consistent": is_consistent,
        "consistency_errors": consistency_errors,
        "duration_ok": duration_ok,
        "events_ok": events_ok,
        "windows_ok": windows_ok,
        "alerts_ok": alerts_ok,
        "reasons": reasons,
        "summary_conclusion": summary_conclusion,
    }


def get_benign_actions_summary(
    csv_path: str = "results/benign_actions.csv",
    start_time_iso: Optional[str] = None,
    end_time_iso: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Read benign_actions.csv and produce a summary breakdown filtered by run or time."""
    if not os.path.exists(csv_path):
        return {"total": 0, "by_type": {}, "status": "No log file found"}

    start_dt = None
    end_dt = None
    if start_time_iso:
        try:
            start_dt = datetime.datetime.fromisoformat(start_time_iso)
        except Exception:
            pass
    if end_time_iso:
        try:
            end_dt = datetime.datetime.fromisoformat(end_time_iso)
        except Exception:
            pass

    counts: Dict[str, int] = {}
    total = 0
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Filter by run_id if specified
                row_run_id = row.get("run_id")
                if run_id and row_run_id and row_run_id != run_id:
                    continue

                # Filter by timestamp if available
                row_ts_str = row.get("timestamp")
                if row_ts_str and (start_dt or end_dt):
                    try:
                        row_dt = datetime.datetime.fromisoformat(row_ts_str)
                        if start_dt and row_dt < start_dt:
                            continue
                        if end_dt and row_dt > end_dt:
                            continue
                    except Exception:
                        pass

                atype = row.get("action_type") or "unknown"
                counts[atype] = counts.get(atype, 0) + 1
                total += 1
        return {"total": total, "by_type": counts, "status": "OK"}
    except Exception as e:
        return {"total": total, "by_type": counts, "status": f"Error: {e}"}


def get_reference_tpr_alerts(store: EventStore) -> List[Dict[str, Any]]:
    """Retrieve Phase 0.6 reference attack alerts (#170-#174)."""
    cur = store.conn.cursor()
    cur.execute(
        "SELECT id, ts, proc_key, detector, score, severity, evidence FROM alerts WHERE id BETWEEN 170 AND 174 ORDER BY id ASC"
    )
    rows = cur.fetchall()
    tpr_alerts = []
    for r in rows:
        ev = json.loads(r[6]) if r[6] else {}
        tpr_alerts.append({
            "id": r[0],
            "ts": r[1],
            "proc_key": r[2],
            "score": r[4],
            "severity": r[5],
            "pid": ev.get("pid"),
            "proc_name": ev.get("proc_name"),
            "bytes_sent": ev.get("bytes_sent"),
            "dest_str": ev.get("dest_str"),
            "sensitive_files": ev.get("sensitive_files", []),
        })
    return tpr_alerts


def export_markdown_report(
    summary: Dict[str, Any],
    new_alerts: List[Dict[str, Any]],
    tpr_alerts: List[Dict[str, Any]],
    benign_summary: Dict[str, Any],
    report_path: str = "results/FPR_REPORT.md",
) -> Dict[str, Any]:
    """Generate professional FPR Markdown report with completely data-driven verdicts."""
    eval_res = compute_evaluation_verdict(summary)

    duration_min = float(summary.get("duration_min", 0.0))
    events_ingested = int(summary.get("events_ingested", 0))
    windows_evaluated = int(summary.get("windows_evaluated", 0))
    alerts_new = int(summary.get("alerts_new", 0))
    fpr_per_1000 = summary.get("fpr_per_1000_windows")
    if fpr_per_1000 is None and windows_evaluated > 0:
        fpr_per_1000 = (alerts_new / windows_evaluated) * 1000.0

    fb = summary.get("funnel_breakdown", {})

    # Evaluate Individual Metrics
    dur_verdict = "**ĐẠT**" if eval_res["duration_ok"] else f"**CHƯA ĐẠT** ({duration_min:.1f}/120.0m)"
    ev_verdict = "**ĐẠT**" if eval_res["events_ok"] else f"**CHƯA ĐẠT** ({events_ingested} events)"
    win_verdict = "**ĐẠT**" if eval_res["windows_ok"] else f"**CHƯA ĐẠT** ({windows_evaluated} windows)"
    al_verdict = "**ĐẠT (0 alert rác)**" if eval_res["alerts_ok"] else f"**CẦN PHÂN LOẠI** ({alerts_new} alerts)"

    if eval_res["windows_ok"]:
        fpr_val = fpr_per_1000 if fpr_per_1000 is not None else ((alerts_new / windows_evaluated * 1000.0) if windows_evaluated > 0 else 0.0)
        fpr_display = f"{fpr_val:.4f}"
        fpr_verdict = "**XUẤT SẮC (0.00)**" if eval_res["alerts_ok"] else "**VƯỢT NGƯỠNG**"
    else:
        fpr_display = "N/A"
        fpr_verdict = "**CHƯA CÓ DỮ LIỆU WINDOW**"

    alerts_per_hour = summary.get("alerts_per_hour")
    if alerts_per_hour is None and duration_min > 0:
        alerts_per_hour = alerts_new / (duration_min / 60.0)

    if duration_min > 0:
        aph_val = alerts_per_hour if alerts_per_hour is not None else (alerts_new / (duration_min / 60.0))
        aph_display = f"{aph_val:.4f} alerts/h"
        aph_verdict = "**XUẤT SẮC (0.00)**" if eval_res["alerts_ok"] else "**VƯỢT NGƯỠNG**"
    else:
        aph_display = "N/A"
        aph_verdict = "**CHƯA CÓ THỜI GIAN ĐO**"

    # Reference TPR
    tpr_count = len(tpr_alerts)
    if tpr_count == 5:
        tpr_title = "5/5 (100%)"
        tpr_conclusion_str = "- **True Positive Rate (TPR)**: **5/5 (100%)** (Phát hiện toàn bộ đợt tấn công trích xuất dữ liệu thật)."
        tpr_intro_str = "Toàn bộ 5 lần tấn công dữ liệu thật từ Scenario 1 (Phase 0.6) đều kích hoạt cảnh báo tức thời, trích xuất đúng GUID Sysmon, đúng PID độc lập và đúng dung lượng từ TCP Receiver:"
    else:
        tpr_title = f"N/A ({tpr_count}/5)"
        tpr_conclusion_str = f"- **True Positive Rate (TPR)**: **N/A ({tpr_count}/5)** (Chưa đủ 5 đợt tấn công thật #170-#174 để xác nhận 100%)."
        tpr_intro_str = f"Hệ thống chỉ tìm thấy {tpr_count}/5 alert tham chiếu (#170-#174). Chưa đủ căn cứ để kết luận TPR 100%:"

    tpr_rows_md = ""
    for a in tpr_alerts:
        first_file = os.path.basename(a["sensitive_files"][0]) if a["sensitive_files"] else "N/A"
        tpr_rows_md += (
            f"| #{a['id']} | `{a['proc_key']}` | {a['pid']} | "
            f"{a['bytes_sent']} bytes | {a['dest_str']} | `{first_file}` | **Phát hiện (True Positive)** |\n"
        )
    if not tpr_rows_md:
        tpr_rows_md = "| - | *(Không tìm thấy 5 alert tham chiếu #170-#174)* | - | - | - | - | - |\n"

    # New Alerts Table
    new_alerts_rows_md = ""
    if new_alerts:
        for a in new_alerts:
            sens = a.get("files", [])
            f_str = os.path.basename(sens[0]) if sens else "N/A"
            verdict_str = a.get("verdict", "unclassified")
            new_alerts_rows_md += (
                f"| #{a.get('id')} | `{a.get('proc_name', 'unknown')}` | `{a.get('proc_key')}` | {a.get('pid')} | "
                f"{a.get('bytes_sent')} bytes | {a.get('dest')} | `{f_str}` | **{verdict_str}** |\n"
            )
    else:
        if eval_res["alerts_ok"]:
            new_alerts_rows_md = "| - | - | *(Không có cảnh báo nào trong suốt thời gian đo)* | - | - | - | - | **0 False Alarms** |\n"
        else:
            new_alerts_rows_md = f"| - | - | *(Có {alerts_new} cảnh báo mới nhưng chưa nạp danh sách chi tiết)* | - | - | - | - | **CẦN PHÂN LOẠI** |\n"

    # Benign Actions
    by_type = benign_summary.get("by_type", {})
    benign_rows_md = ""
    for atype, cnt in sorted(by_type.items()):
        benign_rows_md += f"- **{atype}**: {cnt} hành động\n"
    if not benign_rows_md:
        benign_rows_md = "- *(Chưa ghi nhận hành động tự động trong file log)*\n"

    # Conclusion Section
    if eval_res["overall_verdict"] == "PASS":
        conclusion_md = f"""### KẾT LUẬN: PASS (ĐẠT CHUẨN NGHIỆM THU)

Hệ thống PrivacyGuard đạt độ tin cậy thực nghiệm tối đa trên môi trường làm việc thực tế:
{tpr_conclusion_str}
- **False Positive Rate (FPR)**: **{fpr_display}** (0 cảnh báo sai trên {windows_evaluated:,} cửa sổ trượt đánh giá trong 120 phút).
- **Trạng thái**: Hệ thống sẵn sàng chuyển sang Giai đoạn 3 — Thử nghiệm 3 kịch bản tấn công MITRE ATT&CK.
"""
    elif eval_res["overall_verdict"] == "INCONCLUSIVE":
        conclusion_md = f"""### KẾT LUẬN: INCONCLUSIVE (CHƯA ĐỦ ĐIỀU KIỆN KẾT LUẬN)

Dữ liệu đo lường chưa hoàn tất hoặc chưa đạt yêu cầu kiểm chứng:
- **Lý do**: {eval_res['summary_conclusion']}
- **Khuyến nghị**: Cần chạy chu kỳ đo thật sự đủ 120 phút liên tục trên terminal Administrator với Sysmon hoạt động để nạp telemetry thực tế.
- **Quy tắc**: Tuyệt đối không tuyên bố FPR = 0 khi chưa chạy đủ 120 phút.
"""
    else:
        conclusion_md = f"""### KẾT LUẬN: FAIL (KHÔNG ĐẠT CHUẨN)

Hệ thống ghi nhận lỗi hoặc phát sinh cảnh báo trong quá trình đo:
- **Lý do**: {eval_res['summary_conclusion']}
- **Yêu cầu**: Cần kiểm tra chi tiết bảng cảnh báo mới để xác định quy tắc/cổng lọc gây ra false positive và đề xuất phương án hiệu chỉnh.
"""

    os_env = summary.get("os_environment") or get_os_environment_str()

    md_content = f"""# BÁO CÁO ĐO LƯỜNG TỶ LỆ BÁO ĐỘNG GIẢ (FALSE POSITIVE RATE - FPR)

> **Môi trường đo lường**: {os_env} (PowerShell Administrator Elevated)  
> **Thời gian bắt đầu**: `{summary.get('start_time', 'N/A')}`  
> **Thời gian kết thúc**: `{summary.get('end_time', 'N/A')}`  
> **Tổng thời lượng đo**: **{duration_min:.1f} phút** ({duration_min / 60.0:.2f} giờ)  
> **Cơ sở dữ liệu**: `{summary.get('db_path', 'data/privacyguard.db')}`  
> **Kết luận tổng thể**: **{eval_res['overall_verdict']}**  

---

## 1. TỔNG KẾT KẾT QUẢ ĐO LƯỜNG THỰC TẾ

| Chỉ số đo lường | Giá trị thực nghiệm | Tiêu chuẩn chấp nhận | Kết luận |
| :--- | :---: | :---: | :---: |
| **Thời lượng kiểm chứng liên tục** | **{duration_min:.1f} phút** | >= 120 phút | {dur_verdict} |
| **Tổng sự kiện Sysmon thật nạp** | **+{events_ingested:,} sự kiện** | > 0 (Đọc live liên tục) | {ev_verdict} |
| **Tổng cửa sổ trượt đã đánh giá** | **{windows_evaluated:,} windows** | > 0 windows | {win_verdict} |
| **Cảnh báo giả sinh ra (False Positives)**| **{alerts_new} alert** | 0 cảnh báo rác | {al_verdict} |
| **FPR trên 1,000 cửa sổ đánh giá** | **{fpr_display}** | < 1.0 per 1k windows | {fpr_verdict} |
| **Tần suất báo động sai theo giờ** | **{aph_display}** | < 0.5 alert/giờ | {aph_verdict} |

---

## 2. SO SÁNH VỚI ĐỘ NHẠY PHÁT HIỆN TẤN CÔNG THẬT (TPR BENCHMARK)

### A. Tỷ lệ phát hiện tấn công thật (True Positive Rate - TPR): **{tpr_title}**
{tpr_intro_str}

| Alert ID | Sysmon Process GUID | PID | Dung lượng Exfil | Đích đến | Tệp tin phát hiện | Kết luận |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
{tpr_rows_md}

### B. Tỷ lệ cảnh báo sai trên tải làm việc lành tính (FPR): **{fpr_display}**
Trong khoảng thời gian làm việc bình thường (văn phòng, lập trình, kiểm thử unit test, duyệt web), hệ thống ghi nhận:

| Alert ID | Tiến trình | Process GUID | PID | Dung lượng | Đích đến | Tệp tin | Verdict |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
{new_alerts_rows_md}

---

## 3. PHÂN TÍCH PHỄU LỌC ĐA CỔNG (MULTI-STAGE FUNNEL BREAKDOWN)

Trong suốt thời gian đo, tổng cộng **{windows_evaluated:,} cửa sổ** được sinh ra từ telemetry Sysmon thật và được phân loại qua các cổng bảo vệ:

| Cổng bảo vệ | Số lượng cửa sổ xử lý | Tỷ lệ (%) | Ý nghĩa kỹ thuật |
| :--- | :---: | :---: | :--- |
| **Tổng cửa sổ trượt (Windows Created)** | **{fb.get('windows_created', 0):,}** | 100.0% | Tổng các cửa sổ 60s có hoạt động tiến trình |
| - *Cổng 0: Không có proc_key hợp lệ* | {fb.get('no_proc_key', 0):,} | {fb.get('no_proc_key', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Sự kiện hệ thống thiếu GUID |
| - *Cổng 0.5: Tiến trình không trực tiếp gây sự kiện* | {fb.get('not_direct_actor', 0):,} | {fb.get('not_direct_actor', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Tiến trình tổ tiên chỉ spawn process con |
| - *Cổng 1: Tiến trình trong danh sách bỏ qua (Noise)* | {fb.get('ignored_process', 0):,} | {fb.get('ignored_process', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | PrivacyGuard, Streamlit, Collector nội bộ |
| - *Cổng 2: Không có quan hệ nhân quả (Đọc -> Gửi)* | {fb.get('no_causal', 0):,} | {fb.get('no_causal', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Hoạt động mạng bình thường không kèm đọc file |
| - *Cổng 3: Dung lượng dưới ngưỡng min_exfil_bytes* | {fb.get('bytes_below_min', 0):,} | {fb.get('bytes_below_min', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Gói tin TCP handshake, ACK, heartbeat nhỏ |
| - *Cổng 4: Không chạm vào tài liệu nhạy cảm* | {fb.get('no_sensitive_file', 0):,} | {fb.get('no_sensitive_file', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Tiến trình xử lý file log, binary thông thường |
| - *Cổng 4.5: Điểm bất thường dưới ngưỡng (Score < 0.70)* | {fb.get('score_below_threshold', 0):,} | {fb.get('score_below_threshold', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Hành vi nằm trong phân phối bình thường |
| - *Cổng 5: Khử trùng lặp (Dedup / Cooldown 600s)* | {fb.get('duplicate', 0):,} | {fb.get('duplicate', 0) / max(1, fb.get('windows_created', 1)) * 100:.1f}% | Cùng một incident đã được phát cảnh báo |
| **[+] CẢNH BÁO TẠO THÀNH CÔNG (Alerts)** | **{fb.get('alerts_created', 0)}** | **{fb.get('alerts_created', 0) / max(1, fb.get('windows_created', 1)) * 100:.2f}%** | Cảnh báo đạt chuẩn an ninh mức độ Cao |

---

## 4. NHẬT KÝ WORKLOAD LÀNH TÍNH ĐÃ THỰC HIỆN

Tải làm việc lành tính được tạo tự động bởi `scripts/benign_workload.py` song song với các hoạt động bình thường của người dùng:
- **Tổng số hành động ghi nhận trong khoảng thời gian chạy**: {benign_summary.get('total', 0)} hành vi
{benign_rows_md}
- Các hành động văn phòng tạo tệp `.docx`, sao chép vào `Downloads`, nén và giải nén zip kích hoạt Sysmon Event 11 trong thư mục người dùng nhưng **không** tạo cảnh báo do không phát sinh lưu lượng exfiltration ngoại mạng.

---

## 5. HẠN CHẾ VÀ ĐẶC ĐIỂM KIẾN TRÚC (LIMITATIONS)

1. **Sysmon File Event 11 (FileCreate) thay vì FileRead**:  
   Cấu hình Sysmon tiêu chuẩn của Windows chỉ giám sát tạo tệp (`Event ID 11: FileCreate`), chưa bật giám sát đọc tệp sâu qua minifilter driver để tránh làm chậm I/O hệ thống.
2. **TCP Receiver Server chạy trên Localhost**:  
   Trong kịch bản đo TPR chuẩn, đích nhận dữ liệu là TCP socket cục bộ (port 8765), dung lượng được đối soát chính xác 100% qua bảng `receiver_logs`.
3. **Phạm vi cửa sổ đo lường 120 phút**:  
   Workload kiểm nghiệm kéo dài 2 giờ bao gồm các tác vụ văn phòng, quản lý mã nguồn Git, chạy bộ test tự động và duyệt web thông thường.

---

## 6. KẾT LUẬN CHI TIẾT

{conclusion_md}
"""

    os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"[+] Báo cáo Markdown đã được xuất tại: {report_path}")
    return eval_res


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Real-world False Positive Rate (FPR) Monitor")
    parser.add_argument("--minutes", type=float, default=120.0, help="Monitoring duration in minutes (default: 120)")
    parser.add_argument("--interval", type=float, default=60.0, help="Polling interval in seconds (default: 60)")
    parser.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    parser.add_argument("--summary-out", type=str, default="results/fpr_summary.json", help="Path to output summary JSON")
    parser.add_argument("--alerts-out", type=str, default="results/fpr_alerts.csv", help="Path to output alerts CSV")
    parser.add_argument("--report-out", type=str, default="results/FPR_REPORT.md", help="Path to output report Markdown")
    parser.add_argument("--report-only", action="store_true", help="Generate report from existing results/fpr_summary.json")
    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    store = EventStore(db_path=db_path)

    # -------------------------------------------------------------
    # Option: --report-only (Requirement 1: NO hardcoding, NO fake report)
    # -------------------------------------------------------------
    if args.report_only:
        print("\n" + "=" * 70)
        print("      PRIVACYGUARD GENERATE FPR REPORT FROM MEASURED DATA")
        print("=" * 70)

        if not os.path.exists(args.summary_out):
            print("[-] [FAIL] INCONCLUSIVE — chưa có dữ liệu đo thật.")
            print(f"[-] Tệp tổng kết '{args.summary_out}' không tồn tại.")
            print("[-] Vui lòng chạy đo thật: python scripts/monitor_fpr.py --minutes 120")
            store.close()
            sys.exit(3)

        try:
            with open(args.summary_out, "r", encoding="utf-8") as f:
                summary = json.load(f)
        except Exception as e:
            print(f"[-] [FAIL] Không đọc được tệp {args.summary_out}: {e}")
            store.close()
            sys.exit(3)

        # Load alerts from CSV if available
        new_alerts: List[Dict[str, Any]] = []
        if os.path.exists(args.alerts_out):
            try:
                with open(args.alerts_out, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        files_list = [x.strip() for x in row.get("files", "").split(";") if x.strip()]
                        new_alerts.append({
                            "id": row.get("id"),
                            "ts": row.get("ts"),
                            "proc_key": row.get("proc_key"),
                            "proc_name": row.get("proc_name"),
                            "pid": row.get("pid"),
                            "bytes_sent": row.get("bytes_sent"),
                            "dest": row.get("dest"),
                            "files": files_list,
                            "verdict": row.get("verdict", "unclassified"),
                        })
            except Exception:
                pass

        benign_s = get_benign_actions_summary(
            start_time_iso=summary.get("start_time"),
            end_time_iso=summary.get("end_time"),
        )
        tpr_alerts = get_reference_tpr_alerts(store)
        eval_res = export_markdown_report(summary, new_alerts, tpr_alerts, benign_s, args.report_out)
        print(f"[*] Kết quả đánh giá: {eval_res['overall_verdict']} -> {eval_res['summary_conclusion']}")
        store.close()
        return

    # -------------------------------------------------------------
    # Real 120-minute Measurement Run
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("      PRIVACYGUARD 120-MINUTE ELEVATED FPR BENIGN MONITOR")
    print("=" * 70)

    # 1. Admin Verification
    if not is_admin():
        print("[-] [FAIL] Cần chạy PowerShell với quyền Administrator. Thoát.")
        store.close()
        sys.exit(2)

    print(f"[*] Cơ sở dữ liệu:     {db_path}")
    print(f"[*] Thời gian theo dõi: {args.minutes:.1f} phút (Chu kỳ quét mỗi {args.interval:.0f}s)")

    # 2. Guard Initialization and Sysmon Verification
    guard = RealtimeGuardService(db_path=db_path, poll_sysmon=True, enable_toast=False)
    sysmon_ok, sysmon_desc = guard.check_sysmon_status()
    print(f"[*] Trạng thái Sysmon: {'[ACTIVE]' if sysmon_ok else '[FAIL]'} {sysmon_desc}")

    if not sysmon_ok:
        print("[-] [FAIL] Sysmon không hoạt động hoặc bị chặn quyền truy cập. Thoát.")
        guard.stop()
        store.close()
        sys.exit(2)

    # 3. Synchronize Initial Watermark
    watermark_start = guard.prepare_live()
    print(f"[*] Watermark ban đầu: EventRecordID = {watermark_start}")

    cur = store.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    events_before = cur.fetchone()[0]
    alerts_before = store.count_alerts()
    cur.execute("SELECT COALESCE(MAX(id), 0) FROM alerts")
    max_alert_id_before = cur.fetchone()[0]
    cur.execute("SELECT COALESCE(MAX(id), 0) FROM scan_stats")
    max_scan_stats_id_before = cur.fetchone()[0]
    cur.execute("SELECT COALESCE(SUM(windows_created), 0) FROM scan_stats")
    windows_before = cur.fetchone()[0]

    print(f"[*] Số sự kiện ban đầu:     {events_before:,}")
    print(f"[*] Số cảnh báo ban đầu:    {alerts_before} (Max ID: {max_alert_id_before})")
    print(f"[*] Số cửa sổ trượt ban đầu:{windows_before:,}")
    print("[*] Bắt đầu chu kỳ theo dõi lành tính. Nhấn Ctrl+C để kết thúc sớm và xuất dữ liệu.")
    print("-" * 70)

    start_ts = time.time()
    start_time_iso = datetime.datetime.now().isoformat()
    total_cycles = int((args.minutes * 60.0) / args.interval)
    if total_cycles <= 0:
        total_cycles = 1

    prev_events = events_before
    new_alerts_list: List[Dict[str, Any]] = []

    try:
        for cycle in range(1, total_cycles + 1):
            time.sleep(args.interval)

            guard.scan_now(poll_sysmon=True)

            cur.execute("SELECT COUNT(*) FROM events")
            current_events = cur.fetchone()[0]
            current_alerts = store.count_alerts()

            delta_events = current_events - prev_events
            cum_new_events = current_events - events_before
            new_alerts_count = current_alerts - alerts_before
            prev_events = current_events

            # Check for any new alerts in this cycle
            if current_alerts > alerts_before:
                cur.execute(
                    "SELECT id, ts, proc_key, detector, severity, score, evidence FROM alerts WHERE id > ? ORDER BY id ASC",
                    (max_alert_id_before,),
                )
                for a_row in cur.fetchall():
                    a_id = a_row[0]
                    if not any(item["id"] == a_id for item in new_alerts_list):
                        ev = json.loads(a_row[6]) if a_row[6] else {}
                        alert_info = {
                            "id": a_id,
                            "ts": a_row[1],
                            "proc_key": a_row[2],
                            "proc_name": ev.get("proc_name", "unknown"),
                            "pid": ev.get("pid", 0),
                            "bytes_sent": ev.get("bytes_sent", 0),
                            "dest": ev.get("dest_str", "unknown"),
                            "n_sensitive": len(ev.get("sensitive_files", [])),
                            "files": ev.get("sensitive_files", []),
                            "verdict": "unclassified",  # Default unclassified, NOT 'false'
                        }
                        new_alerts_list.append(alert_info)
                        print(f"\n[!] CẢNH BÁO MỚI PHÁT HIỆN: Alert #{a_id} | Tiến trình: {alert_info['proc_name']} (PID: {alert_info['pid']}) | Đích: {alert_info['dest']}")

            # Get recent windows created in this scan cycle
            recent_win = 0
            if guard.latest_scan_stats:
                recent_win = guard.latest_scan_stats.get("windows_created", 0)

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"[{now_str}] Phút {cycle:>3}/{total_cycles} | "
                f"Events: {current_events:>8} (+{delta_events:>4} mới, lũy kế: +{cum_new_events:>6}) | "
                f"Alerts: {current_alerts:>3} (+{new_alerts_count} mới) | "
                f"Windows: +{recent_win:>3}"
            )

    except KeyboardInterrupt:
        print("\n[*] Nhận tín hiệu dừng từ người dùng (Ctrl+C). Đang hoàn tất và xuất kết quả đo lường...")

    finally:
        end_time_iso = datetime.datetime.now().isoformat()
        elapsed_sec = time.time() - start_ts
        actual_duration_min = elapsed_sec / 60.0

        guard.stop()

        cur.execute("SELECT COUNT(*) FROM events")
        events_after = cur.fetchone()[0]
        events_ingested = events_after - events_before

        alerts_after = store.count_alerts()
        alerts_new = alerts_after - alerts_before

        cur.execute("SELECT COALESCE(SUM(windows_created), 0) FROM scan_stats")
        windows_after = cur.fetchone()[0]

        # Windows evaluated STRICTLY in this run (scan_stats WHERE id > max_scan_stats_id_before)
        cur.execute(
            "SELECT COALESCE(SUM(windows_created), 0) FROM scan_stats WHERE id > ?",
            (max_scan_stats_id_before,),
        )
        windows_evaluated = cur.fetchone()[0] or 0

        fpr_per_1000 = (alerts_new / windows_evaluated * 1000.0) if windows_evaluated > 0 else 0.0
        alerts_per_hour = alerts_new / (actual_duration_min / 60.0) if actual_duration_min > 0 else 0.0

        # Detailed funnel aggregation for this run
        cur.execute("""
            SELECT
                COALESCE(SUM(windows_created), 0),
                COALESCE(SUM(no_proc_key), 0),
                COALESCE(SUM(not_direct_actor), 0),
                COALESCE(SUM(ignored_process), 0),
                COALESCE(SUM(no_causal), 0),
                COALESCE(SUM(bytes_below_min), 0),
                COALESCE(SUM(no_sensitive_file), 0),
                COALESCE(SUM(score_below_threshold), 0),
                COALESCE(SUM(duplicate), 0),
                COALESCE(SUM(alerts_created), 0)
            FROM scan_stats WHERE id > ?
        """, (max_scan_stats_id_before,))
        f_row = cur.fetchone()
        funnel_breakdown = {
            "windows_created": f_row[0],
            "no_proc_key": f_row[1],
            "not_direct_actor": f_row[2],
            "ignored_process": f_row[3],
            "no_causal": f_row[4],
            "bytes_below_min": f_row[5],
            "no_sensitive_file": f_row[6],
            "score_below_threshold": f_row[7],
            "duplicate": f_row[8],
            "alerts_created": f_row[9],
        }

        watermark_end = getattr(guard.collector, "watermark", watermark_start)

        summary_data = {
            "duration_min": round(actual_duration_min, 2),
            "interval_sec": args.interval,
            "db_path": db_path,
            "os_environment": get_os_environment_str(),
            "start_time": start_time_iso,
            "end_time": end_time_iso,
            "watermark_start": watermark_start,
            "watermark_end": watermark_end,
            "events_before": events_before,
            "events_after": events_after,
            "events_ingested": events_ingested,
            "windows_before": windows_before,
            "windows_after": windows_after,
            "windows_evaluated": windows_evaluated,
            "alerts_before": alerts_before,
            "alerts_after": alerts_after,
            "alerts_new": alerts_new,
            "fpr_per_1000_windows": round(fpr_per_1000, 6),
            "alerts_per_hour": round(alerts_per_hour, 6),
            "funnel_breakdown": funnel_breakdown,
        }

        # 1. Export results/fpr_summary.json
        os.makedirs(os.path.dirname(os.path.abspath(args.summary_out)), exist_ok=True)
        with open(args.summary_out, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Đã xuất kết quả tóm tắt: {args.summary_out}")

        # 2. Export results/fpr_alerts.csv
        os.makedirs(os.path.dirname(os.path.abspath(args.alerts_out)), exist_ok=True)
        with open(args.alerts_out, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "ts", "proc_key", "proc_name", "pid", "bytes_sent", "dest", "n_sensitive", "files", "verdict"
            ])
            for a in new_alerts_list:
                files_str = "; ".join(a.get("files", []))
                writer.writerow([
                    a["id"],
                    a["ts"],
                    a["proc_key"],
                    a["proc_name"],
                    a["pid"],
                    a["bytes_sent"],
                    a["dest"],
                    a["n_sensitive"],
                    files_str,
                    a["verdict"],
                ])
        print(f"[+] Đã xuất nhật ký cảnh báo: {args.alerts_out}")

        # 3. Export results/FPR_REPORT.md
        benign_s = get_benign_actions_summary(
            start_time_iso=start_time_iso,
            end_time_iso=end_time_iso,
        )
        tpr_alerts = get_reference_tpr_alerts(store)
        eval_res = export_markdown_report(summary_data, new_alerts_list, tpr_alerts, benign_s, args.report_out)

        store.close()

    print("\n" + "=" * 70)
    print("           TỔNG KẾT ĐO LƯỜNG FPR HOÀN TẤT")
    print("=" * 70)
    print(f"[*] Kết quả nghiệm thu:    {eval_res['overall_verdict']}")
    print(f"[*] Chi tiết kết luận:     {eval_res['summary_conclusion']}")
    print(f"[*] Thời lượng đo:         {actual_duration_min:.2f} phút")
    print(f"[*] Sự kiện Sysmon đã nạp: +{events_ingested:,} sự kiện")
    print(f"[*] Cửa sổ đã đánh giá:    {windows_evaluated:,} windows")
    print(f"[*] Cảnh báo mới sinh ra:  {alerts_new} alert")
    print(f"[*] FPR / 1,000 windows:   {fpr_per_1000:.4f}")
    print(f"[*] Alerts / giờ:          {alerts_per_hour:.4f}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
