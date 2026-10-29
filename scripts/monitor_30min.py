"""30-Minute elevated monitoring script for PrivacyGuard real-time Sysmon verification.

Runs real-time surveillance for 30 minutes, polling Sysmon every 60 seconds.
Verifies that:
1. Event count increases continuously (> 0 new events ingested from host Sysmon).
2. Alert count remains constant (+0 false alarms on idle system).
"""

from __future__ import annotations

import ctypes
import os
import sys
import time

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.guard_service import RealtimeGuardService
from core.store import EventStore


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    print("\n" + "=" * 70)
    print("      PRIVACYGUARD 30-MINUTE ELEVATED SYSMON SURVEILLANCE")
    print("=" * 70)

    if not is_admin():
        print("[-] [FAIL] Cần chạy PowerShell với quyền Administrator. Thoát.")
        sys.exit(2)

    db_path = os.path.join(PROJECT_ROOT, "data", "privacyguard.db")
    print(f"[*] Cơ sở dữ liệu:     {db_path}")

    guard = RealtimeGuardService(db_path=db_path, poll_sysmon=True, enable_toast=False)
    sysmon_ok, sysmon_desc = guard.check_sysmon_status()
    print(f"[*] Trạng thái Sysmon: {'[ACTIVE]' if sysmon_ok else '[FAIL]'} {sysmon_desc}")

    if not sysmon_ok:
        print("[-] [FAIL] Sysmon không hoạt động hoặc bị chặn quyền truy cập. Thoát.")
        guard.stop()
        sys.exit(2)

    watermark_init = guard.prepare_live()
    print(f"[*] Watermark ban đầu: EventRecordID = {watermark_init}")

    store = EventStore(db_path=db_path)
    cur = store.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    initial_events = cur.fetchone()[0]
    initial_alerts = store.count_alerts()
    prev_events = initial_events

    print(f"[*] Số sự kiện ban đầu:  {initial_events}")
    print(f"[*] Số cảnh báo ban đầu: {initial_alerts}")
    print("[*] Bắt đầu chu kỳ theo dõi 30 phút (ghi nhận mỗi 60 giây)...")
    print("-" * 70)

    total_minutes = 30
    try:
        for minute in range(1, total_minutes + 1):
            t_start = time.time()
            time.sleep(60.0)

            guard.scan_now(poll_sysmon=True)

            cur.execute("SELECT COUNT(*) FROM events")
            current_events = cur.fetchone()[0]
            current_alerts = store.count_alerts()

            delta_events = current_events - prev_events
            cum_new_events = current_events - initial_events
            new_alerts = current_alerts - initial_alerts
            prev_events = current_events

            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"[{now_str}] Phút {minute:>2}/{total_minutes} | "
                f"Events: {current_events:>8} (+{delta_events:>4} mới, lũy kế: +{cum_new_events:>5}) | "
                f"Alerts: {current_alerts:>4} (+{new_alerts} cảnh báo)"
            )

        print("-" * 70)
        total_ingested = prev_events - initial_events
        total_new_alerts = store.count_alerts() - initial_alerts

        print("[*] TỔNG KẾT THEO DÕI 30 PHÚT ELEVATED:")
        print(f"    - Tổng sự kiện Sysmon đã nạp: +{total_ingested} sự kiện")
        print(f"    - Tổng cảnh báo mới sinh ra:  +{total_new_alerts} cảnh báo")

        if total_ingested > 0 and total_new_alerts == 0:
            print("[+] KẾT QUẢ: ĐẠT TIÊU CHUẨN NGHIỆM THU E (Sysmon đọc thật liên tục, không bão cảnh báo).")
        else:
            print("[-] KẾT QUẢ: Chưa đạt yêu cầu nghiệm thu E.")

    finally:
        guard.stop()
        store.close()
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
