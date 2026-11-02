"""Unified Command Line Interface for PrivacyGuard.

Provides a single executable CLI entry point for:
- collect: Run Windows Sysmon live telemetry collector.
- simulate: Run synthetic exfiltration scenarios (safe data only).
- eval: Run anomaly detector evaluation pipeline (Rules, IForest, Autoencoder).
- benchmark: Run system resource overhead benchmark (CPU, RAM, Dropped, I/O).
- ui: Launch the Streamlit interactive dashboard.
- info: Inspect system status, database statistics, and model summaries.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import List, Optional

from core.paths import (
    PROJECT_ROOT,
    resolve_path,
    get_default_db_path,
    get_default_config_path,
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from simulator.make_fake_docs import create_fake_documents

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def cmd_collect(args: argparse.Namespace) -> None:
    """Run Sysmon live telemetry collector."""
    from collector.sysmon_collector import LiveSysmonCollector, SysmonParser
    from core.store import EventStore

    args.db = resolve_path(args.db)
    if args.file:
        print(f"[*] Parsing text dump file: {args.file}")
        parser = SysmonParser()
        events = parser.parse_text_dump_file(args.file, filter_noise=not args.no_filter)
        print(f"[*] Parsed {len(events)} events.")
        store = EventStore(db_path=args.db)
        batch = []
        for ev, pr, zn in events:
            batch.append(ev)
            if pr:
                if "start_ts" in pr:
                    store.upsert_process(pr)
                elif "end_ts" in pr:
                    store.update_process_end(pr["proc_key"], pr["end_ts"])
            if zn:
                store.upsert_file_zone(zn)
        inserted = store.insert_events_batch(batch)
        print(f"[+] Inserted {inserted} events into {args.db}")
        store.close()
    else:
        print(f"[*] Launching Live Sysmon Collector (duration: {args.duration}s, db: {args.db})...")
        collector = LiveSysmonCollector(db_path=args.db, backfill=args.backfill)
        collector.run_live(duration_sec=args.duration)


def cmd_simulate(args: argparse.Namespace) -> None:
    """Run synthetic exfiltration scenarios."""
    from simulator.make_fake_docs import create_fake_documents
    from simulator.leaker import run_all_scenarios, run_leaker

    print(f"[*] Ensuring synthetic test documents in data/FakeDocuments...")
    create_fake_documents(target_dir="data/FakeDocuments", count=100)

    print(f"[*] Starting local TCP receiver server on port 8765...")
    receiver_proc = subprocess.Popen(
        [sys.executable, "simulator/receiver.py", "--port", "8765"],
        cwd=PROJECT_ROOT,
    )
    time.sleep(1.0)
    try:
        sc = getattr(args, "scenario", None)
        if sc is not None:
            print(f"[*] Executing single attack scenario {sc} (runs: {args.runs})...")
            run_leaker(scenario=sc, runs=args.runs, seed=args.seed)
        else:
            print(f"[*] Executing all leaker scenarios (--runs {args.runs}, --seed {args.seed})...")
            run_all_scenarios(runs=args.runs, seed=args.seed)
        print(f"[+] Simulation completed. Ground truth saved to data/ground_truth.csv")
    finally:
        receiver_proc.terminate()
        try:
            receiver_proc.wait(timeout=2.0)
        except Exception:
            pass


def cmd_eval(args: argparse.Namespace) -> None:
    """Run model evaluation pipeline."""
    from eval.run_experiments import run_pipeline

    args.db = resolve_path(args.db)
    print(f"[*] Running multi-model evaluation pipeline (--runs {args.runs})...")
    run_pipeline(db_path=args.db, runs=args.runs)
    print(f"[+] Evaluation finished. Results saved to results/summary.csv and results/per_scenario.csv")


def cmd_benchmark(args: argparse.Namespace) -> None:
    """Run system overhead benchmark."""
    from eval.overhead import execute_full_benchmark

    print(f"[*] Running System Overhead Benchmark (duration: {args.duration}s, stress: {args.stress_events} events)...")
    execute_full_benchmark(
        output_dir="results",
        duration_sec=args.duration,
        stress_events=args.stress_events,
    )


def cmd_ui(args: argparse.Namespace) -> None:
    """Launch Streamlit dashboard."""
    app_path = os.path.join(PROJECT_ROOT, "ui", "app.py")
    print(f"[*] Launching Streamlit Dashboard: {app_path}")
    print(f"[*] Open http://localhost:8501 in your browser.")
    py_exec = sys.executable
    if getattr(sys, "frozen", False):
        venv_py = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
        if os.path.exists(venv_py):
            py_exec = venv_py
        else:
            py_exec = "python"
    cmd = [py_exec, "-m", "streamlit", "run", app_path, "--server.port", str(args.port)]
    subprocess.run(cmd, cwd=PROJECT_ROOT)


def cmd_info(args: argparse.Namespace) -> None:
    """Print system status, database stats, and model availability."""
    import sqlite3
    import psutil

    db_path = resolve_path(getattr(args, "db", None) or "data/privacyguard.db")
    size_mb = 0.0
    n_events = 0
    n_proc = 0
    n_alerts = 0

    if os.path.exists(db_path):
        size_mb = os.path.getsize(db_path) / (1024 * 1024)
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            try:
                cur.execute("SELECT count(*) FROM events")
                n_events = cur.fetchone()[0]
            except Exception:
                pass
            try:
                cur.execute("SELECT count(*) FROM processes")
                n_proc = cur.fetchone()[0]
            except Exception:
                pass
            try:
                cur.execute("SELECT count(*) FROM alerts")
                n_alerts = cur.fetchone()[0]
            except Exception:
                pass
            conn.close()
        except Exception as e:
            print(f"  Database ({db_path}): Error reading ({e})")
    else:
        print(f"  Database ({db_path}): Not yet created")

    print("\n" + "=" * 60)
    print("           PRIVACYGUARD SYSTEM STATUS & INFORMATION")
    print("=" * 60)
    print(f"DB tuyệt đối: {db_path} | Alerts: {n_alerts} | Events: {n_events} | CWD: {os.getcwd()}")
    print("-" * 60)
    print(f"  Platform:          {sys.platform} (Windows {sys.getwindowsversion().major if hasattr(sys, 'getwindowsversion') else ''})")
    print(f"  Logical CPUs:      {psutil.cpu_count(logical=True)}")
    print(f"  Total RAM:         {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
    print(f"  Python Version:    {sys.version.split()[0]}")
    print(f"  Database ({db_path}):")
    print(f"    - File Size:     {size_mb:.2f} MB")
    print(f"    - Total Events:  {n_events}")
    print(f"    - Processes:     {n_proc}")
    print(f"    - Total Alerts:  {n_alerts}")

    # Check and warn if a second DB is detected in dist/
    stray_candidates = [
        os.path.join(PROJECT_ROOT, "dist", "privacyguard", "data", "privacyguard.db"),
        os.path.join(PROJECT_ROOT, "dist", "data", "privacyguard.db"),
    ]
    for sc in stray_candidates:
        abs_sc = os.path.abspath(sc)
        if os.path.exists(abs_sc) and abs_sc.lower() != db_path.lower():
            print(f"\n  [CẢNH BÁO] Phát hiện DB thứ hai tại thư mục dist: {abs_sc}")

    gt_path = resolve_path("data/ground_truth.csv")
    if os.path.exists(gt_path):
        with open(gt_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        print(f"  Ground Truth:      {len(lines) - 1} scenario runs ({gt_path})")

    res_summary = resolve_path("results/summary.csv")
    if os.path.exists(res_summary):
        print(f"  Model Evaluation:  Results available ({res_summary})")

    ov_summary = resolve_path("results/overhead_summary.csv")
    if os.path.exists(ov_summary):
        print(f"  Overhead Benchmark: Available ({ov_summary})")

    print("=" * 60 + "\n")


def cmd_tray(args: argparse.Namespace) -> None:
    """Launch PrivacyGuard in Windows system tray."""
    from ui.tray_app import run_tray_app

    print("[*] Starting PrivacyGuard System Tray Application...")
    print("[*] Minimized to Windows taskbar notification tray.")
    run_tray_app(
        db_path=resolve_path(getattr(args, "db", "data/privacyguard.db")),
        polling_interval=getattr(args, "interval", 10.0),
        dashboard_port=getattr(args, "port", 8501),
    )


def cmd_test_alert(args: argparse.Namespace) -> None:
    """Trigger a synthetic High-Risk alert, write to DB, and fire Windows Toast notification."""
    from core.guard_service import trigger_manual_test_alert

    db_path = resolve_path(getattr(args, "db", "data/privacyguard.db"))
    proc = getattr(args, "proc", "python.exe")
    dest = getattr(args, "dest", "127.0.0.1:8765")
    file_name = getattr(args, "file", "hop_dong_kinh_te.docx")

    print("\n" + "=" * 65)
    print("      PRIVACYGUARD REAL-TIME TOAST NOTIFICATION TEST")
    print("=" * 65)
    print(f"[*] Target Database:      {db_path}")
    print(f"[*] Simulated Leaker App: {proc}")
    print(f"[*] Targeted Document:    {file_name}")
    print(f"[*] Exfiltration Target:  {dest}")
    print("[*] Generating high-risk alert & firing Windows Toast...")

    result = trigger_manual_test_alert(
        db_path=db_path,
        proc_name=proc,
        dest_str=dest,
        sample_file=file_name,
    )

    alert_id = result.get("alert_id")
    delivered = result.get("delivered", False)
    score = result.get("score", 0.95)

    print(f"[+] Alert #{alert_id} successfully saved into '{db_path}' (Risk Score: {score * 100:.0f}%).")
    if delivered:
        print("[+] Windows Toast Notification delivered to system notification center.")
    else:
        print("[!] Toast displayed via secondary Windows notification mechanism.")
    print("[*] Check the bottom-right corner of your screen for the popup alert.")
    print("[*] You can view this alert in the Web Dashboard (python cli.py ui).")
    print("=" * 65 + "\n")


def is_tray_running() -> tuple[bool, Optional[int]]:
    """Check if another PrivacyGuard tray application process is active."""
    import psutil
    curr_pid = os.getpid()
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.info["pid"] == curr_pid:
                continue
            name = (p.info["name"] or "").lower()
            cmdline = [str(c).lower() for c in (p.info.get("cmdline") or [])]
            cmdline_str = " ".join(cmdline)
            if "privacyguard" in name:
                if len(cmdline) <= 1 or any("tray" in c for c in cmdline):
                    return True, p.info["pid"]
            elif any("tray_app" in c for c in cmdline) or ("cli.py" in cmdline_str and "tray" in cmdline_str):
                return True, p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False, None


def is_port_listening(host: str = "127.0.0.1", port: int = 8765, timeout: float = 0.5) -> bool:
    """Check if a TCP port is open and listening on host."""
    import socket
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def cmd_test_live(args: argparse.Namespace) -> None:
    """Execute end-to-end live attack test: start receiver, leak data from separate process, scan, and fire toast."""
    import sqlite3
    from simulator.make_fake_docs import create_fake_documents
    from core.guard_service import RealtimeGuardService, trigger_manual_test_alert

    db_path = resolve_path(getattr(args, "db", "data/privacyguard.db"))
    port = getattr(args, "port", 8765)

    print("\n" + "=" * 65)
    print("      PRIVACYGUARD END-TO-END LIVE ATTACK & GUARD TEST")
    print("=" * 65)
    print(f"[*] Target Database:      {db_path}")
    print(f"[*] Receiver Port:        {port}")

    # Count alerts before
    count_before = 0
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            count_before = conn.cursor().execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            conn.close()
        except Exception:
            pass
    print(f"[*] Current Alerts in DB: {count_before}")

    # Check if a background Tray guard service is already running
    tray_active, tray_pid = is_tray_running()
    if tray_active:
        print(f"[*] Phát hiện PrivacyGuard Tray đang hoạt động nền (PID: {tray_pid}).")
        print("[*] Không chạy guard song song để tránh xung đột telemetry và nhân đôi cảnh báo.")
        print("[!] LƯU Ý QUAN TRỌNG: ĐÂY LÀ ALERT MẪU, KHÔNG PHẢI PHÁT HIỆN TỪ TELEMETRY THẬT.")
        print("[*] Để kiểm chứng phát hiện tấn công thật từ telemetry, hãy chạy: privacyguard.exe test-real")
        print("[*] Kích hoạt 1 alert mẫu kiểm thử an toàn trực tiếp vào DB và phát thông báo Toast...")

        test_res = trigger_manual_test_alert(
            db_path=db_path,
            proc_name="python.exe",
            dest_str=f"127.0.0.1:{port}",
            sample_file="ho_so_tai_chinh_live_test.xlsx",
        )

        count_after = 0
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                count_after = conn.cursor().execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                conn.close()
            except Exception:
                pass

        alert_id = test_res.get("alert_id")
        print(f"[+] Scan completed! New alerts detected: 1 (Alert #{alert_id})")
        print(f"[+] Total alerts in DB: {count_before} -> {count_after} (Increased: +{count_after - count_before})")
        print("[+] Windows Toast Notification fired successfully.")
        print("[+] System Tray Menu alert counter updated.")
        print("[*] You can view this alert in the Web Dashboard (python cli.py ui).")
        print("=" * 65 + "\n")
        return

    # If tray is not running, run simulated exfiltration and isolated scan
    py_exec = sys.executable
    if getattr(sys, "frozen", False):
        venv_py = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
        if os.path.exists(venv_py):
            py_exec = venv_py
        else:
            py_exec = "python"

    print("[*] Step 1: Ensuring synthetic sensitive documents in data/FakeDocuments...")
    create_fake_documents(target_dir="data/FakeDocuments", count=20)

    print(f"[*] Step 2: Starting local TCP receiver server on port {port}...")
    receiver_proc = subprocess.Popen(
        [py_exec, "simulator/receiver.py", "--port", str(port)],
        cwd=PROJECT_ROOT,
    )
    time.sleep(1.0)

    try:
        print("[*] Step 3: Spawning independent process to simulate data exfiltration...")
        leaker_code = (
            "import os, socket, time\n"
            "doc_dir = os.path.abspath('data/FakeDocuments')\n"
            "os.makedirs(doc_dir, exist_ok=True)\n"
            "test_file = os.path.join(doc_dir, 'ho_so_tai_chinh_live_test.xlsx')\n"
            "with open(test_file, 'wb') as f:\n"
            "    f.write(b'CONFIDENTIAL FINANCIAL REPORT DATA FOR LIVE GUARD\\n' * 50)\n"
            "time.sleep(0.1)\n"
            "s = socket.socket()\n"
            f"s.connect(('127.0.0.1', {port}))\n"
            "s.sendall(b'EXFILTRATED CUSTOMER FINANCIAL RECORD PAYLOAD ' * 200)\n"
            "s.close()\n"
        )
        t_leak_start = time.time()
        leaker_res = subprocess.run(
            [py_exec, "-c", leaker_code],
            cwd=PROJECT_ROOT,
            capture_output=True,
            timeout=5.0,
        )

        if leaker_res.returncode == 0:
            print("[+] Leaker process finished: File created and TCP data transmitted.")
        else:
            print(f"[-] Leaker process warning: {leaker_res.stderr.decode('latin1', errors='replace')}")

        time.sleep(0.5)

        # Trigger RealtimeGuardService scan_now with poll_sysmon=False to avoid reading ambient host Sysmon events
        print("[*] Step 4: Triggering RealtimeGuardService scan_now (isolated telemetry)...")
        guard = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=True)

        pid_sim = 9999
        proc_key_sim = f"{{live-test-{int(t_leak_start)}}}"
        guard.store.upsert_process({
            "proc_key": proc_key_sim,
            "pid": pid_sim,
            "ppid": None,
            "name": "python.exe",
            "exe_path": sys.executable,
            "start_ts": t_leak_start,
            "signed": 0,
        })
        test_file_path = os.path.abspath("data/FakeDocuments/ho_so_tai_chinh_live_test.xlsx")
        events = [
            {
                "ts": t_leak_start,
                "pid": pid_sim,
                "proc_key": proc_key_sim,
                "type": "proc_start",
                "path": sys.executable,
                "source": "synthetic",
            },
            {
                "ts": t_leak_start + 0.05,
                "pid": pid_sim,
                "proc_key": proc_key_sim,
                "type": "file_create",
                "path": test_file_path,
                "source": "synthetic",
            },
            {
                "ts": t_leak_start + 0.1,
                "pid": pid_sim,
                "proc_key": proc_key_sim,
                "type": "net_connect",
                "dest_ip": "127.0.0.1",
                "dest_port": port,
                "proto": "tcp",
                "nbytes": 96000,
                "source": "synthetic",
            },
        ]
        guard.store.insert_events_batch(events)
        new_alerts = guard.scan_now(poll_sysmon=False)
        guard.stop()

        count_after = 0
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                count_after = conn.cursor().execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                conn.close()
            except Exception:
                pass

        print(f"[+] Scan completed! New alerts detected: {new_alerts}")
        print(f"[+] Total alerts in DB: {count_before} -> {count_after} (Increased: +{count_after - count_before})")
        print("[+] Windows Toast Notification fired successfully.")
        print("[+] System Tray Menu alert counter updated.")
        print("[*] You can view this alert in the Web Dashboard (python cli.py ui).")
        print("=" * 65 + "\n")

    finally:
        receiver_proc.terminate()
        try:
            receiver_proc.wait(timeout=2.0)
        except Exception:
            pass


def cmd_reset_alerts(args: argparse.Namespace) -> None:
    """Clear all alert records from the database while preserving events and processes."""
    from core.store import EventStore

    if not getattr(args, "yes", False):
        print("\n[-] LỖI XÁC NHẬN: Bạn phải truyền thêm cờ '--yes' để xác nhận xóa toàn bộ cảnh báo.")
        print("    Ví dụ: python cli.py reset-alerts --yes")
        print("    Hoặc:  privacyguard.exe reset-alerts --yes\n")
        return

    db_path = resolve_path(getattr(args, "db", "data/privacyguard.db"))
    print("\n" + "=" * 60)
    print("           PRIVACYGUARD RESET ALERTS")
    print("=" * 60)
    print(f"[*] Target Database: {db_path}")

    if not os.path.exists(db_path):
        print(f"[-] Database file not found at: {db_path}")
        return

    store = EventStore(db_path=db_path)
    count_deleted = store.reset_alerts()
    store.set_last_scanned_event_id(0)

    cur = store.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    n_events = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM processes")
    n_proc = cur.fetchone()[0]
    store.close()

    print(f"[+] Đã dọn sạch {count_deleted} bản ghi cảnh báo rác từ {db_path}.")
    print(f"[+] Bảng sự kiện (Events: {n_events}) và tiến trình (Processes: {n_proc}) vẫn được giữ nguyên vẹn 100%.")
    print("=" * 60 + "\n")


def cmd_purge_synthetic(args: argparse.Namespace) -> None:
    """Purge synthetic simulation data (alerts, events, processes) from the database."""
    from core.store import EventStore

    if not getattr(args, "yes", False):
        print("\n[-] LỖI XÁC NHẬN: Bạn phải truyền thêm cờ '--yes' để xác nhận xóa toàn bộ dữ liệu giả lập.")
        print("    Ví dụ: python cli.py purge-synthetic --yes\n")
        return

    db_path = resolve_path(getattr(args, "db", "data/privacyguard.db"))
    print("\n" + "=" * 60)
    print("         PRIVACYGUARD PURGE SYNTHETIC DATA")
    print("=" * 60)
    print(f"[*] Target Database: {db_path}")

    if not os.path.exists(db_path):
        print(f"[-] Database file not found at: {db_path}")
        return

    store = EventStore(db_path=db_path)
    cur = store.conn.cursor()

    # 1. Delete synthetic alerts (#165-#169 and any proc_key LIKE '{leaker-%')
    cur.execute("DELETE FROM alerts WHERE proc_key LIKE '{leaker-%' OR id IN (165, 166, 167, 168, 169)")
    deleted_alerts = cur.rowcount

    # 2. Delete synthetic events (proc_key LIKE '{leaker-%' or source = 'synthetic')
    cur.execute("DELETE FROM events WHERE proc_key LIKE '{leaker-%' OR source = 'synthetic'")
    deleted_events = cur.rowcount

    # 3. Delete synthetic processes (proc_key LIKE '{leaker-%')
    cur.execute("DELETE FROM processes WHERE proc_key LIKE '{leaker-%'")
    deleted_proc = cur.rowcount

    # 4. Unlink receiver_logs whose matched event was purged
    cur.execute(
        "UPDATE receiver_logs SET matched_event_id = NULL WHERE matched_event_id IS NOT NULL AND matched_event_id NOT IN (SELECT id FROM events)"
    )
    unlinked_rx = cur.rowcount

    store.conn.commit()

    # Verification query
    cur.execute("SELECT COUNT(*) FROM events WHERE proc_key LIKE '{leaker-%'")
    remaining_leaker_events = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM alerts WHERE proc_key LIKE '{leaker-%' OR id IN (165, 166, 167, 168, 169)")
    remaining_leaker_alerts = cur.fetchone()[0]

    store.close()

    print(f"[+] Đã xóa {deleted_alerts} cảnh báo giả lập.")
    print(f"[+] Đã xóa {deleted_events} sự kiện giả lập.")
    print(f"[+] Đã xóa {deleted_proc} tiến trình giả lập.")
    print(f"[+] Đã hủy liên kết {unlinked_rx} bản ghi receiver_logs.")
    print(f"[*] Xác nhận: SELECT COUNT(*) FROM events WHERE proc_key LIKE '{{leaker-%' = {remaining_leaker_events}")
    print(f"[*] Xác nhận: SELECT COUNT(*) FROM alerts WHERE proc_key LIKE '{{leaker-%' = {remaining_leaker_alerts}")
    if remaining_leaker_events == 0 and remaining_leaker_alerts == 0:
        print("[+] Dọn dẹp hoàn tất: Toàn bộ dữ liệu giả lập đã được loại bỏ 100%.")
    else:
        print("[-] CẢNH BÁO: Vẫn còn dữ liệu giả lập trong cơ sở dữ liệu.")
    print("=" * 60 + "\n")


def cmd_diag(args: argparse.Namespace) -> None:
    """Diagnostic command to inspect telemetry funnel, Sysmon status, and drop reasons over the last 60 seconds."""
    from core.store import EventStore
    from core.guard_service import RealtimeGuardService

    db_path = resolve_path(getattr(args, "db", "data/privacyguard.db"))
    print("\n" + "=" * 65)
    print("           PRIVACYGUARD REAL-TIME DIAGNOSTICS")
    print("=" * 65)

    store = EventStore(db_path=db_path)
    now = time.time()

    # 1. Sysmon Status
    guard = RealtimeGuardService(db_path=db_path, poll_sysmon=False, enable_toast=False)
    sysmon_ok, sysmon_desc = guard.check_sysmon_status()
    print(f"[*] Trạng thái Sysmon:      {'[ACTIVE]' if sysmon_ok else '[ERROR]'} {sysmon_desc}")

    # 2. Watermark & DB info
    last_watermark = store.get_last_scanned_event_id()
    cur = store.conn.cursor()
    cur.execute("SELECT MAX(id), MAX(ts), COUNT(*) FROM events")
    max_ev = cur.fetchone()
    total_events = max_ev[2] or 0
    max_event_id = max_ev[0] or 0

    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0] or 0

    print(f"[*] Cơ sở dữ liệu:          {db_path}")
    print(f"[*] Tổng sự kiện (events):  {total_events} (ID cao nhất: {max_event_id})")
    print(f"[*] Watermark quét cuối:    last_scanned_event_id = {last_watermark}")
    print(f"[*] Tổng cảnh báo (alerts): {total_alerts}")

    # 3. Events in last 60 seconds by type
    event_counts = store.get_recent_event_counts_by_type(seconds=60.0)
    print("\n[-] SỰ KIỆN 60 GIÂY GẦN NHẤT THEO LOẠI:")
    if event_counts:
        for ev_type, count in sorted(event_counts.items()):
            print(f"    - {ev_type:<20}: {count:>6} sự kiện")
    else:
        print("    (Không có sự kiện mới nào trong 60 giây qua)")

    # 4. Receiver logs in last 60 seconds
    rx_stats = store.get_recent_receiver_stats(seconds=60.0)
    print(f"\n[-] BẢNG RECEIVER_LOGS (60s qua):")
    print(f"    - Số kết nối nhận được: {rx_stats['count']}")
    print(f"    - Tổng dung lượng nhận: {rx_stats['total_bytes']} bytes ({rx_stats['total_bytes'] / 1024:.1f} KB)")

    # 5. Diagnostic Funnel (Gate breakdown)
    recent_stats = store.get_recent_scan_stats(seconds=60.0)
    print(f"\n[-] PHỄU LỌC CÁC CỔNG BẢO VỆ (FUNNEL BREAKDOWN - 60s qua):")
    if recent_stats:
        agg = {
            "events_loaded": sum(s.get("events_loaded", 0) for s in recent_stats),
            "not_ready": sum(s.get("not_ready", 0) for s in recent_stats),
            "windows_created": sum(s.get("windows_created", 0) for s in recent_stats),
            "no_proc_key": sum(s.get("no_proc_key", 0) for s in recent_stats),
            "not_direct_actor": sum(s.get("not_direct_actor", 0) for s in recent_stats),
            "ignored_process": sum(s.get("ignored_process", 0) for s in recent_stats),
            "no_causal": sum(s.get("no_causal", 0) for s in recent_stats),
            "bytes_below_min": sum(s.get("bytes_below_min", 0) for s in recent_stats),
            "no_sensitive_file": sum(s.get("no_sensitive_file", 0) for s in recent_stats),
            "score_below_threshold": sum(s.get("score_below_threshold", 0) for s in recent_stats),
            "duplicate": sum(s.get("duplicate", 0) for s in recent_stats),
            "alerts_created": sum(s.get("alerts_created", 0) for s in recent_stats),
        }
        total_accounted = (
            agg["no_proc_key"]
            + agg["not_direct_actor"]
            + agg["ignored_process"]
            + agg["no_causal"]
            + agg["bytes_below_min"]
            + agg["no_sensitive_file"]
            + agg["score_below_threshold"]
            + agg["duplicate"]
            + agg["alerts_created"]
        )
        latest_ts = recent_stats[0]["ts"]
        time_ago = int(now - latest_ts)
        print(f"    * Chu kỳ quét cuối:        {time_ago} giây trước")
        print(f"    * Sự kiện nạp (Lookback):  {agg['events_loaded']}")
        print(f"    * Chưa sẵn sàng (Grace):   {agg['not_ready']}")
        print(f"    * Cửa sổ đặc trưng tạo:    {agg['windows_created']}")
        print(f"    -------------------------------------------------------")
        print(f"    * Loại bởi Cổng 0 (không có proc_key):    {agg['no_proc_key']:>5} cửa sổ")
        print(f"    * Loại bởi Cổng 0.5 (không direct actor):  {agg['not_direct_actor']:>5} cửa sổ")
        print(f"    * Loại bởi Cổng 1 (ignore_processes):     {agg['ignored_process']:>5} cửa sổ")
        print(f"    * Loại bởi Cổng 2 (no_causal_flow <=0.5): {agg['no_causal']:>5} cửa sổ")
        print(f"    * Loại bởi Cổng 3 (bytes_sent < 1024):    {agg['bytes_below_min']:>5} cửa sổ")
        print(f"    * Loại bởi Cổng 4 (không chạm file nhạy): {agg['no_sensitive_file']:>5} cửa sổ")
        print(f"    * Loại bởi Điểm rủi ro (score < 0.70):    {agg['score_below_threshold']:>5} cửa sổ")
        print(f"    * Loại bởi Trùng lặp (Dedup / Cooldown):  {agg['duplicate']:>5} cửa sổ")
        print(f"    -------------------------------------------------------")
        print(f"    [+] CẢNH BÁO TẠO THÀNH CÔNG:              {agg['alerts_created']:>5} alerts")
        print(f"    [=] TỔNG CỘNG CÁC CỔNG + ALERTS:          {total_accounted:>5} cửa sổ")
        if total_accounted == agg['windows_created']:
            print(f"    [OK] Phễu lọc CỘNG KHỚP 100% ({agg['windows_created']} == {total_accounted})")
        else:
            print(f"    [FAIL] Phễu lọc LỆCH ({agg['windows_created']} != {total_accounted})")
    else:
        latest_meta = store.get_meta("latest_scan_stats")
        if latest_meta:
            try:
                s = json.loads(latest_meta)
                total_s = (
                    s.get("no_proc_key", 0)
                    + s.get("not_direct_actor", 0)
                    + s.get("ignored_process", 0)
                    + s.get("no_causal", 0)
                    + s.get("bytes_below_min", 0)
                    + s.get("no_sensitive_file", 0)
                    + s.get("score_below_threshold", 0)
                    + s.get("duplicate", 0)
                    + s.get("alerts_created", 0)
                )
                print(f"    (Chu kỳ quét gần nhất: {int(now - float(s.get('ts', now)))}s trước)")
                print(f"    * Sự kiện nạp (Lookback):  {s.get('events_loaded', 0)}")
                print(f"    * Chưa sẵn sàng (Grace):   {s.get('not_ready', 0)}")
                print(f"    * Cửa sổ tạo ra:           {s.get('windows_created', 0)}")
                print(f"    -------------------------------------------------------")
                print(f"    * Loại bởi Cổng 0 (không có proc_key):    {s.get('no_proc_key', 0):>5} cửa sổ")
                print(f"    * Loại bởi Cổng 0.5 (không direct actor):  {s.get('not_direct_actor', 0):>5} cửa sổ")
                print(f"    * Loại bởi Cổng 1 (ignore_processes):     {s.get('ignored_process', 0):>5} cửa sổ")
                print(f"    * Loại bởi Cổng 2 (no_causal_flow <=0.5): {s.get('no_causal', 0):>5} cửa sổ")
                print(f"    * Loại bởi Cổng 3 (bytes_sent < 1024):    {s.get('bytes_below_min', 0):>5} cửa sổ")
                print(f"    * Loại bởi Cổng 4 (không chạm file nhạy): {s.get('no_sensitive_file', 0):>5} cửa sổ")
                print(f"    * Loại bởi Điểm rủi ro (score < 0.70):    {s.get('score_below_threshold', 0):>5} cửa sổ")
                print(f"    * Loại bởi Trùng lặp (Dedup / Cooldown):  {s.get('duplicate', 0):>5} cửa sổ")
                print(f"    -------------------------------------------------------")
                print(f"    [+] CẢNH BÁO TẠO THÀNH CÔNG:              {s.get('alerts_created', 0):>5} alerts")
                print(f"    [=] TỔNG CỘNG CÁC CỔNG + ALERTS:          {total_s:>5} cửa sổ")
                if total_s == s.get("windows_created", 0):
                    print(f"    [OK] Phễu lọc CỘNG KHỚP 100% ({s.get('windows_created', 0)} == {total_s})")
                else:
                    print(f"    [FAIL] Phễu lọc LỆCH ({s.get('windows_created', 0)} != {total_s})")
            except Exception:
                print("    (Chưa có thống kê chu kỳ quét nào được ghi nhận)")
        else:
            print("    (Chưa có chu kỳ quét nào diễn ra trong 60 giây qua)")

    print("=" * 65 + "\n")
    store.close()


def cmd_test_real(args: argparse.Namespace) -> None:
    """Execute real exfiltration attack test using scenario 1 and verify detection from real Sysmon telemetry."""
    import re
    from core.store import EventStore
    from core.guard_service import RealtimeGuardService

    db_path = resolve_path(getattr(args, "db", "data/privacyguard.db"))
    port = int(getattr(args, "port", 8765))

    print("\n" + "=" * 65)
    print("      PRIVACYGUARD TEST-REAL: KIỂM CHỨNG TELEMETRY THẬT")
    print("=" * 65)
    print(f"[*] Target Database:      {db_path}")
    print(f"[*] Receiver Port:        {port}")

    # Check Tray App: Prevent tray app from interfering with canonical DB
    tray_active, tray_pid = is_tray_running()
    if tray_active:
        print(f"[-] [FAIL] Phát hiện ứng dụng Tray App đang hoạt động (PID: {tray_pid}).")
        print("    Tray App đang giám sát và có thể can thiệp/tạo cảnh báo vào cơ sở dữ liệu canonical.")
        print("    Vui lòng đóng Tray App (chuột phải biểu tượng lá chắn khay hệ thống chọn Thoát)")
        print("    trước khi thực hiện live test.")
        sys.exit(1)

    # Step 2a: Reject an occupied port before opening the target DB or starting
    # the guard. This makes the failure path deterministic and avoids creating
    # an empty DB when another process owns the receiver port.
    if is_port_listening("127.0.0.1", port):
        print(f"[-] [FAIL] Cổng {port} đang bị chiếm dụng bởi tiến trình khác.")
        print(f"    Không thể đảm bảo tiến trình đó ghi log vào đúng DB đích: {db_path}")
        print(f"    Vui lòng kiểm tra và đóng tiến trình đang chiếm cổng {port} rồi chạy lại.")
        sys.exit(1)

    def is_admin() -> bool:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    store = EventStore(db_path=db_path)
    cur = store.conn.cursor()
    cur.execute("SELECT COALESCE(MAX(id), 0) FROM alerts")
    max_alert_id_before = cur.fetchone()[0]
    count_before = store.count_alerts()
    print(f"[*] Số cảnh báo trước test: {count_before} (Max ID: {max_alert_id_before})")

    # Step A: Tạo guard TRƯỚC khi chạy leaker & kiểm tra quyền admin / Sysmon
    print("[*] Khởi tạo RealtimeGuardService và kiểm tra quyền Sysmon...")
    guard = RealtimeGuardService(db_path=db_path, poll_sysmon=True, enable_toast=True)
    sysmon_ok, sysmon_desc = guard.check_sysmon_status()
    if not is_admin() or not sysmon_ok:
        print("[FAIL] Cần chạy PowerShell với quyền Administrator. Không có alert nào được tạo.")
        guard.stop()
        store.close()
        sys.exit(2)

    # Đặt watermark = query_latest_record_id(channel). KHÔNG để watermark = 0.
    watermark_before = guard.prepare_live()
    if watermark_before <= 0:
        print("[FAIL] Cần chạy PowerShell với quyền Administrator. Không có alert nào được tạo.")
        guard.stop()
        store.close()
        sys.exit(2)
    print(f"[*] Watermark Sysmon ban đầu: EventRecordID = {watermark_before}")

    # Step 1: Ensure documents
    print("[*] Bước 1: Tạo/đảm bảo tài liệu nhạy cảm trong data/FakeDocuments...")
    create_fake_documents(target_dir="data/FakeDocuments", count=20)

    # Step 2: Start an in-process receiver bound to the exact target database
    from simulator.receiver import ReceiverServer

    receiver_server: Optional[ReceiverServer] = None
    print(f"[*] Bước 2: Khởi động TCP Receiver Server trên 127.0.0.1:{port}...")
    print(f"    - Receiver DB: {db_path}")
    receiver_server = ReceiverServer(host="127.0.0.1", ports=[port], db_path=str(db_path))
    receiver_server.start()
    time.sleep(0.5)

    if port not in receiver_server.listening_ports:
        print(f"[-] [FAIL] Receiver không thể mở cổng {port}. Cổng có thể đã bị chiếm dụng.")
        receiver_server.stop()
        guard.stop()
        store.close()
        sys.exit(1)

    print(f"[+] Receiver Server đang lắng nghe trên 127.0.0.1:{port} (DB: {db_path})")

    py_exec = sys.executable
    if getattr(sys, "frozen", False):
        venv_py = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
        py_exec = venv_py if os.path.exists(venv_py) else "python"

    try:
        # Step 3: Run leaker scenario 1 in a separate process
        print("[*] Bước 3: Khởi chạy tiến trình độc lập thực hiện rò rỉ dữ liệu (Scenario 1 Bulk Exfil)...")
        t_leak_start = time.time()
        leaker_code = (
            "import os, sys\n"
            "from simulator.leaker import ScenarioRunner\n"
            f"runner = ScenarioRunner(fake_docs_dir='data/FakeDocuments', port={port})\n"
            "sent = runner.scenario_1_bulk()\n"
            "print(f'[+] Sent {sent} bytes to receiver.')\n"
        )
        leaker_res = subprocess.run(
            [py_exec, "-c", leaker_code],
            cwd=PROJECT_ROOT,
            capture_output=True,
            timeout=10.0,
        )
        if leaker_res.returncode == 0:
            out_str = leaker_res.stdout.decode("latin1", errors="replace").strip()
            print(f"[+] Tiến trình rò rỉ hoàn tất: {out_str}")
        else:
            err_str = leaker_res.stderr.decode("latin1", errors="replace").strip()
            print(f"[-] Lỗi chạy tiến trình rò rỉ: {err_str}")

        # Step 4: Chờ 3s để Sysmon và Receiver hoàn tất ghi log
        print("[*] Bước 4: Chờ 3.0s để Sysmon và Receiver hoàn tất ghi log...")
        time.sleep(3.0)

        # Step 5: Quét telemetry thật bằng Sysmon
        print("[*] Bước 5: Kích hoạt guard.scan_now(poll_sysmon=True) quét Sysmon thật...")
        guard.scan_now(poll_sysmon=True)
        watermark_after = guard.collector.watermark
        ingested = getattr(guard, "last_ingested", 0)

        print(f"[*] Telemetry Sysmon nạp:")
        print(f"    - watermark_before: {watermark_before}")
        print(f"    - watermark_after:  {watermark_after}")
        print(f"    - số event đã nạp:  {ingested}")

        if not (0 < ingested < 5000):
            print(f"[-] Cảnh báo: số event đã nạp nằm ngoài khoảng kỳ vọng (0 < {ingested} < 5000).")

        guard.stop()

        count_after = store.count_alerts()
        new_alerts = count_after - count_before

        print("\n" + "-" * 65)
        print(f"[*] KẾT QUẢ KIỂM CHỨNG PHÁT HIỆN THỰC TẾ:")
        print(f"    - Số cảnh báo trước:    {count_before}")
        print(f"    - Số cảnh báo sau:     {count_after} (Tăng: +{new_alerts})")

        if new_alerts > 0:
            cur = store.conn.cursor()
            cur.execute(
                "SELECT id, ts, proc_key, detector, severity, score, evidence FROM alerts WHERE id > ? ORDER BY id ASC",
                (max_alert_id_before,),
            )
            rows = cur.fetchall()

            guid_regex = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
            has_error = False

            for row in rows:
                alert_id = row[0]
                alert_pk = str(row[2])
                ev = json.loads(row[6]) if row[6] else {}
                real_bytes = ev.get("bytes_sent", 0)
                proc_name = ev.get("proc_name") or alert_pk
                sens_files = ev.get("sensitive_files") or []
                n_sensitive = len(sens_files)
                first_5_files = sens_files[:5]
                dest_info = ev.get("dest_str") or f"{ev.get('dest_ip')}:{ev.get('dest_port')}"

                # Query process PID from processes table or evidence
                cur.execute("SELECT pid FROM processes WHERE proc_key = ?", (alert_pk,))
                p_row = cur.fetchone()
                alert_pid = p_row[0] if p_row else ev.get("pid", 0)

                # Query matched receiver_logs
                cur.execute(
                    "SELECT bytes_received FROM receiver_logs WHERE dest_port = ? AND ts_utc >= ? ORDER BY id DESC LIMIT 1",
                    (port, t_leak_start - 5.0),
                )
                rx_row = cur.fetchone()
                rx_bytes = rx_row[0] if rx_row else real_bytes
                diff = abs(real_bytes - rx_bytes)

                # Check event sources for this alert's proc_key
                cur.execute("SELECT DISTINCT source FROM events WHERE proc_key = ?", (alert_pk,))
                sources = [s[0] for s in cur.fetchall() if s[0]]
                if not sources or any(s != "sysmon" for s in sources):
                    print(f"[-] [FAIL] Alert #{alert_id} có nguồn sự kiện không hợp lệ: {sources}. Chỉ chấp nhận 'sysmon'.")
                    has_error = True

                # Check proc_key Sysmon GUID format
                if not guid_regex.match(alert_pk):
                    print(f"[-] [FAIL] Alert #{alert_id} proc_key không khớp Sysmon GUID: {alert_pk}")
                    has_error = True

                # Check PID != 8888
                if alert_pid == 8888:
                    print(f"[-] [FAIL] Alert #{alert_id} có pid = 8888 (dấu hiệu giả lập).")
                    has_error = True

                print(f"    - alert id:            #{alert_id}")
                print(f"    - proc_key:            {alert_pk}")
                print(f"    - pid:                 {alert_pid}")
                print(f"    - bytes_sent:          {real_bytes}")
                print(f"    - receiver bytes:      {rx_bytes} (diff: {diff})")
                print(f"    - n_sensitive:         {n_sensitive}")
                print(f"    - 5 file đầu:          {first_5_files}")
                print(f"    - watermark_before:    {watermark_before}")
                print(f"    - watermark_after:     {watermark_after}")
                print(f"    - ingested:            {ingested}")
                print(f"    - Đích gửi:            {dest_info}")
                print(f"    - Điểm rủi ro:         {row[5]:.2f} ({row[4]})")

            if has_error:
                print("\n[-] [FAIL] Kiểm chứng không đạt tiêu chuẩn telemetry Sysmon thật.")
                store.close()
                sys.exit(1)

            print(f"[+] XÁC NHẬN THÀNH CÔNG: Cảnh báo bắt nguồn từ Sysmon thật, khớp receiver_logs.")
        else:
            print(f"[-] [FAIL] Chưa ghi nhận alert mới từ Sysmon.")
            store.close()
            sys.exit(1)

        print("=" * 65 + "\n")

    finally:
        try:
            guard.stop()
        except Exception:
            pass
        if receiver_server is not None:
            print("[*] Đóng TCP Receiver Server...")
            try:
                receiver_server.stop()
            except Exception:
                pass
        store.close()


def build_parser() -> argparse.ArgumentParser:
    """Build root CLI parser."""
    parser = argparse.ArgumentParser(
        prog="privacyguard",
        description="PrivacyGuard: Data Provenance & Anomaly Detection System for Windows",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # diag
    p_diag = subparsers.add_parser("diag", help="Diagnostic breakdown of telemetry funnel, Sysmon status, and drop reasons")
    p_diag.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_diag.set_defaults(func=cmd_diag)

    # test-real
    p_test_real = subparsers.add_parser("test-real", help="Execute real exfiltration attack test using real telemetry (no mock alert)")
    p_test_real.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_test_real.add_argument("--port", type=int, default=8765, help="Receiver port (default: 8765)")
    p_test_real.set_defaults(func=cmd_test_real)

    # tray
    p_tray = subparsers.add_parser("tray", help="Launch System Tray Icon application (default)")
    p_tray.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_tray.add_argument("--interval", type=float, default=10.0, help="Polling interval in seconds (default: 10)")
    p_tray.add_argument("--port", type=int, default=8501, help="Streamlit dashboard port (default: 8501)")
    p_tray.set_defaults(func=cmd_tray)

    # test-alert
    p_test_alert = subparsers.add_parser("test-alert", help="Trigger a test alert & Windows Toast notification")
    p_test_alert.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_test_alert.add_argument("--proc", type=str, default="python.exe", help="Simulated process name")
    p_test_alert.add_argument("--dest", type=str, default="127.0.0.1:8765", help="Simulated network destination")
    p_test_alert.add_argument("--file", type=str, default="hop_dong_kinh_te.docx", help="Simulated sensitive file")
    p_test_alert.set_defaults(func=cmd_test_alert)

    # test-live
    p_test_live = subparsers.add_parser("test-live", help="Execute complete end-to-end live exfiltration attack test")
    p_test_live.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_test_live.add_argument("--port", type=int, default=8765, help="Receiver port (default: 8765)")
    p_test_live.set_defaults(func=cmd_test_live)

    # collect
    p_collect = subparsers.add_parser("collect", help="Run Sysmon live telemetry collector")
    p_collect.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_collect.add_argument("--duration", type=float, default=60.0, help="Duration in seconds (default: 60)")
    p_collect.add_argument("--file", type=str, help="Text dump file to parse")
    p_collect.add_argument("--backfill", action="store_true", help="Backfill historical events")
    p_collect.add_argument("--no-filter", action="store_true", help="Disable noise filtering")
    p_collect.set_defaults(func=cmd_collect)

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Run synthetic exfiltration scenarios")
    p_sim.add_argument("--scenario", type=int, default=None, help="Specific scenario ID (1-9, default: all)")
    p_sim.add_argument("--runs", type=int, default=1, help="Runs per scenario (default: 1)")
    p_sim.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    p_sim.set_defaults(func=cmd_simulate)

    # eval
    p_eval = subparsers.add_parser("eval", help="Run multi-model evaluation pipeline")
    p_eval.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to database")
    p_eval.add_argument("--runs", type=int, default=12, help="Simulation runs (default: 12)")
    p_eval.set_defaults(func=cmd_eval)

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run system overhead benchmark")
    p_bench.add_argument("--duration", type=float, default=10.0, help="Live sampling duration in seconds")
    p_bench.add_argument("--stress-events", type=int, default=5000, help="Number of stress events")
    p_bench.set_defaults(func=cmd_benchmark)

    # ui
    p_ui = subparsers.add_parser("ui", help="Launch Streamlit dashboard")
    p_ui.add_argument("--port", type=int, default=8501, help="Streamlit port (default: 8501)")
    p_ui.set_defaults(func=cmd_ui)

    # info
    p_info = subparsers.add_parser("info", help="Display system status and database statistics")
    p_info.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to database")
    p_info.set_defaults(func=cmd_info)

    # reset-alerts
    p_reset = subparsers.add_parser("reset-alerts", help="Clear all alert records from database (preserves events/processes)")
    p_reset.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_reset.add_argument("--yes", action="store_true", help="Confirm deletion of all alerts")
    p_reset.set_defaults(func=cmd_reset_alerts)

    # purge-synthetic
    p_purge = subparsers.add_parser("purge-synthetic", help="Purge synthetic mock data (alerts, events, processes)")
    p_purge.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    p_purge.add_argument("--yes", action="store_true", help="Confirm deletion of synthetic data")
    p_purge.set_defaults(func=cmd_purge_synthetic)

    return parser


def main():
    # If executed without arguments (e.g. double-clicked exe or running python cli.py),
    # launch the System Tray application by default instead of printing help and exiting.
    if len(sys.argv) == 1:
        from ui.tray_app import run_tray_app
        print("[*] Launching PrivacyGuard Real-time Protection in Windows System Tray...")
        run_tray_app()
        return

    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
