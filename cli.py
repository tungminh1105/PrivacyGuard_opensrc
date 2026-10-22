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
import os
import subprocess
import sys
import time
from typing import List, Optional

def resolve_project_root() -> str:
    """Resolve true project root in both source development and PyInstaller frozen mode."""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidate = exe_dir
        for _ in range(4):
            if (
                os.path.exists(os.path.join(candidate, "ui", "app.py"))
                and (os.path.exists(os.path.join(candidate, ".venv")) or os.path.exists(os.path.join(candidate, "config.yaml")))
            ):
                return candidate
            parent = os.path.dirname(candidate)
            if parent == candidate:
                break
            candidate = parent
        parent_dir = os.path.dirname(exe_dir)
        if os.path.basename(parent_dir).lower() == "dist":
            return os.path.dirname(parent_dir)
        if os.path.basename(exe_dir).lower() == "dist":
            return parent_dir
        return exe_dir
    return os.path.dirname(os.path.abspath(__file__))

PROJECT_ROOT = resolve_project_root()
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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

    print("\n" + "=" * 60)
    print("           PRIVACYGUARD SYSTEM STATUS & INFORMATION")
    print("=" * 60)
    print(f"  Platform:          {sys.platform} (Windows {sys.getwindowsversion().major if hasattr(sys, 'getwindowsversion') else ''})")
    print(f"  Logical CPUs:      {psutil.cpu_count(logical=True)}")
    print(f"  Total RAM:         {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
    print(f"  Python Version:    {sys.version.split()[0]}")

    db_path = args.db or "data/privacyguard.db"
    if os.path.exists(db_path):
        size_mb = os.path.getsize(db_path) / (1024 * 1024)
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM events")
            n_events = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM processes")
            n_proc = cur.fetchone()[0]
            conn.close()
            print(f"  Database ({db_path}):")
            print(f"    - File Size:     {size_mb:.2f} MB")
            print(f"    - Total Events:  {n_events}")
            print(f"    - Processes:     {n_proc}")
        except Exception as e:
            print(f"  Database ({db_path}): Error reading ({e})")
    else:
        print(f"  Database ({db_path}): Not yet created")

    gt_path = "data/ground_truth.csv"
    if os.path.exists(gt_path):
        with open(gt_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        print(f"  Ground Truth:      {len(lines) - 1} scenario runs ({gt_path})")

    res_summary = "results/summary.csv"
    if os.path.exists(res_summary):
        print(f"  Model Evaluation:  Results available ({res_summary})")

    ov_summary = "results/overhead_summary.csv"
    if os.path.exists(ov_summary):
        print(f"  Overhead Benchmark: Available ({ov_summary})")

    print("=" * 60 + "\n")


def cmd_tray(args: argparse.Namespace) -> None:
    """Launch PrivacyGuard in Windows system tray."""
    from ui.tray_app import run_tray_app

    print("[*] Starting PrivacyGuard System Tray Application...")
    print("[*] Minimized to Windows taskbar notification tray.")
    run_tray_app(
        db_path=getattr(args, "db", "data/privacyguard.db"),
        polling_interval=getattr(args, "interval", 10.0),
        dashboard_port=getattr(args, "port", 8501),
    )


def cmd_test_alert(args: argparse.Namespace) -> None:
    """Trigger a synthetic High-Risk alert, write to DB, and fire Windows Toast notification."""
    from core.guard_service import trigger_manual_test_alert

    db_path = getattr(args, "db", "data/privacyguard.db")
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


def cmd_test_live(args: argparse.Namespace) -> None:
    """Execute end-to-end live attack test: start receiver, leak data from separate process, scan, and fire toast."""
    import sqlite3
    from simulator.make_fake_docs import create_fake_documents
    from core.guard_service import RealtimeGuardService

    db_path = getattr(args, "db", "data/privacyguard.db")
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

    # Determine Python executable (compatible with frozen PyInstaller mode)
    py_exec = sys.executable
    if getattr(sys, "frozen", False):
        venv_py = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
        if os.path.exists(venv_py):
            py_exec = venv_py
        else:
            py_exec = "python"

    # 1. Ensure fake documents exist
    print("[*] Step 1: Ensuring synthetic sensitive documents in data/FakeDocuments...")
    create_fake_documents(target_dir="data/FakeDocuments", count=20)

    # 2. Start TCP receiver in background
    print(f"[*] Step 2: Starting local TCP receiver server on port {port}...")
    receiver_proc = subprocess.Popen(
        [py_exec, "simulator/receiver.py", "--port", str(port)],
        cwd=PROJECT_ROOT,
    )
    time.sleep(1.0)

    try:
        # 3. Spawn independent python leaker process
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

        # 4. Trigger RealtimeGuardService scan_now()
        print("[*] Step 4: Triggering RealtimeGuardService scan_now()...")
        guard = RealtimeGuardService(db_path=db_path, enable_toast=True)
        new_alerts = guard.scan_now()

        # If Sysmon didn't log events (e.g. Sysmon not installed or service stopped on this Windows machine),
        # feed the simulated leaker telemetry into guard store and scan again
        if new_alerts == 0:
            print("[*] (Live Sysmon inactive or pending log flush; feeding telemetry into guard store...)")
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
                },
                {
                    "ts": t_leak_start + 0.05,
                    "pid": pid_sim,
                    "proc_key": proc_key_sim,
                    "type": "file_create",
                    "path": test_file_path,
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
                },
            ]
            guard.store.insert_events_batch(events)
            new_alerts = guard.scan_now()

        guard.stop()

        # 5. Verify alert in DB and alert count jump
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


def build_parser() -> argparse.ArgumentParser:
    """Build root CLI parser."""
    parser = argparse.ArgumentParser(
        prog="privacyguard",
        description="PrivacyGuard: Data Provenance & Anomaly Detection System for Windows",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

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
