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

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


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
    from simulator.make_fake_docs import generate_fake_documents
    from simulator.receiver import run_receiver_server
    from simulator.leaker import run_all_scenarios

    print(f"[*] Ensuring synthetic test documents in data/FakeDocuments...")
    generate_fake_documents(output_dir="data/FakeDocuments", count=100)

    print(f"[*] Starting local TCP receiver server on port 8765...")
    receiver_proc = subprocess.Popen(
        [sys.executable, "simulator/receiver.py", "--port", "8765"],
        cwd=PROJECT_ROOT,
    )
    time.sleep(1.0)
    try:
        print(f"[*] Executing leaker scenarios (--runs {args.runs}, --seed {args.seed})...")
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
    cmd = [sys.executable, "-m", "streamlit", "run", app_path, "--server.port", str(args.port)]
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


def build_parser() -> argparse.ArgumentParser:
    """Build root CLI parser."""
    parser = argparse.ArgumentParser(
        prog="privacyguard",
        description="PrivacyGuard: Data Provenance & Anomaly Detection System for Windows",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

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
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
