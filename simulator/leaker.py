"""Exfiltration and Control Simulator for PrivacyGuard (Phase B).

Simulates 9 scenarios according to SPEC Section 6:
Scenarios:
  1: Bulk exfiltration: read multiple files, send all at once (Label 1)
  2: Slow trickle exfiltration: read files, send in small chunks with delay (Label 1)
  3: Compressed archive exfiltration: zip files and send archive (Label 1)
  4: Subprocess exfiltration: spawn child python process to send data (Label 1)
  5: Port 443 exfiltration: send data to port 443 (Label 1)
  6: Periodic beaconing: read small file, send periodic heartbeat bursts (Label 1)
  7: Benign cloud backup: sync files to fake_cloud via benign_sync.py (Label 0)
  8: Network-only control: send synthetic traffic, no file reads (Label 0)
  9: File-read-only control: read multiple files, no network traffic (Label 0)

STRICT SAFETY ENFORCEMENT:
- Reads strictly from data/FakeDocuments.
- Transmits network strictly to 127.0.0.1.
- Refuses execution if paths or destinations violate safety boundaries.
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import random
import socket
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from simulator.benign_sync import run_benign_sync
from simulator.receiver import load_simulator_config

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Leaker] %(message)s",
)

GROUND_TRUTH_HEADER = [
    "run_id",
    "scenario",
    "label",
    "proc_name",
    "pid",
    "proc_guid",
    "t_start_utc",
    "t_end_utc",
]


def validate_safe_environment(fake_docs_dir: str, target_host: str) -> str:
    """Strictly validate that fake_docs_dir is synthetic and target_host is loopback."""
    abs_docs = os.path.abspath(fake_docs_dir)

    # 1. Directory must contain 'FakeDocuments'
    if "fakedocuments" not in abs_docs.lower():
        raise ValueError(
            f"SAFETY VIOLATION: Directory '{abs_docs}' is outside FakeDocuments! Execution refused."
        )

    # 2. Never allow real user profile personal folders
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        forbidden = [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join(user_profile, "Downloads"),
        ]
        for fdir in forbidden:
            if os.path.abspath(fdir).lower() == abs_docs.lower():
                raise ValueError(
                    f"SAFETY VIOLATION: Cannot target personal folder '{fdir}'! Execution refused."
                )

    # 3. Network destination must be strictly 127.0.0.1
    if target_host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            f"SAFETY VIOLATION: Target host '{target_host}' is not 127.0.0.1! Execution refused."
        )

    return abs_docs


def resolve_process_guid(pid: int, db_path: str = "data/privacyguard.db") -> str:
    """Retrieve process_guid from database if recorded by Sysmon collector, else format valid GUID."""
    if os.path.exists(db_path):
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT proc_key FROM processes WHERE pid = ? ORDER BY start_ts DESC LIMIT 1",
                (pid,),
            )
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                return str(row[0])
        except Exception:
            pass

    # Fallback pseudo-guid formatted as standard Windows GUID
    return f"{{{pid:08x}-5199-4b2b-a0c7-{int(time.time()):012x}}}"


def format_utc_timestamp(epoch_ts: float) -> str:
    """Format epoch float into UTC string matching Sysmon UtcTime format."""
    dt = datetime.fromtimestamp(epoch_ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def get_fake_files(safe_docs_dir: str, count: Optional[int] = None, rng: Optional[random.Random] = None) -> List[str]:
    """Retrieve list of files from safe FakeDocuments directory."""
    if not os.path.exists(safe_docs_dir):
        raise FileNotFoundError(f"FakeDocuments directory does not exist: {safe_docs_dir}")

    files = [
        os.path.join(safe_docs_dir, f)
        for f in os.listdir(safe_docs_dir)
        if os.path.isfile(os.path.join(safe_docs_dir, f))
    ]
    if not files:
        raise FileNotFoundError(f"No fake documents found in: {safe_docs_dir}")

    files.sort()
    if rng:
        rng.shuffle(files)

    return files[:count] if count else files


def send_tcp_data(host: str, port: int, data: bytes, chunk_size: int = 65536, delay_sec: float = 0.0) -> int:
    """Send bytes over TCP connection strictly to 127.0.0.1."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(f"SAFETY VIOLATION: Host '{host}' is not 127.0.0.1")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        total_sent = 0
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + chunk_size]
            sock.sendall(chunk)
            total_sent += len(chunk)
            offset += len(chunk)
            if delay_sec > 0:
                time.sleep(delay_sec)
        return total_sent
    finally:
        try:
            sock.close()
        except Exception:
            pass


class ScenarioRunner:
    """Executes the 9 simulator scenarios."""

    def __init__(
        self,
        fake_docs_dir: str = "data/FakeDocuments",
        host: str = "127.0.0.1",
        port: int = 8765,
        scenario5_port: int = 443,
        fake_cloud_dir: str = "data/fake_cloud",
        seed: Optional[int] = None,
    ):
        self.safe_docs_dir = validate_safe_environment(fake_docs_dir, host)
        self.host = "127.0.0.1"
        self.port = port
        self.scenario5_port = scenario5_port
        self.fake_cloud_dir = fake_cloud_dir
        self.seed = seed
        self.rng = random.Random(seed)

    def _touch_sensitive_file(self, filename: str = "ho_so_tai_chinh_temp.xlsx") -> str:
        """Create or update a sensitive file in FakeDocuments to emit Sysmon Event 11 (FileCreate)."""
        temp_path = os.path.join(self.safe_docs_dir, filename)
        try:
            with open(temp_path, "wb") as f:
                f.write(b"CONFIDENTIAL FINANCIAL RECORD DATA FOR SYSMON EVENT 11\n" + self.rng.randbytes(512))
            # Small delay so Sysmon log agent has time to register Event 11 before net_connect
            time.sleep(0.05)
        except Exception as e:
            logger.debug("Failed touching sensitive file: %s", e)
        return temp_path

    def scenario_1_bulk(self) -> int:
        """Scenario 1: Read multiple files, send in a single bulk transmission (Label 1)."""
        self._touch_sensitive_file("ho_so_tai_chinh_temp.xlsx")
        files = get_fake_files(self.safe_docs_dir, count=10, rng=self.rng)
        buffer = bytearray()
        for f in files:
            with open(f, "rb") as fp:
                buffer.extend(fp.read())
        return send_tcp_data(self.host, self.port, bytes(buffer))

    def scenario_2_slow_trickle(self) -> int:
        """Scenario 2: Slow trickle: send small chunks with delay over time (Label 1)."""
        self._touch_sensitive_file("sao_ke_tai_khoan_temp.xlsx")
        files = get_fake_files(self.safe_docs_dir, count=5, rng=self.rng)
        buffer = bytearray()
        for f in files:
            with open(f, "rb") as fp:
                buffer.extend(fp.read())
        # Send in 256-byte chunks with 0.02s delay
        return send_tcp_data(self.host, self.port, bytes(buffer), chunk_size=256, delay_sec=0.02)

    def scenario_3_compressed(self) -> int:
        """Scenario 3: Compress fake files into a zip archive and send (Label 1)."""
        self._touch_sensitive_file("hop_dong_kinh_te_temp.docx")
        files = get_fake_files(self.safe_docs_dir, count=8, rng=self.rng)
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                zf.write(f, arcname=os.path.basename(f))
        zip_data = zip_buffer.getvalue()
        return send_tcp_data(self.host, self.port, zip_data)

    def scenario_4_subprocess(self) -> int:
        """Scenario 4: Exfiltrate via a child python subprocess (Label 1)."""
        self._touch_sensitive_file("du_lieu_nhan_su_temp.csv")
        files = get_fake_files(self.safe_docs_dir, count=5, rng=self.rng)
        buffer = bytearray()
        for f in files:
            with open(f, "rb") as fp:
                buffer.extend(fp.read())
        payload = bytes(buffer)

        # Child process receives data via stdin and sends over TCP
        child_code = (
            "import socket, sys\n"
            "data = sys.stdin.buffer.read()\n"
            f"s = socket.socket()\n"
            f"s.connect(('127.0.0.1', {self.port}))\n"
            "s.sendall(data)\n"
            "s.close()\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", child_code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate(input=payload)
        if proc.returncode != 0:
            logger.warning("Child process exfiltration error: %s", stderr.decode("latin1", errors="replace"))
        return len(payload)

    def scenario_5_port_443(self) -> int:
        """Scenario 5: Exfiltrate over port 443 (Label 1)."""
        self._touch_sensitive_file("tai_khoan_ngan_hang_temp.docx")
        files = get_fake_files(self.safe_docs_dir, count=6, rng=self.rng)
        buffer = bytearray()
        for f in files:
            with open(f, "rb") as fp:
                buffer.extend(fp.read())

        target_port = self.scenario5_port
        try:
            return send_tcp_data(self.host, target_port, bytes(buffer))
        except Exception as e:
            logger.warning("Connection to port 443 failed (%s), falling back to primary port %d", e, self.port)
            return send_tcp_data(self.host, self.port, bytes(buffer))

    def scenario_6_periodic_beacon(self) -> int:
        """Scenario 6: Periodic beaconing: small bursts over intervals (Label 1)."""
        self._touch_sensitive_file("khoa_bi_mat_api_temp.txt")
        files = get_fake_files(self.safe_docs_dir, count=2, rng=self.rng)
        sample_data = b""
        for f in files:
            with open(f, "rb") as fp:
                sample_data += fp.read()[:256]

        total_sent = 0
        # 3 beacon bursts of 128 bytes with 0.1s interval
        for _ in range(3):
            burst = sample_data[:128] if len(sample_data) >= 128 else sample_data
            total_sent += send_tcp_data(self.host, self.port, burst)
            time.sleep(0.1)
        return total_sent

    def scenario_7_benign_sync(self) -> int:
        """Scenario 7: Benign cloud backup: sync files to fake_cloud (Label 0)."""
        run_benign_sync(
            src_dir=self.safe_docs_dir,
            dst_dir=self.fake_cloud_dir,
            file_count=5,
            seed=self.seed,
        )
        return 0

    def scenario_8_network_only(self) -> int:
        """Scenario 8: Network-only control: send synthetic bytes, NO file reads (Label 0)."""
        # Generate synthetic bytes purely in memory without reading any files
        dummy_data = self.rng.randbytes(8192)
        return send_tcp_data(self.host, self.port, dummy_data)

    def scenario_9_file_read_only(self) -> int:
        """Scenario 9: File-read-only control: read multiple files, NO network traffic (Label 0)."""
        files = get_fake_files(self.safe_docs_dir, count=10, rng=self.rng)
        total_read = 0
        for f in files:
            with open(f, "rb") as fp:
                total_read += len(fp.read())
        # Zero bytes sent over network
        return 0

    def run_scenario(self, scenario_id: int) -> Tuple[int, int]:
        """Execute scenario by ID. Returns (label, bytes_sent)."""
        if scenario_id == 1:
            return 1, self.scenario_1_bulk()
        elif scenario_id == 2:
            return 1, self.scenario_2_slow_trickle()
        elif scenario_id == 3:
            return 1, self.scenario_3_compressed()
        elif scenario_id == 4:
            return 1, self.scenario_4_subprocess()
        elif scenario_id == 5:
            return 1, self.scenario_5_port_443()
        elif scenario_id == 6:
            return 1, self.scenario_6_periodic_beacon()
        elif scenario_id == 7:
            return 0, self.scenario_7_benign_sync()
        elif scenario_id == 8:
            return 0, self.scenario_8_network_only()
        elif scenario_id == 9:
            return 0, self.scenario_9_file_read_only()
        else:
            raise ValueError(f"Unknown scenario ID: {scenario_id}. Must be 1 to 9.")


def record_ground_truth(
    gt_path: str,
    run_id: str,
    scenario: int,
    label: int,
    proc_name: str,
    pid: int,
    proc_guid: str,
    t_start_utc: str,
    t_end_utc: str,
) -> None:
    """Append a single run record to ground_truth.csv with proper headers."""
    dirname = os.path.dirname(gt_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    file_exists = os.path.exists(gt_path) and os.path.getsize(gt_path) > 0
    with open(gt_path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(GROUND_TRUTH_HEADER)
        writer.writerow([
            run_id,
            scenario,
            label,
            proc_name,
            pid,
            proc_guid,
            t_start_utc,
            t_end_utc,
        ])


def run_leaker(
    scenario: int,
    runs: int = 1,
    seed: Optional[int] = None,
    gt_path: str = "data/ground_truth.csv",
    fake_docs_dir: str = "data/FakeDocuments",
    fake_cloud_dir: str = "data/fake_cloud",
    host: str = "127.0.0.1",
    port: int = 8765,
    scenario5_port: int = 443,
    db_path: str = "data/privacyguard.db",
) -> List[Dict[str, Any]]:
    """Execute scenario runs times, recording ground truth and returning summary."""
    validate_safe_environment(fake_docs_dir, host)

    runner = ScenarioRunner(
        fake_docs_dir=fake_docs_dir,
        host=host,
        port=port,
        scenario5_port=scenario5_port,
        fake_cloud_dir=fake_cloud_dir,
        seed=seed,
    )

    pid = os.getpid()
    proc_name = os.path.basename(sys.executable)
    proc_guid = resolve_process_guid(pid, db_path=db_path)

    # Determine starting run number based on existing rows
    existing_runs = 0
    if os.path.exists(gt_path):
        try:
            with open(gt_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)
                if len(rows) > 1:
                    existing_runs = len(rows) - 1
        except Exception:
            existing_runs = 0

    results: List[Dict[str, Any]] = []

    for k in range(runs):
        run_num = existing_runs + k + 1
        run_id = f"run_{run_num:04d}"

        t_start = time.time()
        t_start_utc = format_utc_timestamp(t_start)

        label, bytes_sent = runner.run_scenario(scenario)

        t_end = time.time()
        t_end_utc = format_utc_timestamp(t_end)

        record_ground_truth(
            gt_path=gt_path,
            run_id=run_id,
            scenario=scenario,
            label=label,
            proc_name=proc_name,
            pid=pid,
            proc_guid=proc_guid,
            t_start_utc=t_start_utc,
            t_end_utc=t_end_utc,
        )

        record = {
            "run_id": run_id,
            "scenario": scenario,
            "label": label,
            "proc_name": proc_name,
            "pid": pid,
            "proc_guid": proc_guid,
            "t_start_utc": t_start_utc,
            "t_end_utc": t_end_utc,
            "bytes_sent": bytes_sent,
        }
        results.append(record)
        logger.info(
            "Completed %s: scenario=%d, label=%d, bytes_sent=%d, duration=%.3fs",
            run_id,
            scenario,
            label,
            bytes_sent,
            t_end - t_start,
        )

    return results


def run_all_scenarios(runs: int = 1, seed: Optional[int] = None) -> List[Dict[str, Any]]:
    """Execute all 9 scenarios sequentially."""
    all_res = []
    for sc in range(1, 10):
        res = run_leaker(scenario=sc, runs=runs, seed=seed)
        all_res.extend(res)
    return all_res


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Exfiltration & Control Simulator")
    parser.add_argument("--scenario", type=int, required=True, help="Scenario ID (1-9)")
    parser.add_argument("--runs", type=int, default=1, help="Number of repetitions")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument("--gt", type=str, default="data/ground_truth.csv", help="Path to ground_truth.csv")
    parser.add_argument("--docs-dir", type=str, default="data/FakeDocuments", help="Path to FakeDocuments")
    parser.add_argument("--cloud-dir", type=str, default="data/fake_cloud", help="Path to fake_cloud")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Must be 127.0.0.1")
    parser.add_argument("--port", type=int, default=None, help="Receiver port")
    parser.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite DB")
    args = parser.parse_args()

    cfg = load_simulator_config()
    host = args.host or cfg["host"]
    port = args.port or cfg["port"]
    scenario5_port = cfg.get("scenario5_port", 443)
    db_path = args.db or cfg["db_path"]

    results = run_leaker(
        scenario=args.scenario,
        runs=args.runs,
        seed=args.seed,
        gt_path=args.gt,
        fake_docs_dir=args.docs_dir,
        fake_cloud_dir=args.cloud_dir,
        host=host,
        port=port,
        scenario5_port=scenario5_port,
        db_path=db_path,
    )
    print(f"Executed scenario {args.scenario} ({len(results)} runs). Ground truth saved to: {args.gt}")


if __name__ == "__main__":
    main()
