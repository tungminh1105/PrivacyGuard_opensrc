"""MITRE ATT&CK Scenario Payload Generator for PrivacyGuard Phase 3.

Executes standalone, one-shot payload scenarios in independent child processes:
1. T1560.001 - Archive via Utility (ZIP compression in memory, exfil)
2. T1041 - Exfiltration Over C2 Channel (bulk binary exfil)
3. T1567 - Exfiltration Over Web Service (HTTP POST payload to alt port)

STRICT SAFETY ENFORCEMENT:
- Binds / connects strictly to 127.0.0.1 (loopback interface).
- Reads and writes ONLY within data/FakeDocuments.
- Generates synthetic random bytes with dummy markers. Never accesses real user files.
- Prints JSON summary to stdout on completion.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import socket
import sys
import time
import zipfile
from typing import List, Tuple

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def validate_target_host(host: str) -> None:
    """Ensure destination host is strictly loopback."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(f"SAFETY VIOLATION: Host must be 127.0.0.1, got: {host}")


def validate_docs_dir(docs_dir: pathlib.Path) -> pathlib.Path:
    """Ensure docs directory is strictly within data/FakeDocuments."""
    resolved = docs_dir.resolve()
    allowed_root = (PROJECT_ROOT / "data" / "FakeDocuments").resolve()
    try:
        resolved.relative_to(allowed_root)
    except ValueError:
        if resolved != allowed_root:
            raise ValueError(
                f"SAFETY VIOLATION: docs_dir must be inside {allowed_root}, got: {resolved}"
            )
    return resolved


def create_fake_sensitive_files(
    docs_dir: pathlib.Path, scenario: str, run_id: str, count: int
) -> List[pathlib.Path]:
    """Create unique sensitive files (.xlsx) to trigger Sysmon Event 11."""
    created_paths: List[pathlib.Path] = []
    docs_dir.mkdir(parents=True, exist_ok=True)

    for i in range(1, count + 1):
        filename = f"mitre_{scenario}_{run_id}_{i}.xlsx"
        filepath = docs_dir / filename
        if filepath.exists():
            filepath.unlink()

        # Each file is ~4KB random bytes + dummy marker
        content = os.urandom(4096) + b"\nCONFIDENTIAL FAKE DATA FOR PHASE3 MITRE TEST\n"
        with open(filepath, "xb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        created_paths.append(filepath)

    return created_paths


def send_bytes_to_socket(host: str, port: int, data: bytes) -> int:
    """Transmit payload to 127.0.0.1:<port> over TCP stream."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    try:
        sock.connect((host, port))
        sock.sendall(data)
        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass
    finally:
        sock.close()
    return len(data)


def run_scenario(
    scenario: str,
    docs_dir: pathlib.Path,
    host: str,
    port: int,
    run_id: str,
) -> Tuple[int, List[pathlib.Path], int]:
    """Execute scenario logic: create files -> wait 0.5s -> build payload -> transmit."""
    scenario_clean = scenario.lower().replace(".", "_")

    if scenario_clean in ("t1560", "t1560_001"):
        # Scenario 1: T1560.001 - Archive via Utility
        # Create 2 files, compress into ZIP in memory, transmit ZIP
        files = create_fake_sensitive_files(docs_dir, "t1560", run_id, count=2)
        time.sleep(0.5)  # Wait for Sysmon Event 11 to precede NetworkConnect

        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in files:
                with open(p, "rb") as f:
                    zf.writestr(p.name, f.read())
        payload = bio.getvalue()
        bytes_sent = send_bytes_to_socket(host, port, payload)
        return (os.getpid(), files, bytes_sent)

    elif scenario_clean == "t1041":
        # Scenario 2: T1041 - Exfiltration Over C2 Channel
        # Create 3 files, concatenate bulk bytes, transmit directly
        files = create_fake_sensitive_files(docs_dir, "t1041", run_id, count=3)
        time.sleep(0.5)

        chunks = []
        for p in files:
            with open(p, "rb") as f:
                chunks.append(f.read())
        payload = b"".join(chunks)
        bytes_sent = send_bytes_to_socket(host, port, payload)
        return (os.getpid(), files, bytes_sent)

    elif scenario_clean == "t1567":
        # Scenario 3: T1567 - Exfiltration Over Web Service (flow-level HTTP POST)
        # Create 2 files, wrap in HTTP POST payload, transmit to alt port
        files = create_fake_sensitive_files(docs_dir, "t1567", run_id, count=2)
        time.sleep(0.5)

        chunks = []
        for p in files:
            with open(p, "rb") as f:
                chunks.append(f.read())
        body = b"".join(chunks)

        headers = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1")
        payload = headers + body
        bytes_sent = send_bytes_to_socket(host, port, payload)
        return (os.getpid(), files, bytes_sent)

    else:
        raise ValueError(f"Unknown scenario: {scenario}. Expected t1560, t1041, or t1567.")


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard MITRE ATT&CK Payload Runner")
    parser.add_argument(
        "--scenario",
        required=True,
        type=str,
        help="Scenario identifier: t1560, t1041, or t1567",
    )
    parser.add_argument(
        "--docs-dir",
        default="data/FakeDocuments",
        type=str,
        help="Target fake sensitive documents directory",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        type=str,
        help="Destination host (must be 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="Destination port",
    )
    parser.add_argument(
        "--run-id",
        default=f"run_{int(time.time())}",
        type=str,
        help="Unique execution identifier",
    )
    args = parser.parse_args()

    try:
        validate_target_host(args.host)
        docs_dir = validate_docs_dir(pathlib.Path(args.docs_dir))

        pid, created_files, bytes_sent = run_scenario(
            scenario=args.scenario,
            docs_dir=docs_dir,
            host=args.host,
            port=args.port,
            run_id=args.run_id,
        )

        result = {
            "scenario": args.scenario.upper(),
            "pid": pid,
            "files": [str(p.resolve()) for p in created_files],
            "bytes_sent": bytes_sent,
            "dest": f"{args.host}:{args.port}",
        }
        # Print JSON on the final line
        print(json.dumps(result))
        sys.exit(0)

    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
