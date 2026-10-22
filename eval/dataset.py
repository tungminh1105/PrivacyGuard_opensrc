"""Dataset generation and temporal splitting for PrivacyGuard (Phase D).

Implements:
1. Scenario sample generation via simulator (scenarios 1-9, multiple runs).
2. Telemetry event recording into SQLite and ground_truth.csv.
3. Feature window extraction and ground-truth labeling.
4. Strict temporal / run-separated train/val/test splitting with zero data leakage.
   (Train set contains ONLY benign samples).
"""

from __future__ import annotations

import csv
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from core.store import EventStore
from core.features import SlidingWindowFeatureExtractor, FEATURE_NAMES
from simulator.make_fake_docs import create_fake_documents
from simulator.receiver import ReceiverServer, load_simulator_config
from simulator.leaker import ScenarioRunner, GROUND_TRUTH_HEADER

logger = logging.getLogger(__name__)


def parse_ground_truth(gt_path: str) -> List[Dict[str, Any]]:
    """Read and parse ground_truth.csv records."""
    if not os.path.exists(gt_path):
        return []

    records = []
    with open(gt_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # Convert timestamps to epoch seconds
                t_start = datetime.strptime(
                    row["t_start_utc"].strip(), "%Y-%m-%d %H:%M:%S.%f"
                ).replace(tzinfo=timezone.utc).timestamp()
                t_end = datetime.strptime(
                    row["t_end_utc"].strip(), "%Y-%m-%d %H:%M:%S.%f"
                ).replace(tzinfo=timezone.utc).timestamp()

                records.append({
                    "run_id": row["run_id"],
                    "scenario": int(row["scenario"]),
                    "label": int(row["label"]),
                    "proc_name": row["proc_name"],
                    "pid": int(row["pid"]),
                    "proc_guid": row["proc_guid"],
                    "t_start": t_start,
                    "t_end": t_end,
                })
            except Exception as e:
                logger.debug("Failed to parse row %s: %s", row, e)
    return records


class DatasetGenerator:
    """Orchestrates simulation execution, window extraction, and dataset splitting."""

    def __init__(
        self,
        db_path: str = "data/privacyguard.db",
        gt_path: str = "data/ground_truth.csv",
        fake_docs_dir: str = "data/FakeDocuments",
        fake_cloud_dir: str = "data/fake_cloud",
        receiver_port: int = 8765,
        scenario5_port: int = 443,
        window_sec: float = 60.0,
        step_sec: float = 15.0,
        seed: int = 42,
    ):
        self.db_path = db_path
        self.gt_path = gt_path
        self.fake_docs_dir = fake_docs_dir
        self.fake_cloud_dir = fake_cloud_dir
        self.receiver_port = receiver_port
        self.scenario5_port = scenario5_port
        self.window_sec = window_sec
        self.step_sec = step_sec
        self.seed = seed
        self.rng = random.Random(seed)

    def ensure_prerequisites(self) -> None:
        """Ensure synthetic documents and target folders exist."""
        if not os.path.exists(self.fake_docs_dir) or len(os.listdir(self.fake_docs_dir)) < 50:
            logger.info("Generating synthetic documents in %s...", self.fake_docs_dir)
            create_fake_documents(target_dir=self.fake_docs_dir, count=100, seed=self.seed)
        os.makedirs(self.fake_cloud_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)

    def run_simulations(self, runs_per_scenario: int = 12) -> List[Dict[str, Any]]:
        """Run all 9 scenarios repeatedly with receiver and log events into DB & ground_truth."""
        self.ensure_prerequisites()

        # Start receiver server on 127.0.0.1
        ports = [self.receiver_port]
        receiver = ReceiverServer(host="127.0.0.1", ports=ports, db_path=self.db_path)
        receiver.start()
        time.sleep(0.3)

        store = EventStore(self.db_path)
        all_new_runs: List[Dict[str, Any]] = []

        try:
            runner = ScenarioRunner(
                fake_docs_dir=self.fake_docs_dir,
                host="127.0.0.1",
                port=self.receiver_port,
                scenario5_port=self.scenario5_port,
                fake_cloud_dir=self.fake_cloud_dir,
                seed=self.seed,
            )

            # Retrieve existing ground truth
            gt_exists = os.path.exists(self.gt_path) and os.path.getsize(self.gt_path) > 0
            existing_count = len(parse_ground_truth(self.gt_path))

            fake_files = [
                os.path.join(self.fake_docs_dir, f)
                for f in sorted(os.listdir(self.fake_docs_dir))
                if os.path.isfile(os.path.join(self.fake_docs_dir, f))
            ]

            run_counter = existing_count + 1

            for sc_id in range(1, 10):
                for r in range(runs_per_scenario):
                    run_id = f"run_{run_counter:04d}"
                    run_counter += 1

                    # Unique pid and process_key for this simulation instance
                    sim_pid = 7000 + (sc_id * 100) + r
                    proc_key = f"{{sim-{sc_id:02d}-{r:03d}-{int(time.time()*1000):x}}}"

                    t_start = time.time()
                    t_start_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

                    # Register process
                    store.upsert_process({
                        "proc_key": proc_key,
                        "pid": sim_pid,
                        "ppid": None,
                        "name": "python.exe",
                        "exe_path": "C:\\Python314\\python.exe",
                        "signed": 0,
                        "publisher": "Unknown",
                        "start_ts": t_start,
                    })

                    # Execute scenario function
                    try:
                        label, bytes_sent = runner.run_scenario(sc_id)
                    except Exception as e:
                        logger.warning("Scenario %d run %d failed: %s", sc_id, r, e)
                        label = 1 if sc_id <= 6 else 0
                        bytes_sent = 10000

                    t_end = time.time()
                    t_end_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
                    store.update_process_end(proc_key, t_end)

                    # Build telemetry events reflecting the execution
                    events_batch: List[Dict[str, Any]] = []

                    # 1. Process start event
                    events_batch.append({
                        "ts": t_start,
                        "pid": sim_pid,
                        "ppid": None,
                        "proc_key": proc_key,
                        "type": "proc_start",
                        "path": "C:\\Python314\\python.exe",
                    })

                    # 2. File interactions (Sysmon FileCreate / temp files)
                    if sc_id in (1, 2, 3, 4, 5, 6, 7, 9):
                        # Touch fake sensitive documents
                        sample_count = 1 if sc_id == 6 else (8 if sc_id == 3 else 5)
                        sampled_docs = self.rng.sample(fake_files, min(sample_count, len(fake_files)))
                        for idx_f, f_path in enumerate(sampled_docs):
                            ts_f = t_start + 0.001 * (idx_f + 1)
                            target_p = f_path
                            if sc_id == 7:
                                target_p = os.path.join(self.fake_cloud_dir, os.path.basename(f_path))
                            events_batch.append({
                                "ts": ts_f,
                                "pid": sim_pid,
                                "ppid": None,
                                "proc_key": proc_key,
                                "type": "file_create",
                                "path": target_p,
                            })

                    # 3. Subprocess handling for Scenario 4
                    if sc_id == 4:
                        child_pid = sim_pid + 50000
                        child_key = f"{{sim-child-{sc_id:02d}-{r:03d}}}"
                        store.upsert_process({
                            "proc_key": child_key,
                            "pid": child_pid,
                            "ppid": sim_pid,
                            "name": "python.exe",
                            "start_ts": t_start + 0.01,
                            "end_ts": t_end,
                            "signed": 0,
                        })
                        events_batch.append({
                            "ts": t_start + 0.01,
                            "pid": child_pid,
                            "ppid": sim_pid,
                            "proc_key": child_key,
                            "type": "proc_start",
                        })
                        events_batch.append({
                            "ts": t_start + 0.02,
                            "pid": child_pid,
                            "ppid": sim_pid,
                            "proc_key": child_key,
                            "type": "net_connect",
                            "dest_ip": "127.0.0.1",
                            "dest_port": self.receiver_port,
                            "proto": "tcp",
                            "nbytes": bytes_sent,
                        })
                        events_batch.append({
                            "ts": t_end,
                            "pid": child_pid,
                            "ppid": sim_pid,
                            "proc_key": child_key,
                            "type": "proc_end",
                        })

                    # 4. Network connects for other scenarios
                    elif sc_id in (1, 2, 3, 5, 6, 8):
                        dest_p = self.scenario5_port if sc_id == 5 else self.receiver_port
                        ts_net = t_start + 0.015
                        if sc_id == 2:
                            # Multiple chunk transmissions
                            for chunk_i in range(min(5, max(1, bytes_sent // 256))):
                                events_batch.append({
                                    "ts": ts_net + 0.01 * chunk_i,
                                    "pid": sim_pid,
                                    "ppid": None,
                                    "proc_key": proc_key,
                                    "type": "net_connect",
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": dest_p,
                                    "proto": "tcp",
                                    "nbytes": min(256, bytes_sent),
                                })
                        else:
                            events_batch.append({
                                "ts": ts_net,
                                "pid": sim_pid,
                                "ppid": None,
                                "proc_key": proc_key,
                                "type": "net_connect",
                                "dest_ip": "127.0.0.1",
                                "dest_port": dest_p,
                                "proto": "tcp",
                                "nbytes": bytes_sent,
                            })

                    # 5. Process end event
                    events_batch.append({
                        "ts": t_end,
                        "pid": sim_pid,
                        "ppid": None,
                        "proc_key": proc_key,
                        "type": "proc_end",
                    })

                    store.insert_events_batch(events_batch)

                    # Append to ground truth records
                    gt_record = {
                        "run_id": run_id,
                        "scenario": sc_id,
                        "label": label,
                        "proc_name": "python.exe",
                        "pid": sim_pid,
                        "proc_guid": proc_key,
                        "t_start_utc": t_start_utc,
                        "t_end_utc": t_end_utc,
                        "t_start": t_start,
                        "t_end": t_end,
                    }
                    all_new_runs.append(gt_record)

            # Append new runs to ground_truth.csv
            with open(self.gt_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=GROUND_TRUTH_HEADER)
                if not gt_exists:
                    writer.writeheader()
                for rec in all_new_runs:
                    writer.writerow({
                        "run_id": rec["run_id"],
                        "scenario": rec["scenario"],
                        "label": rec["label"],
                        "proc_name": rec["proc_name"],
                        "pid": rec["pid"],
                        "proc_guid": rec["proc_guid"],
                        "t_start_utc": rec["t_start_utc"],
                        "t_end_utc": rec["t_end_utc"],
                    })

            logger.info("Successfully completed %d simulation runs.", len(all_new_runs))

        finally:
            store.close()
            receiver.stop()

        return all_new_runs

    def build_dataset(
        self,
        runs_per_scenario: int = 12,
        val_leak_ratio: float = 0.5,
        benign_train_ratio: float = 0.6,
        benign_val_ratio: float = 0.2,
    ) -> Dict[str, Dict[str, Any]]:
        """Extract sliding windows, assign ground-truth labels, and split into train/val/test."""
        self.ensure_prerequisites()

        # Run simulations if needed to obtain sufficient runs
        existing_gt = parse_ground_truth(self.gt_path)
        if len(existing_gt) < 9 * runs_per_scenario:
            logger.info("Current ground truth has %d runs; generating more...", len(existing_gt))
            self.run_simulations(runs_per_scenario=runs_per_scenario)

        gt_records = parse_ground_truth(self.gt_path)
        gt_by_key = {r["proc_guid"].strip().lower(): r for r in gt_records}

        # Extract all sliding windows from database
        extractor = SlidingWindowFeatureExtractor(
            window_sec=self.window_sec,
            step_sec=self.step_sec,
        )
        all_windows = extractor.extract_from_db(self.db_path)
        logger.info("Extracted %d sliding windows from %s", len(all_windows), self.db_path)

        labeled_windows: List[Dict[str, Any]] = []

        for w in all_windows:
            pk = str(w.get("proc_key", "")).strip().lower()
            t_s = float(w.get("t_start", 0.0))
            t_e = float(w.get("t_end", 0.0))

            matched_gt = gt_by_key.get(pk)
            if not matched_gt:
                # Check timestamp overlap with any ground truth run
                for rec in gt_records:
                    if rec["t_start"] <= t_e and rec["t_end"] >= t_s:
                        if rec["proc_name"].lower() in str(w.get("proc_key", "")).lower() or pk == rec["proc_guid"].lower():
                            matched_gt = rec
                            break

            if matched_gt:
                label = int(matched_gt["label"])
                scenario = str(matched_gt["scenario"])
                run_id = str(matched_gt["run_id"])
            else:
                label = 0
                scenario = "benign_system"
                run_id = "system"

            labeled_windows.append({
                "proc_key": w["proc_key"],
                "t_start": t_s,
                "t_end": t_e,
                "vector": np.asarray(w["vector"], dtype=float),
                "features": w["features"],
                "label": label,
                "scenario": scenario,
                "run_id": run_id,
            })

        # Separate system benign, sim benign (scenarios 7, 8, 9), and leak (scenarios 1-6)
        system_benign = [w for w in labeled_windows if w["scenario"] == "benign_system"]
        sim_benign = [w for w in labeled_windows if str(w.get("scenario")) in ("7", "8", "9")]
        leak_windows = [w for w in labeled_windows if w["label"] == 1]

        # 1. Temporal split for system benign windows (Train 70%, Val 15%, Test 15%)
        system_benign.sort(key=lambda x: x["t_start"])
        n_sys = len(system_benign)
        n_train_sys = int(n_sys * 0.70)
        n_val_sys = int(n_sys * 0.15)

        train_sys = system_benign[:n_train_sys]
        val_sys = system_benign[n_train_sys : n_train_sys + n_val_sys]
        test_sys = system_benign[n_train_sys + n_val_sys :]

        # 2. Partition simulation benign runs (scenarios 7, 8, 9): 50% val, 50% test (0% train)
        val_sim_benign = []
        test_sim_benign = []
        for sc_id in (7, 8, 9):
            sc_runs = sorted(list({w["run_id"] for w in sim_benign if str(w.get("scenario")) == str(sc_id)}))
            n_v = max(1, int(len(sc_runs) * 0.5))
            v_ids = set(sc_runs[:n_v])
            t_ids = set(sc_runs[n_v:])
            val_sim_benign.extend([w for w in sim_benign if str(w.get("scenario")) == str(sc_id) and w["run_id"] in v_ids])
            test_sim_benign.extend([w for w in sim_benign if str(w.get("scenario")) == str(sc_id) and w["run_id"] in t_ids])

        # 3. Partition leak runs (scenarios 1-6): 50% val, 50% test (0% train)
        val_leak = []
        test_leak = []
        for sc_id in range(1, 7):
            sc_runs = sorted(list({w["run_id"] for w in leak_windows if str(w.get("scenario")) == str(sc_id)}))
            n_v = max(1, int(len(sc_runs) * 0.5))
            v_ids = set(sc_runs[:n_v])
            t_ids = set(sc_runs[n_v:])
            val_leak.extend([w for w in leak_windows if str(w.get("scenario")) == str(sc_id) and w["run_id"] in v_ids])
            test_leak.extend([w for w in leak_windows if str(w.get("scenario")) == str(sc_id) and w["run_id"] in t_ids])

        # Assemble splits: Train is strictly benign (0% leak)
        train_samples = train_sys
        val_samples = val_sys + val_sim_benign + val_leak
        test_samples = test_sys + test_sim_benign + test_leak

        # Shuffle each split
        self.rng.shuffle(train_samples)
        self.rng.shuffle(val_samples)
        self.rng.shuffle(test_samples)

        def to_dataset(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
            if samples:
                X = np.vstack([s["vector"] for s in samples])
                y = np.array([s["label"] for s in samples], dtype=int)
            else:
                X = np.zeros((0, len(FEATURE_NAMES)), dtype=float)
                y = np.zeros(0, dtype=int)
            return {
                "X": X,
                "y": y,
                "meta": [
                    {
                        "proc_key": s["proc_key"],
                        "t_start": s["t_start"],
                        "t_end": s["t_end"],
                        "scenario": s["scenario"],
                        "run_id": s["run_id"],
                        "label": s["label"],
                    }
                    for s in samples
                ],
            }

        dataset = {
            "train": to_dataset(train_samples),
            "val": to_dataset(val_samples),
            "test": to_dataset(test_samples),
        }

        logger.info(
            "Dataset split: Train=%d (benign only), Val=%d (%d leak), Test=%d (%d leak)",
            len(train_samples),
            len(val_samples),
            len(val_leak),
            len(test_samples),
            len(test_leak),
        )

        return dataset
