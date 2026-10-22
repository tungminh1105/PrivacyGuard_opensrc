"""Feature Extraction Module for PrivacyGuard.

Extracts multidimensional temporal feature vectors from sliding windows per process tree.
Adheres strictly to Sysmon telemetry limitations (no fabricated file_read events).
"""

from __future__ import annotations

import logging
import math
import os
import statistics
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import numpy as np
except ImportError:
    np = None

from core.sensitive import get_sensitivity_score, is_sensitive_path
from core.intel import IntelTracker, is_local_ip, is_tracker
from core.provenance import ProcessHierarchy, build_provenance_graph

logger = logging.getLogger(__name__)

FEATURE_NAMES: List[str] = [
    "n_file_create",
    "n_sensitive_files",
    "ratio_sensitive_events",
    "n_distinct_dirs",
    "n_net_connect",
    "total_bytes_sent",
    "n_distinct_dest_ips",
    "n_new_dest",
    "dest_is_tracker",
    "is_local_dest_only",
    "n_child_proc",
    "is_signed_process",
    "process_lifetime",
    "burstiness",
    "hour_of_day_sin",
    "hour_of_day_cos",
    "has_causal_flow",
]


def sanitize_float(val: Any, default: float = 0.0) -> float:
    """Ensure float value is finite, non-NaN, and non-None."""
    if val is None:
        return default
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return f
    except (ValueError, TypeError):
        return default


def compute_burstiness(timestamps: List[float]) -> float:
    """Calculate burstiness (coefficient of variation of inter-arrival times).

    B = std(dt) / (mean(dt) + 1e-6)
    Returns 0.0 if fewer than 2 events.
    """
    if len(timestamps) < 2:
        return 0.0

    sorted_ts = sorted(timestamps)
    intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    if not intervals or len(intervals) < 2:
        return 0.0

    try:
        mean_dt = statistics.mean(intervals)
        std_dt = statistics.stdev(intervals)
        cv = std_dt / (mean_dt + 1e-6)
        return sanitize_float(cv)
    except Exception:
        return 0.0


def extract_window_features(
    proc_key: str,
    window_events: List[Dict[str, Any]],
    t_start: float,
    t_end: float,
    proc_info: Optional[Dict[str, Any]] = None,
    intel_tracker: Optional[IntelTracker] = None,
    provenance_graph: Optional[Any] = None,
) -> Dict[str, float]:
    """Extract a dictionary of numerical features for a single process sliding window.

    Args:
        proc_key: Process identifier.
        window_events: List of events falling within [t_start, t_end] for this process tree.
        t_start: Start timestamp of the window (epoch seconds).
        t_end: End timestamp of the window (epoch seconds).
        proc_info: Metadata dictionary for the process (signed, start_ts, etc.).
        intel_tracker: IntelTracker instance for destination first-seen checks.
        provenance_graph: Optional NetworkX DiGraph for causal path verification.

    Returns:
        Dict mapping feature name to float value. Guaranteed zero NaNs or Nones.
    """
    proc_meta = proc_info or {}
    tracker = intel_tracker or IntelTracker()

    # 1. File metrics (Sysmon Event 11 FileCreate)
    file_creates = [e for e in window_events if e.get("type") == "file_create"]
    n_file_create = float(len(file_creates))

    sensitive_files: Set[str] = set()
    distinct_dirs: Set[str] = set()

    for fe in file_creates:
        path = fe.get("path")
        if path:
            if is_sensitive_path(path):
                sensitive_files.add(os.path.normpath(path).lower())
            d = os.path.dirname(os.path.normpath(path))
            if d:
                distinct_dirs.add(d.lower())

    n_sensitive_files = float(len(sensitive_files))
    ratio_sensitive = n_sensitive_files / max(1.0, n_file_create)
    n_distinct_dirs = float(len(distinct_dirs))

    # 2. Network metrics (Sysmon Event 3 NetworkConnect)
    net_connects = [e for e in window_events if e.get("type") in ("net_connect", "net_send")]
    n_net_connect = float(len(net_connects))

    total_bytes = 0.0
    dest_ips: Set[str] = set()
    net_timestamps: List[float] = []

    for ne in net_connects:
        total_bytes += sanitize_float(ne.get("nbytes", 0))
        ip = ne.get("dest_ip")
        if ip:
            dest_ips.add(ip.strip())
        net_timestamps.append(float(ne.get("ts", t_start)))

    n_distinct_dest_ips = float(len(dest_ips))

    # 3. Destination Intelligence
    n_new_dest = 0.0
    dest_is_tracker = 0.0
    is_local_only = 1.0 if (dest_ips and all(is_local_ip(ip) for ip in dest_ips)) else 0.0

    for ip in dest_ips:
        if tracker.is_new_destination(proc_key, ip, ts=t_start):
            n_new_dest += 1.0
        if is_tracker(ip):
            dest_is_tracker = 1.0

    # 4. Process Lifecycle & Lineage
    child_spawns = [e for e in window_events if e.get("type") == "proc_start" and e.get("proc_key") != proc_key]
    n_child_proc = float(len(child_spawns))

    is_signed = 1.0 if proc_meta.get("signed") == 1 else 0.0

    proc_start_ts = sanitize_float(proc_meta.get("start_ts"), default=t_start)
    lifetime = max(0.0, t_end - proc_start_ts)

    # 5. Temporal Dynamics (Burstiness & Time of Day)
    burstiness = compute_burstiness(net_timestamps)

    dt_obj = datetime.fromtimestamp(t_start, tz=timezone.utc)
    hour = dt_obj.hour + (dt_obj.minute / 60.0)
    hour_sin = math.sin(2.0 * math.pi * hour / 24.0)
    hour_cos = math.cos(2.0 * math.pi * hour / 24.0)

    # 6. Provenance Causality
    has_causal_flow = 0.0
    if provenance_graph is not None:
        try:
            # Check if any sensitive file node connects to any socket node
            file_nodes = [
                n for n, a in provenance_graph.nodes(data=True)
                if a.get("node_type") == "file" and a.get("is_sensitive", False)
            ]
            socket_nodes = [
                n for n, a in provenance_graph.nodes(data=True)
                if a.get("node_type") == "socket"
            ]
            for fn in file_nodes:
                for sn in socket_nodes:
                    if provenance_graph.has_edge(fn, sn):
                        has_causal_flow = 1.0
                        break
                if has_causal_flow > 0.0:
                    break
        except Exception:
            pass
    elif n_sensitive_files > 0 and n_net_connect > 0:
        # Fallback heuristic: both sensitive files and network events co-occur in the same window
        has_causal_flow = 1.0

    features = {
        "n_file_create": sanitize_float(n_file_create),
        "n_sensitive_files": sanitize_float(n_sensitive_files),
        "ratio_sensitive_events": sanitize_float(ratio_sensitive),
        "n_distinct_dirs": sanitize_float(n_distinct_dirs),
        "n_net_connect": sanitize_float(n_net_connect),
        "total_bytes_sent": sanitize_float(total_bytes),
        "n_distinct_dest_ips": sanitize_float(n_distinct_dest_ips),
        "n_new_dest": sanitize_float(n_new_dest),
        "dest_is_tracker": sanitize_float(dest_is_tracker),
        "is_local_dest_only": sanitize_float(is_local_only),
        "n_child_proc": sanitize_float(n_child_proc),
        "is_signed_process": sanitize_float(is_signed),
        "process_lifetime": sanitize_float(lifetime),
        "burstiness": sanitize_float(burstiness),
        "hour_of_day_sin": sanitize_float(hour_sin),
        "hour_of_day_cos": sanitize_float(hour_cos),
        "has_causal_flow": sanitize_float(has_causal_flow),
    }

    return features


def features_to_vector(features_dict: Dict[str, float]) -> Any:
    """Convert a feature dictionary into an ordered 1D vector (NumPy array or list)."""
    vals = [sanitize_float(features_dict.get(name, 0.0)) for name in FEATURE_NAMES]
    if np is not None:
        return np.array(vals, dtype=np.float64)
    return vals


class SlidingWindowFeatureExtractor:
    """Extracts sliding window feature records from a stream of events."""

    def __init__(
        self,
        window_sec: float = 60.0,
        step_sec: float = 15.0,
        delta_t_provenance: float = 30.0,
    ):
        self.window_sec = window_sec
        self.step_sec = step_sec
        self.delta_t_provenance = delta_t_provenance
        self.intel_tracker = IntelTracker()

    def extract_windows(
        self,
        events: List[Dict[str, Any]],
        processes: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Slice events into sliding windows per process family and extract feature vectors.

        Returns list of dicts:
          {
            "proc_key": str,
            "t_start": float,
            "t_end": float,
            "features": Dict[str, float],
            "vector": np.ndarray / List[float],
            "n_events": int,
          }
        """
        if not events:
            return []

        hierarchy = ProcessHierarchy(processes or [])
        proc_meta_map: Dict[str, Dict[str, Any]] = {}
        if processes:
            for p in processes:
                pk = p.get("proc_key")
                if pk:
                    proc_meta_map[str(pk).strip().lower()] = p

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: float(e.get("ts", 0.0)))
        t_min = float(sorted_events[0].get("ts", 0.0))
        t_max = float(sorted_events[-1].get("ts", 0.0))

        # Identify all distinct root processes
        all_proc_keys = {
            str(e.get("proc_key")).strip().lower()
            for e in sorted_events
            if e.get("proc_key")
        }

        records: List[Dict[str, Any]] = []

        # Iterate in steps
        curr_start = t_min
        while curr_start <= t_max:
            curr_end = curr_start + self.window_sec

            # Events in this time window
            window_slice = [
                e for e in sorted_events
                if curr_start <= float(e.get("ts", 0.0)) <= curr_end
            ]

            if window_slice:
                # Group by process family
                for root_pk in all_proc_keys:
                    family_keys = hierarchy.get_family_keys(root_pk)
                    family_events = [
                        e for e in window_slice
                        if str(e.get("proc_key")).strip().lower() in family_keys
                    ]

                    if family_events:
                        # Build local window provenance graph
                        g = build_provenance_graph(family_events, delta_t_sec=self.delta_t_provenance)

                        f_dict = extract_window_features(
                            proc_key=root_pk,
                            window_events=family_events,
                            t_start=curr_start,
                            t_end=curr_end,
                            proc_info=proc_meta_map.get(root_pk),
                            intel_tracker=self.intel_tracker,
                            provenance_graph=g,
                        )
                        vector = features_to_vector(f_dict)

                        records.append({
                            "proc_key": root_pk,
                            "t_start": curr_start,
                            "t_end": curr_end,
                            "features": f_dict,
                            "vector": vector,
                            "n_events": len(family_events),
                        })

            curr_start += self.step_sec

        return records

    def extract_from_db(
        self,
        db_path: str,
    ) -> List[Dict[str, Any]]:
        """Load events and processes from SQLite database and extract sliding window features."""
        import sqlite3

        if not os.path.exists(db_path):
            logger.warning("Database file not found: %s", db_path)
            return []

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM events ORDER BY ts ASC")
            events = [dict(row) for row in cur.fetchall()]

            cur.execute("SELECT * FROM processes")
            processes = [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

        return self.extract_windows(events=events, processes=processes)
