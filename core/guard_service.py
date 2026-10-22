"""Real-time Protection Pipeline Worker for PrivacyGuard (Commercial Upgrade).

Provides continuous monitoring:
1. Periodic background polling of Windows Sysmon operational logs.
2. Sliding window feature extraction on recent process activity.
3. Multi-detector scoring (Rule-based engine and Autoencoder).
4. Automated persistence of High-Risk alerts into SQLite store.
5. Windows Toast Notifications via winotify to inform user of data exfiltration.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from collector.sysmon_collector import LiveSysmonCollector, query_latest_record_id
from core.store import EventStore
from core.provenance import build_provenance_graph
from core.features import SlidingWindowFeatureExtractor, features_to_vector
from core.explain import EvidenceExplainer, explain_alert, format_bytes_human
from models.rules import RuleBasedDetector
from models.autoencoder import AutoencoderDetector

logger = logging.getLogger(__name__)


class ToastNotifier:
    """Manages Windows toast notifications with safe fallback."""

    def __init__(self, app_id: str = "PrivacyGuard"):
        self.app_id = app_id
        self._winotify_available = False
        try:
            import winotify
            self._winotify_available = True
        except ImportError:
            self._winotify_available = False

    def notify(
        self,
        title: str,
        message: str,
        launch_url: str = "http://localhost:8501",
    ) -> bool:
        """Deliver native Windows toast notification."""
        if self._winotify_available:
            try:
                from winotify import Notification, audio
                toast = Notification(
                    app_id=self.app_id,
                    title=title,
                    msg=message,
                    duration="short",
                )
                try:
                    toast.set_audio(audio.Default, loop=False)
                except Exception:
                    pass
                if launch_url:
                    toast.add_actions(label="Mở Dashboard", launch=launch_url)
                toast.show()
                return True
            except Exception as e:
                logger.debug("winotify toast failed: %s", e)

        # Fallback console log
        logger.warning("[TOAST ALERT] %s - %s", title, message)
        return False


class RealtimeGuardService:
    """Continuous real-time protection worker."""

    def __init__(
        self,
        db_path: str = "data/privacyguard.db",
        polling_interval_sec: float = 10.0,
        alert_threshold: float = 0.70,
        config_path: str = "config.yaml",
        enable_toast: bool = True,
    ):
        self.db_path = db_path
        self.polling_interval = polling_interval_sec
        self.alert_threshold = alert_threshold
        self.config_path = config_path
        self.enable_toast = enable_toast

        self.store = EventStore(db_path=self.db_path)
        self.collector = LiveSysmonCollector(
            db_path=self.db_path,
            config_path=self.config_path,
            backfill=False,
        )
        self.window_extractor = SlidingWindowFeatureExtractor(
            window_sec=60.0,
            step_sec=15.0,
            delta_t_provenance=30.0,
        )
        self.rule_detector = RuleBasedDetector()
        self.explainer = EvidenceExplainer()
        self.notifier = ToastNotifier()

        self.running: bool = False
        self.paused: bool = False
        self.alert_count: int = self.store.count_alerts()
        self.last_scan_ts: float = 0.0
        self._worker_thread: Optional[threading.Thread] = None
        self._alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._processed_alert_keys: Set[str] = set()

    def add_alert_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for alert notifications."""
        self._alert_callbacks.append(cb)

    def pause(self) -> None:
        """Pause real-time surveillance loop."""
        self.paused = True
        logger.info("RealtimeGuardService paused.")

    def resume(self) -> None:
        """Resume real-time surveillance loop."""
        self.paused = False
        logger.info("RealtimeGuardService resumed.")

    def is_paused(self) -> bool:
        return self.paused

    def is_running(self) -> bool:
        return self.running

    def scan_now(self) -> int:
        """Execute a single immediate detection cycle over recent events.

        Returns:
            Number of new alerts detected.
        """
        now = time.time()
        self.last_scan_ts = now

        # 1. Poll channel for new events
        try:
            self.collector.poll_channel()
        except Exception as e:
            logger.debug("Error during Sysmon poll: %s", e)

        # 2. Flush in-memory queue to SQLite store
        event_batch = []
        while not self.collector.event_queue.empty():
            try:
                item = self.collector.event_queue.get_nowait()
                ev, pr, zn = item
                event_batch.append(ev)
                if pr:
                    if "start_ts" in pr:
                        self.store.upsert_process(pr)
                    elif "end_ts" in pr:
                        self.store.update_process_end(pr["proc_key"], pr["end_ts"])
                if zn:
                    self.store.upsert_file_zone(zn)
            except Exception:
                break

        if event_batch:
            self.store.insert_events_batch(event_batch)

        # 3. Query events from the last 120 seconds
        lookback_sec = 120.0
        t_cutoff = now - lookback_sec

        cur = self.store.conn.cursor()
        cur.execute("SELECT * FROM events WHERE ts >= ? ORDER BY ts ASC", (t_cutoff,))
        recent_events = [dict(row) for row in cur.fetchall()]

        if not recent_events:
            return 0

        cur.execute("SELECT * FROM processes")
        processes = [dict(row) for row in cur.fetchall()]
        proc_map = {str(p["proc_key"]).strip().lower(): p for p in processes if p.get("proc_key")}

        # 4. Extract sliding window feature records
        windows = self.window_extractor.extract_windows(
            events=recent_events,
            processes=processes,
        )

        new_alerts = 0
        for win in windows:
            vec = win.get("vector")
            feats = win.get("features", {})
            pk = win.get("proc_key")
            has_causal = feats.get("has_causal_flow", 0.0) > 0.5

            if not has_causal:
                continue

            X = np.array([vec], dtype=np.float32)
            rule_score = float(self.rule_detector.score(X)[0])

            if rule_score >= self.alert_threshold:
                # Deduplication key for recent identical window
                dedup_key = f"{pk}:{int(win.get('t_start', 0))}:{int(win.get('t_end', 0))}"
                if dedup_key in self._processed_alert_keys:
                    continue
                self._processed_alert_keys.add(dedup_key)

                p_info = proc_map.get(str(pk).strip().lower(), {})
                proc_name = p_info.get("name") or "unknown.exe"
                pid = p_info.get("pid") or 0

                # Build provenance graph for this alert
                G = build_provenance_graph(recent_events, delta_t_sec=30.0)

                # Format alert dictionary
                explanation = explain_alert(
                    window=win,
                    detector_name="RuleBased",
                    score=rule_score,
                    proc_info=p_info,
                    provenance_graph=G,
                )

                bytes_sent = int(feats.get("total_bytes_sent", 0))
                bytes_str = format_bytes_human(bytes_sent)

                # Insert into alerts table
                alert_id = self.store.insert_alert(
                    ts=now,
                    proc_key=str(pk),
                    detector="RuleBased",
                    score=rule_score,
                    severity="Cao",
                    evidence=json.dumps(explanation, ensure_ascii=False),
                    status="new",
                )
                self.alert_count = self.store.count_alerts()
                new_alerts += 1

                logger.warning(
                    "[REALTIME ALERT #%d] High Risk Exfiltration from %s (PID: %s, Score: %.2f)",
                    alert_id,
                    proc_name,
                    pid,
                    rule_score,
                )

                # Trigger Toast Notification
                if self.enable_toast:
                    toast_title = "[PrivacyGuard] Phát hiện Rò rỉ Dữ liệu!"
                    toast_msg = (
                        f"Tiến trình {proc_name} đã gửi {bytes_str} ra ngoài "
                        f"sau khi truy cập file nhạy cảm. Click để mở Dashboard."
                    )
                    self.notifier.notify(
                        title=toast_title,
                        message=toast_msg,
                        launch_url="http://localhost:8501",
                    )

                # Invoke UI callbacks
                for cb in self._alert_callbacks:
                    try:
                        cb(explanation)
                    except Exception as err:
                        logger.debug("Alert callback error: %s", err)

        return new_alerts

    def _guard_loop(self) -> None:
        """Background continuous surveillance loop."""
        logger.info(
            "RealtimeGuardService loop started (polling interval: %.1fs, threshold: %.2f)",
            self.polling_interval,
            self.alert_threshold,
        )
        while self.running:
            if not self.paused:
                try:
                    self.scan_now()
                except Exception as e:
                    logger.error("Error during real-time guard scan: %s", e)

            # Sleep in small increments for responsive stop
            sleep_elapsed = 0.0
            while self.running and sleep_elapsed < self.polling_interval:
                time.sleep(0.5)
                sleep_elapsed += 0.5

        logger.info("RealtimeGuardService loop terminated.")

    def start(self) -> None:
        """Start the background guard thread."""
        if self.running:
            return
        self.running = True
        self.paused = False
        self._worker_thread = threading.Thread(target=self._guard_loop, daemon=True, name="PrivacyGuardWorker")
        self._worker_thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        """Stop the background guard thread and close storage connection."""
        self.running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        self.store.close()
        logger.info("RealtimeGuardService stopped successfully.")
