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
import subprocess
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
    """Manages Windows toast notifications with audio and robust fallback."""

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
        """Deliver native Windows toast notification with audio and robust fallbacks."""
        delivered = False

        # 1. Primary: winotify Windows Toast
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
                delivered = True
            except Exception as e:
                logger.debug("winotify toast failed: %s", e)

        # 2. Secondary fallback: PowerShell (New-BurntToastNotification or WindowsRuntime Toast)
        if not delivered:
            try:
                clean_title = title.replace("'", " ").replace('"', ' ')
                clean_msg = message.replace("'", " ").replace('"', ' ')
                ps_script = (
                    f"try {{ "
                    f"  New-BurntToastNotification -Text '{clean_title}', '{clean_msg}' -ErrorAction Stop; "
                    f"}} catch {{ "
                    f"  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
                    f"  $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                    f"  $textNodes = $template.GetElementsByTagName('text'); "
                    f"  $textNodes.Item(0).AppendChild($template.CreateTextNode('{clean_title}')) > $null; "
                    f"  $textNodes.Item(1).AppendChild($template.CreateTextNode('{clean_msg}')) > $null; "
                    f"  $toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
                    f"  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{self.app_id}').Show($toast); "
                    f"}}"
                )
                subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                    capture_output=True,
                    timeout=2.5,
                )
                delivered = True
            except Exception as e:
                logger.debug("PowerShell toast failed: %s", e)

        # 3. Audio Beep chime
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            try:
                import ctypes
                ctypes.windll.user32.MessageBeep(0x00000030)
            except Exception:
                pass

        # 4. Fallback: non-blocking Windows MessageBox if toast failed to show
        if not delivered:
            def _popup():
                try:
                    import ctypes
                    # MB_ICONWARNING (0x30) | MB_TOPMOST (0x40000)
                    ctypes.windll.user32.MessageBoxW(0, message, title, 0x00000030 | 0x00040000)
                except Exception:
                    pass
            t = threading.Thread(target=_popup, daemon=True)
            t.start()

        # Make strings console safe for legacy Windows code pages
        try:
            safe_title = title.encode("ascii", "replace").decode("ascii")
            safe_msg = message.encode("ascii", "replace").decode("ascii")
            logger.info("[TOAST ALERT] %s - %s (Delivered: %s)", safe_title, safe_msg, delivered)
        except Exception:
            pass
        return delivered


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

        # 3. Query events from the last 120 seconds with robust timestamp normalization
        lookback_sec = 120.0
        cur = self.store.conn.cursor()

        # Check max timestamp in DB in case of simulated or skewed event timestamps
        cur.execute("SELECT MAX(ts) FROM events")
        max_ts_row = cur.fetchone()
        max_ts_val = max_ts_row[0] if (max_ts_row and max_ts_row[0]) else now
        effective_now = max(float(now), float(max_ts_val))
        t_cutoff = effective_now - lookback_sec

        cur.execute("SELECT * FROM events WHERE ts >= ? ORDER BY ts ASC", (t_cutoff,))
        recent_events = [dict(row) for row in cur.fetchall()]

        # Fallback if empty: fetch latest 100 events within 180s of the most recent event
        if not recent_events:
            cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 100")
            recent_events = list(reversed([dict(row) for row in cur.fetchall()]))
            if recent_events:
                last_event_ts = float(recent_events[-1].get("ts", 0))
                recent_events = [e for e in recent_events if (last_event_ts - float(e.get("ts", 0))) <= 180.0]

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

    def trigger_test_alert(
        self,
        proc_name: str = "python.exe",
        pid: int = 8888,
        dest_str: str = "127.0.0.1:8765",
        sample_file: str = "hop_dong_kinh_te.docx",
        score: float = 0.95,
    ) -> Dict[str, Any]:
        """Synthesize and persist a test High-Risk alert, then fire Windows Toast notification.

        Used to verify real-time notification mechanism and database persistence.
        """
        now = time.time()
        proc_key = f"{proc_name}:{pid}"
        bytes_sent = 142560
        bytes_str = format_bytes_human(bytes_sent)

        # Mock structured explanation
        explanation = {
            "headline": f"🔴 [CẢNH BÁO MẪU: KIỂM TRA HỆ THỐNG] Tiến trình {proc_name} (PID: {pid}) gửi dữ liệu nhạy cảm ra ngoài",
            "narrative": (
                f"🔴 [CẢNH BÁO NGUY HIỂM: PHÁT HIỆN GỬI TRỘM DỮ LIỆU (BẢN MẪU KIỂM THỬ)]\n"
                f"- Ứng dụng nghi vấn: {proc_name} (Mã tiến trình: {pid})\n"
                f"- Hành vi bị bắt quả tang: Ứng dụng này vừa lén mở/tạo 1 tệp nhạy cảm của bạn ('{sample_file}'), "
                f"sau đó lập tức kết nối và truyền {bytes_str} dữ liệu ra ngoài Internet tới máy chủ {dest_str}.\n"
                f"- Mức độ đe dọa: Cực kỳ nguy hiểm ({int(score * 100)}% rủi ro rò rỉ bí mật).\n"
                f"- Lộ trình rò rỉ: [Tệp tin '{sample_file}'] ➔ [Tiến trình {proc_name}] ➔ [Mạng Internet: {dest_str}]."
            ),
            "advice": "Tạm dừng hoặc đóng tiến trình ngay lập tức. Cắt kết nối mạng hoặc chặn cổng bằng Firewall.",
            "risk_pct": int(score * 100),
            "proc_name": proc_name,
            "pid": pid,
            "proc_key": proc_key,
            "exe_path": f"C:\\Windows\\System32\\{proc_name}",
            "score": score,
            "detector": "TestAlertSimulator",
            "sensitive_files": [f"C:\\Users\\***\\Documents\\{sample_file}"],
            "sample_files_summary": sample_file,
            "bytes_sent": bytes_sent,
            "bytes_formatted": bytes_str,
            "dest_str": dest_str,
            "country_or_domain": "Localhost (Test Receiver)",
            "has_causal_flow": True,
            "causal_flow_text": "Có (Tệp nhạy cảm -> Tiến trình -> Gửi gói tin mạng)",
            "causal_chain": [
                {"step": 1, "action": "Đọc tệp nhạy cảm", "target": sample_file},
                {"step": 2, "action": "Xử lý dữ liệu", "target": f"{proc_name} (PID {pid})"},
                {"step": 3, "action": "Gửi ra mạng", "target": dest_str},
            ],
            "contributing_factors": [
                {"factor": "Đọc tệp nhạy cảm bảo mật cao", "weight": "+40%"},
                {"factor": "Lượng dữ liệu gửi ra ngoài lớn", "weight": "+30%"},
                {"factor": "Quan hệ nhân quả trực tiếp Đọc-Gửi", "weight": "+25%"},
            ],
            "suggested_firewall_rule": f'netsh advfirewall firewall add rule name="PrivacyGuard Block {proc_name}" dir=out action=block program="C:\\Windows\\System32\\{proc_name}"',
            "safety_warning": "CẢNH BÁO AN TOÀN: Đây là cảnh báo kiểm thử (Test Alert) để xác nhận hệ thống thông báo.",
        }

        # Insert into alerts table
        alert_id = self.store.insert_alert(
            ts=now,
            proc_key=proc_key,
            detector="TestAlertSimulator",
            score=score,
            severity="Cao",
            evidence=json.dumps(explanation, ensure_ascii=False),
            status="new",
        )
        self.alert_count = self.store.count_alerts()

        # Fire Toast Notification
        toast_title = "[PrivacyGuard] CẢNH BÁO: Rò rỉ Dữ liệu Nhạy cảm!"
        toast_msg = (
            f"Tiến trình {proc_name} vừa gửi {bytes_str} dữ liệu "
            f"file '{sample_file}' tới {dest_str}! (Rủi ro: {int(score * 100)}%)"
        )
        delivered = self.notifier.notify(
            title=toast_title,
            message=toast_msg,
            launch_url="http://localhost:8501",
        )

        # Trigger registered callbacks
        for cb in self._alert_callbacks:
            try:
                cb(explanation)
            except Exception as err:
                logger.debug("Alert callback error: %s", err)

        logger.info(
            "[TEST ALERT #%d] Generated high-risk alert for %s (PID: %d, delivered: %s)",
            alert_id,
            proc_name,
            pid,
            delivered,
        )
        return {
            "alert_id": alert_id,
            "proc_name": proc_name,
            "pid": pid,
            "score": score,
            "delivered": delivered,
            "explanation": explanation,
        }

    def stop(self, timeout: float = 3.0) -> None:
        """Stop the background guard thread and close storage connection."""
        self.running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        self.store.close()
        logger.info("RealtimeGuardService stopped successfully.")


def trigger_manual_test_alert(
    db_path: str = "data/privacyguard.db",
    proc_name: str = "python.exe",
    dest_str: str = "127.0.0.1:8765",
    sample_file: str = "hop_dong_kinh_te.docx",
) -> Dict[str, Any]:
    """Convenience helper to create a test alert and trigger toast notification directly."""
    service = RealtimeGuardService(db_path=db_path)
    try:
        return service.trigger_test_alert(
            proc_name=proc_name,
            dest_str=dest_str,
            sample_file=sample_file,
        )
    finally:
        service.stop()

