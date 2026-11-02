"""Real-time Protection Pipeline Worker for PrivacyGuard (M2 research prototype).

Provides continuous monitoring:
1. Periodic background polling of Windows Sysmon operational logs.
2. Sliding window feature extraction on recent process activity.
3. Rule-based causal scoring (Autoencoder is an offline evaluation baseline,
   not part of the live scan path).
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

from core.paths import resolve_path, get_default_config_path, get_default_db_path, PROJECT_ROOT
from collector.sysmon_collector import LiveSysmonCollector, query_latest_record_id
from core.store import EventStore
from core.provenance import build_provenance_graph
from core.features import SlidingWindowFeatureExtractor, features_to_vector
from core.explain import EvidenceExplainer, explain_alert, format_bytes_human
from models.rules import RuleBasedDetector
from core.sensitive import is_sensitive_path

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
        self.last_delivered: bool = False
        self.last_fail_reason: Optional[str] = None

    def notify(
        self,
        title: str,
        message: str,
        launch_url: str = "http://localhost:8501",
    ) -> bool:
        """Deliver native Windows toast notification with audio and robust fallbacks."""
        delivered = False
        fail_reason: Optional[str] = None

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
                fail_reason = f"winotify: {e}"
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
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                    capture_output=True,
                    timeout=2.5,
                )
                if res.returncode == 0:
                    delivered = True
                    fail_reason = None
                else:
                    err_msg = res.stderr.decode("latin1", errors="replace").strip()
                    fail_reason = f"powershell exit {res.returncode}: {err_msg}"
            except Exception as e:
                fail_reason = f"powershell: {e}"
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

        self.last_delivered = delivered
        self.last_fail_reason = fail_reason

        # Make strings console safe for legacy Windows code pages
        try:
            safe_title = title.encode("ascii", "replace").decode("ascii")
            safe_msg = message.encode("ascii", "replace").decode("ascii")
            logger.info(
                "[TOAST NOTIFICATION] Title='%s' | Delivered=%s | Reason=%s",
                safe_title,
                delivered,
                fail_reason or "Delivered successfully",
            )
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
        poll_sysmon: bool = True,
    ):
        self.db_path = resolve_path(db_path) if db_path != ":memory:" else db_path
        self.config_path = resolve_path(config_path)
        self.polling_interval = polling_interval_sec
        self.alert_threshold = alert_threshold
        self.enable_toast = enable_toast
        self.poll_sysmon = poll_sysmon

        self.store = EventStore(db_path=self.db_path)
        self.collector = LiveSysmonCollector(
            db_path=self.db_path,
            config_path=self.config_path,
            backfill=False,
        )
        self.config = getattr(self.collector, "config", {}) or {}
        self.window_extractor = SlidingWindowFeatureExtractor(
            window_sec=60.0,
            step_sec=15.0,
            delta_t_provenance=30.0,
        )
        self.rule_detector = RuleBasedDetector()
        self.explainer = EvidenceExplainer()
        self.notifier = ToastNotifier()

        # Build normalized ignore_processes set (matched by basename lowercase + optional .exe)
        noise_filters = self.config.get("noise_filters", {})
        raw_ignored = noise_filters.get("ignore_processes", ["privacyguard.exe", "collector", "streamlit"])
        self.ignored_process_names: Set[str] = set()
        for item in raw_ignored:
            b = os.path.basename(str(item)).strip().lower()
            if b:
                self.ignored_process_names.add(b)
                if b.endswith(".exe"):
                    self.ignored_process_names.add(b[:-4])
                else:
                    self.ignored_process_names.add(b + ".exe")
        # Ensure self and core utilities are always ignored
        self.ignored_process_names.update([
            "privacyguard",
            "privacyguard.exe",
            "collector",
            "streamlit",
            "tray_app.py",
        ])

        self.running: bool = False
        self.paused: bool = False
        self.alert_count: int = self.store.count_alerts()
        self.sysmon_error: Optional[str] = getattr(self.collector, "sysmon_error", None)
        self.last_scan_ts: float = 0.0
        self.last_scanned_rx_id: int = self.store.get_max_receiver_log_id()
        self.latest_scan_stats: Dict[str, Any] = {}
        self.last_ingested: int = 0
        self.toast_warning: Optional[str] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._processed_alert_keys: Set[str] = set()

    def check_sysmon_status(self) -> tuple[bool, str]:
        """Check whether Sysmon operational channel is accessible or requires elevation."""
        try:
            import win32evtlog
            handle = win32evtlog.EvtQuery(
                self.collector.channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                "*[System[(EventID=1 or EventID=3 or EventID=11)]]",
            )
            return True, "Active (Operational)"
        except ImportError:
            return False, "win32evtlog module not available"
        except Exception as e:
            err_str = str(e)
            if "5" in err_str or "Access is denied" in err_str or "denied" in err_str.lower():
                return False, "Thiếu quyền Admin (Access Denied)"
            return False, f"Lỗi Sysmon: {e}"

    def prepare_live(self) -> int:
        """Synchronize collector watermark to the latest live Sysmon record ID before monitoring."""
        return self.collector.prepare_live()

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

    def scan_now(self, poll_sysmon: Optional[bool] = None) -> int:
        """Execute a single immediate detection cycle over recent events with strict hard gating.

        Args:
            poll_sysmon: Optional override to control whether Sysmon channel is queried.
                         Defaults to self.poll_sysmon.

        Returns:
            Number of new alerts detected.
        """
        now = time.time()
        self.last_scan_ts = now

        # 1. Controlled Sysmon polling (only if enabled)
        should_poll = self.poll_sysmon if poll_sysmon is None else poll_sysmon
        ingested = 0
        if should_poll:
            try:
                ingested = self.collector.poll_channel()
                self.sysmon_error = getattr(self.collector, "sysmon_error", None)
            except Exception as e:
                logger.debug("Error during Sysmon poll: %s", e)
                self.sysmon_error = str(e)
        self.last_ingested = ingested

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

        # 3. Check for new events and pending receiver logs using persistent watermark
        cur = self.store.conn.cursor()
        cur.execute("SELECT MAX(id), MAX(ts) FROM events")
        max_row = cur.fetchone()
        if not max_row or max_row[0] is None:
            return 0

        max_event_id = int(max_row[0])
        max_ts_val = float(max_row[1]) if max_row[1] is not None else now
        last_scanned_id = self.store.get_last_scanned_event_id()
        max_rx_id = self.store.get_max_receiver_log_id()

        # Check if there are any un-enriched net_connect events with nbytes == 0 in the last 60 seconds
        cur.execute("SELECT COUNT(*) FROM events WHERE type IN ('net_connect', 'net_send') AND nbytes = 0 AND ts >= ?", (now - 60.0,))
        pending_zero_bytes_count = int(cur.fetchone()[0])

        # If no new events, no new receiver logs, and no pending zero-byte events, exit immediately!
        if last_scanned_id > 0 and max_event_id <= last_scanned_id and max_rx_id <= self.last_scanned_rx_id and pending_zero_bytes_count == 0:
            return 0

        # Query recent events within bounded lookback window (max 180s from max_ts_val)
        rt_config = self.config.get("realtime_guard", {})
        lookback_sec = float(rt_config.get("lookback_sec", 120.0))
        max_lookback_sec = float(rt_config.get("max_lookback_sec", 180.0))
        t_cutoff = max(float(now) - lookback_sec, max_ts_val - max_lookback_sec)

        cur.execute("SELECT * FROM events WHERE ts >= ? ORDER BY ts ASC", (t_cutoff,))
        recent_events = [dict(row) for row in cur.fetchall()]

        # If no events in lookback window, update watermark and return
        if not recent_events:
            self.store.set_last_scanned_event_id(max_event_id)
            self.last_scanned_rx_id = max_rx_id
            return 0

        # Parse extra_json for src_port if present
        for e in recent_events:
            if not e.get("src_port"):
                extra = e.get("extra_json")
                if isinstance(extra, str):
                    try:
                        e["src_port"] = json.loads(extra).get("src_port")
                    except Exception:
                        pass
                elif isinstance(extra, dict):
                    e["src_port"] = extra.get("src_port")

        # Telemetry enrichment: query unmatched receiver_logs in [t_cutoff - 10, max_ts + 10]
        rx_logs = self.store.get_receiver_logs(
            t_start=t_cutoff - 10.0,
            t_end=max_ts_val + 10.0,
            unmatched_only=True,
        )

        for e in recent_events:
            if e.get("type") in ("net_connect", "net_send") and int(e.get("nbytes", 0)) == 0 and rx_logs:
                e_dest_port = e.get("dest_port")
                e_src_port = e.get("src_port")
                e_ts = float(e.get("ts", 0))

                matched_rx = None
                # Method 1: Match by (dest_port, src_port)
                if e_src_port is not None:
                    candidates = [
                        rx for rx in rx_logs
                        if rx.get("matched_event_id") is None
                        and rx.get("dest_port") == e_dest_port
                        and rx.get("src_port") == e_src_port
                    ]
                    if candidates:
                        matched_rx = min(candidates, key=lambda rx: abs(rx["ts_utc"] - e_ts))

                # Method 2: Match by (dest_port, |ts_utc - event.ts| <= 5s)
                if matched_rx is None and e_dest_port is not None:
                    candidates = [
                        rx for rx in rx_logs
                        if rx.get("matched_event_id") is None
                        and rx.get("dest_port") == e_dest_port
                        and abs(rx["ts_utc"] - e_ts) <= 5.0
                    ]
                    if candidates:
                        matched_rx = min(candidates, key=lambda rx: abs(rx["ts_utc"] - e_ts))

                if matched_rx is not None:
                    real_bytes = int(matched_rx["bytes_received"])
                    e["nbytes"] = real_bytes
                    ev_id = int(e["id"]) if e.get("id") else None
                    rx_id = int(matched_rx["id"])
                    # Mark in-memory candidate so subsequent events in this cycle do not reuse it
                    matched_rx["matched_event_id"] = ev_id or -1
                    if ev_id is not None:
                        try:
                            self.store.update_event_nbytes(ev_id, real_bytes)
                            self.store.set_receiver_log_matched_event_id(rx_id, ev_id)
                        except Exception as err:
                            logger.debug("Failed updating event nbytes or matched_event_id in DB: %s", err)

        # Grace period: only evaluate events with ts <= now - 3 seconds (or offline / already-enriched events)
        scoring_cutoff_ts = now - 3.0
        ready_events = [
            e for e in recent_events
            if (float(e.get("ts", 0)) <= scoring_cutoff_ts) or (not should_poll) or (int(e.get("nbytes", 0)) > 0)
        ]

        # Initialize diagnostic funnel counters
        counts = {
            "ts": now,
            "events_loaded": len(recent_events),
            "not_ready": len(recent_events) - len(ready_events),
            "windows_created": 0,
            "no_proc_key": 0,
            "not_direct_actor": 0,
            "ignored_process": 0,
            "no_causal": 0,
            "bytes_below_min": 0,
            "no_sensitive_file": 0,
            "score_below_threshold": 0,
            "duplicate": 0,
            "alerts_created": 0,
        }

        if not ready_events:
            self.store.insert_scan_stats(counts)
            self.latest_scan_stats = counts
            return 0

        cur.execute("SELECT * FROM processes")
        processes = [dict(row) for row in cur.fetchall()]
        proc_map = {str(p["proc_key"]).strip().lower(): p for p in processes if p.get("proc_key")}

        # 4. Extract sliding window feature records on ready events
        windows = self.window_extractor.extract_windows(
            events=ready_events,
            processes=processes,
        )
        counts["windows_created"] = len(windows)

        min_exfil_bytes = int(rt_config.get("min_exfil_bytes", 1024))
        cooldown_sec = float(rt_config.get("alert_cooldown_sec", 600.0))

        detected_alerts: List[Dict[str, Any]] = []
        cycle_seen_signatures: Set[tuple] = set()

        # Direct actors: processes that directly performed file creation or network connection
        direct_actors = {
            str(e.get("proc_key")).strip().lower()
            for e in ready_events
            if e.get("type") in ("file_create", "net_connect", "net_send") and e.get("proc_key")
        }

        for win in windows:
            vec = win.get("vector")
            feats = win.get("features", {})
            pk = win.get("proc_key")

            # CỔNG 0: Must have valid proc_key
            if not pk:
                counts["no_proc_key"] += 1
                continue

            # CỔNG 0.5: Skip ancestor processes that did not directly generate file or network events
            if direct_actors and str(pk).strip().lower() not in direct_actors:
                counts["not_direct_actor"] += 1
                continue

            p_info = proc_map.get(str(pk).strip().lower(), {})
            raw_name = p_info.get("name") or win.get("proc_name") or ""
            raw_exe = p_info.get("exe_path") or ""
            proc_basename = os.path.basename(raw_name or raw_exe or str(pk)).strip().lower()

            # HARD GATE 1: Process MUST NOT be in ignore_processes
            if proc_basename in self.ignored_process_names or proc_basename.removesuffix(".exe") in self.ignored_process_names:
                counts["ignored_process"] += 1
                continue

            # HARD GATE 2: Must have verified causal flow
            has_causal = feats.get("has_causal_flow", 0.0) > 0.5
            if not has_causal:
                counts["no_causal"] += 1
                continue

            # Extract window events strictly belonging to this proc_key in [t_start, t_end]
            t_start = float(win.get("t_start", 0.0))
            t_end = float(win.get("t_end", 0.0))
            proc_win_events = [
                e for e in ready_events
                if str(e.get("proc_key")).strip().lower() == str(pk).strip().lower()
                and t_start <= float(e.get("ts", 0.0)) <= t_end
            ]

            # HARD GATE 3: Minimum exfiltration bytes threshold (rejects bytes_sent < min_exfil_bytes)
            proc_net_events = [e for e in proc_win_events if e.get("type") in ("net_connect", "net_send")]
            proc_bytes = sum(int(e.get("nbytes", 0)) for e in proc_net_events)
            bytes_sent = proc_bytes if proc_net_events else int(feats.get("total_bytes_sent", 0))
            if bytes_sent < min_exfil_bytes:
                counts["bytes_below_min"] += 1
                continue

            # HARD GATE 4: Must touch at least 1 sensitive file (strictly for this window and proc_key)
            proc_win_files = [
                e.get("path")
                for e in proc_win_events
                if e.get("type") == "file_create"
                and e.get("path")
                and is_sensitive_path(e.get("path"))
            ]
            sensitive_files = list(dict.fromkeys([os.path.normpath(f) for f in proc_win_files]))

            if not sensitive_files:
                counts["no_sensitive_file"] += 1
                continue

            # Scoring: check risk score against threshold
            X = np.array([vec], dtype=np.float32)
            rule_score = float(self.rule_detector.score(X)[0])
            if rule_score < self.alert_threshold:
                counts["score_below_threshold"] += 1
                continue

            # Destination
            dest_ip = "127.0.0.1"
            dest_port = 8765
            if proc_net_events:
                dest_ip = proc_net_events[-1].get("dest_ip") or dest_ip
                dest_port = proc_net_events[-1].get("dest_port") or dest_port
            else:
                dest_ip = win.get("dest_ip") or dest_ip
                dest_port = win.get("dest_port") or dest_port
            dest_str = f"{dest_ip}:{dest_port}"

            norm_file_tuple = tuple(sorted([os.path.basename(f).strip().lower() for f in sensitive_files]))

            # In-cycle deduplication (prevent duplicate alerts for the same incident in the same scan cycle)
            incident_sig = (str(pk), dest_str, norm_file_tuple)
            if incident_sig in cycle_seen_signatures:
                counts["duplicate"] += 1
                continue
            cycle_seen_signatures.add(incident_sig)

            # HARD GATE 5: Persistent deduplication against alerts table in DB within cooldown_sec
            if self.store.has_recent_similar_alert(
                proc_key=str(pk),
                dest_str=dest_str,
                sample_files=sensitive_files,
                cooldown_sec=cooldown_sec,
                now=now,
            ):
                counts["duplicate"] += 1
                continue

            # Populate window metadata strictly for this process and window
            win["sensitive_files"] = sensitive_files
            win["dest_ip"] = dest_ip
            win["dest_port"] = dest_port
            feats["total_bytes_sent"] = bytes_sent
            feats["n_sensitive_files"] = len(sensitive_files)

            # Build local provenance graph strictly for this proc_key's window events (no global G)
            local_G = build_provenance_graph(proc_win_events, delta_t_sec=30.0)

            proc_name = p_info.get("name") or win.get("proc_name") or "unknown.exe"
            pid = p_info.get("pid") or win.get("pid") or 0

            # Format alert dictionary
            explanation = explain_alert(
                window=win,
                detector_name="RuleBased",
                score=rule_score,
                proc_info=p_info,
                provenance_graph=local_G,
            )

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
            counts["alerts_created"] += 1

            logger.warning(
                "[REALTIME ALERT #%d] High Risk Exfiltration from %s (PID: %s, Score: %.2f, Bytes: %d)",
                alert_id,
                proc_name,
                pid,
                rule_score,
                bytes_sent,
            )

            detected_alerts.append({
                "alert_id": alert_id,
                "proc_name": proc_name,
                "pid": pid,
                "score": rule_score,
                "bytes_sent": bytes_sent,
                "dest_str": dest_str,
                "explanation": explanation,
            })

            # Invoke UI callbacks
            for cb in self._alert_callbacks:
                try:
                    cb(explanation)
                except Exception as err:
                    logger.debug("Alert callback error: %s", err)

        # Strict funnel balance verification: windows_created must equal the sum of all terminal branches
        total_accounted = (
            counts["no_proc_key"]
            + counts["not_direct_actor"]
            + counts["ignored_process"]
            + counts["no_causal"]
            + counts["bytes_below_min"]
            + counts["no_sensitive_file"]
            + counts["score_below_threshold"]
            + counts["duplicate"]
            + counts["alerts_created"]
        )
        if total_accounted != counts["windows_created"]:
            logger.warning(
                "Funnel mismatch: windows_created=%d != total_accounted=%d (diff=%d)",
                counts["windows_created"],
                total_accounted,
                counts["windows_created"] - total_accounted,
            )
        assert total_accounted == counts["windows_created"], (
            f"Funnel mismatch: windows_created={counts['windows_created']} != total_accounted={total_accounted}"
        )

        # Record diagnostic stats for the scan cycle
        self.store.insert_scan_stats(counts)
        self.latest_scan_stats = counts

        # 5. Persist watermark without advancing past unready zero-byte network events
        unready_ids = [
            int(e["id"]) for e in recent_events
            if e.get("id") is not None and (
                (float(e.get("ts", 0)) > scoring_cutoff_ts and int(e.get("nbytes", 0)) == 0)
                or (e.get("type") in ("net_connect", "net_send") and int(e.get("nbytes", 0)) == 0 and (now - float(e.get("ts", 0))) < 15.0)
            )
        ]

        if unready_ids:
            min_unready_id = min(unready_ids)
            new_watermark = max(last_scanned_id, min_unready_id - 1)
        else:
            new_watermark = max_event_id

        self.store.set_last_scanned_event_id(new_watermark)
        self.last_scanned_rx_id = max_rx_id

        # 6. Single consolidated Toast Notification per scan cycle with transparency
        if self.enable_toast and detected_alerts:
            if len(detected_alerts) == 1:
                al = detected_alerts[0]
                t_title = "[PrivacyGuard] Phát hiện Rò rỉ Dữ liệu!"
                t_msg = (
                    f"Tiến trình {al['proc_name']} đã gửi {format_bytes_human(al['bytes_sent'])} ra ngoài ({al['dest_str']}) "
                    f"sau khi truy cập file nhạy cảm. Click để mở Dashboard."
                )
            else:
                top_al = max(detected_alerts, key=lambda a: a["score"])
                t_title = f"[PrivacyGuard] Phát hiện {len(detected_alerts)} Vụ Rò rỉ Dữ liệu!"
                t_msg = (
                    f"Nghiêm trọng nhất: {top_al['proc_name']} (Điểm: {int(top_al['score'] * 100)}%) "
                    f"đã gửi {format_bytes_human(top_al['bytes_sent'])} ra {top_al['dest_str']}. Click để mở Dashboard."
                )
            delivered = self.notifier.notify(
                title=t_title,
                message=t_msg,
                launch_url="http://localhost:8501",
            )
            if not delivered:
                self.toast_warning = (
                    f"⚠️ Toast Windows bị chặn bởi OS ({getattr(self.notifier, 'last_fail_reason', 'Muted')}). "
                    f"Cảnh báo ({len(detected_alerts)} vụ) đã được lưu đầy đủ vào Database."
                )
            else:
                self.toast_warning = None

        return len(detected_alerts)

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

    def stop(self) -> None:
        """Stop the background guard thread."""
        self.running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("RealtimeGuardService stopped successfully.")

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
            "severity": "Cao",
            "risk_level": "Cao",
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

