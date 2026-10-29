"""Windows System Tray Application for PrivacyGuard (Commercial Upgrade).

Provides an interactive system tray icon in the Windows taskbar notifications area:
- Real-time protection status monitoring (Running / Paused / Admin Required).
- One-click launch for the Streamlit Web Dashboard.
- Immediate manual scan trigger (Scan Now).
- Live alert counter continuously synced with canonical SQLite database.
- Periodic 2-second background refresh to update tooltip and menu dynamic labels.
- Startup diagnostics logged to data/privacyguard.log.
- Graceful termination of background worker daemon.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from typing import Optional

from PIL import Image, ImageDraw
import pystray
from pystray import Menu, MenuItem

# Centralized path resolver
from core.paths import (
    PROJECT_ROOT,
    get_project_root,
    resolve_path,
    get_default_db_path,
    get_default_config_path,
    cleanup_dist_stray_db,
)
from core.guard_service import RealtimeGuardService

find_project_root = get_project_root

logger = logging.getLogger("privacyguard.tray")


def configure_tray_logger() -> str:
    """Configure persistent logging to data/privacyguard.log."""
    log_path = resolve_path("data/privacyguard.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)
    return log_path


def is_port_listening(host: str = "127.0.0.1", port: int = 8501, timeout: float = 0.3) -> bool:
    """Check if a network socket port is currently listening and accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def get_asset_path(filename: str) -> Optional[str]:
    """Resolve asset file path across standalone executable and source environments."""
    candidates = []
    # 1. PyInstaller temporary extraction folder
    if hasattr(sys, "_MEIPASS"):
        candidates.append(os.path.join(sys._MEIPASS, "assets", filename))
        candidates.append(os.path.join(sys._MEIPASS, filename))
    # 2. Directory containing the running executable
    if hasattr(sys, "executable") and sys.executable:
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, "assets", filename))
        candidates.append(os.path.join(exe_dir, filename))
    # 3. Project root directory
    candidates.append(os.path.join(PROJECT_ROOT, "assets", filename))
    candidates.append(os.path.join(PROJECT_ROOT, filename))

    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None


def get_python_executable() -> str:
    """Find appropriate python interpreter, prioritizing project .venv in PROJECT_ROOT."""
    venv_py = os.path.abspath(os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe"))
    if os.path.exists(venv_py):
        return venv_py
    if not getattr(sys, "frozen", False) and "python" in os.path.basename(sys.executable).lower():
        return sys.executable
    sys_py = shutil.which("python")
    return sys_py or "python"


def create_shield_icon_image(size: int = 64, color: tuple = (16, 185, 129)) -> Image.Image:
    """Dynamically generate a professional cybersecurity shield icon using Pillow."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    scale = size / 64.0

    def pt(x, y):
        return (int(x * scale), int(y * scale))

    shield_pts = [
        pt(32, 4),
        pt(58, 14),
        pt(58, 38),
        pt(32, 60),
        pt(6, 38),
        pt(6, 14),
    ]
    fill_rgba = (color[0], color[1], color[2], 255)
    outline_rgba = (max(0, color[0] - 30), max(0, color[1] - 30), max(0, color[2] - 30), 255)

    d.polygon(shield_pts, fill=fill_rgba, outline=outline_rgba, width=max(1, int(2 * scale)))

    # Inner checkmark in white
    check_pts = [pt(22, 32), pt(29, 40), pt(44, 22)]
    d.line(check_pts, fill=(255, 255, 255, 255), width=max(2, int(4 * scale)))

    return img


class PrivacyGuardTrayApp:
    """Manages the Windows taskbar notification tray icon and background guard daemon."""

    def __init__(
        self,
        db_path: str = "data/privacyguard.db",
        polling_interval: float = 10.0,
        dashboard_port: int = 8501,
    ):
        # 1. Standardize absolute paths
        self.db_path = resolve_path(db_path)
        self.config_path = get_default_config_path()
        self.dashboard_port = dashboard_port

        # 2. Configure file logging
        log_file = configure_tray_logger()

        # 3. Clean up any empty stray database in dist/
        cleanup_dist_stray_db()

        # 4. Initialize real-time protection worker
        self.guard_service = RealtimeGuardService(
            db_path=self.db_path,
            polling_interval_sec=polling_interval,
            alert_threshold=0.70,
            config_path=self.config_path,
            enable_toast=True,
        )

        # 5. Check Sysmon availability and rights
        is_sysmon_ok, sysmon_status = self.guard_service.check_sysmon_status()
        self._sysmon_error: Optional[str] = None if is_sysmon_ok else sysmon_status

        # 6. Read actual alert count from DB
        initial_alerts = self.query_db_alert_count()
        self.guard_service.alert_count = initial_alerts
        self._last_rendered_count = initial_alerts

        # 7. Write clear startup log banner
        logger.info("==================================================")
        logger.info("      PRIVACYGUARD SYSTEM TRAY STARTUP")
        logger.info("==================================================")
        logger.info("  CWD:                 %s", os.getcwd())
        logger.info("  PROJECT_ROOT:        %s", PROJECT_ROOT)
        logger.info("  Canonical DB path:   %s", self.db_path)
        logger.info("  Config path:         %s", self.config_path)
        logger.info("  Log file:            %s", log_file)
        logger.info("  Current DB Alerts:   %d", initial_alerts)
        logger.info("  Sysmon Status:       %s", sysmon_status)
        logger.info("==================================================")

        self._streamlit_proc: Optional[subprocess.Popen] = None
        self._icon: Optional[pystray.Icon] = None
        self._running: bool = False
        self._refresh_thread: Optional[threading.Thread] = None

        # Load or generate icon image
        icon_path = get_asset_path("icon.png") or get_asset_path("icon.ico")
        if icon_path and os.path.exists(icon_path):
            try:
                self.icon_image = Image.open(icon_path)
            except Exception:
                self.icon_image = create_shield_icon_image()
        else:
            self.icon_image = create_shield_icon_image()

        # Connect callback to update icon tooltip on new alerts
        self.guard_service.add_alert_callback(self._on_alert_detected)

    def query_db_alert_count(self) -> int:
        """Query alert count directly from canonical SQLite database."""
        try:
            if os.path.exists(self.db_path):
                conn = sqlite3.connect(self.db_path, timeout=1.0)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM alerts")
                row = cur.fetchone()
                count = int(row[0]) if row else 0
                conn.close()
                return count
        except Exception as e:
            logger.debug("Failed querying alert count from db (%s): %s", self.db_path, e)
        return 0

    def get_alert_count_text(self, item: MenuItem) -> str:
        """Return dynamic alert count label queried directly from SQLite (no RAM fallback)."""
        count = self.query_db_alert_count()
        self.guard_service.alert_count = count
        return f"Xem số cảnh báo ({count} alerts)"

    def get_status_text(self, item: MenuItem) -> str:
        """Return dynamic status text for the context menu."""
        if self._sysmon_error or getattr(self.guard_service, "sysmon_error", None):
            return "Trạng thái: Lỗi quyền Admin (Chạy lại bằng Run as administrator)"
        if self.guard_service.is_paused():
            return "Trạng thái: Đã tạm dừng (Paused)"
        tw = getattr(self.guard_service, "toast_warning", None)
        if tw:
            return "Trạng thái: Đang bảo vệ (⚠️ Toast bị chặn bởi OS, xem Dashboard)"
        return "Trạng thái: Đang bảo vệ (Running)"

    def _determine_title(self, count: int) -> str:
        """Compute the appropriate icon title/tooltip based on current system state."""
        if self._sysmon_error or getattr(self.guard_service, "sysmon_error", None):
            return "PrivacyGuard - Lỗi quyền Admin - chạy lại bằng Run as administrator"
        if self.guard_service.is_paused():
            return "PrivacyGuard - Đã tạm dừng bảo vệ"
        tw = getattr(self.guard_service, "toast_warning", None)
        if tw:
            return f"PrivacyGuard - {count} cảnh báo (Toast bị tắt bởi OS, xem Dashboard)"
        return f"PrivacyGuard - Đang bảo vệ ({count} cảnh báo)"

    def _on_alert_detected(self, alert_data: dict) -> None:
        """Callback invoked whenever the guard service detects a High Risk exfiltration."""
        count = self.query_db_alert_count()
        self.guard_service.alert_count = count
        self._last_rendered_count = count
        if self._icon:
            self._icon.title = f"PrivacyGuard - Phát hiện {count} cảnh báo rủi ro!"
            try:
                self._icon.update_menu()
            except Exception as e:
                logger.debug("Failed updating tray menu on alert: %s", e)

    def toggle_pause(self, icon: pystray.Icon, item: MenuItem) -> None:
        """Toggle protection pause/resume."""
        count = self.query_db_alert_count()
        self.guard_service.alert_count = count
        if self.guard_service.is_paused():
            self.guard_service.resume()
        else:
            self.guard_service.pause()

        if self._icon:
            self._icon.title = self._determine_title(count)
            try:
                self._icon.update_menu()
            except Exception:
                pass

    def open_dashboard(self, icon: Optional[pystray.Icon] = None, item: Optional[MenuItem] = None) -> None:
        """Launch Streamlit web dashboard in background and open default browser."""
        url = f"http://localhost:{self.dashboard_port}"
        app_script = os.path.abspath(os.path.join(PROJECT_ROOT, "ui", "app.py"))
        py_exe = get_python_executable()

        if not os.path.exists(app_script):
            logger.error("Streamlit app script not found: %s", app_script)

        # Check if port is already active
        already_listening = is_port_listening("127.0.0.1", self.dashboard_port, timeout=0.2)

        # Start Streamlit if not already listening and process is not running
        if not already_listening and (self._streamlit_proc is None or self._streamlit_proc.poll() is not None):
            cmd = [
                py_exe,
                "-m",
                "streamlit",
                "run",
                app_script,
                "--server.port",
                str(self.dashboard_port),
                "--server.headless",
                "true",
                "--browser.serverAddress",
                "localhost",
            ]
            log_path = resolve_path("data/streamlit_daemon.log")
            try:
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                log_file = open(log_path, "a", encoding="utf-8")
                self._streamlit_proc = subprocess.Popen(
                    cmd,
                    cwd=PROJECT_ROOT,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )
                logger.info(
                    "Launched Streamlit Dashboard daemon (PID: %s, Executable: %s, Log: %s)",
                    self._streamlit_proc.pid,
                    py_exe,
                    log_path,
                )
            except Exception as e:
                logger.error("Failed to start Streamlit process: %s", e)
                print(f"[-] Error launching Streamlit dashboard: {e}")

        # Wait for Streamlit server to bind port and accept connections (up to 8 seconds)
        max_wait_sec = 8.0
        start_wait = time.time()
        port_open = False
        while time.time() - start_wait < max_wait_sec:
            if is_port_listening("127.0.0.1", self.dashboard_port, timeout=0.3):
                port_open = True
                break
            if self._streamlit_proc is not None and self._streamlit_proc.poll() is not None:
                exit_code = self._streamlit_proc.poll()
                log_path = resolve_path("data/streamlit_daemon.log")
                logger.error("Streamlit terminated prematurely with exit code %s. Check %s", exit_code, log_path)
                print(f"[-] Streamlit exited unexpectedly with code {exit_code}. Check {log_path}")
                break
            time.sleep(0.4)

        if not port_open:
            logger.warning(
                "Port %d not confirmed listening after %.1fs. Opening browser anyway...",
                self.dashboard_port,
                time.time() - start_wait,
            )

        webbrowser.open(url)

    def scan_now(self, icon: Optional[pystray.Icon] = None, item: Optional[MenuItem] = None) -> None:
        """Trigger an immediate manual scan in a background worker thread."""
        def _scan():
            new_alerts = self.guard_service.scan_now()
            count = self.query_db_alert_count()
            self.guard_service.alert_count = count
            self._last_rendered_count = count

            if getattr(self.guard_service, "sysmon_error", None):
                self._sysmon_error = self.guard_service.sysmon_error

            if self._icon:
                self._icon.title = self._determine_title(count)
                try:
                    self._icon.update_menu()
                except Exception:
                    pass

            self.guard_service.notifier.notify(
                title="[PrivacyGuard] Quét Hoàn Tất",
                message=f"Đã quét các sự kiện gần nhất. Tổng số cảnh báo: {count} (Mới: {new_alerts}).",
                launch_url=f"http://localhost:{self.dashboard_port}",
            )

        t = threading.Thread(target=_scan, daemon=True)
        t.start()

    def _refresh_worker(self) -> None:
        """Periodic background thread to sync tray icon title and menu with database count every 2 seconds."""
        logger.debug("TrayMenuRefresher thread started.")
        while self._running:
            try:
                count = self.query_db_alert_count()
                self.guard_service.alert_count = count

                # Check if Sysmon reported error during scans
                guard_err = getattr(self.guard_service, "sysmon_error", None)
                if guard_err:
                    self._sysmon_error = guard_err

                expected_title = self._determine_title(count)

                if self._icon is not None:
                    current_title = getattr(self._icon, "title", "")
                    if current_title != expected_title or count != self._last_rendered_count:
                        self._last_rendered_count = count
                        self._icon.title = expected_title
                        try:
                            self._icon.update_menu()
                        except Exception as me:
                            logger.debug("update_menu failed: %s", me)
            except Exception as e:
                logger.debug("Error in tray refresh worker: %s", e)

            # Sleep 2 seconds in small 0.1s increments for responsive exit
            for _ in range(20):
                if not self._running:
                    break
                time.sleep(0.1)

        logger.debug("TrayMenuRefresher thread stopped.")

    def exit_app(self, icon: pystray.Icon, item: MenuItem) -> None:
        """Safely terminate real-time worker, streamlit process, and remove tray icon."""
        logger.info("Exiting PrivacyGuard System Tray Application...")
        self._running = False
        self.guard_service.stop()

        if self._streamlit_proc is not None:
            try:
                self._streamlit_proc.terminate()
                self._streamlit_proc.wait(timeout=2.0)
            except Exception:
                try:
                    self._streamlit_proc.kill()
                except Exception:
                    pass

        icon.stop()

    def run(self) -> None:
        """Start the background guard service and run the pystray main loop."""
        logger.info("Starting PrivacyGuard Real-time Guard Service...")
        self._running = True
        self.guard_service.start()

        # Start background 2-second menu refresh worker
        self._refresh_thread = threading.Thread(
            target=self._refresh_worker,
            daemon=True,
            name="TrayMenuRefresher",
        )
        self._refresh_thread.start()

        initial_count = self.query_db_alert_count()
        self._last_rendered_count = initial_count
        initial_title = self._determine_title(initial_count)

        menu = Menu(
            MenuItem(self.get_status_text, self.toggle_pause, default=False),
            MenuItem("Mở Web Dashboard", self.open_dashboard, default=True),
            MenuItem("Quét ngay (Scan Now)", self.scan_now),
            MenuItem(self.get_alert_count_text, self.open_dashboard),
            Menu.SEPARATOR,
            MenuItem("Thoát (Exit)", self.exit_app),
        )

        self._icon = pystray.Icon(
            name="PrivacyGuard",
            icon=self.icon_image,
            title=initial_title,
            menu=menu,
        )

        logger.info("PrivacyGuard tray icon active in Windows taskbar.")
        self._icon.run()


def run_tray_app(
    db_path: str = "data/privacyguard.db",
    polling_interval: float = 10.0,
    dashboard_port: int = 8501,
) -> None:
    """Launch PrivacyGuard System Tray Application."""
    app = PrivacyGuardTrayApp(
        db_path=db_path,
        polling_interval=polling_interval,
        dashboard_port=dashboard_port,
    )
    app.run()


def main():
    run_tray_app()


if __name__ == "__main__":
    main()
