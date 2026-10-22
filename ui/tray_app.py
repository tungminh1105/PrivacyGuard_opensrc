"""Windows System Tray Application for PrivacyGuard (Commercial Upgrade).

Provides an interactive system tray icon in the Windows taskbar notifications area:
- Real-time protection status monitoring (Running / Paused).
- One-click launch for the Streamlit Web Dashboard.
- Immediate manual scan trigger (Scan Now).
- Live alert counter and notification integration.
- Graceful termination of background worker daemon.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
import webbrowser
from typing import Optional

from PIL import Image, ImageDraw
import pystray
from pystray import Menu, MenuItem

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.guard_service import RealtimeGuardService

logger = logging.getLogger(__name__)


def create_shield_icon_image(size: int = 64, color: tuple = (16, 185, 129)) -> Image.Image:
    """Dynamically generate a professional cybersecurity shield icon using Pillow."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Scale coordinates to given size
    scale = size / 64.0

    def pt(x, y):
        return (int(x * scale), int(y * scale))

    # Shield polygon contour
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

    # Inner checkmark / lock accent in white
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
        self.db_path = db_path
        self.dashboard_port = dashboard_port
        self.guard_service = RealtimeGuardService(
            db_path=self.db_path,
            polling_interval_sec=polling_interval,
            alert_threshold=0.70,
            enable_toast=True,
        )

        self._streamlit_proc: Optional[subprocess.Popen] = None
        self._icon: Optional[pystray.Icon] = None

        # Load or generate icon image
        icon_path = os.path.join(PROJECT_ROOT, "assets", "icon.png")
        if os.path.exists(icon_path):
            try:
                self.icon_image = Image.open(icon_path)
            except Exception:
                self.icon_image = create_shield_icon_image()
        else:
            self.icon_image = create_shield_icon_image()

        # Connect callback to update icon tooltip on new alerts
        self.guard_service.add_alert_callback(self._on_alert_detected)

    def _on_alert_detected(self, alert_data: dict) -> None:
        """Callback invoked whenever the guard service detects a High Risk exfiltration."""
        if self._icon:
            count = self.guard_service.alert_count
            self._icon.title = f"PrivacyGuard - Phát hiện {count} cảnh báo rủi ro!"

    def get_status_text(self, item: MenuItem) -> str:
        """Return dynamic status text for the context menu."""
        if self.guard_service.is_paused():
            return "Trạng thái: Đã tạm dừng (Paused)"
        return "Trạng thái: Đang bảo vệ (Running)"

    def toggle_pause(self, icon: pystray.Icon, item: MenuItem) -> None:
        """Toggle protection pause/resume."""
        if self.guard_service.is_paused():
            self.guard_service.resume()
            self._icon.title = f"PrivacyGuard - Đang bảo vệ ({self.guard_service.alert_count} cảnh báo)"
        else:
            self.guard_service.pause()
            self._icon.title = "PrivacyGuard - Đã tạm dừng bảo vệ"

    def open_dashboard(self, icon: Optional[pystray.Icon] = None, item: Optional[MenuItem] = None) -> None:
        """Launch Streamlit web dashboard in background and open default browser."""
        url = f"http://localhost:{self.dashboard_port}"
        app_script = os.path.join(PROJECT_ROOT, "ui", "app.py")

        # Start Streamlit if not already running
        if self._streamlit_proc is None or self._streamlit_proc.poll() is not None:
            cmd = [
                sys.executable,
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
            try:
                self._streamlit_proc = subprocess.Popen(
                    cmd,
                    cwd=PROJECT_ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info("Launched Streamlit Dashboard daemon (PID: %s)", self._streamlit_proc.pid)
                # Give server brief time to initialize
                time.sleep(1.5)
            except Exception as e:
                logger.error("Failed to start Streamlit: %s", e)

        # Open browser
        webbrowser.open(url)

    def scan_now(self, icon: pystray.Icon, item: MenuItem) -> None:
        """Trigger an immediate manual scan in a background worker thread."""
        def _scan():
            new_alerts = self.guard_service.scan_now()
            count = self.guard_service.alert_count
            self.guard_service.notifier.notify(
                title="[PrivacyGuard] Quét Hoàn Tất",
                message=f"Đã quét các sự kiện gần nhất. Tổng số cảnh báo: {count} (Mới: {new_alerts}).",
                launch_url=f"http://localhost:{self.dashboard_port}",
            )
        t = threading.Thread(target=_scan, daemon=True)
        t.start()

    def get_alert_count_text(self, item: MenuItem) -> str:
        """Return dynamic alert count label."""
        count = self.guard_service.alert_count
        return f"Xem số cảnh báo ({count} alerts)"

    def exit_app(self, icon: pystray.Icon, item: MenuItem) -> None:
        """Safely terminate real-time worker, streamlit process, and remove tray icon."""
        logger.info("Exiting PrivacyGuard System Tray Application...")
        self.guard_service.stop()

        if self._streamlit_proc is not None:
            try:
                self._streamlit_proc.terminate()
            except Exception:
                pass

        icon.stop()

    def run(self) -> None:
        """Start the background guard service and run the pystray main loop."""
        logger.info("Starting PrivacyGuard Real-time Guard Service...")
        self.guard_service.start()

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
            title=f"PrivacyGuard - Đang bảo vệ ({self.guard_service.alert_count} cảnh báo)",
            menu=menu,
        )

        logger.info("PrivacyGuard tray icon active in Windows taskbar.")
        self._icon.run()


def main():
    app = PrivacyGuardTrayApp()
    app.run()


if __name__ == "__main__":
    main()
