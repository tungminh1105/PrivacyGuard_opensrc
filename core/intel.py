"""Threat Intelligence and Destination Classification Module for PrivacyGuard.

Provides:
- Local IP / LAN classification (127.0.0.1, RFC1918 private subnets).
- Tracker and ad-domain identification.
- First-seen destination tracking per application process.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger(__name__)

DEFAULT_TRACKERS: List[str] = [
    "google-analytics.com",
    "doubleclick.net",
    "facebook.net",
    "telemetry",
    "metrics",
    "adservice",
    "scorecardresearch.com",
    "segment.io",
    "mixpanel.com",
    "sentry.io",
]


def load_intel_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load threat_intel section from config.yaml."""
    if os.path.exists(config_path) and yaml is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and "threat_intel" in data:
                    return data["threat_intel"]
        except Exception:
            pass
    return {"tracker_domains": DEFAULT_TRACKERS}


_INTEL_CONFIG = load_intel_config()


def is_local_ip(ip_or_host: Optional[str]) -> bool:
    """Determine if an IP address or hostname is local (loopback, RFC1918 private, link-local)."""
    if not ip_or_host:
        return False

    target = ip_or_host.strip().lower()
    if target in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::"):
        return True

    # Strip port if present e.g. "192.168.1.1:8080"
    if ":" in target and not target.count(":") > 1:  # IPv4 with port
        target = target.split(":")[0]

    try:
        ip_obj = ipaddress.ip_address(target)
        return (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
        )
    except ValueError:
        # Not a raw IP address; check if ends with .local or localhost
        if target.endswith(".local") or target.endswith(".localhost"):
            return True
        return False


def is_tracker(dest: Optional[str], config: Optional[Dict[str, Any]] = None) -> bool:
    """Check if destination IP or domain matches known tracker patterns."""
    if not dest:
        return False

    cfg = config or _INTEL_CONFIG
    tracker_list = cfg.get("tracker_domains", DEFAULT_TRACKERS)
    clean_dest = dest.strip().lower()

    for pattern in tracker_list:
        pat_lower = pattern.lower()
        if pat_lower in clean_dest:
            return True

    return False


def get_country(ip: Optional[str]) -> str:
    """Classify country origin for an IP address ('LOCAL' for loopback/private, 'UNKNOWN' offline)."""
    if not ip or is_local_ip(ip):
        return "LOCAL"
    return "UNKNOWN"


class IntelTracker:
    """Maintains first-seen timestamps of network destinations per application/process."""

    def __init__(self):
        # Maps (app_key, dest) -> first_seen_epoch_float
        self._history: Dict[Tuple[str, str], float] = {}

    def is_new_destination(self, app_key: str, dest: str, ts: Optional[float] = None) -> bool:
        """Check if destination is newly observed for this application.

        If new, records observation timestamp and returns True; otherwise False.
        """
        if not app_key or not dest:
            return False

        key = (str(app_key).strip(), str(dest).strip().lower())
        if key not in self._history:
            self._history[key] = ts if ts is not None else 0.0
            return True
        return False

    def first_seen(self, app_key: str, dest: str) -> Optional[float]:
        """Return the first timestamp a destination was observed for this application."""
        key = (str(app_key).strip(), str(dest).strip().lower())
        return self._history.get(key)

    def get_known_destinations(self, app_key: str) -> Set[str]:
        """Return all destinations previously observed for an application."""
        target_app = str(app_key).strip()
        return {d for (a, d) in self._history.keys() if a == target_app}

    def clear(self) -> None:
        """Reset destination history cache."""
        self._history.clear()


# Global tracker instance
global_intel_tracker = IntelTracker()


def is_new_destination(app_key: str, dest: str, ts: Optional[float] = None) -> bool:
    """Module-level convenience wrapper for global destination tracking."""
    return global_intel_tracker.is_new_destination(app_key, dest, ts=ts)


def first_seen(app_key: str, dest: str) -> Optional[float]:
    """Module-level convenience wrapper for first_seen lookup."""
    return global_intel_tracker.first_seen(app_key, dest)
