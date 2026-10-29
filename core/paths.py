"""Centralized path resolution module for PrivacyGuard.

Guarantees a single source of truth for repository root and absolute paths across
both source execution and PyInstaller frozen standalone binaries.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from typing import Optional

logger = logging.getLogger(__name__)


def get_project_root() -> str:
    """Resolve the true project root directory containing config.yaml and ui/app.py.

    Handles both source development and PyInstaller frozen executable environments
    (including --onedir in dist/privacyguard/ and --onefile in dist/).
    """
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidate = exe_dir
        for _ in range(5):
            # Check for project markers
            has_app = os.path.exists(os.path.join(candidate, "ui", "app.py"))
            has_config = os.path.exists(os.path.join(candidate, "config.yaml"))
            has_venv = os.path.exists(os.path.join(candidate, ".venv"))
            if has_app and (has_config or has_venv):
                return os.path.abspath(candidate)
            parent = os.path.dirname(candidate)
            if parent == candidate:
                break
            candidate = parent

        # Fallback if inside dist/privacyguard or dist
        parent_dir = os.path.dirname(exe_dir)
        if os.path.basename(parent_dir).lower() == "dist":
            return os.path.abspath(os.path.dirname(parent_dir))
        if os.path.basename(exe_dir).lower() == "dist":
            return os.path.abspath(parent_dir)

        return os.path.abspath(exe_dir)

    # In source mode, this file is in <PROJECT_ROOT>/core/paths.py
    core_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.dirname(core_dir))


PROJECT_ROOT: str = get_project_root()


def resolve_path(p: str) -> str:
    """Resolve any relative path against PROJECT_ROOT to guarantee an absolute path."""
    if not p:
        return PROJECT_ROOT
    if os.path.isabs(p):
        return os.path.abspath(p)
    return os.path.abspath(os.path.join(PROJECT_ROOT, p))


def get_default_db_path() -> str:
    """Return absolute path to the canonical SQLite database."""
    return resolve_path("data/privacyguard.db")


def get_default_config_path() -> str:
    """Return absolute path to config.yaml."""
    return resolve_path("config.yaml")


def cleanup_dist_stray_db() -> Optional[str]:
    """Inspect and safely remove empty stray database created in dist/ directory.

    Safety: ONLY deletes if alerts == 0 and events == 0, and path != canonical DB.
    """
    canonical_db = get_default_db_path()
    stray_candidates = [
        os.path.join(PROJECT_ROOT, "dist", "privacyguard", "data", "privacyguard.db"),
        os.path.join(PROJECT_ROOT, "dist", "data", "privacyguard.db"),
    ]

    for stray_path in stray_candidates:
        abs_stray = os.path.abspath(stray_path)
        if not os.path.exists(abs_stray):
            continue
        if abs_stray.lower() == canonical_db.lower():
            continue

        try:
            conn = sqlite3.connect(abs_stray)
            cur = conn.cursor()
            alerts_count = 0
            events_count = 0
            try:
                cur.execute("SELECT COUNT(*) FROM alerts")
                row = cur.fetchone()
                alerts_count = int(row[0]) if row else 0
            except sqlite3.OperationalError:
                pass

            try:
                cur.execute("SELECT COUNT(*) FROM events")
                row = cur.fetchone()
                events_count = int(row[0]) if row else 0
            except sqlite3.OperationalError:
                pass
            conn.close()

            if alerts_count == 0 and events_count == 0:
                logger.info("[CLEANUP] Removing empty stray DB at: %s", abs_stray)
                for ext in ["", "-wal", "-shm"]:
                    target = abs_stray + ext
                    if os.path.exists(target):
                        try:
                            os.remove(target)
                        except Exception as e:
                            logger.warning("Could not delete %s: %s", target, e)
                # Remove empty data directory if empty
                stray_dir = os.path.dirname(abs_stray)
                try:
                    if os.path.exists(stray_dir) and not os.listdir(stray_dir):
                        os.rmdir(stray_dir)
                except Exception:
                    pass
                return abs_stray
            else:
                logger.warning(
                    "[CLEANUP] Stray DB at %s contains data (alerts=%d, events=%d). Not removing.",
                    abs_stray,
                    alerts_count,
                    events_count,
                )
        except Exception as e:
            logger.warning("[CLEANUP] Error inspecting stray DB at %s: %s", abs_stray, e)

    return None
