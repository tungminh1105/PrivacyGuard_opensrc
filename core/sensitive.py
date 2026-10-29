"""Sensitive path identification and scoring module for PrivacyGuard.

Identifies user-sensitive paths and files (Documents, FakeDocuments, Desktop,
credentials, browser cookies, financial and legal files) according to config.yaml.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_SENSITIVE_CONFIG: Dict[str, Any] = {
    "exclude_directories": [
        "AppData\\Local\\Temp",
        "AppData\\Local\\Microsoft\\Edge",
        "AppData\\Local\\Google",
        "AppData\\Local\\Packages",
        "data\\pytest_tmp",
        "build",
        "dist",
        ".venv",
        "__pycache__",
    ],
    "directories": [
        "Documents",
        "FakeDocuments",
        "Desktop",
        "Downloads",
        "Pictures",
        ".ssh",
        ".aws",
    ],
    "file_patterns": [
        "Login Data",
        "Cookies",
        "Local State",
        "Web Data",
        "credential",
        "password",
        "token",
        "secret",
        "mat_khau",
        "hop_dong",
        "bang_luong",
        "bao_cao",
        "cmnd",
        "can_cuoc",
        "sao_ke",
        "id_rsa",
        "id_ed25519",
    ],
    "sensitive_extensions": [
        ".docx",
        ".xlsx",
        ".pdf",
        ".kdbx",
        ".pem",
        ".key",
        ".ppk",
        ".pfx",
        ".p12",
        ".env",
        ".csv",
    ],
    "zero_score_patterns": [
        "C:\\Windows\\System32",
        "C:\\Windows\\WinSxS",
        "C:\\Windows\\Prefetch",
    ],
}


def load_sensitive_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load sensitive_paths section from config.yaml with fallback to defaults."""
    if os.path.exists(config_path) and yaml is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and "sensitive_paths" in data:
                    cfg = data["sensitive_paths"]
                    return {
                        "exclude_directories": cfg.get("exclude_directories", DEFAULT_SENSITIVE_CONFIG["exclude_directories"]),
                        "directories": cfg.get("directories", DEFAULT_SENSITIVE_CONFIG["directories"]),
                        "file_patterns": cfg.get("file_patterns", DEFAULT_SENSITIVE_CONFIG["file_patterns"]),
                        "sensitive_extensions": [
                            ext.lower()
                            for ext in cfg.get("sensitive_extensions", DEFAULT_SENSITIVE_CONFIG["sensitive_extensions"])
                        ],
                        "zero_score_patterns": cfg.get("zero_score_patterns", DEFAULT_SENSITIVE_CONFIG["zero_score_patterns"]),
                    }
        except Exception:
            pass
    return DEFAULT_SENSITIVE_CONFIG


# Global cached config
_CONFIG = load_sensitive_config()


def get_sensitivity_score(path: Optional[str], config: Optional[Dict[str, Any]] = None) -> float:
    """Calculate sensitivity score in range [0.0, 1.0] for a given file or directory path.

    Rules:
      - 0.0: Empty paths, system binaries, WinSxS, Prefetch, System32, and exclude_directories (Temp, Edge cache, Google, Packages, pytest_tmp, build, dist, .venv).
      - 1.0: Browser credential databases (Login Data, Cookies), cryptographic keys (.pem, .key), SSH keys, passwords.
      - 0.8: Sensitive documents (.docx, .xlsx, .pdf, .csv) inside user folders (Documents, FakeDocuments, Desktop).
      - 0.5: Generic files located inside sensitive user directories.
      - 0.4: Sensitive extensions found outside user folders.

    Args:
        path: Path string to evaluate.
        config: Optional configuration override.

    Returns:
        float score between 0.0 and 1.0.
    """
    if not path or not str(path).strip():
        return 0.0

    cfg = config or _CONFIG
    norm_path = os.path.normpath(str(path)).replace("/", "\\")
    lower_path = norm_path.lower()
    file_name = os.path.basename(norm_path).lower()
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()

    # 1. Exclude directories filter (Temp, Edge cache, Google cache, Packages, pytest_tmp, build, dist, .venv)
    exclude_dirs = cfg.get("exclude_directories", DEFAULT_SENSITIVE_CONFIG.get("exclude_directories", []))
    for ex_dir in exclude_dirs:
        ex_norm = os.path.normpath(ex_dir).replace("/", "\\").lower().strip("\\")
        if f"\\{ex_norm}\\" in f"\\{lower_path}\\" or lower_path.startswith(f"{ex_norm}\\") or lower_path == ex_norm:
            return 0.0

    # 2. Zero-score filter for system internal locations
    for zero_pat in cfg.get("zero_score_patterns", []):
        if zero_pat.lower().replace("/", "\\") in lower_path:
            return 0.0

    if "$mft" in lower_path or "pagefile.sys" in lower_path or "swapfile.sys" in lower_path:
        return 0.0

    # 3. Check if path resides within a recognized sensitive directory (matching by directory components, not substring)
    dir_name = os.path.dirname(norm_path)
    dir_components = [p.lower() for p in dir_name.replace("/", "\\").split("\\") if p]

    in_sensitive_dir = False
    for sdir in cfg.get("directories", []):
        sdir_norm = os.path.normpath(sdir).replace("/", "\\").lower().strip("\\")
        sdir_parts = [p for p in sdir_norm.split("\\") if p]
        if sdir_parts:
            n, m = len(sdir_parts), len(dir_components)
            if any(dir_components[i:i+n] == sdir_parts for i in range(m - n + 1)):
                in_sensitive_dir = True
                break

    # 4. Check file patterns
    has_sensitive_pattern = False
    high_secret_matched = False
    high_secret_indicators = [
        "login data",
        "cookies",
        "local state",
        "web data",
        ".kdbx",
        ".pem",
        ".key",
        ".ppk",
        ".pfx",
        ".p12",
        ".env",
        "id_rsa",
        "id_ed25519",
        "credential",
        "password",
        "mat_khau",
    ]
    for pat in cfg.get("file_patterns", []):
        if pat.lower() in file_name:
            has_sensitive_pattern = True
            if pat.lower() in high_secret_indicators:
                high_secret_matched = True
            break

    # High secret cryptographic / credential extensions or key files
    for secret_pat in [".kdbx", ".pem", ".key", ".ppk", ".pfx", ".p12", ".env", "id_rsa", "id_ed25519"]:
        if secret_pat in file_name:
            has_sensitive_pattern = True
            high_secret_matched = True
            break

    # 5. Check sensitive extensions
    has_sensitive_ext = ext in [e.lower() for e in cfg.get("sensitive_extensions", [])]

    # Must be either in a sensitive directory, or match a sensitive pattern, or have sensitive extension
    if not in_sensitive_dir and not has_sensitive_pattern and not has_sensitive_ext:
        return 0.0

    if high_secret_matched:
        return 1.0

    if in_sensitive_dir:
        if has_sensitive_pattern or has_sensitive_ext:
            return 0.8
        return 0.5

    if has_sensitive_pattern:
        return 0.7

    if has_sensitive_ext:
        return 0.4

    return 0.0


def is_sensitive_path(path: Optional[str], threshold: float = 0.4) -> bool:
    """Determine whether path is considered sensitive (score >= threshold)."""
    return get_sensitivity_score(path) >= threshold


# Alias for SPEC Section 7 line 173 compliance
def sensitivity(path: Optional[str]) -> float:
    """Alias for get_sensitivity_score."""
    return get_sensitivity_score(path)
