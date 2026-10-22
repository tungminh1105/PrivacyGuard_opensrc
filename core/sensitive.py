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
      - 0.0: Empty paths, system binaries, WinSxS, Prefetch, System32.
      - 1.0: Browser credential databases (Login Data, Cookies), cryptographic keys (.pem, .key), SSH keys.
      - 0.8: Sensitive documents (.docx, .xlsx, .pdf, .csv) inside user folders (Documents, FakeDocuments, Desktop).
      - 0.5: Generic files located inside sensitive user directories.
      - 0.4: Sensitive extensions found outside user folders.

    Args:
        path: Path string to evaluate.
        config: Optional configuration override.

    Returns:
        float score between 0.0 and 1.0.
    """
    if not path or not path.strip():
        return 0.0

    cfg = config or _CONFIG
    norm_path = os.path.normpath(path).replace("/", "\\")
    lower_path = norm_path.lower()
    file_name = os.path.basename(norm_path).lower()
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()

    # 1. Zero-score filter for system internal locations
    for zero_pat in cfg.get("zero_score_patterns", []):
        if zero_pat.lower().replace("/", "\\") in lower_path:
            return 0.0

    if "$mft" in lower_path or "pagefile.sys" in lower_path or "swapfile.sys" in lower_path:
        return 0.0

    # 2. Maximum sensitivity (1.0): Passwords, tokens, SSH/crypto keys, browser auth data
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
        ".aws\\credentials",
        ".ssh\\id_",
    ]
    for secret_pat in high_secret_indicators:
        if secret_pat in lower_path or secret_pat in file_name:
            return 1.0

    # 3. Check if path resides within a recognized sensitive directory
    in_sensitive_dir = False
    for sdir in cfg.get("directories", []):
        sdir_norm = f"\\{sdir.lower().strip('\\')}\\"
        # Check both bounded directory name and path end
        if sdir_norm in f"\\{lower_path}\\" or lower_path.startswith(f"{sdir.lower()}\\"):
            in_sensitive_dir = True
            break

    # 4. Check if file has a sensitive extension or name pattern
    has_sensitive_ext = ext in [e.lower() for e in cfg.get("sensitive_extensions", [])]

    has_sensitive_pattern = False
    for pat in cfg.get("file_patterns", []):
        if pat.lower() in file_name:
            has_sensitive_pattern = True
            break

    # 5. Determine combined score
    if in_sensitive_dir:
        if has_sensitive_ext or has_sensitive_pattern:
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
