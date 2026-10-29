"""Global pytest configuration and fixtures for PrivacyGuard test suite."""

import os
import shutil
import tempfile
from pathlib import Path
import pytest

# Prevent Windows junction deletion PermissionError on Python 3.14 during sessionfinish
try:
    import _pytest.pathlib

    def _safe_cleanup_dead_symlinks(root):
        try:
            for p in root.iterdir():
                try:
                    if p.is_symlink():
                        try:
                            p.unlink()
                        except Exception:
                            try:
                                os.rmdir(p)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

    _pytest.pathlib.cleanup_dead_symlinks = _safe_cleanup_dead_symlinks
except Exception:
    pass


@pytest.fixture
def tmp_path():
    """Custom tmp_path fixture that uses tempfile.mkdtemp and safely cleans up on Windows."""
    d = tempfile.mkdtemp(prefix="pg_test_")
    p = Path(d)
    try:
        yield p
    finally:
        shutil.rmtree(d, ignore_errors=True)
