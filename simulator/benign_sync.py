"""Benign cloud synchronization simulator for PrivacyGuard.

Simulates normal background backup/sync activity (Label 0).
STRICT SAFETY ENFORCEMENT:
- Only reads files from data/FakeDocuments.
- Only writes files to data/fake_cloud.
- Strictly refuses any paths outside these synthetic test directories.
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import shutil
import sys
import time
from typing import List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [BenignSync] %(message)s",
)


def validate_sync_paths(src_dir: str, dst_dir: str) -> Tuple[str, str]:
    """Validate source and destination paths to enforce safety bounds."""
    abs_src = os.path.abspath(src_dir)
    abs_dst = os.path.abspath(dst_dir)

    if "fakedocuments" not in abs_src.lower():
        raise ValueError(
            f"SAFETY VIOLATION: Source directory '{abs_src}' must be within FakeDocuments!"
        )

    if "fake_cloud" not in abs_dst.lower():
        raise ValueError(
            f"SAFETY VIOLATION: Destination directory '{abs_dst}' must be within fake_cloud!"
        )

    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        forbidden = [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join(user_profile, "Downloads"),
        ]
        for fdir in forbidden:
            if os.path.abspath(fdir).lower() in (abs_src.lower(), abs_dst.lower()):
                raise ValueError(
                    f"SAFETY VIOLATION: Cannot touch user folder '{fdir}'! Use synthetic directories only."
                )

    return abs_src, abs_dst


def run_benign_sync(
    src_dir: str = "data/FakeDocuments",
    dst_dir: str = "data/fake_cloud",
    file_count: Optional[int] = 10,
    seed: Optional[int] = None,
) -> int:
    """Sync files from FakeDocuments to fake_cloud.

    Args:
        src_dir: Source fake docs folder (must be within FakeDocuments).
        dst_dir: Destination fake cloud folder (must be within fake_cloud).
        file_count: Number of files to sync (default 10, None for all).
        seed: Random seed for selecting files.

    Returns:
        Number of files synced.
    """
    safe_src, safe_dst = validate_sync_paths(src_dir, dst_dir)
    os.makedirs(safe_dst, exist_ok=True)

    if not os.path.exists(safe_src):
        logger.warning("Source directory %s does not exist.", safe_src)
        return 0

    candidates = [
        os.path.join(safe_src, f)
        for f in os.listdir(safe_src)
        if os.path.isfile(os.path.join(safe_src, f))
    ]
    if not candidates:
        logger.warning("No files found in %s to sync.", safe_src)
        return 0

    rng = random.Random(seed)
    candidates.sort()
    rng.shuffle(candidates)

    selected = candidates[:file_count] if file_count else candidates
    synced = 0

    for file_path in selected:
        filename = os.path.basename(file_path)
        dest_file = os.path.join(safe_dst, filename)

        # Simulate read and write
        try:
            with open(file_path, "rb") as f_in:
                data = f_in.read()
            with open(dest_file, "wb") as f_out:
                f_out.write(data)
            synced += 1
            # Brief sleep between files to simulate file IO pace
            time.sleep(0.01)
        except Exception as e:
            logger.error("Error syncing file %s: %s", filename, e)

    logger.info("Successfully synced %d files to %s (Label 0)", synced, safe_dst)
    return synced


def main():
    parser = argparse.ArgumentParser(description="Benign Cloud Backup Simulator (Label 0)")
    parser.add_argument("--src", type=str, default="data/FakeDocuments", help="Source fake docs directory")
    parser.add_argument("--dst", type=str, default="data/fake_cloud", help="Destination fake cloud directory")
    parser.add_argument("--count", type=int, default=10, help="Number of files to sync")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    args = parser.parse_args()

    synced = run_benign_sync(
        src_dir=args.src,
        dst_dir=args.dst,
        file_count=args.count,
        seed=args.seed,
    )
    print(f"Synced {synced} files from {args.src} to {args.dst}")


if __name__ == "__main__":
    main()
