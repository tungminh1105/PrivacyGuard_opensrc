"""Generate synthetic fake documents with sensitive-sounding names for PrivacyGuard.

Creates 50-200 files in data/FakeDocuments containing meaningless random content.
STRICT SAFETY RULE: Only generates files within designated FakeDocuments directory.
Never touches real user folders (Documents, Desktop, Downloads).
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
from typing import List, Optional

# Base list of sensitive sounding document names across categories
SENSITIVE_TEMPLATES = [
    ("hop_dong_thue_nha", "docx"),
    ("bang_luong_thang_10", "xlsx"),
    ("bao_cao_tai_chinh_q3", "xlsx"),
    ("cmnd_can_cuoc_cong_dan", "pdf"),
    ("so_yeu_ly_lich", "docx"),
    ("sao_ke_ngan_hang_vcb", "pdf"),
    ("mat_khau_server_noi_bo", "txt"),
    ("danh_sach_nhan_su_2026", "xlsx"),
    ("thong_tin_the_tin_dung", "csv"),
    ("hop_dong_lao_dong_2026", "docx"),
    ("ke_hoach_kinh_doanh_mat", "docx"),
    ("ma_nguon_du_an_bi_mat", "txt"),
    ("danh_sach_khach_hang_vip", "xlsx"),
    ("chung_minh_thu_nhan_vien", "pdf"),
    ("tai_lieu_dau_thau_2026", "docx"),
    ("bao_cao_kiem_toan_noi_bo", "xlsx"),
    ("thoa_thuan_bao_mat_nda", "docx"),
    ("ghi_chu_cuoc_hop_ban_giam_doc", "txt"),
    ("thong_tin_tai_khoan_ngan_hang", "csv"),
    ("chu_ky_so_ca_nhan", "pdf"),
    ("scan_ho_chieu_tong_giam_doc", "pdf"),
    ("bien_ban_ban_giao_tai_san", "docx"),
    ("danh_sach_luong_thuong_tet", "xlsx"),
    ("database_production_credentials", "txt"),
    ("api_keys_aws_production", "txt"),
    ("private_key_backup", "pem"),
    ("chung_tu_thue_thu_nhap", "pdf"),
    ("so_do_ha_tang_mang_noi_bo", "png"),
    ("du_toan_ngan_sach_nam_2026", "xlsx"),
    ("hop_dong_chuyen_nhuong_co_phan", "docx"),
]


def validate_fake_docs_path(path: str) -> str:
    """Validate that the target directory strictly points to a FakeDocuments folder."""
    abs_path = os.path.abspath(path)
    base_name = os.path.basename(abs_path)
    if "fakedocuments" not in base_name.lower() and "fakedocuments" not in abs_path.lower():
        raise ValueError(
            f"SAFETY VIOLATION: Refusing to create files in '{abs_path}'. "
            "Target directory name must contain 'FakeDocuments'."
        )

    # Explicit protection against system or real user profile folders
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        forbidden_dirs = [
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join(user_profile, "Downloads"),
        ]
        for fdir in forbidden_dirs:
            if os.path.abspath(fdir).lower() == abs_path.lower():
                raise ValueError(
                    f"SAFETY VIOLATION: Cannot use user directory '{abs_path}'! Must use FakeDocuments."
                )

    return abs_path


def generate_random_content(rng: random.Random, size_bytes: int) -> bytes:
    """Generate meaningless random text/bytes."""
    words = [
        "".join(rng.choices(string.ascii_letters, k=rng.randint(3, 10)))
        for _ in range(max(10, size_bytes // 8))
    ]
    text = " ".join(words)
    raw = text.encode("utf-8", errors="replace")
    if len(raw) < size_bytes:
        raw += rng.randbytes(size_bytes - len(raw))
    return raw[:size_bytes]


def create_fake_documents(
    target_dir: str = "data/FakeDocuments",
    count: int = 100,
    seed: Optional[int] = None,
) -> List[str]:
    """Create between 50 and 200 synthetic fake documents in target_dir.

    Args:
        target_dir: Directory path, must resolve to FakeDocuments.
        count: Number of files to create (clamped between 50 and 200).
        seed: Random seed for deterministic reproducibility.

    Returns:
        List of absolute file paths created.
    """
    safe_dir = validate_fake_docs_path(target_dir)
    os.makedirs(safe_dir, exist_ok=True)

    # Clamp count to [50, 200]
    total_count = max(50, min(200, count))
    rng = random.Random(seed)

    created_paths: List[str] = []
    generated_names = set()

    for i in range(total_count):
        template_idx = i % len(SENSITIVE_TEMPLATES)
        base_name, ext = SENSITIVE_TEMPLATES[template_idx]
        version = (i // len(SENSITIVE_TEMPLATES)) + 1
        if version > 1:
            file_name = f"{base_name}_v{version}.{ext}"
        else:
            file_name = f"{base_name}.{ext}"

        # Ensure uniqueness
        if file_name in generated_names:
            file_name = f"{base_name}_{i+1:03d}.{ext}"
        generated_names.add(file_name)

        file_path = os.path.join(safe_dir, file_name)
        # Random size between 512 bytes and 32 KB
        file_size = rng.randint(512, 32768)
        content = generate_random_content(rng, file_size)

        with open(file_path, "wb") as f:
            f.write(content)

        created_paths.append(file_path)

    return created_paths


def main():
    parser = argparse.ArgumentParser(description="Create synthetic fake documents for PrivacyGuard")
    parser.add_argument("--dir", type=str, default="data/FakeDocuments", help="Target FakeDocuments directory")
    parser.add_argument("--count", type=int, default=100, help="Number of files (50-200)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    files = create_fake_documents(target_dir=args.dir, count=args.count, seed=args.seed)
    print(f"Successfully generated {len(files)} fake documents in: {os.path.abspath(args.dir)}")


if __name__ == "__main__":
    main()
