"""Benign user workload generator for PrivacyGuard False Positive Rate (FPR) testing.

Executes normal everyday activities periodically (every 2-5 minutes):
1. Document lifecycle: create/edit .txt/.docx in Documents, copy to Downloads, zip, unzip.
2. Developer workflow: git status, git diff, pytest run.
3. Web activity: download small files/pages to Downloads.

Logs every action to results/benign_actions.csv in real time.
STRICT SAFETY RULE:
- Does NOT touch data/FakeDocuments.
- Does NOT execute any simulator/test-real code.
- Operates safely without requiring Administrator privileges.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import os
import random
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from typing import Dict, Any, Optional

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class BenignWorkloadRunner:
    """Executes realistic everyday user and developer actions."""

    def __init__(self, output_csv: str = "results/benign_actions.csv", run_id: Optional[str] = None):
        self.output_csv = os.path.abspath(output_csv)
        os.makedirs(os.path.dirname(self.output_csv), exist_ok=True)

        user_profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        self.doc_dir = os.path.join(user_profile, "Documents", "BenignWorkload")
        self.dl_dir = os.path.join(user_profile, "Downloads", "BenignWorkload")

        os.makedirs(self.doc_dir, exist_ok=True)
        os.makedirs(self.dl_dir, exist_ok=True)

        self.action_counter = 0
        self.run_id = run_id or f"run_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._init_csv()

    def _init_csv(self) -> None:
        """Initialize CSV log with header if not already present."""
        if not os.path.exists(self.output_csv) or os.path.getsize(self.output_csv) == 0:
            with open(self.output_csv, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "run_id",
                    "id",
                    "timestamp",
                    "action_type",
                    "target_path",
                    "duration_sec",
                    "status",
                    "details",
                ])

    def log_action(
        self,
        action_type: str,
        target_path: str,
        duration_sec: float,
        status: str,
        details: str,
    ) -> None:
        """Append an action record to benign_actions.csv."""
        self.action_counter += 1
        ts_now = datetime.datetime.now().isoformat()
        with open(self.output_csv, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                self.run_id,
                self.action_counter,
                ts_now,
                action_type,
                target_path,
                f"{duration_sec:.3f}",
                status,
                details,
            ])
            f.flush()
        print(f"[{ts_now}] [{self.run_id} #{self.action_counter}] {action_type:<16} | Status: {status} ({duration_sec:.2f}s) | {details}")

    def action_document_lifecycle(self) -> Dict[str, Any]:
        """Create/update a text/docx file in Documents, copy to Downloads, zip and unzip."""
        t0 = time.time()
        file_name = f"ke_hoach_cong_viec_{int(t0) % 1000}.docx"
        doc_path = os.path.join(self.doc_dir, file_name)
        dl_path = os.path.join(self.dl_dir, file_name)
        zip_path = os.path.join(self.dl_dir, f"backup_{int(t0) % 1000}.zip")
        extract_dir = os.path.join(self.dl_dir, f"extracted_{int(t0) % 1000}")

        try:
            # 1. Create document with realistic project notes
            content = (
                f"BÁO CÁO TIẾN ĐỘ VÀ KẾ HOẠCH CÔNG VIỆC THÁNG {datetime.datetime.now().strftime('%m/%Y')}\n"
                f"Ngày tạo: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                "1. Hoàn tất kiểm thử hiệu năng mô hình Anomaly Detection.\n"
                "2. Rà soát cấu hình tường lửa Windows và chính sách bảo mật nội bộ.\n"
                "3. Kiểm tra tính toàn vẹn dữ liệu hệ thống phân tán.\n"
                "Nội dung lưu hành nội bộ bộ phận kỹ thuật.\n"
            ) * 15
            with open(doc_path, "w", encoding="utf-8") as f:
                f.write(content)

            # 2. Copy to Downloads
            shutil.copy2(doc_path, dl_path)

            # 3. Zip archive
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.write(dl_path, arcname=file_name)

            # 4. Unzip archive
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            dur = time.time() - t0
            self.log_action(
                action_type="doc_lifecycle",
                target_path=doc_path,
                duration_sec=dur,
                status="SUCCESS",
                details=f"Created {file_name} ({len(content)} bytes), copied to Downloads, zipped & extracted",
            )
            return {"status": "SUCCESS", "duration": dur}
        except Exception as e:
            dur = time.time() - t0
            self.log_action(
                action_type="doc_lifecycle",
                target_path=doc_path,
                duration_sec=dur,
                status="ERROR",
                details=str(e),
            )
            return {"status": "ERROR", "error": str(e)}

    def action_git_status_and_diff(self) -> Dict[str, Any]:
        """Run git status and git diff in repository."""
        t0 = time.time()
        try:
            res_status = subprocess.run(
                ["git", "status"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=15.0,
            )
            res_diff = subprocess.run(
                ["git", "diff", "--stat"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=15.0,
            )
            dur = time.time() - t0
            summary = "git status & diff executed cleanly"
            if res_status.returncode != 0:
                summary = f"git status exited with {res_status.returncode}"
            self.log_action(
                action_type="git_ops",
                target_path=PROJECT_ROOT,
                duration_sec=dur,
                status="SUCCESS" if res_status.returncode == 0 else "WARNING",
                details=summary,
            )
            return {"status": "SUCCESS", "duration": dur}
        except Exception as e:
            dur = time.time() - t0
            self.log_action(
                action_type="git_ops",
                target_path=PROJECT_ROOT,
                duration_sec=dur,
                status="ERROR",
                details=str(e),
            )
            return {"status": "ERROR", "error": str(e)}

    def action_pytest_run(self) -> Dict[str, Any]:
        """Run a lightweight fast unit test within the repository."""
        t0 = time.time()
        py_exec = sys.executable
        try:
            res = subprocess.run(
                [py_exec, "-m", "pytest", "tests/test_explain.py", "-q"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=30.0,
            )
            dur = time.time() - t0
            out = res.stdout.strip().replace("\n", " ")
            self.log_action(
                action_type="pytest_test",
                target_path="tests/test_explain.py",
                duration_sec=dur,
                status="SUCCESS" if res.returncode == 0 else "FAILURE",
                details=f"Ran test_explain.py -> {out[:60]}",
            )
            return {"status": "SUCCESS", "duration": dur}
        except Exception as e:
            dur = time.time() - t0
            self.log_action(
                action_type="pytest_test",
                target_path="tests/test_sensitive.py",
                duration_sec=dur,
                status="ERROR",
                details=str(e),
            )
            return {"status": "ERROR", "error": str(e)}

    def action_web_download(self) -> Dict[str, Any]:
        """Simulate downloading a small public document/page to Downloads."""
        t0 = time.time()
        dest_file = os.path.join(self.dl_dir, f"web_download_{int(t0) % 1000}.html")
        url = "https://www.google.com"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BenignWorkload/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = resp.read()
            with open(dest_file, "wb") as f:
                f.write(data)

            dur = time.time() - t0
            self.log_action(
                action_type="web_download",
                target_path=dest_file,
                duration_sec=dur,
                status="SUCCESS",
                details=f"Downloaded {len(data)} bytes from {url} to Downloads",
            )
            return {"status": "SUCCESS", "duration": dur}
        except Exception as e:
            # Fallback to local file creation if offline / restricted network
            try:
                with open(dest_file, "w", encoding="utf-8") as f:
                    f.write(f"<html><body>Local offline sample document at {datetime.datetime.now()}</body></html>")
                dur = time.time() - t0
                self.log_action(
                    action_type="web_download",
                    target_path=dest_file,
                    duration_sec=dur,
                    status="SUCCESS",
                    details=f"Saved local HTML document ({e})",
                )
                return {"status": "SUCCESS", "duration": dur}
            except Exception as err:
                dur = time.time() - t0
                self.log_action(
                    action_type="web_download",
                    target_path=dest_file,
                    duration_sec=dur,
                    status="ERROR",
                    details=str(err),
                )
                return {"status": "ERROR", "error": str(err)}


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Benign User Workload Simulator")
    parser.add_argument("--minutes", type=float, default=120.0, help="Total execution duration in minutes (default: 120)")
    parser.add_argument("--interval-min", type=float, default=120.0, help="Minimum interval between actions in seconds (default: 120 = 2 min)")
    parser.add_argument("--interval-max", type=float, default=300.0, help="Maximum interval between actions in seconds (default: 300 = 5 min)")
    parser.add_argument("--run-id", type=str, default=None, help="Optional run identifier for tracking in CSV")
    parser.add_argument("--output", type=str, default="results/benign_actions.csv", help="Path to output CSV log")
    parser.add_argument("--once", action="store_true", help="Run each action once immediately and exit (for validation)")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("      PRIVACYGUARD REALISTIC BENIGN WORKLOAD GENERATOR")
    print("=" * 70)
    print(f"[*] Thời gian chạy dự kiến: {args.minutes:.1f} phút")
    print(f"[*] Tần suất thực hiện:     Mỗi {args.interval_min:.0f}s - {args.interval_max:.0f}s (2-5 phút)")
    print(f"[*] Tệp nhật ký hành động:  {args.output}")
    print("=" * 70)

    runner = BenignWorkloadRunner(output_csv=args.output, run_id=args.run_id)

    if args.once:
        print("[*] Chế độ chạy thử nghiệm (--once): Thực thi tuần tự mỗi hành động 1 lần...")
        runner.action_document_lifecycle()
        runner.action_git_status_and_diff()
        runner.action_pytest_run()
        runner.action_web_download()
        print("[+] Thử nghiệm thành công! Toàn bộ hành động lành tính đã được ghi vào CSV.")
        return

    actions = [
        runner.action_document_lifecycle,
        runner.action_git_status_and_diff,
        runner.action_pytest_run,
        runner.action_web_download,
    ]

    start_ts = time.time()
    end_ts = start_ts + (args.minutes * 60.0)

    print("[*] Bắt đầu tạo tải lành tính liên tục. Nhấn Ctrl+C để dừng an toàn bất kỳ lúc nào.\n")
    iteration = 0
    try:
        while time.time() < end_ts:
            iteration += 1
            # Execute random benign action
            chosen_action = random.choice(actions)
            chosen_action()

            # Calculate sleep interval
            remaining = end_ts - time.time()
            if remaining <= 0:
                break
            sleep_time = random.uniform(args.interval_min, args.interval_max)
            sleep_time = min(sleep_time, remaining)

            next_run_str = (datetime.datetime.now() + datetime.timedelta(seconds=sleep_time)).strftime("%H:%M:%S")
            print(f"    -> Nghỉ {sleep_time:.1f} giây. Lần chạy tiếp theo vào lúc: {next_run_str}...")
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n[*] Đã nhận tín hiệu dừng (Ctrl+C). Kết thúc an toàn.")

    elapsed_min = (time.time() - start_ts) / 60.0
    print("\n" + "=" * 70)
    print(f"[*] HOÀN TẤT TẠO WORKLOAD LÀNH TÍNH:")
    print(f"    - Thời gian chạy thực tế: {elapsed_min:.2f} phút")
    print(f"    - Tổng hành động đã làm:  {runner.action_counter} hành vi")
    print(f"    - Nhật ký lưu tại:        {runner.output_csv}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
