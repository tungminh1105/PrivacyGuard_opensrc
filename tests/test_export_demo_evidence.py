"""Tests for Phase 4 Demo Evidence Exporter.

Verifies:
1. Export script creates all 4 required files (phase3_summary.json, phase2_fpr_summary.json, alerts_175_177.csv, manifest.json).
2. Metrics in manifest match authentic benchmarks: TPR 3/3 (100%), FPR 0/1000 windows, byte diff = 0, alerts #175-#177.
3. SHA-256 hashes in manifest match actual disk file hashes.
4. Output does not leak real user private directories or un-sanitized paths.
5. Operates safely in read-only mode without requiring Administrator privileges.
"""

from __future__ import annotations

import csv
import hashlib
import json
import pathlib
import subprocess
import sys
import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

from scripts.export_demo_evidence import export_demo_evidence, compute_file_sha256


class TestExportDemoEvidence:
    """Test suite for Phase 4 demo evidence export logic."""

    @pytest.fixture
    def default_paths(self):
        db_path = PROJECT_ROOT / "data" / "privacyguard.db"
        results_dir = PROJECT_ROOT / "results"
        return db_path, results_dir

    def test_export_creates_all_deliverables_in_temp_dir(self, default_paths, tmp_path):
        db_path, results_dir = default_paths
        out_dir = tmp_path / "demo_export"

        manifest = export_demo_evidence(db_path, results_dir, out_dir)

        # Assert all 4 files exist
        assert (out_dir / "phase3_summary.json").is_file()
        assert (out_dir / "phase2_fpr_summary.json").is_file()
        assert (out_dir / "alerts_175_177.csv").is_file()
        assert (out_dir / "manifest.json").is_file()

        # Assert manifest structure
        assert manifest["export_version"] == "1.0.0"
        assert len(manifest["commit_hash"]) >= 7
        assert "timestamp" in manifest

    def test_manifest_metrics_match_authentic_benchmarks(self, default_paths, tmp_path):
        db_path, results_dir = default_paths
        out_dir = tmp_path / "demo_export"

        manifest = export_demo_evidence(db_path, results_dir, out_dir)
        metrics = manifest["metrics"]
        counts = manifest["counts"]

        # Metric: TPR 3/3 (100%)
        assert metrics["tpr"] == 1.0
        assert metrics["tpr_scenarios_detected"] == 3
        assert metrics["tpr_scenarios_total"] == 3
        assert "3/3" in metrics["tpr_display"]

        # Metric: FPR 0/1000 windows over ~121.94 min
        assert metrics["fpr_per_1000_windows"] == 0.0
        assert metrics["fpr_duration_min"] >= 120.0
        assert metrics["fpr_windows_evaluated"] >= 70000

        # Metric: Byte diff fidelity (diff = 0)
        assert metrics["byte_diff_max"] == 0

        # Metric: Telemetry authenticity (100% sysmon, 0 synthetic)
        assert metrics["all_sources_sysmon"] is True
        assert metrics["synthetic_events"] == 0

        # Canonical DB is frozen at 10 alerts (#170-#179). Any additional alert
        # indicates an accidental write to the canonical DB and must fail this test.
        assert counts["total_alerts"] == 10
        assert counts["reference_alerts"] == 5
        assert counts["phase3_alerts"] == 3
        assert counts["phase3_alert_ids"] == [175, 176, 177]

    def test_manifest_sha256_hashes_match_disk_files(self, default_paths, tmp_path):
        db_path, results_dir = default_paths
        out_dir = tmp_path / "demo_export"

        manifest = export_demo_evidence(db_path, results_dir, out_dir)

        for filename, file_info in manifest["files"].items():
            disk_file = out_dir / filename
            assert disk_file.exists(), f"Manifest file missing from disk: {filename}"

            actual_sha = compute_file_sha256(disk_file)
            actual_size = disk_file.stat().st_size

            assert (
                actual_sha == file_info["sha256"]
            ), f"SHA256 mismatch for {filename}: {actual_sha} != {file_info['sha256']}"
            assert (
                actual_size == file_info["size_bytes"]
            ), f"Size mismatch for {filename}: {actual_size} != {file_info['size_bytes']}"

    def test_alerts_csv_content_and_sanitization(self, default_paths, tmp_path):
        db_path, results_dir = default_paths
        out_dir = tmp_path / "demo_export"

        export_demo_evidence(db_path, results_dir, out_dir)
        csv_file = out_dir / "alerts_175_177.csv"

        with open(csv_file, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        # Exactly 3 alerts
        assert len(reader) == 3

        alert_ids = [int(r["id"]) for r in reader]
        assert alert_ids == [175, 176, 177]

        for row in reader:
            assert row["detector"] == "RuleBased"
            assert row["severity"] == "Cao"
            assert float(row["score"]) >= 0.70
            assert int(row["bytes_sent"]) > 1024
            assert int(row["n_sensitive"]) >= 1

            # Check sanitization: no paths should contain personal user directories (e.g. C:\Users\)
            files_field = row["files"]
            assert "C:\\Users\\" not in files_field
            assert "C:/Users/" not in files_field

            ev = json.loads(row["evidence_json"])
            for sf in ev.get("sensitive_files", []):
                assert "C:\\Users\\" not in sf
                assert "C:/Users/" not in sf

    def test_summaries_have_relative_db_path(self, default_paths, tmp_path):
        db_path, results_dir = default_paths
        out_dir = tmp_path / "demo_export"

        export_demo_evidence(db_path, results_dir, out_dir)

        p3_data = json.loads((out_dir / "phase3_summary.json").read_text(encoding="utf-8"))
        p2_data = json.loads((out_dir / "phase2_fpr_summary.json").read_text(encoding="utf-8"))

        # Assert db_path is not absolute and equals clean relative path
        assert p3_data.get("db_path") == "data/privacyguard.db"
        assert not pathlib.Path(p3_data["db_path"]).is_absolute()
        assert "D:\\KERNAL" not in p3_data["db_path"]
        assert "D:/KERNAL" not in p3_data["db_path"]

        assert p2_data.get("db_path") == "data/privacyguard.db"
        assert not pathlib.Path(p2_data["db_path"]).is_absolute()
        assert "D:\\KERNAL" not in p2_data["db_path"]
        assert "D:/KERNAL" not in p2_data["db_path"]

    def test_no_file_in_out_dir_contains_kernal_or_file_uri(self, default_paths, tmp_path):
        db_path, results_dir = default_paths
        out_dir = tmp_path / "demo_export"

        export_demo_evidence(db_path, results_dir, out_dir)

        # Scan all generated files in out_dir
        for fpath in out_dir.iterdir():
            if fpath.is_file():
                content = fpath.read_text(encoding="utf-8", errors="replace")
                assert "D:\\KERNAL" not in content, f"File {fpath.name} contains D:\\KERNAL"
                assert "D:/KERNAL" not in content, f"File {fpath.name} contains D:/KERNAL"
                assert "file:///D:/" not in content, f"File {fpath.name} contains file:///D:/"
                assert "file:///d:/" not in content.lower(), f"File {fpath.name} contains file:///d:/"

    def test_export_cli_execution(self, tmp_path):
        out_dir = tmp_path / "cli_demo_export"

        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "export_demo_evidence.py"),
            "--db",
            str(PROJECT_ROOT / "data" / "privacyguard.db"),
            "--results-dir",
            str(PROJECT_ROOT / "results"),
            "--out",
            str(out_dir),
        ]

        res = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15.0,
        )

        assert res.returncode == 0
        assert "Export completed successfully!" in res.stdout
        assert (out_dir / "manifest.json").is_file()
