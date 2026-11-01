"""Unit and integration tests for Phase 3 MITRE ATT&CK payload generator and reports.

Verifies:
1. Safety bounds of simulator/mitre_payload.py (host validation, directory isolation).
2. Integrity of results/mitre_results.csv, results/mitre_alerts.csv, results/mitre_summary.json, and results/MITRE_REPORT.md (skipped until live execution completes).
"""

from __future__ import annotations

import csv
import io
import json
import os
import pathlib
import re
import pytest

from simulator.mitre_payload import (
    validate_target_host,
    validate_docs_dir,
)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
GUID_REGEX = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
)


class TestMitrePayloadSafety:
    """Ensure safety constraints of the payload runner are enforced."""

    def test_validate_target_host_loopback_allowed(self):
        validate_target_host("127.0.0.1")
        validate_target_host("localhost")

    def test_validate_target_host_external_rejected(self):
        with pytest.raises(ValueError, match="SAFETY VIOLATION"):
            validate_target_host("8.8.8.8")
        with pytest.raises(ValueError, match="SAFETY VIOLATION"):
            validate_target_host("192.168.1.1")

    def test_validate_docs_dir_inside_fake_documents(self):
        allowed = PROJECT_ROOT / "data" / "FakeDocuments"
        sub = allowed / "subfolder"
        assert validate_docs_dir(allowed) == allowed.resolve()
        assert validate_docs_dir(sub) == sub.resolve()

    def test_validate_docs_dir_outside_rejected(self):
        with pytest.raises(ValueError, match="SAFETY VIOLATION"):
            validate_docs_dir(PROJECT_ROOT / "core")
        with pytest.raises(ValueError, match="SAFETY VIOLATION"):
            validate_docs_dir(pathlib.Path("C:/Windows"))


class TestMitreReportIntegrity:
    """Validate Phase 3 MITRE evaluation output artifacts when present."""

    @pytest.fixture(autouse=True)
    def setup_paths(self):
        self.results_csv = PROJECT_ROOT / "results" / "mitre_results.csv"
        self.alerts_csv = PROJECT_ROOT / "results" / "mitre_alerts.csv"
        self.summary_json = PROJECT_ROOT / "results" / "mitre_summary.json"
        self.report_md = PROJECT_ROOT / "results" / "MITRE_REPORT.md"

    def test_mitre_results_csv_structure_and_metrics(self):
        if not self.results_csv.exists():
            pytest.skip("results/mitre_results.csv does not exist yet (run elevated Phase 3 script first)")

        with open(self.results_csv, "r", encoding="utf-8", errors="replace") as f:
            reader = list(csv.DictReader(f))

        # Must have exactly 3 scenarios evaluated
        assert len(reader) == 3, f"Expected 3 scenario rows, got {len(reader)}"

        techniques = [r["technique"] for r in reader]
        assert "T1560.001" in techniques
        assert "T1041" in techniques
        assert "T1567" in techniques

        seen_proc_keys = set()
        seen_pids = set()

        for row in reader:
            # Check detection and validity
            detected = int(row["detected"])
            valid = int(row["valid"])
            assert detected == 1, f"Scenario {row['scenario_id']} was not detected (detected={detected})"
            assert valid == 1, f"Scenario {row['scenario_id']} failed validation checks (valid={valid})"

            # GUID and PID validity
            pk = row["proc_key"]
            assert GUID_REGEX.match(pk), f"Invalid Sysmon GUID proc_key: {pk}"
            seen_proc_keys.add(pk)

            pid = int(row["pid"])
            assert pid > 0 and pid != 8888, f"Invalid or mock PID detected: {pid}"
            seen_pids.add(pid)

            # Alert ID > 174 (distinct from Phase 0.6 reference alerts #170-#174)
            alert_id = int(row["alert_id"])
            assert alert_id > 174, f"Alert ID {alert_id} violates Phase 3 constraint (must be > 174)"

            # Byte transmission fidelity
            diff = int(row["bytes_diff"])
            assert diff <= 1, f"Byte count discrepancy too large: diff={diff}"

            # Sensitive files detected
            n_sens = int(row["n_sensitive"])
            assert n_sens >= 1, f"Scenario {row['scenario_id']} reported 0 sensitive files"

            # Telemetry source must be authentic sysmon
            assert row["source_sysmon"].lower() in ("true", "1")

        # Distinct processes for each scenario
        assert len(seen_proc_keys) == 3, "Each scenario must have a unique Sysmon proc_key GUID"
        assert len(seen_pids) == 3, "Each scenario must have a distinct child PID"

    def test_mitre_summary_json_integrity(self):
        if not self.summary_json.exists():
            pytest.skip("results/mitre_summary.json does not exist yet")

        with open(self.summary_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data.get("phase") == 3
        assert data.get("total") == 3
        if data.get("detected") == 3:
            assert data.get("tpr") == 1.0
            assert data.get("all_valid") is True

        assert data.get("old_alerts_intact") is True
        assert data.get("all_sources_sysmon") is True
        assert data.get("synthetic_events") == 0
        assert data.get("config_unchanged") is True

    def test_mitre_report_markdown_content(self):
        if not self.report_md.exists():
            pytest.skip("results/MITRE_REPORT.md does not exist yet")

        with open(self.report_md, "r", encoding="utf-8") as f:
            content = f.read()

        assert "T1560" in content
        assert "T1041" in content
        assert "T1567" in content
        assert "TPR" in content
        assert "Sysmon" in content
        assert "Event 22" in content  # Documentation of DNS gap
