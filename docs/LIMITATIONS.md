# PrivacyGuard: System Limitations and Constraints

This document outlines key limitations of the current telemetry and detection architecture, specifically arising from the transition to Microsoft Sysmon and single-session data constraints.

---

## 1. No File Read Telemetry (`file_read`)
- **Limitation**: Sysmon does not log file read events. It monitors file creation via Event ID 11 (`FileCreate`), but lacks an event provider for file access/reading.
- **Impact on Feature Engineering**:
  - Features defined in the specification that depend on file reading (e.g. `bytes_read`, `n_file_read`, and `ratio_sensitive`) cannot be computed directly from actual file read events.
  - Instead, these features are adapted to leverage file creation (`FileCreate`), downloaded file metadata, and process lifecycle events.
  - **Strict Policy**: Synthetic or fabricated `file_read` events will NOT be generated to mask this limitation. All reported metrics represent actual telemetry.

---

## 2. Lack of File Rename/Move Tracking in Event 11
- **Limitation**: Sysmon Event 11 only records initial file creation, not file renames or moves.
- **Impact on Browser Downloads**:
  - Web browsers such as Google Chrome initially download files with a temporary extension (e.g. `Không được xác nhận 585344.crdownload`), and later rename the completed download to its final destination (e.g. `BlueStacksInstaller_..._(3).exe`).
  - Sysmon logs these as separate `FileCreate` occurrences (the temporary `.crdownload` file and the final target file), without emitting an explicit rename event that connects the temporary hash/name to the final executable.
  - Data provenance and temporal analysis must correlate these events based on process identity (`ProcessGuid`), timestamp proximity, and destination directories.

---

## 3. Inherent Vulnerability and Absence of `Zone.Identifier`
- **Limitation**: `Zone.Identifier` is an NTFS Alternate Data Stream (ADS) created by applications implementing the `IAttachmentExecute` interface (such as modern web browsers) to record download origin (`HostUrl`, `ReferrerUrl`, `ZoneId`).
- **Absence Scenarios**:
  - Files created via CLI tools, scripts (`curl`, `python`, `powershell`), or non-browser utilities often do not create a `Zone.Identifier` stream.
  - Files created on non-NTFS partitions (FAT32, exFAT, network shares) do not support Alternate Data Streams.
  - Sophisticated applications or malicious actors can deliberately omit, strip, or wipe `:Zone.Identifier` streams upon downloading.
- **Handling**:
  - When a `Zone.Identifier` stream cannot be resolved or is absent, PrivacyGuard records `'unknown'` for download origin attributes without raising errors.

---

## 4. Network Byte Count Granularity
- **Limitation**: Sysmon Event ID 3 (`NetworkConnect`) records connection initiation, remote IP, destination port, and transport protocol, but does NOT track per-connection packet/byte volume (`nbytes = 0`).
- **Impact**: Byte-level transmission metrics rely on socket-level instrumentation or simulator ground-truth correlation.

---

## 5. Single Measurement Session Insufficient for Model Training
- **Limitation**: A single 60-second live collection session represents only a single point-in-time sample, serving as a functional smoke test to verify collector correctness.
- **Impact on Machine Learning & Deep Learning**:
  - Machine learning models (rules baseline, Isolation Forest, Autoencoder, LSTM) cannot be reliably trained on a single brief measurement session.
  - As mandated by SPEC Section 8, training requires comprehensive benign baseline data collected over multiple days across diverse normal workloads (web browsing, office productivity, cloud synchronization, OS updates).
  - Training on a single brief capture would cause severe overfitting, high false positive rates, and poor generalization.

---

## 6. Heuristic Noise Tagging vs. True Telemetry (tag_patterns Assumption)
- **Design Decision**: In order to avoid dropping authentic application activity, high-volume app data paths (`\AppData\Local\Packages\`, `\AppData\Local\Temp`, browser caches, `Code Cache`, `INetCache`) are retained in the `events` table rather than dropped, and flagged with `noise_candidate=1` inside `extra_json`.
- **Limitation & Hypothesis**: The current list of `tag_patterns` in `config.yaml` is an operational heuristic/assumption that requires empirical validation during Phase D (Modeling & Anomaly Detection).
- **Risk of Mislabeling**: Genuine application telemetry (such as Anthropic Claude's `sentry\scope_v3.json` and `sentry\session.json`, or embedded web engines like `msedgewebview2` in Office Hub) routinely writes to and reads from these directory patterns. Tagging these locations as noise candidates may lead downstream feature extraction or detection models to misidentify legitimate application behavior as benign noise, potentially masking data flows if not properly calibrated during Phase D.

