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

---

## 7. Simulator Scenarios with Only Network Signals (Absence of File Read Telemetry)
Because Sysmon lacks a `file_read` event provider (as detailed in Limitation 1), the collector cannot observe processes reading sensitive files from `FakeDocuments`. Consequently, several simulation scenarios exhibit **only network signals** in the captured telemetry, without correlated file read events:

- **Scenario 1 (Bulk Exfiltration)**: Reads multiple files and transmits in a single batch. In Sysmon, only the resulting `net_connect` (Event 3) is recorded; all preceding file read actions are completely invisible.
- **Scenario 2 (Slow Trickle Exfiltration)**: Reads files and transmits small chunks over time. Emits only a temporal sequence of `net_connect` events without file telemetry.
- **Scenario 5 (Port 443 Exfiltration)**: Reads files and transmits to destination port 443. Sysmon logs only `net_connect` (Event 3) to port 443, identical in telemetry pattern to non-sensitive web traffic.
- **Scenario 6 (Periodic Beaconing)**: Reads a small file and sends periodic heartbeats. Appears purely as periodic `net_connect` bursts.
- **Scenario 8 (Network-Only Control)**: Generates random bytes in memory and transmits without touching any file on disk. Emits only `net_connect` (Event 3). Because file reads are invisible, Scenario 8 produces an almost indistinguishable telemetry footprint to Scenarios 1, 2, 5, and 6.

### Contrast with Other Scenarios:
- **Scenario 3 (Compressed Archive)**: If the compressed archive is generated in-memory, it exhibits only network signals. If written to disk as a temporary archive, Sysmon records a `file_create` (Event 11) for the `.zip` file followed by `net_connect`.
- **Scenario 4 (Subprocess Exfiltration)**: Spawns a child process, producing a `proc_start` (Event 1) parent-child lineage followed by `net_connect` (Event 3) from the child.
- **Scenario 7 (Benign Cloud Backup)**: Copies files to `data/fake_cloud`, creating `file_create` (Event 11) events for the destination files, with zero network connections.
- **Scenario 9 (File-Read-Only Control)**: Only reads files without network activity. Because Sysmon does not log file reads, Scenario 9 produces **zero** file events and **zero** network events.

---

## 8. Autoencoder Sensitivity to Low-Volume and Trickle Patterns
- **Limitation**: The deep-learning MLP Autoencoder scores anomalies via Mean Squared Error (MSE) reconstruction loss across all 17 feature dimensions.
- **Impact on Scenarios 2 & 6**:
  - In large bulk exfiltrations (Scenarios 1, 3, 5), reconstruction error is high across byte volume, causal flow, and sensitive ratios, leading to reliable detection.
  - However, in Scenario 2 (Slow Trickle) and Scenario 6 (Periodic Beaconing), transmission volumes per window are minimal. The subtle anomaly in network burstiness or low byte counts is often diluted by the remaining 15 feature dimensions, resulting in lower recall (~65.3%) and higher false negatives compared to the Rule-Based engine ($F_1 = 0.9897$) and Isolation Forest ($F_1 = 0.9360$).
- **Scientific Implication**: Unsupervised Autoencoders must be complemented with temporal sequence models (e.g., LSTM/GRU or sliding Markov chains) or rule-based causal flow gates to effectively capture low-and-slow exfiltration.

---

## 9. Administrative Privilege Requirement for Sysmon Driver
- **Limitation**: Microsoft Sysmon relies on a ring-0 kernel minifilter driver (`SysmonDrv.sys`) and an operational event channel.
- **Deployment Constraint**:
  - Installing, updating, or configuring Sysmon XML schemas requires elevated Administrator privileges on Windows.
  - Although the PrivacyGuard Collector (`sysmon_collector.py`) and UI execute safely in user mode without requiring kernel write access, any target system must have Sysmon pre-installed by an administrator.

---

## 10. Causality-Based Inference vs. Cryptographic Payload Proof
- **Ethical & Privacy Design Choice**: PrivacyGuard deliberately avoids installing self-signed root CA certificates or deploying TLS/HTTPS man-in-the-middle proxies.
- **Consequence**:
  - Detection relies on temporal and spatial provenance: proving that process $P$ accessed sensitive file $F$ and subsequently initiated connection to socket $S$ within temporal window $\Delta t = 30s$ with outbound traffic volume $V$.
  - While this provides a strong causal chain without invading user privacy or breaking end-to-end encryption, it constitutes probabilistic causal correlation rather than cryptographic proof of payload plaintext.


