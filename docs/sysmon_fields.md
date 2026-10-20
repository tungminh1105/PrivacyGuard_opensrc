# Sysmon Event ID and Field Mapping

This document specifies the exact mapping between Windows Sysmon Event Log entries and the PrivacyGuard event schema. All field names and Event IDs are verified against real Sysmon log samples collected on Windows (`docs/sysmon_sample.txt`, `docs/sysmon_fc.txt`, `docs/sysmon_downloads.txt`).

## 1. Supported Sysmon Event IDs

Only the following four official Sysmon Event IDs are supported:
- **Event ID 1**: Process Create (`ProcessCreate`)
- **Event ID 3**: Network Connection Detected (`NetworkConnect`)
- **Event ID 5**: Process Terminated (`ProcessTerminate`)
- **Event ID 11**: File Created (`FileCreate`)

---

## 2. Event ID 1: Process Create (`proc_start`)

### Sysmon Raw Fields
- `UtcTime`: Timestamp in UTC format (`YYYY-MM-DD HH:MM:SS.mmm`)
- `ProcessGuid`: Unique process identifier GUID (e.g. `{db9fa507-6d19-6ad7-2f14-000000007100}`)
- `ProcessId`: Operating system PID
- `Image`: Full path to executable (e.g. `C:\Windows\System32\tasklist.exe`)
- `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`
- `CommandLine`: Full command line used to launch the process
- `CurrentDirectory`: Working directory
- `User`: User account (e.g. `DESKTOP-402J9M1\Tungminh`)
- `LogonGuid`, `LogonId`, `TerminalSessionId`, `IntegrityLevel`, `Hashes`
- `ParentProcessGuid`: GUID of the parent process
- `ParentProcessId`: PID of the parent process
- `ParentImage`: Executable path of the parent process
- `ParentCommandLine`: Command line of the parent process
- `ParentUser`: User account of the parent process

### Mapping to PrivacyGuard Schema
- `events.type`: `'proc_start'`
- `events.ts`: Epoch seconds (float) parsed from `UtcTime`
- `events.proc_key`: `ProcessGuid`
- `events.pid`: `ProcessId` (int)
- `events.ppid`: `ParentProcessId` (int)
- `events.path`: `Image`
- `events.dest_ip`: `NULL`
- `events.dest_port`: `NULL`
- `events.proto`: `NULL`
- `events.nbytes`: `0`

### Mapping to `processes` Table
- `processes.proc_key`: `ProcessGuid`
- `processes.pid`: `ProcessId`
- `processes.ppid`: `ParentProcessId`
- `processes.name`: Base executable filename from `Image`
- `processes.exe_path`: `Image`
- `processes.signed`: `0` or `1` (from authenticode verification)
- `processes.publisher`: `Company` or authenticode signer
- `processes.start_ts`: Epoch seconds parsed from `UtcTime`
- `processes.end_ts`: `NULL`

---

## 3. Event ID 3: Network Connection (`net_connect`)

### Sysmon Raw Fields
- `UtcTime`: Timestamp in UTC (`YYYY-MM-DD HH:MM:SS.mmm`)
- `ProcessGuid`: Process GUID
- `ProcessId`: PID
- `Image`: Executable path
- `User`: User account
- `Protocol`: Transport protocol (`tcp` or `udp`)
- `Initiated`: Boolean (`true` / `false`)
- `SourceIsIpv6`: Boolean
- `SourceIp`: Local IP address
- `SourceHostname`: Local hostname
- `SourcePort`: Local port
- `DestinationIsIpv6`: Boolean
- `DestinationIp`: Remote destination IP address
- `DestinationHostname`: Destination hostname if resolved
- `DestinationPort`: Remote destination port (int)
- `DestinationPortName`: Service name if recognized (e.g. `https`)

### Mapping to PrivacyGuard Schema
- `events.type`: `'net_connect'`
- `events.ts`: Epoch seconds (float) parsed from `UtcTime`
- `events.proc_key`: `ProcessGuid`
- `events.pid`: `ProcessId` (int)
- `events.ppid`: `NULL`
- `events.path`: `NULL`
- `events.dest_ip`: `DestinationIp`
- `events.dest_port`: `DestinationPort` (int)
- `events.proto`: `Protocol` (e.g. `'tcp'`, `'udp'`)
- `events.nbytes`: `0` (Sysmon connection events do not record payload size)

---

## 4. Event ID 5: Process Terminated (`proc_end`)

### Sysmon Raw Fields
- `UtcTime`: Timestamp in UTC
- `ProcessGuid`: Process GUID
- `ProcessId`: PID
- `Image`: Executable path
- `User`: User account

### Mapping to PrivacyGuard Schema
- `events.type`: `'proc_end'`
- `events.ts`: Epoch seconds (float) parsed from `UtcTime`
- `events.proc_key`: `ProcessGuid`
- `events.pid`: `ProcessId` (int)
- `events.ppid`: `NULL`
- `events.path`: `Image`
- `events.dest_ip`: `NULL`
- `events.dest_port`: `NULL`
- `events.proto`: `NULL`
- `events.nbytes`: `0`
- Updates `processes.end_ts = ts` where `proc_key = ProcessGuid`.

---

## 5. Event ID 11: File Created (`file_create`)

### Sysmon Raw Fields
- `UtcTime`: Timestamp in UTC
- `ProcessGuid`: Process GUID
- `ProcessId`: PID
- `Image`: Executable path creating the file
- `TargetFilename`: Full destination path of the created file
- `CreationUtcTime`: Timestamp when file was created
- `User`: User account

### Mapping to PrivacyGuard Schema
- `events.type`: `'file_create'`
- `events.ts`: Epoch seconds (float) parsed from `UtcTime`
- `events.proc_key`: `ProcessGuid`
- `events.pid`: `ProcessId` (int)
- `events.ppid`: `NULL`
- `events.path`: Base path of `TargetFilename` (see Zone.Identifier rule below)
- `events.dest_ip`: `NULL`
- `events.dest_port`: `NULL`
- `events.proto`: `NULL`
- `events.nbytes`: `0` (or file size if readable)

### Special Handling: Zone.Identifier (NTFS ADS)
- When `TargetFilename` ends with `:Zone.Identifier`, it represents metadata attached to the downloaded file.
- The base file path is extracted by removing `:Zone.Identifier`.
- The parser reads the Zone.Identifier stream if available to extract:
  - `host_domain`: Host domain parsed from `HostUrl` (query strings removed)
  - `referrer_domain`: Referrer domain parsed from `ReferrerUrl` (query strings removed)
  - `zone_id`: Zone identifier integer (e.g. `3` for Internet)
- If Zone.Identifier is missing or cannot be read, fields are populated as `'unknown'`.

### Deduplication Rule
- Events matching `(ProcessGuid, TargetFilename, UtcTime)` within a session or batch are treated as duplicates and deduplicated.
