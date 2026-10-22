"""Sysmon collector and parser module for PrivacyGuard.

Collects and parses Windows Sysmon operational logs (Event ID 1, 3, 5, 11).
Normalizes events into the schema specified in SPEC Section 4.
Uses EventRecordID watermark polling every 1 second (no callback/subscription).
Filters collector process and Sysmon binary events.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import queue
import re
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

try:
    import yaml
except ImportError:
    yaml = None

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.store import EventStore

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "database": {
        "db_path": "data/privacyguard.db",
        "wal_mode": True,
        "batch_size": 500,
        "flush_interval_sec": 1.0,
    },
    "sysmon": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "events": {
            "process_create": {
                "event_id": 1,
                "type": "proc_start",
                "fields": {
                    "utc_time": "UtcTime",
                    "process_guid": "ProcessGuid",
                    "process_id": "ProcessId",
                    "image": "Image",
                    "parent_process_guid": "ParentProcessGuid",
                    "parent_process_id": "ParentProcessId",
                    "command_line": "CommandLine",
                    "user": "User",
                },
            },
            "network_connect": {
                "event_id": 3,
                "type": "net_connect",
                "fields": {
                    "utc_time": "UtcTime",
                    "process_guid": "ProcessGuid",
                    "process_id": "ProcessId",
                    "image": "Image",
                    "protocol": "Protocol",
                    "dest_ip": "DestinationIp",
                    "dest_port": "DestinationPort",
                },
            },
            "process_terminate": {
                "event_id": 5,
                "type": "proc_end",
                "fields": {
                    "utc_time": "UtcTime",
                    "process_guid": "ProcessGuid",
                    "process_id": "ProcessId",
                    "image": "Image",
                    "user": "User",
                },
            },
            "file_create": {
                "event_id": 11,
                "type": "file_create",
                "fields": {
                    "utc_time": "UtcTime",
                    "process_guid": "ProcessGuid",
                    "process_id": "ProcessId",
                    "image": "Image",
                    "target_filename": "TargetFilename",
                    "creation_utc_time": "CreationUtcTime",
                    "user": "User",
                },
            },
        },
    },
    "noise_filters": {
        "enabled": True,
        "drop_patterns": [
            "C:\\Windows\\Prefetch",
            "C:\\Windows\\WinSxS",
            "$Mft",
            "pagefile.sys",
            "swapfile.sys",
            "\\Microsoft\\Windows\\Recent\\",
        ],
        "tag_patterns": [
            "\\AppData\\Local\\Temp",
            "\\AppData\\Local\\Packages\\",
            "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
            "Code Cache",
            "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache",
            "\\AppData\\Local\\Microsoft\\Windows\\INetCache",
        ],
        "ignore_processes": ["privacyguard", "python.exe"],
    },
    "simulator": {
        "receiver_host": "127.0.0.1",
        "receiver_port": 8765,
        "scenario5_port": 443,
        "fake_docs_dir": "data/FakeDocuments",
        "fake_cloud_dir": "data/fake_cloud",
        "ground_truth_path": "data/ground_truth.csv",
    },
}


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file with fallback to default config."""
    if os.path.exists(config_path) and yaml is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            logger.warning("Failed to parse %s: %s. Using default config.", config_path, e)
    return DEFAULT_CONFIG


def read_file_with_bom(path: str) -> str:
    """Read file content detecting encoding via BOM (UTF-16 LE, UTF-16 BE, UTF-8-sig)."""
    with open(path, "rb") as f:
        raw = f.read()
    if raw.startswith(b"\xff\xfe"):
        content = raw.decode("utf-16-le", errors="replace")
    elif raw.startswith(b"\xfe\xff"):
        content = raw.decode("utf-16-be", errors="replace")
    elif raw.startswith(b"\xef\xbb\xbf"):
        content = raw.decode("utf-8-sig", errors="replace")
    else:
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("latin-1")
    return content.lstrip("\ufeff")


def parse_utc_timestamp(ts_str: Optional[str]) -> float:
    """Parse Sysmon UTC string or ISO timestamp into epoch seconds float."""
    if not ts_str:
        return time.time()
    clean = ts_str.strip().replace("T", " ").rstrip("Z")
    try:
        if "." in clean:
            parts = clean.split(".")
            date_part = parts[0]
            frac_part = parts[1][:6]
            clean = f"{date_part}.{frac_part}"
            dt = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S.%f")
        else:
            dt = datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return time.time()


def extract_domain(url: Optional[str]) -> str:
    """Extract only the domain/host from a URL, stripping paths and query strings."""
    if not url or url.strip() in ("", "-", "unknown"):
        return "unknown"
    target = url.strip()
    try:
        if not re.match(r"^[a-zA-Z]+://", target):
            target = "http://" + target
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or parsed.netloc
        if host:
            return host.lower().split(":")[0]
    except Exception:
        pass
    return "unknown"


def parse_zone_identifier_content(content: str) -> Dict[str, str]:
    """Parse ZoneTransfer metadata from Zone.Identifier stream content."""
    zone_id = "unknown"
    host_domain = "unknown"
    referrer_domain = "unknown"
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("ZoneId="):
            zone_id = line.split("=", 1)[1].strip() or "unknown"
        elif line.startswith("HostUrl="):
            host_domain = extract_domain(line.split("=", 1)[1].strip())
        elif line.startswith("ReferrerUrl="):
            referrer_domain = extract_domain(line.split("=", 1)[1].strip())
    return {
        "zone_id": zone_id,
        "host_domain": host_domain,
        "referrer_domain": referrer_domain,
    }


def read_zone_identifier(base_path: str) -> Dict[str, str]:
    """Attempt to read NTFS Alternate Data Stream :Zone.Identifier for a file path.

    Returns dict with zone_id, host_domain, referrer_domain ('unknown' if absent).
    Never raises an exception if the file or stream does not exist.
    """
    stream_path = f"{base_path}:Zone.Identifier"
    try:
        with open(stream_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return parse_zone_identifier_content(content)
    except Exception:
        return {
            "zone_id": "unknown",
            "host_domain": "unknown",
            "referrer_domain": "unknown",
        }


def extract_event_record_id_from_xml(xml_content: str) -> Optional[int]:
    """Extract EventRecordID integer from event XML."""
    try:
        root = ET.fromstring(xml_content)
        for child in root:
            if child.tag.endswith("System"):
                for sc in child:
                    if sc.tag.endswith("EventRecordID") and sc.text:
                        return int(sc.text.strip())
    except Exception:
        pass
    return None


def query_latest_record_id(channel: str) -> int:
    """Query the largest EventRecordID currently present in the channel."""
    try:
        import win32evtlog
        q = win32evtlog.EvtQuery(
            channel,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        )
        events = win32evtlog.EvtNext(q, 1)
        if events:
            xml_data = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
            rid = extract_event_record_id_from_xml(xml_data)
            if rid is not None:
                return rid
    except Exception as e:
        logger.debug("Failed to query latest record ID from %s: %s", channel, e)
    return 0


class SysmonParser:
    """Parses Sysmon events from XML or text dumps and normalizes them."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        self._init_mappings()
        self.seen_dedup_keys: Set[Tuple[Any, ...]] = set()
        self.collector_guid: Optional[str] = None

    def _init_mappings(self) -> None:
        """Initialize event ID and field name lookups from config."""
        events_cfg = self.config.get("sysmon", {}).get("events", {})
        self.id_to_event_cfg: Dict[int, Dict[str, Any]] = {}
        self.known_field_names: Set[str] = set()

        for key, info in events_cfg.items():
            eid = int(info.get("event_id", 0))
            self.id_to_event_cfg[eid] = info
            fields = info.get("fields", {})
            for mapped_name in fields.values():
                self.known_field_names.add(mapped_name)

        # Standard Sysmon fields that may appear in event blocks
        self.known_field_names.update({
            "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion",
            "Description", "Product", "Company", "OriginalFileName", "CommandLine",
            "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId",
            "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
            "ParentImage", "ParentCommandLine", "ParentUser", "Protocol", "Initiated",
            "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName",
            "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort",
            "DestinationPortName", "TargetFilename", "CreationUtcTime"
        })

    def check_drop_reason(self, event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Check if an event matches a dropping condition (Sysmon binary, collector process, or drop_patterns).

        Returns:
            (reason, matched_pattern) or (None, None)
        """
        path = event.get("path") or ""
        image = event.get("image") or ""
        lower_path = path.lower() if path else ""
        lower_image = image.lower() if image else ""

        # 1. Filter sysmon service/executable itself
        if "sysmon" in lower_path or "sysmon" in lower_image:
            pattern = path if "sysmon" in lower_path else image
            return "sysmon", pattern

        # 2. Filter collector's own process by PID or cached GUID
        collector_pid = os.getpid()
        if event.get("pid") == collector_pid:
            return "collector", f"collector_pid={collector_pid}"
        if self.collector_guid and event.get("proc_key") == self.collector_guid:
            return "collector", f"collector_guid={self.collector_guid}"

        filters = self.config.get("noise_filters", {})
        if not filters.get("enabled", True):
            return None, None

        drop_patterns = filters.get("drop_patterns")
        if drop_patterns is None:
            drop_patterns = filters.get("path_patterns", [])

        norm_path = lower_path.replace("/", "\\")
        norm_image = lower_image.replace("/", "\\")

        for pattern in drop_patterns:
            pat_norm = pattern.lower().replace("/", "\\")
            if (norm_path and pat_norm in norm_path) or (norm_image and pat_norm in norm_image):
                return "drop_pattern", pattern

        return None, None

    def check_tag_pattern(self, event: Dict[str, Any]) -> Optional[str]:
        """Check if an event matches tag_patterns for noise candidates.

        Returns:
            matched_pattern or None
        """
        filters = self.config.get("noise_filters", {})
        if not filters.get("enabled", True):
            return None

        path = event.get("path") or ""
        image = event.get("image") or ""
        lower_path = path.lower() if path else ""
        lower_image = image.lower() if image else ""

        norm_path = lower_path.replace("/", "\\")
        norm_image = lower_image.replace("/", "\\")

        tag_patterns = filters.get("tag_patterns", [])
        for pattern in tag_patterns:
            pat_norm = pattern.lower().replace("/", "\\")
            if (norm_path and pat_norm in norm_path) or (norm_image and pat_norm in norm_image):
                return pattern

        return None

    def is_drop(self, event: Dict[str, Any]) -> bool:
        """Check if an event should be dropped completely."""
        reason, _ = self.check_drop_reason(event)
        return reason is not None

    def is_noise(self, event: Dict[str, Any]) -> bool:
        """Alias for is_drop to preserve API compatibility."""
        return self.is_drop(event)

    def normalize_event(
        self,
        event_id: int,
        fields: Dict[str, str],
        event_record_id: Optional[int] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Normalize parsed raw fields into schema objects.

        Returns:
            (event_dict, process_dict, zone_dict)
        """
        cfg = self.id_to_event_cfg.get(event_id)
        if not cfg:
            return None, None, None

        field_map = cfg.get("fields", {})
        event_type = cfg.get("type", "unknown")

        utc_time_field = field_map.get("utc_time", "UtcTime")
        proc_guid_field = field_map.get("process_guid", "ProcessGuid")
        proc_id_field = field_map.get("process_id", "ProcessId")
        image_field = field_map.get("image", "Image")

        utc_str = fields.get(utc_time_field)
        ts = parse_utc_timestamp(utc_str)
        proc_guid = fields.get(proc_guid_field, "").strip()
        if not proc_guid:
            return None, None, None

        # Check deduplication by event_record_id if available
        if event_record_id is not None:
            dedup_rec_key = ("record_id", event_record_id)
            if dedup_rec_key in self.seen_dedup_keys:
                return None, None, None
            self.seen_dedup_keys.add(dedup_rec_key)

        try:
            pid = int(fields.get(proc_id_field, 0))
        except (ValueError, TypeError):
            pid = 0

        # Track collector's own process GUID
        if pid == os.getpid():
            self.collector_guid = proc_guid

        ppid = None
        path = None
        dest_ip = None
        dest_port = None
        proto = None
        extra_json: Dict[str, Any] = {}

        if event_record_id is not None:
            extra_json["event_record_id"] = event_record_id

        proc_record: Optional[Dict[str, Any]] = None
        zone_record: Optional[Dict[str, Any]] = None

        if event_id == 1:  # ProcessCreate
            parent_pid_field = field_map.get("parent_process_id", "ParentProcessId")
            try:
                ppid = int(fields.get(parent_pid_field, 0)) if fields.get(parent_pid_field) else None
            except (ValueError, TypeError):
                ppid = None
            path = fields.get(image_field)
            exe_path = path
            name = os.path.basename(exe_path) if exe_path else None
            proc_record = {
                "proc_key": proc_guid,
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe_path": exe_path,
                "signed": None,
                "publisher": fields.get("Company"),
                "start_ts": ts,
                "end_ts": None,
            }

        elif event_id == 5:  # ProcessTerminate
            path = fields.get(image_field)
            proc_record = {
                "proc_key": proc_guid,
                "end_ts": ts,
            }

        elif event_id == 3:  # NetworkConnect
            dest_ip = fields.get(field_map.get("dest_ip", "DestinationIp"))
            dest_port_val = fields.get(field_map.get("dest_port", "DestinationPort"))
            try:
                dest_port = int(dest_port_val) if dest_port_val else None
            except (ValueError, TypeError):
                dest_port = None
            proto = fields.get(field_map.get("protocol", "Protocol"))

        elif event_id == 11:  # FileCreate
            target_fn_field = field_map.get("target_filename", "TargetFilename")
            raw_target_fn = fields.get(target_fn_field, "").strip()
            if not raw_target_fn:
                return None, None, None

            # Deduplication rule for file create: (ProcessGuid, TargetFilename, UtcTime)
            dedup_key = (proc_guid, raw_target_fn, utc_str)
            if dedup_key in self.seen_dedup_keys:
                return None, None, None
            self.seen_dedup_keys.add(dedup_key)

            # Check if this is a Zone.Identifier Alternate Data Stream
            if re.search(r":Zone\.Identifier.*$", raw_target_fn, flags=re.IGNORECASE):
                base_path = re.sub(r":Zone\.Identifier.*$", "", raw_target_fn, flags=re.IGNORECASE)
                path = base_path
                zone_data = read_zone_identifier(base_path)
                extra_json["zone"] = zone_data
                zone_record = {
                    "path": base_path,
                    "host_domain": zone_data["host_domain"],
                    "referrer_domain": zone_data["referrer_domain"],
                    "zone_id": zone_data["zone_id"],
                    "proc_key": proc_guid,
                    "ts": ts,
                }
            else:
                path = raw_target_fn

        # Check if event matches tag_patterns to flag noise_candidate=1
        if self.check_tag_pattern({"path": path, "image": fields.get(image_field)}):
            extra_json["noise_candidate"] = 1

        event_record = {
            "ts": ts,
            "pid": pid,
            "ppid": ppid,
            "proc_key": proc_guid,
            "type": event_type,
            "path": path,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "nbytes": 0,
            "image": fields.get(image_field),
            "extra_json": extra_json if extra_json else None,
        }

        return event_record, proc_record, zone_record

    def parse_text_block(
        self, block: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Parse a single text block from Sysmon event dump."""
        eid: Optional[int] = None
        eid_m = re.search(r"Event ID:\s*(\d+)", block)
        if eid_m:
            eid = int(eid_m.group(1))
        elif "File created:" in block:
            eid = 11
        elif "Process Create:" in block:
            eid = 1
        elif "Network connection detected:" in block:
            eid = 3
        elif "Process terminated:" in block:
            eid = 5

        if eid is None or eid not in self.id_to_event_cfg:
            return None, None, None

        event_record_id: Optional[int] = None
        rec_m = re.search(r"Event\[(\d+)\]", block)
        if rec_m:
            try:
                event_record_id = int(rec_m.group(1))
            except ValueError:
                event_record_id = None

        fields: Dict[str, str] = {}
        curr_key: Optional[str] = None

        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(">"):
                line = line[1:].strip()

            m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
            if m and m.group(1) in self.known_field_names:
                curr_key = m.group(1)
                fields[curr_key] = m.group(2)
            elif curr_key:
                # Wrapped continuation of previous field value without adding space
                fields[curr_key] += line

        return self.normalize_event(eid, fields, event_record_id=event_record_id)

    def parse_xml_event(
        self, xml_content: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Parse a Sysmon event represented as XML string."""
        try:
            root = ET.fromstring(xml_content)
        except Exception as e:
            logger.debug("Failed to parse event XML: %s", e)
            return None, None, None

        def find_child(parent, tag_name):
            for child in parent:
                if child.tag.endswith(tag_name):
                    return child
            return None

        system_elem = find_child(root, "System")
        if system_elem is None:
            return None, None, None

        eid_elem = find_child(system_elem, "EventID")
        if eid_elem is None or not eid_elem.text:
            return None, None, None

        try:
            eid = int(eid_elem.text.strip())
        except ValueError:
            return None, None, None

        if eid not in self.id_to_event_cfg:
            return None, None, None

        event_record_id = extract_event_record_id_from_xml(xml_content)

        event_data_elem = find_child(root, "EventData")
        fields: Dict[str, str] = {}
        if event_data_elem is not None:
            for d in event_data_elem:
                name = d.attrib.get("Name")
                if name:
                    fields[name] = d.text or ""

        if "UtcTime" not in fields:
            time_created = find_child(system_elem, "TimeCreated")
            if time_created is not None:
                sys_time = time_created.attrib.get("SystemTime")
                if sys_time:
                    fields["UtcTime"] = sys_time

        return self.normalize_event(eid, fields, event_record_id=event_record_id)

    def parse_text_dump_file(
        self, path: str, filter_noise: bool = True
    ) -> List[Tuple[Dict[str, Any], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]]:
        """Parse a complete text dump file containing Sysmon events."""
        raw_text = read_file_with_bom(path)
        if "Event[" in raw_text:
            blocks = re.split(r"\n(?=\s*Event\[\d+\]:)", raw_text)
        else:
            blocks = re.split(r"\n(?=\s*Computer:)", raw_text)

        results = []
        for block in blocks:
            b = block.strip()
            if not b:
                continue
            ev, pr, zn = self.parse_text_block(b)
            if ev is not None:
                if filter_noise and self.is_drop(ev):
                    continue
                results.append((ev, pr, zn))
        return results


class LiveSysmonCollector:
    """Collects Sysmon events in real-time from Windows Event Log using watermark polling."""

    def __init__(
        self,
        db_path: str = "data/privacyguard.db",
        config_path: str = "config.yaml",
        backfill: bool = False,
        max_queue_size: int = 100000,
    ):
        self.config = load_config(config_path)
        self.store = EventStore(
            db_path=db_path,
            wal_mode=self.config.get("database", {}).get("wal_mode", True),
        )
        self.parser = SysmonParser(config=self.config)
        self.channel = self.config.get("sysmon", {}).get("channel", "Microsoft-Windows-Sysmon/Operational")
        self.batch_size = self.config.get("database", {}).get("batch_size", 500)
        self.flush_interval = self.config.get("database", {}).get("flush_interval_sec", 1.0)
        self.backfill = backfill
        self.max_queue_size = max_queue_size

        self.watermark: int = 0
        self.event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.running = False
        self.total_received = 0
        self.total_written = 0
        self.tagged_count = 0
        self.dropped_events = 0
        self.historical_count = 0
        self.start_ts = 0.0
        self.filtered_sysmon = 0
        self.filtered_collector = 0
        self.filtered_drop_patterns = 0
        self.audit_csv_path: Optional[str] = "data/filtered_audit.csv"
        self._audit_header_written: bool = False

    @property
    def filtered_noise_pattern(self) -> int:
        return self.filtered_drop_patterns

    @filtered_noise_pattern.setter
    def filtered_noise_pattern(self, val: int) -> None:
        self.filtered_drop_patterns = val

    def _writer_worker(self) -> None:
        """Background thread worker to flush queued events to SQLite store in batches."""
        event_batch: List[Dict[str, Any]] = []
        last_flush = time.time()

        while self.running or not self.event_queue.empty():
            try:
                item = self.event_queue.get(timeout=0.2)
                ev, pr, zn = item
                event_batch.append(ev)
                if pr is not None:
                    if "start_ts" in pr:
                        self.store.upsert_process(pr)
                    elif "end_ts" in pr:
                        self.store.update_process_end(pr["proc_key"], pr["end_ts"])
                if zn is not None:
                    self.store.upsert_file_zone(zn)
                self.event_queue.task_done()
            except queue.Empty:
                pass

            now = time.time()
            if len(event_batch) >= self.batch_size or (now - last_flush >= self.flush_interval and event_batch):
                inserted = self.store.insert_events_batch(event_batch)
                self.total_written += inserted
                event_batch.clear()
                last_flush = now

        # Flush any remaining items
        if event_batch:
            inserted = self.store.insert_events_batch(event_batch)
            self.total_written += inserted
            event_batch.clear()

    def check_filter_reason(self, ev: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Check if an event matches a dropping condition (Sysmon, collector, drop_patterns).

        Returns:
            (reason, matched_pattern) or (None, None)
        """
        return self.parser.check_drop_reason(ev)

    def log_filtered_event(
        self,
        ev: Dict[str, Any],
        pr: Optional[Dict[str, Any]],
        reason: str,
        matched_pattern: str,
    ) -> None:
        """Write a filtered event record to data/filtered_audit.csv."""
        if not self.audit_csv_path:
            return

        image = ev.get("image") or (pr.get("exe_path") if pr else "") or ""
        ev_type = ev.get("type", "")
        if ev_type == "net_connect":
            path_or_dest = f"{ev.get('dest_ip')}:{ev.get('dest_port')}"
        else:
            path_or_dest = ev.get("path") or ""

        try:
            if not self._audit_header_written:
                dirname = os.path.dirname(self.audit_csv_path)
                if dirname and not os.path.exists(dirname):
                    os.makedirs(dirname, exist_ok=True)
                if not os.path.exists(self.audit_csv_path) or os.path.getsize(self.audit_csv_path) == 0:
                    with open(self.audit_csv_path, "w", encoding="utf-8", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            "ts",
                            "proc_key",
                            "Image",
                            "type",
                            "path_or_dest",
                            "filter_reason",
                            "matched_pattern",
                        ])
                self._audit_header_written = True

            with open(self.audit_csv_path, "a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    ev.get("ts", time.time()),
                    ev.get("proc_key", ""),
                    image,
                    ev_type,
                    path_or_dest,
                    reason,
                    matched_pattern,
                ])
        except Exception as e:
            logger.debug("Failed to write to audit log %s: %s", self.audit_csv_path, e)

    def process_event(
        self, ev: Dict[str, Any], pr: Optional[Dict[str, Any]], zn: Optional[Dict[str, Any]]
    ) -> bool:
        """Process a single normalized event through filter, queue, and metrics."""
        self.total_received += 1

        if self.backfill and ev.get("ts", 0.0) < self.start_ts:
            self.historical_count += 1

        reason, matched_pattern = self.check_filter_reason(ev)
        if reason == "sysmon":
            self.filtered_sysmon += 1
            self.log_filtered_event(ev, pr, reason, matched_pattern or "sysmon")
            return False
        elif reason == "collector":
            self.filtered_collector += 1
            self.log_filtered_event(ev, pr, reason, matched_pattern or "collector")
            return False
        elif reason in ("drop_pattern", "noise_pattern"):
            self.filtered_drop_patterns += 1
            self.log_filtered_event(ev, pr, "drop_pattern", matched_pattern or "drop_pattern")
            return False

        # Tag candidate noise patterns in extra_json without dropping
        matched_tag = self.parser.check_tag_pattern(ev)
        has_tag_flag = (
            isinstance(ev.get("extra_json"), dict)
            and ev["extra_json"].get("noise_candidate") == 1
        )
        if matched_tag or has_tag_flag:
            if ev.get("extra_json") is None:
                ev["extra_json"] = {}
            if isinstance(ev["extra_json"], dict):
                ev["extra_json"]["noise_candidate"] = 1
            self.tagged_count += 1

        try:
            self.event_queue.put_nowait((ev, pr, zn))
            return True
        except queue.Full:
            self.dropped_events += 1
            logger.warning("Event queue full! Dropping event (total dropped: %d)", self.dropped_events)
            return False

    def poll_once_from_events(
        self, raw_events: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]]
    ) -> int:
        """Process a batch of events through polling logic using watermark (for test simulation)."""
        accepted = 0
        for ev, pr, zn in raw_events:
            rec_id = None
            extra = ev.get("extra_json")
            if isinstance(extra, dict):
                rec_id = extra.get("event_record_id")

            # In live mode (not backfill), discard if <= watermark
            if not self.backfill and rec_id is not None and rec_id <= self.watermark:
                continue

            if self.process_event(ev, pr, zn):
                accepted += 1
                if rec_id is not None and rec_id > self.watermark:
                    self.watermark = rec_id
        return accepted

    def poll_channel(self) -> int:
        """Query channel for events with EventRecordID > watermark."""
        try:
            import win32evtlog
        except ImportError:
            return 0

        xpath = f"*[System[EventRecordID > {self.watermark}]]"
        new_count = 0
        try:
            query_handle = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                xpath,
            )
        except Exception as e:
            logger.debug("EvtQuery error on %s: %s", self.channel, e)
            return 0

        while True:
            try:
                events = win32evtlog.EvtNext(query_handle, 100)
            except Exception:
                break
            if not events:
                break

            for h_ev in events:
                try:
                    xml_data = win32evtlog.EvtRender(h_ev, win32evtlog.EvtRenderEventXml)
                    ev, pr, zn = self.parser.parse_xml_event(xml_data)
                    if ev is not None:
                        rec_id = None
                        extra = ev.get("extra_json")
                        if isinstance(extra, dict):
                            rec_id = extra.get("event_record_id")

                        if not self.backfill and rec_id is not None and rec_id <= self.watermark:
                            continue

                        if self.process_event(ev, pr, zn):
                            new_count += 1
                            if rec_id is not None and rec_id > self.watermark:
                                self.watermark = rec_id
                except Exception as err:
                    self.dropped_events += 1
                    logger.debug("Error processing event XML: %s", err)

        return new_count

    def print_metrics(self) -> None:
        """Print summary session metrics including dropped ratio and filter breakdown."""
        total_filtered_drop = self.filtered_sysmon + self.filtered_collector + self.filtered_drop_patterns
        dropped_ratio = (
            (self.dropped_events / self.total_received * 100.0) if self.total_received > 0 else 0.0
        )
        print("\n" + "=" * 55)
        print("COLLECTOR SESSION METRICS:")
        print(f"  Mode:                  {'Backfill (Historical)' if self.backfill else 'Live (Watermark Polling)'}")
        print(f"  Final Watermark:       EventRecordID={self.watermark}")
        if self.backfill:
            print(f"  Historical events:     {self.historical_count}")
        print(f"  Total events received: {self.total_received}")
        print(f"  Total events written:  {self.total_written}")
        print(f"  Tagged count (noise):  {self.tagged_count} (noise_candidate=1)")
        print(f"  Total events dropped:  {total_filtered_drop}")
        print(f"    - Drop (Sysmon binary):        {self.filtered_sysmon}")
        print(f"    - Drop (Collector process):    {self.filtered_collector}")
        print(f"    - Drop (System drop_patterns): {self.filtered_drop_patterns}")
        if self.audit_csv_path:
            print(f"  Filtered audit log:    {self.audit_csv_path}")
        print(f"  Buffer overflow drops: {self.dropped_events}")
        print(f"  Dropped ratio:         {dropped_ratio:.2f}% (SPEC requirement: < 1.0%)")
        print("=" * 55 + "\n")

    def run_live(self, duration_sec: Optional[float] = None) -> None:
        """Run watermark polling loop for specified duration or until interrupted."""
        try:
            import win32evtlog
        except ImportError:
            logger.error("pywin32 (win32evtlog) is required for live collection.")
            return

        # Determine starting watermark
        if not self.backfill:
            self.watermark = query_latest_record_id(self.channel)
            logger.info("Live mode: Starting watermark set to EventRecordID=%d (ignoring earlier records)", self.watermark)
        else:
            self.watermark = 0
            logger.info("Backfill mode: Ingesting historical events from beginning (watermark=0)")

        self.start_ts = time.time()
        self.running = True

        # Start writer worker thread
        writer_thread = threading.Thread(target=self._writer_worker, daemon=True)
        writer_thread.start()

        logger.info(
            "Sysmon live collector active (channel: %s, polling: 1s, watermark: %d). Duration: %s seconds. Press Ctrl+C to stop.",
            self.channel,
            self.watermark,
            duration_sec or "Unlimited",
        )

        last_heartbeat = time.time()
        try:
            while self.running:
                now = time.time()
                if duration_sec and (now - self.start_ts) >= duration_sec:
                    logger.info("Collection duration (%s seconds) reached.", duration_sec)
                    break

                # Poll channel for events newer than watermark
                self.poll_channel()

                # Print status every 10 seconds as requested
                if now - last_heartbeat >= 10.0:
                    elapsed = now - self.start_ts
                    print(
                        f"[{elapsed:3.0f}s] Live status: {self.total_received} events received, "
                        f"{self.total_written} written ({self.tagged_count} tagged), {self.dropped_events} dropped (current watermark: {self.watermark})",
                        flush=True,
                    )
                    last_heartbeat = now

                time.sleep(1.0)

        except KeyboardInterrupt:
            logger.info("Stop requested by user.")
        finally:
            self.running = False
            writer_thread.join(timeout=5.0)
            self.store.close()
            self.print_metrics()


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Sysmon Collector & Parser")
    parser.add_argument("--file", type=str, help="Path to text dump file to parse and import")
    parser.add_argument("--db", type=str, default="data/privacyguard.db", help="Path to SQLite database")
    parser.add_argument("--duration", type=float, default=60.0, help="Live collection duration in seconds")
    parser.add_argument("--backfill", action="store_true", default=False, help="Backfill historical events from channel instead of only future events")
    parser.add_argument("--no-filter", action="store_true", help="Disable noise filtering")
    args = parser.parse_args()

    if args.file:
        print(f"Reading file: {args.file}")
        sysmon_parser = SysmonParser()
        events = sysmon_parser.parse_text_dump_file(args.file, filter_noise=not args.no_filter)
        print(f"Parsed {len(events)} valid events from {args.file}")
        store = EventStore(db_path=args.db)
        batch = []
        for ev, pr, zn in events:
            batch.append(ev)
            if pr:
                if "start_ts" in pr:
                    store.upsert_process(pr)
                elif "end_ts" in pr:
                    store.update_process_end(pr["proc_key"], pr["end_ts"])
            if zn:
                store.upsert_file_zone(zn)
        inserted = store.insert_events_batch(batch)
        print(f"Inserted {inserted} events into {args.db}")
        store.close()
    else:
        collector = LiveSysmonCollector(
            db_path=args.db,
            backfill=args.backfill,
        )
        collector.run_live(duration_sec=args.duration)


if __name__ == "__main__":
    main()
