"""Unit tests for Sysmon collector and parser using real sample fixtures."""

import os
import pytest
from collector.sysmon_collector import (
    SysmonParser,
    extract_domain,
    parse_zone_identifier_content,
    read_file_with_bom,
)


@pytest.fixture
def parser():
    return SysmonParser()


def test_bom_detection():
    """Verify BOM detection reads UTF-16 LE sample files without error."""
    for fname in ["sysmon_sample.txt", "sysmon_fc.txt", "sysmon_downloads.txt"]:
        p = os.path.join("docs", fname)
        assert os.path.exists(p)
        content = read_file_with_bom(p)
        assert len(content) > 0
        assert not content.startswith("\ufeff")


def test_parse_sysmon_sample(parser):
    """Test parsing Event 1 (ProcessCreate), Event 3 (NetworkConnect), Event 5 (ProcessTerminate)."""
    p = os.path.join("docs", "sysmon_sample.txt")
    results = parser.parse_text_dump_file(p, filter_noise=False)
    assert len(results) > 0

    types = {ev["type"] for ev, _, _ in results}
    assert "proc_start" in types
    assert "net_connect" in types
    assert "proc_end" in types

    # Check process_guid as proc_key
    for ev, _, _ in results:
        assert ev["proc_key"].startswith("{") and ev["proc_key"].endswith("}")

    # Check network event properties
    net_events = [ev for ev, _, _ in results if ev["type"] == "net_connect"]
    assert len(net_events) > 0
    sample_net = net_events[0]
    assert sample_net["dest_ip"] is not None
    assert sample_net["dest_port"] is not None
    assert sample_net["proto"] in ["tcp", "udp"]


def test_parse_sysmon_file_create(parser):
    """Test parsing Event 11 (FileCreate) without noise filtering."""
    p = os.path.join("docs", "sysmon_fc.txt")
    results = parser.parse_text_dump_file(p, filter_noise=False)
    assert len(results) > 0

    for ev, _, _ in results:
        assert ev["type"] == "file_create"
        assert ev["path"] is not None
        assert ev["proc_key"].startswith("{")


def test_parse_sysmon_downloads_and_zone(parser):
    """Test downloads file parsing with special characters and Zone.Identifier handling."""
    p = os.path.join("docs", "sysmon_downloads.txt")
    results = parser.parse_text_dump_file(p, filter_noise=False)
    assert len(results) >= 6

    paths = [ev["path"] for ev, _, _ in results]

    # Rule 3: Special characters must NOT be altered or corrupted
    has_vietnamese = any("Không đư?c xác nh?n" in path for path in paths)
    assert has_vietnamese, "Special characters in filename must be preserved verbatim."

    # Rule 4: File names with spaces and parentheses must be intact
    has_spaces_and_parens = any(" (3).exe" in path for path in paths)
    assert has_spaces_and_parens, "Filenames with spaces and parentheses must remain intact."

    # Rule 5: Zone.Identifier stream must be stripped from path
    for path in paths:
        assert ":Zone.Identifier" not in path


def test_extract_domain():
    """Verify domain extraction strips protocols, paths, query strings, and ports."""
    assert extract_domain("https://www.example.com/download/file.exe?token=123") == "www.example.com"
    assert extract_domain("http://sub.domain.org:8080/path?a=1&b=2") == "sub.domain.org"
    assert extract_domain("bluestacks.com") == "bluestacks.com"
    assert extract_domain("") == "unknown"
    assert extract_domain("-") == "unknown"
    assert extract_domain(None) == "unknown"


def test_parse_zone_identifier_content():
    """Verify ZoneTransfer INI content parsing."""
    raw_ads = """[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://www.bluestacks.com/download.html?utm_source=ads
HostUrl=https://ak-build.bluestacks.com/installer.exe?session=xyz
"""
    parsed = parse_zone_identifier_content(raw_ads)
    assert parsed["zone_id"] == "3"
    assert parsed["host_domain"] == "ak-build.bluestacks.com"
    assert parsed["referrer_domain"] == "www.bluestacks.com"

    # Incomplete / missing Zone.Identifier returns unknown without error
    empty_parsed = parse_zone_identifier_content("")
    assert empty_parsed["zone_id"] == "unknown"
    assert empty_parsed["host_domain"] == "unknown"
    assert empty_parsed["referrer_domain"] == "unknown"


def test_deduplication(parser):
    """Verify duplicate events are dropped according to Rule 2."""
    p = os.path.join("docs", "sysmon_downloads.txt")
    # First parse fills seen_dedup_keys
    first_run = parser.parse_text_dump_file(p, filter_noise=False)
    # Second parse on same parser instance should deduplicate all file create events
    second_run = parser.parse_text_dump_file(p, filter_noise=False)
    assert len(second_run) == 0


def test_noise_filtering(parser):
    """Verify system noise filtering removes Prefetch and app cache paths."""
    noise_event = {
        "ts": 1700000000.0,
        "pid": 100,
        "ppid": None,
        "proc_key": "{guid}",
        "type": "file_create",
        "path": "C:\\Windows\\Prefetch\\CMD.EXE-A1B2C3D4.pf",
    }
    assert parser.is_noise(noise_event) is True

    app_cache_event = {
        "ts": 1700000000.0,
        "pid": 100,
        "ppid": None,
        "proc_key": "{guid}",
        "type": "file_create",
        "path": "C:\\Users\\User\\AppData\\Local\\Packages\\SomeApp\\LocalCache\\cache.json",
    }
    assert parser.is_noise(app_cache_event) is True

    user_doc_event = {
        "ts": 1700000000.0,
        "pid": 100,
        "ppid": None,
        "proc_key": "{guid}",
        "type": "file_create",
        "path": "C:\\Users\\User\\Documents\\FakeDocuments\\contract.docx",
    }
    assert parser.is_noise(user_doc_event) is False


def test_xml_event_parsing(parser):
    """Verify XML event parsing with ElementTree."""
    sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-10-20T13:31:07.2670000Z" />
    <Execution ProcessID="2000" ThreadID="3000" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-10-20 13:31:07.267</Data>
    <Data Name="ProcessGuid">{db9fa507-61bd-6ad7-b700-000000007100}</Data>
    <Data Name="ProcessId">2948</Data>
    <Data Name="Image">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="DestinationIp">142.250.190.46</Data>
    <Data Name="DestinationPort">443</Data>
  </EventData>
</Event>"""
    ev, pr, zn = parser.parse_xml_event(sample_xml)
    assert ev is not None
    assert ev["type"] == "net_connect"
    assert ev["proc_key"] == "{db9fa507-61bd-6ad7-b700-000000007100}"
    assert ev["dest_ip"] == "142.250.190.46"
    assert ev["dest_port"] == 443
    assert ev["proto"] == "tcp"
