"""Offline unit tests for IPFindX v4 (no network required)."""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ipfindx.core.models import IPRecord, ReconResult, ThreatReport
from ipfindx.core.utils import (
    expand_targets,
    is_public_ip,
    normalize_ip,
    parse_ports,
    read_ip_file,
    RateLimiter,
)
from ipfindx.core.cache import TTLCache
from ipfindx.storage.history import HistoryDB
from ipfindx.exporters import export_csv, export_html, export_json, export_ndjson


# ------------------------------------------------------------------ utils


class TestIPValidation:
    def test_public_ip_accepted(self):
        assert is_public_ip("8.8.8.8")
        assert is_public_ip("1.1.1.1")

    def test_private_rejected(self):
        assert not is_public_ip("192.168.1.1")
        assert not is_public_ip("10.0.0.5")
        assert not is_public_ip("127.0.0.1")

    def test_reserved_and_loopback(self):
        assert not is_public_ip("0.0.0.0")
        assert not is_public_ip("169.254.1.1")

    def test_invalid_rejected(self):
        assert not is_public_ip("999.1.2.3")
        assert not is_public_ip("not-an-ip")
        assert not is_public_ip("")

    def test_normalize(self):
        assert normalize_ip(" 8.8.8.8 ") == "8.8.8.8"


class TestTargetExpansion:
    def test_single_ip(self):
        assert list(expand_targets("8.8.8.8")) == ["8.8.8.8"]

    def test_cidr(self):
        ips = list(expand_targets("8.8.8.0/30"))
        assert ips == ["8.8.8.1", "8.8.8.2"]

    def test_range(self):
        ips = list(expand_targets("8.8.8.1-8.8.8.3"))
        assert ips == ["8.8.8.1", "8.8.8.2", "8.8.8.3"]

    def test_private_cidr_skipped(self):
        assert list(expand_targets("192.168.0.0/30")) == []

    def test_garbage_yields_nothing(self):
        assert list(expand_targets("banana")) == []
        assert list(expand_targets("")) == []

    def test_range_capped(self):
        ips = list(expand_targets("1.0.0.0-255.255.255.255"))
        assert len(ips) == 65536  # safety cap: 65535 + first IP

    def test_parse_ports(self):
        assert parse_ports("80,443,1000-1003") == [80, 443, 1000, 1001, 1002, 1003]
        assert parse_ports("0") == []
        assert parse_ports("70000") == []
        assert parse_ports("abc") == []

    def test_read_ip_file(self, tmp_path):
        f = tmp_path / "ips.txt"
        f.write_text("8.8.8.8\n# comment\n\n1.1.1.1\n")
        assert read_ip_file(str(f)) == ["8.8.8.8", "1.1.1.1"]


# ------------------------------------------------------------------ models


class TestModels:
    def _record(self):
        return IPRecord(ip="8.8.8.8", status="success", country="United States",
                        country_code="US", city="Ashburn", lat=39.03, lon=-77.5,
                        isp="Google LLC", asn="AS15169", source="test")

    def test_roundtrip(self):
        rec = self._record()
        assert IPRecord.from_dict(rec.to_dict()) == rec

    def test_maps_url(self):
        assert "39.03" in self._record().maps_url

    def test_maps_url_none_without_coords(self):
        rec = IPRecord(ip="1.2.3.4", status="success")
        assert rec.maps_url is None

    def test_ok_flag(self):
        assert self._record().ok
        assert not IPRecord(ip="1.1.1.1", status="fail").ok

    def test_threat_defaults(self):
        t = ThreatReport(ip="8.8.8.8")
        assert t.score == 0 and t.level == "minimal" and t.signals == []


# ------------------------------------------------------------------ threat


class TestThreatScoring:
    def test_clean_ip_scores_zero(self):
        from ipfindx.intel.threat import assess_threat

        rec = IPRecord(ip="8.8.8.8", status="success")
        t = assess_threat(rec, open_ports=[], abuseipdb_key=None, timeout=1)
        assert t.score == 0
        assert t.level == "minimal"

    def test_proxy_flag_raises_score(self):
        from ipfindx.intel.threat import assess_threat

        rec = IPRecord(ip="1.2.3.4", status="success", is_proxy=True)
        t = assess_threat(rec, timeout=1)
        assert t.score >= 30
        assert any("proxy" in s.lower() for s in t.signals)

    def test_datacenter_keyword(self):
        from ipfindx.intel.threat import assess_threat

        rec = IPRecord(ip="1.2.3.4", status="success", isp="Amazon AWS")
        t = assess_threat(rec, timeout=1)
        assert t.is_datacenter
        assert t.score >= 15

    def test_telnet_open_adds_signals(self):
        from ipfindx.intel.threat import assess_threat

        rec = IPRecord(ip="1.2.3.4", status="success")
        t = assess_threat(rec, open_ports=[23], timeout=1)
        assert t.score >= 10
        assert any("Telnet" in s for s in t.signals)

    def test_score_clamped(self):
        from ipfindx.intel.threat import assess_threat

        rec = IPRecord(ip="1.2.3.4", status="success", is_proxy=True,
                       reverse_dns="tor.example.com")
        t = assess_threat(rec, open_ports=[22, 23, 3389, 5900], timeout=1)
        assert 0 <= t.score <= 100


# ------------------------------------------------------------------ cache


class TestTTLCache:
    def test_set_get_roundtrip(self, tmp_path):
        c = TTLCache(str(tmp_path / "c.sqlite3"), ttl=60)
        try:
            c.set("k", {"a": 1})
            assert c.get("k") == {"a": 1}
        finally:
            c.close()

    def test_expiry(self, tmp_path):
        c = TTLCache(str(tmp_path / "c.sqlite3"), ttl=-1)
        try:
            c.set("k", "v")
            assert c.get("k") is None
        finally:
            c.close()

    def test_purge_and_clear(self, tmp_path):
        c = TTLCache(str(tmp_path / "c.sqlite3"), ttl=60)
        try:
            c.set("a", 1)
            c.set("b", 2)
            assert c.clear() == 2
            assert c.get("a") is None
        finally:
            c.close()


# ------------------------------------------------------------------ history


class TestHistory:
    def test_record_and_entries(self, tmp_path):
        db = HistoryDB(str(tmp_path / "h.sqlite3"))
        try:
            db.record("8.8.8.8", {"record": {"ip": "8.8.8.8", "city": "A"}}, source="t")
            entries = db.entries()
            assert len(entries) == 1 and entries[0]["ip"] == "8.8.8.8"
        finally:
            db.close()

    def test_diff_detects_changes(self, tmp_path):
        db = HistoryDB(str(tmp_path / "h.sqlite3"))
        try:
            db.record("1.1.1.1", {"record": {"ip": "1.1.1.1", "city": "Old"}})
            diffs = db.diff_fields("1.1.1.1", {"record": {"ip": "1.1.1.1", "city": "New"}})
            assert diffs == {"city": ("Old", "New")}
        finally:
            db.close()

    def test_diff_empty_when_no_history(self, tmp_path):
        db = HistoryDB(str(tmp_path / "h.sqlite3"))
        try:
            assert db.diff_fields("9.9.9.9", {"record": {}}) == {}
        finally:
            db.close()

    def test_last_snapshot(self, tmp_path):
        db = HistoryDB(str(tmp_path / "h.sqlite3"))
        try:
            db.record("2.2.2.2", {"record": {"ip": "2.2.2.2"}})
            assert db.last_snapshot("2.2.2.2") == {"record": {"ip": "2.2.2.2"}}
            assert db.last_snapshot("3.3.3.3") is None
        finally:
            db.close()


# --------------------------------------------------------------- exporters


def _sample_report():
    rec = IPRecord(ip="8.8.8.8", status="success", country="United States",
                   country_code="US", city="Ashburn", lat=39.03, lon=-77.5,
                   isp="Google LLC", asn="AS15169", source="test")
    threat = ThreatReport(ip="8.8.8.8", score=15, level="low",
                          signals=["Datacenter/hosting infrastructure"])
    return rec, threat


class TestExporters:
    def test_export_json(self, tmp_path):
        rec, threat = _sample_report()
        from ipfindx.core.models import LookupReport

        path = export_json([LookupReport(record=rec, threat=threat)], str(tmp_path))
        with open(path) as fh:
            data = json.load(fh)
        assert data["record"]["ip"] == "8.8.8.8"
        assert data["threat"]["score"] == 15

    def test_export_ndjson(self, tmp_path):
        rec, threat = _sample_report()
        from ipfindx.core.models import LookupReport

        reports = [LookupReport(record=rec, threat=threat) for _ in range(3)]
        path = export_ndjson(reports, str(tmp_path))
        with open(path) as fh:
            lines = [json.loads(l) for l in fh if l.strip()]
        assert len(lines) == 3

    def test_export_csv(self, tmp_path):
        rec, threat = _sample_report()
        from ipfindx.core.models import LookupReport

        path = export_csv([LookupReport(record=rec, threat=threat)], str(tmp_path))
        with open(path) as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["ip"] == "8.8.8.8"
        assert rows[0]["risk_score"] == "15"

    def test_export_html(self, tmp_path):
        rec, threat = _sample_report()
        from ipfindx.core.models import LookupReport

        path = export_html([LookupReport(record=rec, threat=threat)], str(tmp_path))
        content = Path(path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "8.8.8.8" in content
        assert "Threat Assessment" in content
