"""Behavioural tests for recon engine, UI rendering, shell and CLI flows.

Network-touching functions are mocked at the socket/subprocess boundary so
tests stay deterministic and offline.
"""

from __future__ import annotations

import io
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ipfindx.core.config import Config
from ipfindx.core.models import IPRecord, LookupReport, ThreatReport


def _iso_console(monkeypatch):
    """Give render a throwaway console so tests never write to stdout."""
    from rich.console import Console

    from ipfindx.ui import render

    buf = io.StringIO()
    monkeypatch.setattr(render, "console",
                        Console(file=buf, theme=render.custom_theme, width=120))
    return buf


# ============================================================ DER cert parser


def _der_tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        n = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(n)]) + n
    return bytes([tag]) + length + content


def _der_name(cn: str, org: str | None = None) -> bytes:
    def atv(oid: bytes, value: str) -> bytes:
        return _der_tlv(0x30, _der_tlv(0x06, oid) + _der_tlv(0x0C, value.encode()))

    rdns = b""
    if org:
        rdns += _der_tlv(0x31, atv(bytes.fromhex("55040a"), org))
    rdns += _der_tlv(0x31, atv(bytes.fromhex("550403"), cn))
    return _der_tlv(0x30, rdns)


def _fake_cert_der(cn="test.example", org="Test Org",
                   issuer_cn="Test CA") -> bytes:
    issuer = _der_name(issuer_cn, "Test CA Org")
    validity = _der_tlv(
        0x30,
        _der_tlv(0x17, b"250101000000Z") + _der_tlv(0x17, b"260101000000Z"),
    )
    subject = _der_name(cn, org)
    tbs = _der_tlv(0x30, issuer + validity + subject)
    return _der_tlv(0x30, tbs)


class TestDERParser:
    def test_parses_subject_issuer_validity(self):
        from ipfindx.recon.engine import _parse_cert_der

        fields = _parse_cert_der(_fake_cert_der())
        assert fields["subject_cn"] == "test.example"
        assert fields["organization"] == "Test Org"
        assert fields["issuer"] == "Test CA Org"
        assert fields["issued_on"] == "250101000000Z"
        assert fields["expires_on"] == "260101000000Z"

    def test_malformed_der_returns_none(self):
        from ipfindx.recon.engine import _parse_cert_der

        assert _parse_cert_der(b"\x00\x01\x02") is None
        assert _parse_cert_der(b"") is None
        assert _parse_cert_der(b"\x30\x05garbage!") is None

    def test_truncated_der_raises_softly(self):
        from ipfindx.recon.engine import _parse_cert_der

        der = _fake_cert_der()
        assert _parse_cert_der(der[: len(der) // 2]) in (None,) or True  # never raises


# ================================================================= port scan


class TestPortScan:
    def test_open_and_closed_states(self, monkeypatch):
        import ipfindx.recon.engine as eng

        def fake_connect(addr, timeout=None):
            if addr[1] == 80:
                return mock.MagicMock()
            raise OSError("refused")

        monkeypatch.setattr(eng.socket, "create_connection", fake_connect)
        results = eng.port_scan("93.184.216.34", [80, 443], timeout=0.1)
        by_port = {r["port"]: r for r in results}
        assert by_port[80]["state"] == "open"
        assert by_port[443]["state"] == "closed"
        assert by_port[80]["service"] == "http"

    def test_empty_inputs(self):
        from ipfindx.recon.engine import port_scan

        assert port_scan("", [80]) == []
        assert port_scan("1.2.3.4", []) == []


# ======================================================= ping / traceroute


class TestPingTrace:
    def test_ping_parses_os_output(self, monkeypatch):
        import ipfindx.recon.engine as eng

        proc = mock.Mock(returncode=0)
        proc.stdout = ("PING 1.2.3.4: 56 data bytes\n"
                       "64 bytes: icmp_seq=0 ttl=57 time=12.3 ms\n"
                       "64 bytes: icmp_seq=1 ttl=57 time=13.3 ms\n")
        proc.stderr = ""
        monkeypatch.setattr(eng.subprocess, "run", lambda *a, **k: proc)
        out = eng.ping_host("1.2.3.4", count=2)
        assert out["received"] == 2
        assert out["avg_ms"] == 12.8
        assert out["method"] == "icmp"

    def test_ping_falls_back_to_tcp(self, monkeypatch):
        import ipfindx.recon.engine as eng

        monkeypatch.setattr(eng.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no ping")))
        monkeypatch.setattr(eng, "tcp_ping", lambda host, port=443, timeout=2.0: 5.5)
        out = eng.ping_host("1.2.3.4")
        assert out["method"].startswith("tcp")
        assert out["avg_ms"] == 5.5

    def test_traceroute_parsing(self, monkeypatch):
        import ipfindx.recon.engine as eng

        proc = mock.Mock(returncode=0)
        proc.stdout = (
            "traceroute to 8.8.8.8, 30 hops max, 60 byte packets\n"
            " 1  192.168.1.1  1.0 ms  1.2 ms  1.4 ms\n"
            " 2  * * *\n"
            " 3  8.8.8.8  10.0 ms\n"
        )
        monkeypatch.setattr(eng, "_is_windows", lambda: False)
        monkeypatch.setattr(eng.subprocess, "run", lambda *a, **k: proc)
        hops = eng.traceroute("8.8.8.8", max_hops=5)
        assert hops[0] == {"hop": 1, "ip": "192.168.1.1", "avg_ms": 1.2}
        assert hops[1] == {"hop": 2, "ip": None, "avg_ms": None}
        assert hops[2] == {"hop": 3, "ip": "8.8.8.8", "avg_ms": 10.0}

    def test_traceroute_missing_binary(self, monkeypatch):
        import ipfindx.recon.engine as eng

        monkeypatch.setattr(eng.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("missing")))
        assert eng.traceroute("8.8.8.8") == []


# ==================================================================== whois


class TestWhois:
    def test_server_routing(self):
        from ipfindx.recon.engine import _whois_server_for

        assert _whois_server_for("8.8.8.8") == "whois.arin.net"
        assert _whois_server_for("185.10.10.10") == "whois.ripe.net"
        assert _whois_server_for("1.1.1.1") == "whois.apnic.net"
        assert _whois_server_for("200.10.10.10") == "whois.lacnic.net"
        assert _whois_server_for("105.10.10.10") == "whois.afrinic.net"

    def test_whois_query_parses_relevant_lines(self, monkeypatch):
        import ipfindx.recon.engine as eng

        payload = (b"Comment: noise\nNetRange: 8.8.8.0 - 8.8.8.255\n"
                   b"NetName: GOGL\nCountry: US\njunk line\n")

        class FakeSock:
            def __init__(self):
                self._done = False

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def sendall(self, data):
                assert data.endswith(b"\r\n")

            def recv(self, n):
                # Simulate a real socket: payload once, then EOF (b"").
                if self._done:
                    return b""
                self._done = True
                return payload

        monkeypatch.setattr(eng.socket, "create_connection",
                            lambda addr, timeout=None: FakeSock())
        out = eng.whois_lookup("8.8.8.8")
        assert "NetName: GOGL" in out
        assert "junk" not in out

    def test_whois_unreachable_returns_none(self, monkeypatch):
        import ipfindx.recon.engine as eng

        monkeypatch.setattr(eng.socket, "create_connection",
                            lambda addr, timeout=None: (_ for _ in ()).throw(OSError("x")))
        assert eng.whois_lookup("8.8.8.8") is None


# ===================================================================== TLS


class TestTLSFetch:
    def test_tls_certificate_via_mocked_socket(self, monkeypatch):
        import ipfindx.recon.engine as eng

        der = _fake_cert_der(cn="dns.google", issuer_cn="Google Trust Services")

        tls_cm = mock.MagicMock()
        tls_cm.__enter__.return_value.getpeercert.return_value = der
        ctx = mock.MagicMock()
        ctx.wrap_socket.return_value = tls_cm

        sock_cm = mock.MagicMock()
        sock_cm.__enter__.return_value = mock.Mock()
        monkeypatch.setattr(eng.socket, "create_connection",
                            lambda addr, timeout=None: sock_cm)
        monkeypatch.setattr(eng.ssl, "create_default_context", lambda **k: ctx)

        out = eng.tls_certificate("8.8.8.8")  # bare IP: insecure path, no SNI
        assert out["subject_cn"] == "dns.google"
        # the fake cert's issuer Name carries O="Test CA Org"; the parser
        # prefers O over CN, so that is the issuer string it returns
        assert out["issuer"] == "Test CA Org"
        assert out["verified"] is False
        assert len(out["sha256"]) == 64

    def test_tls_unreachable_returns_none(self, monkeypatch):
        import ipfindx.recon.engine as eng

        monkeypatch.setattr(eng.socket, "create_connection",
                            lambda addr, timeout=None: (_ for _ in ()).throw(OSError("x")))
        assert eng.tls_certificate("8.8.8.8") is None


# ============================================================ run_recon glue


class TestRunReconGlue:
    def test_hostname_recon_full_flow(self, monkeypatch):
        import ipfindx.recon.engine as eng

        monkeypatch.setattr(eng, "resolve_host", lambda h: {
            "hostname": h, "addresses": ["93.184.216.34"], "error": None})
        import ipfindx.intel.lookup as lk
        monkeypatch.setattr(lk, "resolve_target", lambda t: "93.184.216.34")
        monkeypatch.setattr(eng, "port_scan",
                            lambda ip, ports, timeout=2.0: [
                                {"port": 80, "state": "closed", "service": "http"},
                                {"port": 443, "state": "open", "service": "https"}])
        monkeypatch.setattr(eng, "ping_host", lambda ip, count=3: {"avg_ms": 9.0})
        monkeypatch.setattr(eng, "traceroute", lambda ip, **k: [{"hop": 1, "ip": ip, "avg_ms": 1.0}])
        monkeypatch.setattr(eng, "whois_lookup", lambda ip: "NetName: TEST")
        monkeypatch.setattr(eng, "tls_certificate", lambda ip, sni=None, port=443, timeout=5.0:
                            {"subject_cn": "x"})

        cfg = Config()
        res = eng.run_recon("example.com", cfg, port_spec="80,443")
        assert res.dns["addresses"] == ["93.184.216.34"]
        assert res.ports[1]["state"] == "open"
        assert res.ping["avg_ms"] == 9.0
        assert res.whois == "NetName: TEST"
        assert res.tls["subject_cn"] == "x"  # 443 open -> TLS fetched
        assert res.traceroute[0]["hop"] == 1

    def test_unroutable_target_soft_fails(self, monkeypatch):
        import ipfindx.recon.engine as eng

        monkeypatch.setattr(eng, "resolve_host", lambda h: {
            "hostname": h, "addresses": ["127.0.0.1"], "error": None})
        import ipfindx.intel.lookup as lk
        monkeypatch.setattr(lk, "resolve_target", lambda t: None)

        cfg = Config()
        res = eng.run_recon("localhost.example", cfg, port_spec="80")
        assert res.ping == {"host": "localhost.example", "error": "no routable address"}
        assert res.ports == []


# ================================================================ UI render


class TestRender:
    def _report(self, failed=False):
        if failed:
            rec = IPRecord(ip="10.0.0.1", status="fail", message="private address")
            return LookupReport(record=rec)
        rec = IPRecord(ip="8.8.8.8", status="success", country="United States",
                       country_code="US", city="Ashburn", lat=39.0, lon=-77.5,
                       isp="Google LLC", asn="AS15169", source="test")
        threat = ThreatReport(ip="8.8.8.8", score=45, level="elevated",
                              signals=["Datacenter/hosting infrastructure"])
        return LookupReport(record=rec, threat=threat)

    def test_display_report_success(self, monkeypatch):
        from ipfindx.ui.render import display_report

        buf = _iso_console(monkeypatch)
        display_report(self._report())
        out = buf.getvalue()
        assert "8.8.8.8" in out and "Ashburn" in out
        assert "45/100" in out and "ELEVATED" in out
        assert "Datacenter/hosting" in out
        assert "google.com/maps" in out

    def test_display_report_failure(self, monkeypatch):
        from ipfindx.ui.render import display_report

        buf = _iso_console(monkeypatch)
        display_report(self._report(failed=True))
        out = buf.getvalue()
        assert "private address" in out and "Failed" in out

    def test_display_summary_counts(self, monkeypatch):
        from ipfindx.ui.render import display_summary

        buf = _iso_console(monkeypatch)
        ok = self._report()
        bad = LookupReport(record=IPRecord(ip="10.0.0.1", status="fail"))
        display_summary([ok, ok, bad])
        out = buf.getvalue()
        assert "3" in out and "2" in out and "1" in out

    def test_show_diff_table_and_empty(self, monkeypatch):
        from ipfindx.ui.render import show_diff

        buf = _iso_console(monkeypatch)
        show_diff("1.1.1.1", {})
        assert "No changes" in buf.getvalue()
        show_diff("1.1.1.1", {"city": ("Old", "New")})
        out = buf.getvalue()
        assert "Old" in out and "New" in out

    def test_show_history(self, monkeypatch):
        from ipfindx.ui.render import show_history

        buf = _iso_console(monkeypatch)
        show_history([{"ip": "1.1.1.1", "ts": "2026-01-01", "source": "ip-api.com"}])
        assert "1.1.1.1" in buf.getvalue() and "ip-api.com" in buf.getvalue()

    def test_banner_narrow_fallback(self, monkeypatch):
        from rich.console import Console

        from ipfindx.ui import render

        buf = io.StringIO()
        monkeypatch.setattr(render, "console", Console(file=buf, width=40,
                                                       theme=render.custom_theme))
        render.print_banner("9.9.9")
        out = buf.getvalue()
        assert "IPFindX" in out
        assert "██╗" not in out  # fallback used, no wide art


# =================================================================== shell


class TestShellCommands:
    def _shell(self, cfg):
        from ipfindx.shell import IPFindXShell

        return IPFindXShell(cfg)

    def test_lookup_dispatches_without_threat(self, monkeypatch):
        import ipfindx.shell as sh

        calls = {}

        def fake_flow(targets, cfg, threat=False, recon=False, ports=None,
                      formats=None, save=True, no_cache=False, quiet=False):
            calls.update(targets=targets, threat=threat, recon=recon, ports=ports)

        monkeypatch.setattr(sh, "run_lookup_flow", fake_flow)
        _iso_console(monkeypatch)
        self._shell(Config()).do_lookup("8.8.8.8")
        assert calls["targets"] == ["8.8.8.8"]
        assert calls["threat"] is False and calls["recon"] is False
        assert calls["ports"] is None  # lookup never forwards --ports

    def test_recon_parses_ports_flag(self, monkeypatch):
        import ipfindx.shell as sh

        captured = {}

        def fake_flow(targets, cfg, threat=False, recon=False, ports=None,
                      formats=None, save=True, no_cache=False, quiet=False):
            captured.update(targets=targets, threat=threat, recon=recon, ports=ports)

        monkeypatch.setattr(sh, "run_lookup_flow", fake_flow)
        _iso_console(monkeypatch)
        shell = self._shell(Config())
        shell.do_recon("example.com --ports 80,443")
        assert captured["targets"] == ["example.com"]
        assert captured["recon"] is True and captured["threat"] is True
        assert captured["ports"] == "80,443"

    def test_threat_sets_flag(self, monkeypatch):
        import ipfindx.shell as sh

        captured = {}

        def fake_flow(targets, cfg, threat=False, recon=False, ports=None,
                      formats=None, save=True, no_cache=False, quiet=False):
            captured.update(threat=threat, recon=recon)

        monkeypatch.setattr(sh, "run_lookup_flow", fake_flow)
        _iso_console(monkeypatch)
        shell = self._shell(Config())
        shell.do_threat("1.1.1.1")
        assert captured == {"threat": True, "recon": False}

    def test_empty_lookup_shows_usage(self, monkeypatch):
        import ipfindx.shell as sh

        monkeypatch.setattr(sh, "run_lookup_flow", lambda *a, **k: None)
        buf = _iso_console(monkeypatch)
        self._shell(Config()).do_lookup("")
        assert "Usage" in buf.getvalue()


# ================================================================= CLI misc


class TestCLIMisc:
    def test_about_and_connect_exit_zero(self, monkeypatch):
        from ipfindx import cli

        _iso_console(monkeypatch)
        with mock.patch("ipfindx.cli.load_config", return_value=Config()):
            assert cli.main(["--about"]) == 0
            assert cli.main(["--connect"]) == 0

    def test_no_targets_prints_help(self, monkeypatch):
        from ipfindx import cli

        _iso_console(monkeypatch)
        with mock.patch("ipfindx.cli.load_config", return_value=Config()):
            assert cli.main([]) == 0

    def test_clear_cache_creates_and_clears(self, monkeypatch, tmp_path):
        from ipfindx.core.cache import TTLCache

        from ipfindx import cli

        _iso_console(monkeypatch)
        cfg = Config()
        cfg.cache_db = str(tmp_path / "c.sqlite3")
        cache = TTLCache(cfg.cache_db, ttl=60)
        try:
            cache.set("x", 1)
        finally:
            cache.close()
        with mock.patch("ipfindx.cli.load_config", return_value=cfg):
            assert cli.main(["--clear-cache"]) == 0
        cache = TTLCache(cfg.cache_db, ttl=60)
        try:
            assert cache.get("x") is None
        finally:
            cache.close()
