"""Regression tests for v4 manual/integration bugfixes.

Covers console stream routing, exit codes, --no-save, /31 counting, range
truncation, IPv6 literals, provider schema hardening, Tor single-flight,
ping/traceroute fixes, volatile diff fields, missing list files, config
errors, and export filename collisions.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ipfindx.core.config import Config, ConfigError, load_config
from ipfindx.core.models import IPRecord, LookupReport
from ipfindx.core.utils import (
    TargetLimitError,
    expand_targets,
    expand_targets_limited,
    normalize_ip,
)
from ipfindx.storage.history import HistoryDB

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cfg(**kw) -> Config:
    cfg = Config()
    cfg.cache_enabled = False
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def _iso_console(monkeypatch, stream=None):
    from rich.console import Console

    from ipfindx.ui import render

    buf = stream if stream is not None else io.StringIO()
    monkeypatch.setattr(
        render, "console", Console(file=buf, theme=render.custom_theme, width=120)
    )
    return buf


# ===================================================================== 1
# Console stdout vs --json stderr


class TestConsoleRouting:
    def test_normal_mode_uses_stdout(self, monkeypatch):
        from ipfindx import cli
        from ipfindx.ui import render

        _iso_console(monkeypatch)
        with mock.patch("ipfindx.cli.load_config", return_value=_cfg()):
            assert cli.main(["--about"]) == 0
        # after a normal call the live console must target stdout
        assert render.console.file is sys.stdout

    def test_json_mode_uses_stderr_then_restores(self, monkeypatch, tmp_path):
        from ipfindx import cli
        from ipfindx.ui import render

        cfg = _cfg(history_db=str(tmp_path / "h.sqlite3"),
                   cache_db=str(tmp_path / "c.sqlite3"))
        fake = IPRecord(ip="8.8.8.8", status="success", city="X", source="t")

        with mock.patch("ipfindx.cli.load_config", return_value=cfg), \
                mock.patch("ipfindx.intel.lookup.fetch_geo", return_value=fake), \
                mock.patch("ipfindx.intel.lookup.resolve_target",
                           side_effect=lambda t: t if t.count(".") == 3 else None):
            rc = cli.main(["-i", "8.8.8.8", "--json", "-q", "--no-save", "--no-cache"])
        assert rc == 0
        # subsequent non-json call must restore stdout
        with mock.patch("ipfindx.cli.load_config", return_value=cfg):
            assert cli.main(["--about", "-q"]) == 0
        assert render.console.file is sys.stdout


# ===================================================================== 2
# Entrypoint exit codes


class TestEntrypointExitCodes:
    def _run_script(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        return subprocess.run(
            [sys.executable, *args],
            capture_output=True, text=True, cwd=ROOT, env=env, timeout=30,
        )

    def test_root_script_propagates_nonzero(self, tmp_path):
        # missing list file → exit 1
        proc = self._run_script(
            os.path.join(ROOT, "ipfindx.py"),
            "-l", str(tmp_path / "missing.txt"), "-q",
        )
        assert proc.returncode == 1
        assert "Could not read list file" in proc.stderr or "Could not read list file" in proc.stdout

    def test_module_entrypoint_propagates_nonzero(self, tmp_path):
        proc = self._run_script(
            "-m", "ipfindx",
            "-l", str(tmp_path / "missing.txt"), "-q",
        )
        assert proc.returncode == 1


# ===================================================================== 3
# --no-save filesystem behaviour


class TestNoSaveFilesystem:
    def test_no_save_writes_neither_history_nor_exports(self, monkeypatch, tmp_path):
        from ipfindx import cli

        hist = tmp_path / "hist.sqlite3"
        out = tmp_path / "out"
        cfg = _cfg(history_db=str(hist), output_dir=str(out),
                   cache_db=str(tmp_path / "c.sqlite3"))
        fake = IPRecord(ip="8.8.8.8", status="success", city="X", source="t")
        _iso_console(monkeypatch)

        with mock.patch("ipfindx.cli.load_config", return_value=cfg), \
                mock.patch("ipfindx.intel.lookup.fetch_geo", return_value=fake):
            rc = cli.main(["-i", "8.8.8.8", "-q", "--no-save", "--no-cache", "-f", "json"])
        assert rc == 0
        assert not hist.exists()
        assert not out.exists() or not any(out.iterdir())


# ===================================================================== 4+5
# /31 counting + range truncation


class TestTargetExpansionFixes:
    def test_slash31_count_and_limit(self):
        assert len(expand_targets_limited("8.8.8.0/31", 2)) == 2
        with pytest.raises(TargetLimitError) as exc:
            expand_targets_limited("8.8.8.0/31", 1)
        assert exc.value.requested == 2

    def test_slash32_is_one(self):
        assert expand_targets_limited("8.8.8.8/32", 1) == ["8.8.8.8"]

    def test_large_range_not_silently_truncated(self):
        # 8.0.0.0-8.1.0.0 → 65537 addresses; previously silent-capped at 65536
        with pytest.raises(TargetLimitError) as exc:
            expand_targets_limited("8.0.0.0-8.1.0.0", 1000)
        assert exc.value.requested == 65537

        hits = expand_targets_limited("8.0.0.0-8.1.0.0", 70000)
        assert len(hits) == 65537

    def test_expand_targets_raises_instead_of_silent_cap(self):
        with pytest.raises(TargetLimitError):
            list(expand_targets("8.0.0.0-8.1.0.0"))  # default hard cap 65536


# ===================================================================== 6
# IPv6 numeric-tail literals


class TestIPv6Literals:
    @pytest.mark.parametrize("addr", [
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
        "2001:4860:4860::8844",
    ])
    def test_bare_ipv6_not_stripped_as_port(self, addr):
        hits = list(expand_targets(addr))
        assert hits == [normalize_ip(addr)]

    def test_bracketed_ipv6_with_port(self):
        hits = list(expand_targets("[2001:4860:4860::8888]:443"))
        assert hits == [normalize_ip("2001:4860:4860::8888")]

    def test_ipv4_port_still_works(self):
        assert list(expand_targets("8.8.8.8:53")) == ["8.8.8.8"]


# ===================================================================== 7
# Malformed provider JSON


class TestProviderSchemaHardening:
    @pytest.mark.parametrize("payload", [[], None, "oops", 42])
    def test_non_object_json_fails_soft(self, payload):
        from ipfindx.intel import providers

        providers.reset_rate_limiters()
        resp = mock.Mock(status_code=200, headers={})
        resp.json.return_value = payload
        with mock.patch.object(providers.requests, "get", return_value=resp):
            rec = providers.fetch_from_provider("ip-api", "1.2.3.4", timeout=1)
        assert not rec.ok
        assert "bad response" in rec.message or "expected JSON object" in rec.message
        providers.reset_rate_limiters()

    def test_ipwhois_malformed_nested_objects(self):
        from ipfindx.intel import providers

        providers.reset_rate_limiters()
        resp = mock.Mock(status_code=200, headers={})
        resp.json.return_value = {
            "success": True, "ip": "1.2.3.4",
            "timezone": "not-a-dict",
            "connection": ["nope"],
            "security": "x",
            "flag": None,
        }
        with mock.patch.object(providers.requests, "get", return_value=resp):
            rec = providers.fetch_from_provider("ipwhois", "1.2.3.4", timeout=1)
        assert rec.ok  # soft nested handling — still a success record
        assert rec.timezone is None
        assert rec.isp is None
        providers.reset_rate_limiters()


# ===================================================================== 8
# Tor single-flight


class TestTorSingleFlight:
    def setup_method(self):
        from ipfindx.intel import threat

        threat.reset_tor_cache()

    def teardown_method(self):
        from ipfindx.intel import threat

        threat.reset_tor_cache()

    def test_success_single_flight_across_workers(self, monkeypatch):
        from ipfindx.intel import threat

        calls = []

        def fake_fetch(timeout=10.0):
            calls.append(1)
            return {"1.2.3.4", "5.6.7.8"}

        monkeypatch.setattr(threat, "fetch_tor_exits", fake_fetch)
        results = []

        def worker():
            results.append(threat.load_tor_exits(cache=None, timeout=1))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(calls) == 1
        assert all(r == {"1.2.3.4", "5.6.7.8"} for r in results)

    def test_failure_cached_shortly_not_per_target(self, monkeypatch):
        from ipfindx.intel import threat

        calls = []

        def fake_fetch(timeout=10.0):
            calls.append(1)
            return set()

        monkeypatch.setattr(threat, "fetch_tor_exits", fake_fetch)
        for _ in range(20):
            assert threat.load_tor_exits(cache=None, timeout=1) == set()
        assert len(calls) == 1

    def test_sqlite_cache_used_when_enabled(self, monkeypatch, tmp_path):
        from ipfindx.core.cache import TTLCache
        from ipfindx.intel import threat

        cache = TTLCache(str(tmp_path / "c.sqlite3"), ttl=3600)
        try:
            calls = []

            def fake_fetch(timeout=10.0):
                calls.append(1)
                return {"9.9.9.9"}

            monkeypatch.setattr(threat, "fetch_tor_exits", fake_fetch)
            assert "9.9.9.9" in threat.load_tor_exits(cache=cache, timeout=1)
            threat.reset_tor_cache()
            # second process-equivalent call should hit SQLite, not HTTP
            assert "9.9.9.9" in threat.load_tor_exits(cache=cache, timeout=1)
            assert len(calls) == 1
        finally:
            cache.close()


# ===================================================================== 9
# Ping TCP fallback when ICMP returns no replies


class TestPingTcpFallback:
    def test_returncode_1_no_replies_falls_back_to_tcp(self, monkeypatch):
        import ipfindx.recon.engine as eng

        proc = mock.Mock(returncode=1, stdout="PING …\n", stderr="")
        monkeypatch.setattr(eng.subprocess, "run", lambda *a, **k: proc)
        monkeypatch.setattr(eng, "tcp_ping", lambda host, port=443, timeout=2.0: 12.5)
        out = eng.ping_host("1.2.3.4", count=2)
        assert out["method"] == "tcp:443"
        assert out["avg_ms"] == 12.5
        assert out["received"] == 1

    def test_icmp_success_preserved(self, monkeypatch):
        import ipfindx.recon.engine as eng

        proc = mock.Mock(
            returncode=0,
            stdout="64 bytes: icmp_seq=0 ttl=57 time=9.0 ms\n"
                   "64 bytes: icmp_seq=1 ttl=57 time=11.0 ms\n",
            stderr="",
        )
        monkeypatch.setattr(eng.subprocess, "run", lambda *a, **k: proc)
        monkeypatch.setattr(eng, "tcp_ping",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no tcp")))
        out = eng.ping_host("1.2.3.4", count=2)
        assert out["method"] == "icmp"
        assert out["avg_ms"] == 10.0


# ===================================================================== 10
# Windows tracert


class TestWindowsTracert:
    def test_windows_command_and_parsing(self, monkeypatch):
        import ipfindx.recon.engine as eng

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            out = mock.Mock(returncode=0)
            out.stdout = (
                "Tracing route to 8.8.8.8 over a maximum of 5 hops\n"
                "\n"
                "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
                "  2     *        *        *     Request timed out.\n"
                "  3    10 ms    11 ms    12 ms  8.8.8.8\n"
            )
            out.stderr = ""
            return out

        monkeypatch.setattr(eng, "_is_windows", lambda: True)
        monkeypatch.setattr(eng.subprocess, "run", fake_run)
        hops = eng.traceroute("8.8.8.8", max_hops=5, timeout=2.0)
        assert captured["cmd"][0] == "tracert"
        assert "-d" in captured["cmd"] and "-h" in captured["cmd"]
        assert hops[0] == {"hop": 1, "ip": "192.168.1.1", "avg_ms": 1.0}
        assert hops[1]["ip"] is None
        assert hops[2]["ip"] == "8.8.8.8"
        assert hops[2]["avg_ms"] == 11.0


# ===================================================================== 11
# Volatile diff fields


class TestVolatileDiff:
    def test_ignores_timing_and_cache_metadata(self, tmp_path):
        db = HistoryDB(str(tmp_path / "h.sqlite3"))
        try:
            db.record("1.1.1.1", {
                "record": {
                    "ip": "1.1.1.1", "city": "A",
                    "fetchedAt": "t1", "lookupMs": 10,
                    "extra": {"cached": True, "flag": 1},
                }
            })
            diffs = db.diff_fields("1.1.1.1", {
                "record": {
                    "ip": "1.1.1.1", "city": "A",
                    "fetchedAt": "t2", "lookupMs": 99,
                    "extra": {"cached": False, "flag": 1},
                }
            })
            assert diffs == {}
            diffs2 = db.diff_fields("1.1.1.1", {
                "record": {
                    "ip": "1.1.1.1", "city": "B",
                    "fetchedAt": "t3", "lookupMs": 1,
                    "extra": {"cached": True, "flag": 1},
                }
            })
            assert diffs2 == {"city": ("A", "B")}
        finally:
            db.close()


# ===================================================================== 12
# Missing list file exit code


class TestMissingListFile:
    def test_missing_list_returns_nonzero(self, monkeypatch, tmp_path):
        from ipfindx import cli

        _iso_console(monkeypatch)
        with mock.patch("ipfindx.cli.load_config", return_value=_cfg()):
            rc = cli.main(["-l", str(tmp_path / "nope.txt"), "-q"])
        assert rc == 1


# ===================================================================== 13
# Malformed config


class TestConfigErrors:
    def test_missing_explicit_config(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(str(tmp_path / "missing.json"))

    def test_malformed_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ConfigError) as exc:
            load_config(str(path))
        assert "malformed" in str(exc.value).lower() or "JSON" in str(exc.value)

    def test_invalid_numeric_type(self, tmp_path):
        path = tmp_path / "badtype.json"
        path.write_text('{"timeout": "fast", "max_targets": 10}', encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(str(path))

    def test_cli_reports_config_error(self, monkeypatch, tmp_path):
        from ipfindx import cli

        path = tmp_path / "bad.json"
        path.write_text("{", encoding="utf-8")
        buf = _iso_console(monkeypatch)
        rc = cli.main(["-c", str(path), "-q"])
        assert rc == 2
        assert "malformed" in buf.getvalue().lower() or "JSON" in buf.getvalue()


# ===================================================================== 14
# Same-second export collision


class TestExportCollision:
    def test_two_exports_get_distinct_paths(self, tmp_path):
        from ipfindx.exporters import export_csv, export_json

        reports = [LookupReport(record=IPRecord(ip="1.1.1.1", status="success"))]
        paths = {export_json(reports, str(tmp_path)) for _ in range(5)}
        paths |= {export_csv(reports, str(tmp_path)) for _ in range(5)}
        assert len(paths) == 10
        for p in paths:
            assert Path(p).is_file()


# ===================================================================== 15
# Datacenter keyword normalisation


class TestChoopaKeyword:
    def test_choopa_matches_lowercase_haystack(self):
        from ipfindx.intel.threat import _classify_datacenter

        rec = IPRecord(ip="1.2.3.4", status="success", isp="Choopa, LLC")
        assert _classify_datacenter(rec) is True
