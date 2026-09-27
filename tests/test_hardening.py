"""Regression tests for the v4.1 hardening fixes.

Covers: cache concurrency, rate limiting, recon/threat decoupling,
--no-cache semantics, target-expansion limits, invalid-target preservation,
CSV injection sanitization, export semantics, quiet mode, --json stdout
purity, shell markup, lookup timing, HTML completeness/injection.
"""

from __future__ import annotations

import concurrent.futures
import csv
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ipfindx.core.cache import TTLCache
from ipfindx.core.config import Config
from ipfindx.core.models import IPRecord, LookupReport, ThreatReport
from ipfindx.core.utils import (
    MultiRateLimiter,
    RateLimiter,
    TargetLimitError,
    expand_targets_limited,
)


# ===================================================================== 1
# TTLCache concurrency


class TestTTLCacheConcurrency:
    def _hammer(self, cache, worker_id, ops=120):
        for i in range(ops):
            key = f"w{worker_id}-k{i % 17}"
            if i % 3 == 0:
                cache.set(key, {"w": worker_id, "i": i})
            elif i % 3 == 1:
                cache.get(key)
            else:
                cache.delete(key)

    def test_many_threads_no_corruption(self, tmp_path):
        cache = TTLCache(str(tmp_path / "c.sqlite3"), ttl=300)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(self._hammer, cache, w, 150) for w in range(16)]
                for f in futures:
                    f.result(timeout=60)
            # deterministic final state: re-set every key once
            for w in range(16):
                cache.set(f"w{w}-k0", w)
            for w in range(16):
                assert cache.get(f"w{w}-k0") == w
        finally:
            cache.close()

    def test_threads_use_their_own_connections(self, tmp_path):
        cache = TTLCache(str(tmp_path / "c.sqlite3"), ttl=300)
        try:
            conns = []

            def grab():
                conns.append(cache._connection())

            threads = [threading.Thread(target=grab) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert len({id(c) for c in conns}) == 8  # 8 distinct connections
        finally:
            cache.close()

    def test_wal_mode_enabled(self, tmp_path):
        cache = TTLCache(str(tmp_path / "c.sqlite3"), ttl=300)
        try:
            mode = cache._connection().execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"
        finally:
            cache.close()

    def test_close_is_idempotent_and_other_threads_keep_working(self, tmp_path):
        cache = TTLCache(str(tmp_path / "c.sqlite3"), ttl=300)
        try:
            cache.set("a", 1)
        finally:
            cache.close()
        cache.close()  # must not raise
        result = {}

        def worker():
            # a fresh TTLCache instance still opens a working connection
            c = TTLCache(str(tmp_path / "c.sqlite3"), ttl=300)
            try:
                result["val"] = c.get("a")
            finally:
                c.close()

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert result["val"] == 1

    def test_set_get_roundtrip_and_expiry(self, tmp_path):
        cache = TTLCache(str(tmp_path / "c.sqlite3"), ttl=300)
        try:
            cache.set("k", {"a": 1})
            assert cache.get("k") == {"a": 1}
            cache.set("old", "v", ttl=-1)
            assert cache.get("old") is None
        finally:
            cache.close()


# ===================================================================== 2
# Rate limiting


def _fake_response(status=200, payload=None, headers=None, raise_exc=None):
    """Build a response-like object keeping the REAL requests exceptions usable."""
    resp = mock.Mock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.json.return_value = payload if payload is not None else {}
    if raise_exc is not None:
        resp.raise_for_status.side_effect = raise_exc
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestRateLimiting:
    def test_rate_limiter_is_thread_safe_and_paces(self):
        lim = RateLimiter(50)  # 20 ms spacing
        intervals = []

        def worker():
            t0 = time.monotonic()
            lim.wait()
            intervals.append(t0)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(intervals) == 5  # no exceptions, all waited

    def test_rate_limiter_spacing(self):
        lim = RateLimiter(100)  # 10 ms
        marks = []
        for _ in range(4):
            lim.wait()
            marks.append(time.monotonic())
        gaps = [b - a for a, b in zip(marks, marks[1:])]
        assert all(g >= 0.008 for g in gaps)  # ~10 ms spacing, tolerant

    def test_penalize_pushes_next_slot(self):
        lim = RateLimiter(1000)
        lim.wait()
        lim.penalize(0.25)
        t0 = time.monotonic()
        lim.wait()
        assert time.monotonic() - t0 >= 0.2

    def test_multi_rate_limiter_independent_per_provider(self):
        multi = MultiRateLimiter(1000)
        a1, b1 = multi.limiter("ip-api"), multi.limiter("ipwhois")
        a2, b2 = multi.limiter("ip-api"), multi.limiter("ipwhois")
        assert a1 is a2 and b1 is b2 and a1 is not b1
        multi.penalize("ip-api", 0.2)
        # other provider unaffected
        t0 = time.monotonic()
        multi.wait("ipwhois")
        assert time.monotonic() - t0 < 0.1

    def test_configured_rate_limit_stays_in_effect(self):
        from ipfindx.intel import providers

        providers.reset_rate_limiters()
        resp = _fake_response(status=200,
                              payload={"status": "success", "query": "1.2.3.4"})
        with mock.patch.object(providers.requests, "get", return_value=resp):
            providers.fetch_geo("1.2.3.4", ["ip-api"], rate_limit=7.5)
            # The configured rate must stay in effect for provider requests:
            # _request_json() reuses the limiter built for 7.5 req/s (interval
            # 1/7.5 s) instead of silently rebuilding a default-4.0 one, and
            # repeated calls never rebuild the limiter set.
            assert providers._limiters_rate == 7.5
            lim = providers._get_limiters(providers._limiters_rate)
            assert lim.limiter("ip-api")._interval == pytest.approx(1 / 7.5)
            assert providers._get_limiters(providers._limiters_rate) is lim
        providers.reset_rate_limiters()

    def test_provider_429_penalty_respected(self):
        from ipfindx.intel import providers

        providers.reset_rate_limiters()
        resp = _fake_response(
            status=429, headers={"Retry-After": "0.05"},
            raise_exc=providers.requests.exceptions.HTTPError("429"),
        )

        penalized = []
        with mock.patch.object(providers.requests, "get", return_value=resp), \
                mock.patch.object(providers, "_get_limiters") as mlim:
            lim = mock.Mock()
            lim.wait.return_value = None
            lim.penalize.side_effect = lambda name, s: penalized.append((name, s))
            mlim.return_value = lim
            rec = providers.fetch_from_provider("ip-api", "1.2.3.4", timeout=1)

        assert penalized == [("ip-api", 0.05)]
        assert not rec.ok
        providers.reset_rate_limiters()

    def test_fetch_geo_failover_on_provider_failure(self):
        from ipfindx.intel import providers

        providers.reset_rate_limiters()
        calls = []

        def fake(name, ip, timeout=10.0, **kw):
            calls.append(name)
            if name == "ip-api":
                return IPRecord(ip=ip, status="fail", message="down", source=name)
            return IPRecord(ip=ip, status="success", source=name)

        with mock.patch.object(providers, "fetch_from_provider", side_effect=fake):
            rec = providers.fetch_geo("1.2.3.4", ["ip-api", "ipwhois"])
        assert rec.ok and rec.source == "ipwhois"
        assert calls == ["ip-api", "ipwhois"]
        providers.reset_rate_limiters()


# ===================================================================== 3
# recon / threat independence


def _cfg(**kw):
    cfg = Config()
    cfg.cache_enabled = False
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def _patched_lookup(monkeypatch):
    """Stub provider fetch + recon + threat so no network is touched."""
    from ipfindx.intel import lookup as lk

    rec = IPRecord(ip="8.8.8.8", status="success", city="A")
    monkeypatch.setattr(lk, "fetch_geo", lambda *a, **k: rec)

    recon_calls = []

    def fake_recon(target, cfg, port_spec=""):
        recon_calls.append(target)

        class R:
            ports = [{"port": 443, "state": "open", "service": "https"}]
            dns = ping = whois = tls = {}
            traceroute = []

        return R()

    monkeypatch.setattr(lk, "run_recon", fake_recon) if hasattr(lk, "run_recon") else None
    import ipfindx.recon.engine as eng
    monkeypatch.setattr(eng, "run_recon", fake_recon)

    threats = []

    def fake_threat(record, open_ports=None, **kw):
        threats.append(open_ports)
        return ThreatReport(ip=record.ip, score=1, level="low",
                            open_ports=list(open_ports or []))

    import ipfindx.intel.threat as th
    monkeypatch.setattr(th, "assess_threat", fake_threat)
    # lookup.py imported the symbol directly at module load, so patch there too
    import importlib

    lk_mod = importlib.import_module("ipfindx.intel.lookup")
    monkeypatch.setattr(lk_mod, "assess_threat", fake_threat)

    # offline determinism: resolve_target never performs real DNS in tests
    def fake_resolve(target):
        import ipaddress

        from ipfindx.core.utils import is_public_ip

        try:
            ipaddress.ip_address(target)
        except ValueError:
            return None  # hostname: never resolved offline
        return target if is_public_ip(target) else None

    monkeypatch.setattr(lk_mod, "resolve_target", fake_resolve)
    return recon_calls, threats


class TestReconThreatCombos:
    def test_neither(self, monkeypatch):
        recon_calls, threats = _patched_lookup(monkeypatch)
        r = lookup("8.8.8.8", config=_cfg(), threat=False, recon=False)
        assert r.record.ok and r.threat is None and r.recon is None
        assert recon_calls == [] and threats == []

    def test_threat_only(self, monkeypatch):
        from ipfindx.intel import lookup as lk

        recon_calls, threats = _patched_lookup(monkeypatch)
        r = lk.lookup("8.8.8.8", config=_cfg(), threat=True, recon=False)
        assert r.threat is not None and r.recon is None
        assert recon_calls == [] and threats == [None]

    def test_recon_only_no_threat(self, monkeypatch):
        from ipfindx.intel import lookup as lk

        recon_calls, threats = _patched_lookup(monkeypatch)
        r = lk.lookup("8.8.8.8", config=_cfg(), threat=False, recon=True)
        assert r.recon is not None and r.threat is None  # the core fix
        assert recon_calls == ["8.8.8.8"] and threats == []

    def test_both_reuse_recon_ports(self, monkeypatch):
        from ipfindx.intel import lookup as lk

        recon_calls, threats = _patched_lookup(monkeypatch)
        r = lk.lookup("8.8.8.8", config=_cfg(), threat=True, recon=True)
        assert r.recon is not None and r.threat is not None
        assert recon_calls == ["8.8.8.8"]  # ran once, not twice
        assert threats == [[443]]  # open ports flowed into the scorer


from ipfindx import lookup  # noqa: E402  (used in combo tests)


# ===================================================================== 4
# --no-cache semantics


class TestNoCache:
    def test_no_cache_creates_no_db_file(self, tmp_path, monkeypatch):
        _patched_lookup(monkeypatch)  # keep provider/threat HTTP out of the test
        db_path = str(tmp_path / "cache.sqlite3")
        cfg = _cfg(cache_db=db_path)
        cfg.cache_enabled = True  # cache on, but --no-cache must win
        lookup("8.8.8.8", config=cfg, threat=True, no_cache=True)
        assert not os.path.exists(db_path)

    def test_cache_enabled_creates_db_file(self, tmp_path, monkeypatch):
        _patched_lookup(monkeypatch)
        db_path = str(tmp_path / "cache.sqlite3")
        cfg = _cfg(cache_db=db_path)
        cfg.cache_enabled = True
        lookup("8.8.8.8", config=cfg, threat=False, no_cache=False)
        assert os.path.exists(db_path)

    def test_no_cache_does_not_populate(self, tmp_path, monkeypatch):
        _patched_lookup(monkeypatch)  # no real provider requests
        db_path = str(tmp_path / "cache.sqlite3")
        cfg = _cfg(cache_db=db_path)
        cfg.cache_enabled = True
        lookup("8.8.8.8", config=cfg, threat=False, no_cache=True)
        lookup("8.8.8.8", config=cfg, threat=False, no_cache=False)
        cache = TTLCache(db_path, ttl=300)
        try:
            assert cache.get("geo:8.8.8.8") is not None  # only 2nd run wrote
        finally:
            cache.close()


# ===================================================================== 5
# target-expansion limits


class TestTargetLimits:
    def test_small_cidr_ok(self):
        assert len(expand_targets_limited("8.8.8.0/30", 4096)) == 2

    def test_small_range_ok(self):
        assert len(expand_targets_limited("8.8.8.1-8.8.8.5", 4096)) == 5

    def test_exact_limit_ok(self):
        assert len(expand_targets_limited("8.8.8.0/30", 2)) == 2

    def test_over_limit_cidr_raises(self):
        with pytest.raises(TargetLimitError) as exc:
            expand_targets_limited("10.0.0.0/8", 4096)
        assert exc.value.requested > 16_000_000

    def test_over_limit_range_raises(self):
        with pytest.raises(TargetLimitError) as exc:
            expand_targets_limited("1.0.0.0-1.1.255.255", 1000)
        assert exc.value.requested == 131072

    def test_no_materialisation_before_check(self):
        # a /8 would be 16M hosts — must raise without building the list
        with pytest.raises(TargetLimitError):
            expand_targets_limited("10.0.0.0/8", 10)

    def test_single_ip_requests_one(self):
        assert expand_targets_limited("8.8.8.8", 1) == ["8.8.8.8"]


# ===================================================================== 6
# invalid targets preserved in batch


class TestBatchInvalidTargets:
    def _run(self, targets, **kw):
        from ipfindx.intel.lookup import scan_batch

        cfg = _cfg(max_targets=kw.pop("max_targets", 4096))
        return scan_batch(targets, config=cfg, **kw)

    def test_mixed_valid_and_invalid(self, monkeypatch):
        _patched_lookup(monkeypatch)
        reports = self._run(["8.8.8.8", "999.999.1.1", "1.1.1.1"])
        assert len(reports) == 3
        assert reports[0].record.ok
        assert not reports[1].record.ok and "999.999.1.1" in (reports[1].record.ip)
        assert reports[2].record.ok

    def test_multiple_invalid_all_reported(self, monkeypatch):
        _patched_lookup(monkeypatch)
        reports = self._run(["nope.invalid", "banana", "192.168.1.1"])
        assert len(reports) == 3
        assert all(not r.record.ok for r in reports)

    def test_all_invalid_not_empty(self, monkeypatch):
        _patched_lookup(monkeypatch)
        reports = self._run(["zzz.invalid", "banana"])
        assert len(reports) == 2 and all(not r.record.ok for r in reports)

    def test_over_limit_spec_becomes_failure(self, monkeypatch):
        _patched_lookup(monkeypatch)
        reports = self._run(["10.0.0.0/8"], max_targets=100)
        assert len(reports) == 1 and not reports[0].record.ok
        assert "exceeds" in reports[0].record.message

    def test_exit_code_nonzero_when_all_fail(self, tmp_path):
        import io

        from rich.console import Console

        from ipfindx import cli
        from ipfindx.ui import render

        # isolate this in-process run from the shared console
        original = render.console
        render.console = Console(file=io.StringIO(), theme=render.custom_theme)
        cfg = _cfg(history_db=str(tmp_path / "h.sqlite3"),
                   cache_db=str(tmp_path / "c.sqlite3"))
        try:
            with mock.patch("ipfindx.cli.load_config", return_value=cfg), \
                    mock.patch("ipfindx.intel.lookup.resolve_target",
                               return_value=None):  # no real DNS for 'banana'
                rc = cli.main(["-i", "banana", "--no-save", "-q"])
        finally:
            render.console = original
        assert rc == 1


# ===================================================================== 7
# CSV formula injection


class TestCSVInjection:
    def test_dangerous_prefixes_are_guarded(self):
        from ipfindx.exporters.csv_export import sanitize_csv_value

        for evil in ('=HYPERLINK("http://example","x")', "+CMD", "@SUM(1,2)",
                     "-2+3", "\tTAB", "\rCR"):
            guarded = sanitize_csv_value(evil)
            assert guarded.startswith("'")
            assert guarded[1:] == evil

    def test_safe_values_unchanged(self):
        from ipfindx.exporters.csv_export import sanitize_csv_value

        assert sanitize_csv_value("Ashburn") == "Ashburn"
        assert sanitize_csv_value("Google LLC") == "Google LLC"
        assert sanitize_csv_value("dns.google") == "dns.google"
        assert sanitize_csv_value(8) == 8
        assert sanitize_csv_value(39.03) == 39.03
        assert sanitize_csv_value(True) is True
        assert sanitize_csv_value("") == ""
        assert sanitize_csv_value(None) is None

    def test_export_csv_sanitizes_record_fields(self, tmp_path):
        rec = IPRecord(ip="1.2.3.4", status="success", city="=HYPERLINK(\"x\",\"y\")",
                       isp="+CMD", org="@SUM(1,2)", asn="AS123", country="US")
        report = LookupReport(record=rec)
        from ipfindx.exporters.csv_export import export_csv

        path = export_csv([report], str(tmp_path))
        with open(path, newline="") as fh:
            rows = list(csv.DictReader(fh))
        row = rows[0]
        assert row["city"].startswith("'=")
        assert row["isp"].startswith("'+")
        assert row["org"].startswith("'@")
        assert row["country"] == "US"  # safe value untouched
        assert row["ip"] == "1.2.3.4"


# ===================================================================== 8
# export semantics


def _report(ip="8.8.8.8"):
    return LookupReport(record=IPRecord(ip=ip, status="success", city="X"))


class TestExportSemantics:
    def test_batch_json_is_valid_array(self, tmp_path):
        path = export_json([_report("1.1.1.1"), _report("2.2.2.2")], str(tmp_path))
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, list) and len(data) == 2

    def test_single_json_is_object(self, tmp_path):
        path = export_json([_report()], str(tmp_path))
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, dict)

    def test_ndjson_lines(self, tmp_path):
        path = export_ndjson([_report("1.1.1.1"), _report("2.2.2.2")], str(tmp_path))
        with open(path) as fh:
            lines = [json.loads(l) for l in fh if l.strip()]
        assert len(lines) == 2 and lines[0]["record"]["ip"] == "1.1.1.1"

    def test_all_formats_unique_paths(self, tmp_path):
        from ipfindx.cli import _save_reports

        reports = [_report("1.1.1.1"), _report("2.2.2.2")]
        paths = _save_reports(reports, ["json", "csv", "html", "ndjson"], str(tmp_path))
        assert len(paths) == 4
        assert len(set(paths)) == 4  # exactly once each, no duplicates

    def test_json_plus_ndjson_no_duplicate(self, tmp_path):
        from ipfindx.cli import _save_reports

        paths = _save_reports([_report()], ["json", "ndjson"], str(tmp_path))
        assert len(paths) == 2 and len(set(paths)) == 2
        assert paths[0].endswith(".json") and paths[1].endswith(".ndjson")

    def test_duplicate_format_flags_deduped(self):
        from ipfindx.cli import _formats

        args = mock.Mock(format="json,json,ndjson,all")
        fmts = _formats(args)
        assert len(fmts) == len(set(fmts))  # no duplicates
        assert sorted(fmts) == ["csv", "html", "json", "ndjson"]


from ipfindx.exporters import export_json, export_ndjson  # noqa: E402


# ===================================================================== 9+10
# CLI quiet mode + --json stdout purity (subprocess level)
#
# Subprocess tests must stay offline: the child process stubs fetch_geo so no
# provider/network/DNS calls occur, while still verifying real stdout/stderr
# and exit codes from a fresh CLI process.


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Bootstraps a CLI subprocess with a deterministic offline geo stub.
# sys.argv after ``python -c <code>`` is ``['-c', ...cli_args]``.
_OFFLINE_CLI_BOOTSTRAP = r"""
import sys
from unittest import mock

from ipfindx.core.models import IPRecord


def _fake_geo(ip, providers, timeout=10.0, rate_limit=None, **kw):
    return IPRecord(
        ip=ip,
        status="success",
        city="Offline",
        country="Test",
        country_code="XX",
        source="offline-stub",
        lookup_ms=0,
    )


with mock.patch("ipfindx.intel.lookup.fetch_geo", side_effect=_fake_geo):
    from ipfindx.cli import main
    raise SystemExit(main(sys.argv[1:]))
"""


def _cli(*cli_args, timeout=120):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    # Ensure the package is importable the same way as running from the repo root.
    env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return subprocess.run(
        [sys.executable, "-c", _OFFLINE_CLI_BOOTSTRAP, *cli_args],
        capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT,
    )


class TestCLIJsonPurity:
    def test_json_stdout_parses_even_with_invalid_format(self):
        proc = _cli("-i", "8.8.8.8", "--json", "-q", "--no-save",
                    "-f", "invalidformat", "--no-cache")
        assert proc.returncode == 0
        assert "Unknown format" in proc.stderr  # warning went to stderr
        data = json.loads(proc.stdout)  # stdout is pure JSON
        assert data["record"]["ip"] == "8.8.8.8"

    def test_json_stdout_no_banner(self):
        proc = _cli("-i", "1.1.1.1", "--json", "--no-save", "--no-cache")
        data = json.loads(proc.stdout)
        assert data["record"]["ip"] == "1.1.1.1"
        assert "IPFindX" not in proc.stdout  # banner not on stdout

    def test_json_batch_is_array(self):
        listfile = os.path.join(ROOT, ".tmp_targets_test.txt")
        with open(listfile, "w") as fh:
            fh.write("8.8.8.8\n1.1.1.1\n")
        try:
            proc = _cli("-l", listfile, "--json", "-q", "--no-save", "--no-cache")
            data = json.loads(proc.stdout)
            assert isinstance(data, list) and len(data) == 2
        finally:
            os.unlink(listfile)

    def test_quiet_suppresses_banner(self):
        proc = _cli("-i", "8.8.8.8", "-q", "--no-save", "--no-cache", "--json")
        # banner art must not appear anywhere; result panels on stderr are OK
        assert "██" not in proc.stderr
        assert "IPFindX v" not in proc.stderr
        json.loads(proc.stdout)  # stdout still pure JSON


# ===================================================================== 11
# interactive shell markup


class TestShellIntro:
    def test_intro_renders_without_literal_tags(self, monkeypatch):
        import io

        from rich.console import Console

        from ipfindx.shell import IPFindXShell
        from ipfindx.ui import render

        buf = io.StringIO()
        monkeypatch.setattr(render, "console",
                            Console(file=buf, theme=render.custom_theme, width=100))
        shell = IPFindXShell(_cfg())
        assert shell.intro is None  # cmd.Cmd must not print raw markup
        shell._print_intro()
        out = buf.getvalue()
        assert "[banner]" not in out and "[info]" not in out and "[bold]" not in out
        assert "interactive shell" in out


# ===================================================================== 12
# lookup timing


class TestLookupTiming:
    def test_ipapi_measures_actual_request(self):
        from ipfindx.intel import providers

        resp = _fake_response(payload={"status": "success", "query": "1.2.3.4",
                                       "country": "X"})
        real_sleep = time.sleep

        def slow_get(*a, **k):
            real_sleep(0.03)  # simulate 30 ms of network time
            return resp

        providers.reset_rate_limiters()
        with mock.patch.object(providers.requests, "get", side_effect=slow_get):
            rec = providers._provider_ipapi("1.2.3.4", timeout=5)
        assert rec.lookup_ms is not None
        assert rec.lookup_ms >= 25  # timer wrapped the (slowed) request
        providers.reset_rate_limiters()

    def test_all_providers_populate_lookup_ms(self):
        from ipfindx.intel import providers

        payloads = {
            "ip-api": {"status": "success", "query": "1.2.3.4"},
            "ipwhois": {"success": True, "ip": "1.2.3.4"},
            "ipinfo": {"ip": "1.2.3.4", "org": "AS1 X"},
        }
        for name, payload in payloads.items():
            providers.reset_rate_limiters()
            resp = mock.Mock(status_code=200)
            resp.headers = {}
            resp.json.return_value = payload
            with mock.patch.object(providers, "requests") as mreq:
                mreq.get.return_value = resp
                rec = providers.PROVIDERS[name]("1.2.3.4", timeout=5)
            assert rec.ok
            assert isinstance(rec.lookup_ms, int) and rec.lookup_ms >= 0
        providers.reset_rate_limiters()


# ===================================================================== 13
# HTML completeness + injection


class TestHTMLCompleteness:
    def _build(self, tmp_path, **recon_fields):
        from ipfindx.exporters.html_report import export_html
        from ipfindx.recon.engine import _is_ip  # noqa: F401

        class R:
            dns = recon_fields.get("dns", {})
            ping = recon_fields.get("ping", {})
            traceroute = recon_fields.get("traceroute", [])
            ports = recon_fields.get("ports", [])
            whois = recon_fields.get("whois")
            tls = recon_fields.get("tls", {})

        rec = IPRecord(ip="1.2.3.4", status="success")
        rep = LookupReport(record=rec)
        rep.recon = R()
        return export_html([rep], str(tmp_path))

    def test_dns_and_whois_included(self, tmp_path):
        path = self._build(
            tmp_path,
            dns={"hostname": "example.com", "addresses": ["93.184.216.34"]},
            whois="NetName: EXAMPLE-CORP\nCountry: US",
        )
        html = Path(path).read_text(encoding="utf-8")
        assert "DNS resolution" in html and "93.184.216.34" in html
        assert "WHOIS" in html and "EXAMPLE-CORP" in html

    def test_html_escaping_of_whois(self, tmp_path):
        path = self._build(tmp_path,
                           whois="NetName: <script>alert(1)</script>")
        html = Path(path).read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_escaping_of_record_fields(self, tmp_path):
        from ipfindx.exporters.html_report import export_html

        rec = IPRecord(ip="1.2.3.4", status="success",
                       city="<img src=x onerror=alert(1)>", isp="<b>bold</b>")
        path = export_html([LookupReport(record=rec)], str(tmp_path))
        html = Path(path).read_text(encoding="utf-8")
        assert "<img src=x" not in html
        assert "&lt;img" in html


# ===================================================================== 14
# extra behaviour coverage (providers parsing, DNS, exporters, models)


class TestProviderParsing:
    def test_ipapi_fail_status(self):
        from ipfindx.intel import providers

        resp = mock.Mock(status_code=200)
        resp.headers = {}
        resp.json.return_value = {"status": "fail", "message": "reserved range"}
        with mock.patch.object(providers, "requests") as mreq:
            mreq.get.return_value = resp
            rec = providers._provider_ipapi("192.168.1.1", timeout=1)
        assert not rec.ok and rec.message == "reserved range"

    def test_ipwhois_parses_connection_and_security(self):
        from ipfindx.intel import providers

        resp = mock.Mock(status_code=200)
        resp.headers = {}
        resp.json.return_value = {
            "success": True, "ip": "1.2.3.4", "country": "X",
            "country_code": "XX", "city": "Y", "latitude": 1.0,
            "longitude": 2.0, "timezone": {"id": "Z"},
            "connection": {"isp": "I", "org": "O", "asn": 123, "domain": "d"},
            "security": {"proxy": True, "hosting": False},
        }
        with mock.patch.object(providers, "requests") as mreq:
            mreq.get.return_value = resp
            rec = providers._provider_ipwhois("1.2.3.4", timeout=1)
        assert rec.ok and rec.asn == "AS123" and rec.is_proxy is True

    def test_ipinfo_parses_org_and_privacy(self):
        from ipfindx.intel import providers

        resp = mock.Mock(status_code=200)
        resp.headers = {}
        resp.json.return_value = {"ip": "1.2.3.4", "org": "AS15169 Google LLC",
                                  "loc": "39.03,-77.5", "city": "A",
                                  "privacy": {"vpn": True, "hosting": True}}
        with mock.patch.object(providers, "requests") as mreq:
            mreq.get.return_value = resp
            rec = providers._provider_ipinfo("1.2.3.4", timeout=1)
        assert rec.ok and rec.asn == "AS15169" and rec.is_proxy is True
        assert rec.lat == 39.03

    def test_fetch_from_provider_network_error_soft_fails(self):
        from ipfindx.intel import providers

        with mock.patch.object(providers.requests, "get",
                               side_effect=providers.requests.exceptions.ConnectTimeout("x")):
            rec = providers.fetch_from_provider("ip-api", "1.2.3.4", timeout=1)
        assert not rec.ok and "ip-api" in rec.message

    def test_fetch_from_provider_malformed_json(self):
        from ipfindx.intel import providers

        resp = _fake_response()
        resp.json.side_effect = ValueError("bad json")
        with mock.patch.object(providers.requests, "get", return_value=resp):
            rec = providers.fetch_from_provider("ip-api", "1.2.3.4", timeout=1)
        assert not rec.ok and "bad response" in rec.message

    def test_unknown_provider(self):
        from ipfindx.intel import providers

        rec = providers.fetch_from_provider("nope", "1.2.3.4")
        assert not rec.ok and "unknown provider" in rec.message


class TestDNS:
    def test_resolve_host_error_is_soft(self):
        from ipfindx.recon.dns import resolve_host

        out = resolve_host("this-host-does-not-exist-xyz.invalid")
        assert out["addresses"] == [] and out["error"]


class TestScanBatchConcurrency:
    def test_concurrent_batch_with_mocked_providers(self, monkeypatch):
        from ipfindx.intel import lookup as lk

        _patched_lookup(monkeypatch)
        cfg = _cfg(max_targets=100)
        cfg.batch_workers = 16
        seen_progress = []

        reports = lk.scan_batch(
            ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
             "nope.invalid", "8.8.4.4", "1.0.0.1"],
            config=cfg, threat=True, recon=False,
            progress=lambda d, t, c: seen_progress.append((d, t)),
        )
        assert len(reports) == 7
        ok = [r for r in reports if r.record.ok]
        bad = [r for r in reports if not r.record.ok]
        assert len(ok) == 6 and len(bad) == 1
        assert seen_progress[-1] == (6, 6)
        # order preserved: first valid target first
        assert reports[0].record.ip == "8.8.8.8"


class TestHistoryIntegration:
    def test_record_and_diff_roundtrip(self, tmp_path):
        from ipfindx.storage.history import HistoryDB

        db = HistoryDB(str(tmp_path / "h.sqlite3"))
        try:
            db.record("1.1.1.1", {"record": {"ip": "1.1.1.1", "city": "Old"}})
            diffs = db.diff_fields("1.1.1.1", {"record": {"ip": "1.1.1.1", "city": "New"}})
            assert diffs == {"city": ("Old", "New")}
            assert db.seen_ips() == ["1.1.1.1"]
        finally:
            db.close()
