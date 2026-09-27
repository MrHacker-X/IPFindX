"""IPFindX command-line interface."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Tuple

from ipfindx import __version__
from ipfindx.core.config import Config, ConfigError, load_config
from ipfindx.core.models import LookupReport
from ipfindx.core.utils import read_ip_file
from ipfindx.exporters import export_csv, export_html, export_json, export_ndjson
from ipfindx.intel.lookup import lookup, scan_batch
from ipfindx.storage.history import HistoryDB
from ipfindx.ui import render

__all__ = ["main", "build_parser", "run_lookup_flow"]

PROGRAM = "ipfindx"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=f"IPFindX v{__version__} — Advanced IP Intelligence, Threat Scoring "
                    "and Network Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  ipfindx -i 8.8.8.8                       single lookup
  ipfindx -i 8.8.8.8 -t                    with threat scoring
  ipfindx -i example.com -t -r             full recon + threat report
  ipfindx -i 8.8.8.0/28                    CIDR scan (all usable hosts)
  ipfindx -i 8.8.8.1-8.8.8.5               range scan
  ipfindx -l targets.txt -t -f csv,html    batch from file with exports
  ipfindx --myip -t                        intelligence on your own IP
  ipfindx --history                        recent lookups
  ipfindx --diff 8.8.8.8                   changes since last lookup
""",
    )
    tgt = parser.add_argument_group("targets")
    tgt.add_argument("-i", "--ip", metavar="TARGET",
                     help="single target: IP, CIDR (8.8.8.0/24) or range (8.8.8.1-8.8.8.9)")
    tgt.add_argument("-l", "--list", metavar="FILE", dest="list_file",
                     help="file with one target per line (# comments allowed)")
    tgt.add_argument("-m", "--myip", action="store_true",
                     help="run intelligence on your own public IP")

    mode = parser.add_argument_group("modes")
    mode.add_argument("--about", action="store_true", help="about IPFindX")
    mode.add_argument("--connect", action="store_true", help="contact / community links")
    mode.add_argument("--interactive", action="store_true", help="interactive shell mode")
    mode.add_argument("--history", nargs="?", const="*", metavar="IP",
                      help="show lookup history (optionally for one IP)")
    mode.add_argument("--diff", metavar="IP",
                      help="compare a fresh lookup with the previous stored one")
    mode.add_argument("--clear-cache", action="store_true", help="purge the lookup cache")

    enr = parser.add_argument_group("enrichment")
    enr.add_argument("-t", "--threat", action="store_true",
                     help="threat assessment and 0-100 risk score")
    enr.add_argument("-r", "--recon", action="store_true",
                     help="network recon: DNS, ping, traceroute, ports, whois, TLS")
    enr.add_argument("-p", "--ports", metavar="SPEC",
                     help="port spec for recon, e.g. 80,443,1000-2000")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="DIR", default=None,
                     help="output directory (default: output-ipfindx)")
    out.add_argument("-f", "--format", metavar="FMT",
                     help="export formats: json,csv,html,ndjson,all (comma separated)")
    out.add_argument("--no-save", action="store_true",
                     help="don't write any files (exports and history)")
    out.add_argument("--json", action="store_true", help="print raw JSON report to stdout")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress banner/progress")

    cfgg = parser.add_argument_group("configuration")
    cfgg.add_argument("-c", "--config", metavar="FILE", help="JSON config file")
    cfgg.add_argument("--workers", type=int, metavar="N", help="concurrent workers for batches")
    cfgg.add_argument("--timeout", type=float, metavar="S", help="network timeout in seconds")
    cfgg.add_argument("--no-cache", action="store_true", help="bypass the lookup cache")
    return parser


# ------------------------------------------------------------------ helpers


def _configure_console(*, json_mode: bool) -> None:
    """Bind rich output to stderr in --json mode; otherwise restore stdout.

    Safe to call repeatedly in the same process so a prior --json invocation
    cannot leave the console permanently bound to stderr.
    """
    from rich.console import Console as _Console

    stream = sys.stderr if json_mode else sys.stdout
    render.console = _Console(theme=render.custom_theme, file=stream)


def _apply_overrides(cfg: Config, args: argparse.Namespace) -> None:
    if args.output:
        cfg.output_dir = args.output
    if args.workers:
        cfg.batch_workers = max(1, args.workers)
    if args.timeout:
        cfg.timeout = args.timeout


def _formats(args: argparse.Namespace) -> List[str]:
    """Parse -f into a de-duplicated, ordered list of format names."""
    if not args.format:
        return ["json"]
    fmts: List[str] = []
    for part in args.format.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part == "all":
            for f in ("json", "csv", "html", "ndjson"):
                if f not in fmts:
                    fmts.append(f)
        elif part in {"json", "csv", "html", "ndjson"}:
            if part not in fmts:
                fmts.append(part)
        else:
            render.console.print(f"[warning]Unknown format '{part}' ignored[/warning]")
    return fmts or ["json"]


def _save_reports(reports: List[LookupReport], formats: List[str], out_dir: str) -> List[str]:
    """Write each requested export exactly once; returns the written paths."""
    paths: List[str] = []
    try:
        if "json" in formats:
            paths.append(export_json(reports, out_dir))
        if "ndjson" in formats:
            paths.append(export_ndjson(reports, out_dir))
        if "csv" in formats:
            paths.append(export_csv(reports, out_dir))
        if "html" in formats:
            paths.append(export_html(reports, out_dir))
    except OSError as exc:
        render.console.print(f"[danger]Could not write output: {exc}[/danger]")
    for p in paths:
        render.console.print(f"[success]Saved:[/success] [saved_path]{p}[/saved_path]")
    return paths


def _record_history(reports: List[LookupReport], cfg: Config) -> None:
    try:
        with HistoryDB(cfg.history_db) as db:
            for r in reports:
                if r.record.ok:
                    db.record(r.record.ip, r.to_dict(), source=r.record.source)
    except Exception:
        pass  # history is best-effort; never break a scan over it


def _my_public_ip(timeout: float) -> Optional[str]:
    import requests

    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": f"{PROGRAM}/{__version__}"})
            if resp.ok and resp.text.strip():
                return resp.text.strip()
        except requests.exceptions.RequestException:
            continue
    return None


def _collect_targets(args: argparse.Namespace) -> Tuple[Optional[List[str]], Optional[str]]:
    """Return ``(targets, error)``.

    * ``(None, message)`` — list file could not be read (caller should exit ≠ 0)
    * ``([], None)`` — no targets supplied (caller may print help, exit 0)
    * ``([…], None)`` — ready to scan
    """
    targets: List[str] = []
    if args.ip:
        targets.append(args.ip)
    if args.list_file:
        try:
            targets.extend(read_ip_file(args.list_file))
        except OSError as exc:
            return None, f"Could not read list file: {exc}"
    if args.myip:
        targets.append("__MYIP__")
    return targets, None


def _resolve_myip(targets: List[str], cfg: Config) -> List[str]:
    out = []
    for t in targets:
        if t == "__MYIP__":
            ip = _my_public_ip(cfg.timeout)
            if ip is None:
                render.console.print("[danger]Could not determine your public IP[/danger]")
                out.append("127.0.0.1")  # will fail validation cleanly
            else:
                out.append(ip)
        else:
            out.append(t)
    return out


def run_lookup_flow(targets: List[str], cfg: Config, threat: bool = False,
                    recon: bool = False, ports: Optional[str] = None,
                    no_cache: bool = False, quiet: bool = False,
                    formats: Optional[List[str]] = None,
                    save: bool = True) -> List[LookupReport]:
    """Shared execution path used by both the CLI and the interactive shell.

    ``quiet`` suppresses the live progress UI (results are still displayed).
    When ``save`` is False (``--no-save``), neither exports nor history are
    written.
    """
    targets = _resolve_myip(targets, cfg)
    single = len(targets) == 1 and "/" not in targets[0] and "-" not in targets[0]

    if single:
        report = lookup(targets[0], config=cfg, threat=threat, recon=recon,
                        no_cache=no_cache, ports=ports)
        reports = [report]
        render.display_report(report)
    else:
        reports = []
        if quiet:
            reports = scan_batch(targets, config=cfg, threat=threat, recon=recon,
                                 ports=ports, no_cache=no_cache)
        else:
            with render.make_progress() as progress:
                task = progress.add_task("Scanning targets…", total=None)

                def on_progress(done: int, total: int, current: str) -> None:
                    progress.update(task, total=total, completed=done,
                                    description=f"Scanning ({current})")

                reports = scan_batch(targets, config=cfg, threat=threat, recon=recon,
                                     ports=ports, no_cache=no_cache,
                                     progress=on_progress)
        for r in reports:
            render.display_report(r, show_maps=(len(reports) <= 8))
        render.display_summary(reports)

    if save and formats:
        _save_reports(reports, formats, cfg.output_dir)
    if save:
        _record_history(reports, cfg)
    return reports


# --------------------------------------------------------------------- main


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Console routing FIRST so banners/warnings honour --json purity, and so
    # a previous --json call in this process cannot leave stderr as default.
    _configure_console(json_mode=bool(args.json))

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        render.console.print(f"[danger]{exc}[/danger]")
        return 2

    _apply_overrides(cfg, args)
    formats = _formats(args)

    if not args.quiet:
        render.print_banner(__version__)

    try:
        if args.about:
            render.show_about(__version__)
            return 0
        if args.connect:
            render.show_connect()
            return 0
        if args.clear_cache:
            from ipfindx.core.cache import TTLCache

            cache = TTLCache(cfg.cache_db, ttl=cfg.cache_ttl)
            try:
                render.show_cache_cleared(cache.clear())
                return 0
            finally:
                cache.close()
        if args.history:
            db = HistoryDB(cfg.history_db)
            try:
                ip = None if args.history == "*" else args.history
                entries = db.entries(ip=ip, limit=50)
                if entries:
                    render.show_history(entries)
                else:
                    render.console.print("[info]No history yet — run a lookup first.[/info]")
                return 0
            finally:
                db.close()
        if args.diff:
            return _run_diff(args.diff, cfg, args)
        if args.interactive:
            from ipfindx.shell import run_shell

            run_shell(cfg, quiet=args.quiet)
            return 0

        targets, collect_err = _collect_targets(args)
        if collect_err is not None:
            render.console.print(f"[danger]{collect_err}[/danger]")
            return 1
        if not targets:
            parser.print_help()
            return 0

        reports = run_lookup_flow(
            targets, cfg,
            threat=args.threat, recon=args.recon, ports=args.ports,
            no_cache=args.no_cache, quiet=args.quiet,
            formats=None if args.no_save else formats,
            save=not args.no_save,
        )
        if args.json:
            import json

            data = reports[0].to_dict() if len(reports) == 1 else [r.to_dict() for r in reports]
            print(json.dumps(data, indent=2))
        failed = sum(1 for r in reports if not r.record.ok)
        return 1 if reports and failed == len(reports) else 0
    except KeyboardInterrupt:
        render.console.print("\n[warning]Interrupted.[/warning]")
        return 130


def _run_diff(ip: str, cfg: Config, args: argparse.Namespace) -> int:
    db = HistoryDB(cfg.history_db)
    try:
        report = lookup(ip, config=cfg, threat=args.threat, no_cache=True)
        if not report.record.ok:
            render.display_report(report)
            return 1
        diffs = db.diff_fields(ip, report.to_dict())
        render.show_diff(ip, diffs)
        db.record(ip, report.to_dict(), source=report.record.source)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
