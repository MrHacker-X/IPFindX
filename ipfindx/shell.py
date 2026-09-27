"""Interactive shell mode — a mini recon console built on the standard library."""

from __future__ import annotations

import cmd
import shlex
from typing import List, Optional

from ipfindx import __version__
from ipfindx.cli import run_lookup_flow, _formats
from ipfindx.core.config import Config
from ipfindx.storage.history import HistoryDB
from ipfindx.ui import render

__all__ = ["run_shell"]

_BANNER_ART = r"""
██╗██████╗ ███████╗██╗███╗   ██╗██████╗ ██╗  ██╗
██║██╔══██╗██╔════╝██║████╗  ██║██╔══██╗╚██╗██╔╝
██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║ ╚███╔╝
██║██╔═══╝ ██╔══╝  ██║██║╚██╗██║██║  ██║ ██╔██╗
██║██║     ██║     ██║██║ ╚████║██████╔╝██╔╝ ██╗
╚═╝╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝
"""


class IPFindXShell(cmd.Cmd):
    # Rich markup must NOT go through cmd.Cmd's plain stdout (it would print
    # the tags literally); intro is rendered via render.console instead.
    intro = None
    prompt = "ipfindx> "

    def __init__(self, cfg: Config):
        super().__init__()
        self.cfg = cfg

    def _print_intro(self) -> None:
        width = render.console.size.width
        art = _BANNER_ART if width >= 60 else ""  # degrade to text-only on narrow terminals
        render.console.print(
            f"[banner]{art}[/banner]"
            f"[bold cyan]IPFindX v{__version__} — interactive shell[/bold cyan]\n"
            f"[dim]Type [bold]help[/bold] for commands, [bold]exit[/bold] to quit.[/dim]\n"
        )

    # ----------------------------------------------------------- utilities

    def _parse(self, line: str) -> List[str]:
        try:
            return shlex.split(line)
        except ValueError:
            return line.split()

    def _run(self, line: str, threat: bool, recon: bool) -> None:
        parts = self._parse(line)
        if not parts:
            render.console.print("[warning]Usage: lookup <ip|cidr|range|host>[/warning]")
            return
        ports = None
        if "--ports" in parts:
            idx = parts.index("--ports")
            if idx + 1 < len(parts):
                ports = parts[idx + 1]
                parts = parts[:idx] + parts[idx + 2:]
        target = " ".join(parts)
        try:
            run_lookup_flow(
                [target], self.cfg, threat=threat, recon=recon, ports=ports,
                formats=["json"], save=True,
            )
        except KeyboardInterrupt:
            render.console.print("\n[warning]Cancelled.[/warning]")

    # ------------------------------------------------------------ commands

    def do_lookup(self, line: str) -> None:
        """lookup <target> — geolocation + network intelligence for one target."""
        self._run(line, threat=False, recon=False)

    def do_threat(self, line: str) -> None:
        """threat <target> — lookup with full threat scoring."""
        self._run(line, threat=True, recon=False)

    def do_recon(self, line: str) -> None:
        """recon <target> [--ports SPEC] — lookup + recon + threat scoring."""
        self._run(line, threat=True, recon=True)

    def do_batch(self, line: str) -> None:
        """batch <file> — scan a file of targets (one per line)."""
        parts = self._parse(line)
        if not parts:
            render.console.print("[warning]Usage: batch <file>[/warning]")
            return
        from ipfindx.core.utils import read_ip_file

        try:
            targets = read_ip_file(parts[0])
        except OSError as exc:
            render.console.print(f"[danger]{exc}[/danger]")
            return
        if not targets:
            render.console.print("[warning]No targets found in file.[/warning]")
            return
        run_lookup_flow(targets, self.cfg, formats=["json", "csv", "html"], save=True)

    def do_history(self, line: str) -> None:
        """history [ip] — show recent lookups."""
        ip = (self._parse(line) or [None])[0]
        db = HistoryDB(self.cfg.history_db)
        try:
            entries = db.entries(ip=ip, limit=30)
        finally:
            db.close()
        if entries:
            render.show_history(entries)
        else:
            render.console.print("[info]No history yet.[/info]")

    def do_diff(self, line: str) -> None:
        """diff <ip> — show what changed since the previous lookup."""
        parts = self._parse(line)
        if not parts:
            render.console.print("[warning]Usage: diff <ip>[/warning]")
            return
        ip = parts[0]
        db = HistoryDB(self.cfg.history_db)
        try:
            from ipfindx.intel.lookup import lookup

            report = lookup(ip, config=self.cfg, no_cache=True)
            if report.record.ok:
                render.show_diff(ip, db.diff_fields(ip, report.to_dict()))
                db.record(ip, report.to_dict(), source=report.record.source)
            else:
                render.display_report(report)
        finally:
            db.close()

    def do_config(self, line: str) -> None:
        """config — show the active configuration."""
        from dataclasses import fields

        table = render.Table(title="[bold]Active Configuration[/bold]",
                             header_style="table_header", border_style="panel_border")
        table.add_column("Key", style="field")
        table.add_column("Value", style="value", overflow="fold")
        for f in fields(Config):
            value = getattr(self.cfg, f.name)
            if f.name in {"abuseipdb_key", "ipinfo_token"} and value:
                value = value[:4] + "••••"
            table.add_row(f.name, str(value))
        render.console.print(table)

    def do_output(self, line: str) -> None:
        """output <dir> — change where reports are saved."""
        parts = self._parse(line)
        if not parts:
            render.console.print(f"[info]Output directory: {self.cfg.output_dir}[/info]")
            return
        self.cfg.output_dir = parts[0]
        render.console.print(f"[success]Output directory set to {parts[0]}[/success]")

    def do_clear(self, line: str) -> None:
        """clear — clear the screen."""
        render.console.clear()

    def do_exit(self, line: str) -> bool:
        """exit — leave the shell."""
        render.console.print("[info]Goodbye.[/info]")
        return True

    do_quit = do_exit
    do_EOF = do_exit


def run_shell(cfg: Config, quiet: bool = False) -> None:
    shell = IPFindXShell(cfg)
    if not quiet:
        shell._print_intro()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        render.console.print("\n[info]Goodbye.[/info]")
