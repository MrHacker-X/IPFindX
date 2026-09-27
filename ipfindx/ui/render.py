"""Rich terminal rendering: banner, risk gauge, tables and summaries."""

from __future__ import annotations

from typing import List, TYPE_CHECKING

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

if TYPE_CHECKING:  # pragma: no cover
    from ipfindx.core.models import LookupReport

__all__ = ["console", "print_banner", "display_report", "display_summary",
           "make_progress", "show_about", "show_connect", "show_history",
           "show_diff", "show_cache_cleared"]

custom_theme = Theme({
    "info": "bold blue",
    "warning": "bold yellow",
    "danger": "bold red",
    "success": "bold green",
    "banner": "bold gold1",
    "field": "bold gold1",
    "value": "white",
    "panel_border": "bold blue",
    "table_header": "bold gold1",
    "saved_path": "bold blue",
})

console = Console(theme=custom_theme)

_BANNER = '''
██╗██████╗ ███████╗██╗███╗   ██╗██████╗ ██╗  ██╗
██║██╔══██╗██╔════╝██║████╗  ██║██╔══██╗╚██╗██╔╝
██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║ ╚███╔╝
██║██╔═══╝ ██╔══╝  ██║██║╚██╗██║██║  ██║ ██╔██╗
██║██║     ██║     ██║██║ ╚████║██████╔╝██╔╝ ██╗
╚═╝╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝
'''

_TAGLINE = "⚡ GEOLOCATION • THREAT SCORES • RECON • BATCH • SHELL ⚡"
_FOOTER = "python 3.9+ · stdlib recon · every probe fails soft"


def _info_grid(version: str) -> Table:
    grid = Table.grid(padding=(0, 4))
    grid.add_column()
    grid.add_column()
    grid.add_row(
        Text.assemble(("VERSION ", "dim"), (f"v{version}", "bold gold1")),
        Text.assemble(("ENGINE  ", "dim"), ("3-provider failover", "white")),
    )
    grid.add_row(
        Text.assemble(("AUTHOR  ", "dim"), ("Alex Butler", "italic green")),
        Text.assemble(("ORG     ", "dim"), ("Vritra Security Organization", "italic green")),
    )
    grid.add_row(
        Text.assemble(("CACHE   ", "dim"), ("SQLite TTL + history", "white")),
        Text.assemble(("MODES   ", "dim"), ("CLI · Shell · Library", "white")),
    )
    return grid

_LEVEL_STYLE = {
    "minimal": "success", "low": "success", "moderate": "warning",
    "elevated": "bold yellow", "high": "danger", "critical": "bold red",
}


def print_banner(version: str = "4.0.0") -> None:
    banner_width = max(len(line) for line in _BANNER.splitlines())
    if console.size.width < banner_width + 16:
        fallback = Text(justify="center")
        fallback.append("⚡ IPFindX ⚡\n", style="banner")
        fallback.append(f"v{version} • Alex Butler • Vritra Security Organization\n", style="italic green")
        fallback.append("Advanced IP Intelligence & Reconnaissance Toolkit\n", style="bold cyan")
        console.print(Panel(fallback, border_style="bold magenta", padding=(1, 2),
                            expand=False))
    else:
        body = Group(
            Text(_BANNER, style="banner", justify="center"),
            Text(_TAGLINE, style="bold cyan", justify="center"),
            Text("─" * (banner_width + 4), style="dim gold1", justify="center"),
            Align.center(_info_grid(version)),
            Text(_FOOTER, style="italic dim green", justify="center"),
        )
        console.print(Panel(
            body,
            title=f"[bold gold1]⌘ IPFindX v{version}[/bold gold1]",
            subtitle="[info]Vritra Security Organization[/info]",
            border_style="panel_border",
            padding=(0, 2),
            width=banner_width + 16,
        ))
    console.print()


def _risk_text(score: int, level: str) -> Text:
    style = _LEVEL_STYLE.get(level, "white")
    blocks = "█" * (score // 5) + "░" * (20 - score // 5)
    return Text(f"{blocks} {score}/100 [{level.upper()}]", style=style)


def display_report(report: "LookupReport", show_maps: bool = True) -> None:
    rec = report.record

    if not rec.ok:
        console.print(Panel(
            f"[danger]{rec.message or 'lookup failed'}[/danger]",
            title=f"[bold]Failed · {rec.ip}[/bold]", border_style="danger",
            expand=False,
        ))
        return

    table = Table(
        title=f"[bold]IP Intelligence · {rec.ip}[/bold]",
        show_header=True, header_style="table_header", border_style="panel_border",
    )
    table.add_column("Field", style="field", width=22)
    table.add_column("Value", style="value", overflow="fold")

    rows = [
        ("Country", f"{rec.country or '-'} ({rec.country_code or '-'})"),
        ("Region", rec.region_name or rec.region),
        ("City", rec.city),
        ("ZIP", rec.zip),
        ("Coordinates", f"{rec.lat}, {rec.lon}" if rec.lat is not None else None),
        ("Timezone", rec.timezone),
        ("Currency", rec.currency),
        ("ISP", rec.isp),
        ("Organisation", rec.org),
        ("ASN", rec.asn),
        ("Reverse DNS", rec.reverse_dns),
        ("Mobile / Proxy / Hosting", f"{rec.is_mobile} / {rec.is_proxy} / {rec.is_hosting}"),
        ("Source", rec.source),
        ("Lookup time", f"{rec.lookup_ms} ms" if rec.lookup_ms else None),
    ]
    for name, value in rows:
        if value is not None:
            table.add_row(f"• {name}", str(value))
    if rec.extra.get("cached"):
        table.add_row("• Cache", "[success]HIT[/success]")
    console.print(table)

    if report.threat:
        t = report.threat
        lines = _risk_text(t.score, t.level)
        if t.signals:
            for s in t.signals:
                lines.append("\n  ⚠ ", style="warning")
                lines.append(s, style="warning")
        else:
            lines.append("\n  ✓ No threat signals detected", style="success")
        console.print(Panel(lines, title="[bold]Threat Assessment[/bold]",
                            border_style=_LEVEL_STYLE.get(t.level, "white"),
                            expand=False))

    if report.recon:
        _display_recon(report.recon)

    if show_maps and rec.maps_url:
        console.print(Panel(
            f"[info]View on Google Maps:[/info]\n[saved_path]{rec.maps_url}[/saved_path]",
            title="[bold]Location[/bold]", border_style="panel_border",
            expand=False,
        ))


def _display_recon(recon) -> None:
    if recon.ports:
        open_rows = [p for p in recon.ports if p.get("state") == "open"]
        table = Table(title="[bold]Open Ports[/bold]", header_style="table_header",
                      border_style="success")
        table.add_column("Port", style="field", justify="right")
        table.add_column("Service")
        for p in open_rows:
            table.add_row(str(p["port"]), p.get("service", "unknown"))
        if open_rows:
            console.print(table)
        else:
            console.print(Panel("[success]No open ports found in scanned range[/success]",
                                title="[bold]Port Scan[/bold]", border_style="success",
                                expand=False))
    ping = recon.ping or {}
    if ping:
        if ping.get("avg_ms") is not None:
            console.print(Panel(
                f"[success]reachable[/success] · avg {ping['avg_ms']} ms ({ping.get('method')})",
                title="[bold]Ping[/bold]", border_style="panel_border", expand=False))
        else:
            console.print(Panel("[warning]unreachable / ICMP blocked[/warning]",
                                title="[bold]Ping[/bold]", border_style="warning",
                                expand=False))
    if recon.whois:
        console.print(Panel(recon.whois, title="[bold]WHOIS[/bold]",
                            border_style="panel_border", expand=False))
    if recon.tls:
        tls = recon.tls
        console.print(Panel(
            f"[field]CN:[/field] {tls.get('subject_cn')}  [field]Issuer:[/field] {tls.get('issuer')}\n"
            f"[field]Valid:[/field] {tls.get('issued_on')} → {tls.get('expires_on')}",
            title="[bold]TLS Certificate[/bold]", border_style="panel_border",
            expand=False))


def display_summary(reports: List["LookupReport"]) -> None:
    ok = [r for r in reports if r.record.ok]
    fails = len(reports) - len(ok)
    countries: dict = {}
    risky: List["LookupReport"] = []
    for r in ok:
        c = r.record.country_code or "??"
        countries[c] = countries.get(c, 0) + 1
        if r.threat and r.threat.score >= 40:
            risky.append(r)

    table = Table(title="[bold]Scan Summary[/bold]", header_style="table_header",
                  border_style="panel_border")
    table.add_column("Metric", style="field")
    table.add_column("Value", style="value")
    table.add_row("• Targets scanned", str(len(reports)))
    table.add_row("• Succeeded", f"[success]{len(ok)}[/success]")
    if fails:
        table.add_row("• Failed", f"[danger]{fails}[/danger]")
    top = sorted(countries.items(), key=lambda kv: -kv[1])[:5]
    if top:
        table.add_row("• Top countries", ", ".join(f"{c}×{n}" for c, n in top))
    if risky:
        table.add_row("• Elevated+ risk", f"[danger]{len(risky)}[/danger] "
                      f"({', '.join(r.record.ip for r in risky[:5])})")
    console.print(table)


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def show_about(version: str = "4.0.0") -> None:
    console.print(Panel(
        f"[banner]IPFindX v{version}[/banner]\n"
        "Advanced IP intelligence, threat scoring and network reconnaissance.\n\n"
        "[field]Author:[/field] Alex Butler · Vritra Security Organization",
        title="[bold]About[/bold]", border_style="panel_border", expand=False))


def show_connect() -> None:
    console.print(Panel(
        "[field]GitHub:[/field]    https://github.com/MrHacker-X\n"
        "[field]Website:[/field]   https://vritrasec.com\n"
        "[field]Community:[/field] https://t.me/VritraSec",
        title="[bold]Connect[/bold]", border_style="panel_border", expand=False))


def show_history(entries: List[dict]) -> None:
    table = Table(title="[bold]Lookup History[/bold]", header_style="table_header",
                  border_style="panel_border")
    table.add_column("IP", style="field")
    table.add_column("Timestamp")
    table.add_column("Source")
    for e in entries:
        table.add_row(e.get("ip", ""), e.get("ts", ""), e.get("source") or "-")
    console.print(table)


def show_diff(ip: str, diffs: dict) -> None:
    if not diffs:
        console.print(Panel(f"[success]No changes since last lookup of {ip}[/success]",
                            title="[bold]Diff[/bold]", border_style="success",
                            expand=False))
        return
    table = Table(title=f"[bold]Changes for {ip}[/bold]", header_style="table_header",
                  border_style="warning")
    table.add_column("Field", style="field")
    table.add_column("Previous", style="value", overflow="fold")
    table.add_column("Current", style="success", overflow="fold")
    for field, (old, new) in diffs.items():
        table.add_row(field, "—" if old is None else str(old),
                      "—" if new is None else str(new))
    console.print(table)


def show_cache_cleared(n: int) -> None:
    console.print(Panel(f"[success]Cleared {n} cache entr{'ies' if n != 1 else 'y'}[/success]",
                        title="[bold]Cache[/bold]", border_style="success",
                        expand=False))
