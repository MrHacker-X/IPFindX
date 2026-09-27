"""Self-contained HTML report generator (no external assets, opens offline)."""

from __future__ import annotations

import datetime
import html
import os
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # pragma: no cover
    from ipfindx.core.models import LookupReport

__all__ = ["export_html"]

_CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--orange:#db6d28;--red:#f85149;--purple:#bc8cff}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);
color:var(--text);padding:2rem;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:1.6rem;margin-bottom:.25rem}
h1 code{color:var(--accent);font-size:1.35rem}
.sub{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem;margin:1.5rem 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.15rem}
.card h3{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:.4rem}
.card .v{font-size:1.05rem;font-weight:600;word-break:break-word}
.card .s{font-size:.78rem;color:var(--muted)}
.badge{display:inline-block;padding:.2rem .7rem;border-radius:999px;font-size:.78rem;font-weight:700}
.b-minimal{background:rgba(63,185,80,.15);color:var(--green)}
.b-low{background:rgba(63,185,80,.25);color:var(--green)}
.b-moderate{background:rgba(210,153,34,.15);color:var(--yellow)}
.b-elevated{background:rgba(219,109,40,.18);color:var(--orange)}
.b-high{background:rgba(248,81,73,.18);color:var(--red)}
.b-critical{background:rgba(248,81,73,.3);color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
td,th{padding:.45rem .6rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}
tr:last-child td{border-bottom:none}
.mono{font-family:'Cascadia Code',Consolas,monospace;font-size:.8rem}
.kv td:first-child{color:var(--muted);width:38%}
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;
padding:1.1rem 1.25rem;margin:1rem 0}
.section h2{font-size:.95rem;margin-bottom:.75rem;color:var(--accent)}
.sig{display:inline-block;background:rgba(88,166,255,.12);border:1px solid rgba(88,166,255,.35);
color:var(--accent);border-radius:6px;padding:.15rem .55rem;font-size:.78rem;margin:.15rem .2rem .15rem 0}
.open{color:var(--green);font-weight:700}.closed{color:var(--muted)}
footer{margin-top:2rem;color:var(--muted);font-size:.75rem;text-align:center}
a{color:var(--accent);text-decoration:none}
"""

_LEVELS = ("minimal", "low", "moderate", "elevated", "high", "critical")


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else "—"


def _badge(level: str) -> str:
    if level not in _LEVELS:
        level = "minimal"
    return f'<span class="badge b-{level}">{level.upper()} · RISK</span>'


def _render_report(rep: "LookupReport") -> str:
    rec = rep.record
    threat = rep.threat
    recon = rep.recon

    flags = ""
    if rec.is_hosting:
        flags += '<span class="sig">HOSTING</span>'
    if rec.is_proxy:
        flags += '<span class="sig">PROXY/VPN</span>'
    if rec.is_mobile:
        flags += '<span class="sig">MOBILE</span>'
    if threat and threat.tor_exit:
        flags += '<span class="sig">TOR EXIT</span>'

    maps = (
        f'<a href="{html.escape(rec.maps_url)}" target="_blank">📍 Google Maps</a>'
        if rec.maps_url else ""
    )

    geo_cards = f"""
<div class="grid">
  <div class="card"><h3>Location</h3><div class="v">{_esc(rec.city or rec.region_name or rec.country)}</div>
    <div class="s">{_esc(', '.join(filter(None, [rec.city, rec.region_name, rec.country])))}</div></div>
  <div class="card"><h3>Coordinates</h3><div class="v mono">{_esc(rec.lat)}, {_esc(rec.lon)}</div>
    <div class="s">{maps}</div></div>
  <div class="card"><h3>Timezone</h3><div class="v">{_esc(rec.timezone)}</div>
    <div class="s">UTC offset {_esc(rec.offset)}</div></div>
  <div class="card"><h3>ASN</h3><div class="v mono">{_esc(rec.asn)}</div>
    <div class="s">{_esc(rec.as_name or rec.isp)}</div></div>
</div>"""

    intel_rows = "".join(
        f"<tr><td>{k}</td><td class='mono'>{_esc(v)}</td></tr>"
        for k, v in [
            ("IP address", rec.ip),
            ("Continent", f"{rec.continent or ''} ({rec.continent_code or '-'})"),
            ("Country", f"{rec.country or ''} ({rec.country_code or '-'})"),
            ("Region", rec.region_name or rec.region),
            ("City / district", f"{rec.city or '-'} / {rec.district or '-'}"),
            ("Postal code", rec.zip),
            ("Currency", rec.currency),
            ("ISP", rec.isp),
            ("Organisation", rec.org),
            ("Reverse DNS", rec.reverse_dns),
            ("Data source", rec.source),
            ("Lookup time", f"{rec.lookup_ms} ms" if rec.lookup_ms else None),
            ("Fetched at", rec.fetched_at),
        ]
    )

    threat_html = ""
    if threat:
        signals = "".join(f'<span class="sig">{_esc(s)}</span>' for s in threat.signals) or \
            '<span class="s">No threat signals detected.</span>'
        abuse = f"<tr><td>AbuseIPDB confidence</td><td class='mono'>{threat.abuse_confidence}%</td></tr>" \
            if threat.abuse_confidence is not None else ""
        score_pct = max(0, min(100, threat.score))
        bar_color = {"minimal": "var(--green)", "low": "var(--green)",
                     "moderate": "var(--yellow)", "elevated": "var(--orange)",
                     "high": "var(--red)", "critical": "var(--red)"}.get(threat.level, "var(--accent)")
        threat_html = f"""
<div class="section">
  <h2>🛡 Threat Assessment {_badge(threat.level)}</h2>
  <div style="background:var(--border);border-radius:6px;height:10px;margin:.4rem 0 1rem">
    <div style="background:{bar_color};width:{score_pct}%;height:10px;border-radius:6px"></div>
  </div>
  <table class="kv">
    <tr><td>Risk score</td><td class="mono">{threat.score}/100</td></tr>
    {abuse}
  </table>
  <div style="margin-top:.8rem">{signals}</div>
</div>"""

    recon_html = ""
    if recon:
        # --- DNS (forward resolution) ------------------------------------
        dns = recon.dns or {}
        dns_addrs = dns.get("addresses") or []
        dns_html = ""
        if dns_addrs or dns.get("error") or dns.get("hostname"):
            addr_rows = "".join(
                f"<tr><td class='mono'>{_esc(a)}</td></tr>" for a in dns_addrs
            ) or f"<tr><td class='mono'>{_esc(dns.get('error'))}</td></tr>"
            dns_html = (f"<div class='section'><h2>🔎 DNS resolution</h2>"
                        f"<p class='s'>hostname: {_esc(dns.get('hostname'))}</p>"
                        f"<table>{addr_rows}</table></div>")

        # --- port scan ----------------------------------------------------
        rows = ""
        for p in recon.ports:
            state = "open" if p.get("state") == "open" else "closed"
            rows += (f"<tr><td class='mono'>{p.get('port')}</td>"
                     f"<td>{_esc(p.get('service'))}</td>"
                     f"<td class='{state}'>{'OPEN' if state == 'open' else 'closed'}</td></tr>")
        ports_html = (f"<div class='section'><h2>🛡 Port scan</h2>"
                      f"<table><tr><th>Port</th><th>Service</th><th>State</th></tr>"
                      f"{rows or '<tr><td colspan=3>no results</td></tr>'}</table></div>")

        # --- ping ----------------------------------------------------------
        ping = recon.ping or {}
        ping_line = (f"avg {ping.get('avg_ms')} ms ({ping.get('method')})"
                     if ping.get("avg_ms") else "unreachable / blocked")
        ping_html = (f"<div class='section'><h2>📡 Ping</h2>"
                     f"<p class='mono'>{_esc(ping_line)}</p></div>")

        # --- traceroute ----------------------------------------------------
        hops = ""
        for h in recon.traceroute:
            latency = "—" if h.get("avg_ms") is None else f"{h['avg_ms']} ms"
            hops += (f"<tr><td class='mono'>{h.get('hop')}</td><td class='mono'>{_esc(h.get('ip'))}</td>"
                     f"<td class='mono'>{_esc(latency)}</td></tr>")
        trace_html = (f"<div class='section'><h2>🛰 Traceroute</h2>"
                      f"<table><tr><th>Hop</th><th>IP</th><th>Latency</th></tr>{hops}</table></div>"
                      if hops else "")

        # --- WHOIS ----------------------------------------------------------
        whois_html = ""
        if recon.whois:
            whois_rows = "".join(
                f"<tr><td class='mono'>{_esc(line)}</td></tr>"
                for line in recon.whois.splitlines() if line.strip()
            )
            whois_html = (f"<div class='section'><h2>📜 WHOIS</h2>"
                          f"<table>{whois_rows}</table></div>")

        # --- TLS -------------------------------------------------------------
        tls = recon.tls or {}
        tls_html = f"""
<div class="section">
<h2>🔐 TLS certificate</h2>
<table class="kv">
  <tr><td>Subject CN</td><td class="mono">{_esc(tls.get('subject_cn'))}</td></tr>
  <tr><td>Issuer</td><td class="mono">{_esc(tls.get('issuer'))}</td></tr>
  <tr><td>Valid</td><td class="mono">{_esc(tls.get('issued_on'))} → {_esc(tls.get('expires_on'))}</td></tr>
  <tr><td>SHA-256</td><td class="mono">{_esc((tls.get('sha256') or '')[:32])}…</td></tr>
</table>
</div>""" if tls else ""

        recon_html = dns_html + ports_html + ping_html + trace_html + whois_html + tls_html

    return f"""
<div class="report">
  <h1><code>{_esc(rec.ip)}</code> {flags}</h1>
  <div class="sub">IPFindX v4 intelligence report · generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · source: {_esc(rec.source)}</div>
  {geo_cards}
  <div class="section"><h2>🌐 Network intelligence</h2>
  <table class="kv">{intel_rows}</table></div>
  {threat_html}
  {recon_html}
</div>"""


def export_html(reports: List["LookupReport"], output_dir: str) -> str:
    from ipfindx.exporters.stamp import export_stamp

    os.makedirs(output_dir, exist_ok=True)
    stamp = export_stamp()
    path = os.path.join(output_dir, f"report-{stamp}.html")
    if len(reports) == 1:
        body = _render_report(reports[0])
    else:
        body = "".join(_render_report(r) for r in reports)
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPFindX Report · {stamp}</title><style>{_CSS}</style></head>
<body><div class="wrap">{body}
<footer>Generated by IPFindX v4 — Advanced IP Intelligence Toolkit · self-contained file, works offline</footer>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
