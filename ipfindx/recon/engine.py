"""Network reconnaissance engine: ping, traceroute, TCP port scan, whois, TLS.

All probes use the Python standard library (socket / ssl / subprocess) so the
tool keeps a minimal dependency footprint. Every probe fails soft: an error
becomes an entry in the result, never a crash.
"""

from __future__ import annotations

import datetime
import re
import socket
import ssl
import subprocess
from typing import Dict, List, Optional

from ipfindx.core.config import Config
from ipfindx.core.utils import parse_ports
from ipfindx.recon.dns import resolve_host

__all__ = ["run_recon", "tcp_ping", "traceroute", "port_scan", "whois_lookup", "tls_certificate"]

_SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc",
    8080: "http-alt", 8443: "https-alt",
}

_WHOIS_SECTION_RE = re.compile(
    r"(?is)^\s*(netname|orgname|org-name|organisation|organization|descr|owner|"
    r"mnt-by|country|admin-c|tech-c|abuse-mailbox|inetnum|netrange)\s*:\s*(.+)$"
)


def run_recon(target: str, cfg: Config, port_spec: str = "", do_ping: bool = True,
              do_trace: bool = True, do_whois: bool = True) -> "object":
    """Run the full recon suite against *target* and return a ReconResult."""
    from ipfindx.core.models import ReconResult  # avoid circular import

    res = ReconResult(target=target)

    # normalise hostname -> routable IP (prefer public IPv4)
    if not _is_ip(target):
        res.dns = resolve_host(target)
        from ipfindx.intel.lookup import resolve_target

        ip = resolve_target(target)
    else:
        from ipfindx.core.utils import is_public_ip

        ip = target if is_public_ip(target) else None

    if ip is None:
        res.ping = {"host": target, "error": "no routable address"}
        return res

    res.ports = port_scan(ip, parse_ports(port_spec or ",".join(map(str, cfg.top_ports))), timeout=cfg.recon_timeout)

    if do_ping and ip:
        res.ping = ping_host(ip, count=cfg.ping_count)
    if do_trace and ip:
        res.traceroute = traceroute(ip, max_hops=cfg.max_trace_hops, timeout=cfg.recon_timeout)
    if do_whois and ip:
        res.whois = whois_lookup(ip)
    if 443 in [p.get("port") for p in res.ports if p.get("state") == "open"]:
        sni = target if not _is_ip(target) else None
        res.tls = tls_certificate(ip, sni=sni, timeout=max(cfg.recon_timeout, 5.0)) or {}
    return res


def _is_ip(candidate: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------- probes


def tcp_ping(host: str, port: int = 443, timeout: float = 2.0) -> Optional[float]:
    """TCP connect latency in ms, or None when unreachable."""
    import time

    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - start) * 1000, 1)
    except OSError:
        return None


def ping_host(host: str, count: int = 3) -> dict:
    """ICMP ping via the OS binary (falls back to TCP probe on failure).

    TCP fallback runs when the ping binary is missing **or** when it runs but
    returns no usable RTT samples (e.g. returncode=1 / 100% loss).
    """
    out: Dict = {"host": host, "method": "icmp", "sent": count, "received": 0, "avg_ms": None, "error": None}
    icmp_error: Optional[str] = None
    try:
        proc = subprocess.run(
            ["ping", "-n" if _is_windows() else "-c", str(count), host],
            capture_output=True, text=True, timeout=max(10, count * 5),
        )
        text = proc.stdout or ""
        times = [float(m) for m in re.findall(r"time[=<]([\d.]+)", text)]
        if times:
            out["received"] = len(times)
            out["avg_ms"] = round(sum(times) / len(times), 1)
            return out
        icmp_error = (proc.stderr or "no response").strip()[:200] or "no replies"
    except (OSError, subprocess.TimeoutExpired) as exc:
        icmp_error = str(exc)[:200]

    # ICMP unavailable or empty — try a TCP probe
    latency = tcp_ping(host, 443)
    out["method"] = "tcp:443"
    if latency is not None:
        out["received"] = 1
        out["avg_ms"] = latency
        out["error"] = None
    else:
        out["error"] = icmp_error
    return out


def traceroute(host: str, max_hops: int = 15, timeout: float = 2.0) -> List[dict]:
    """Traceroute via the OS binary (``traceroute`` / Windows ``tracert``).

    Returns an empty list when the binary is missing or the probe fails.
    There is no automatic TCP traceroute fallback.
    """
    windows = _is_windows()
    try:
        if windows:
            # -d: no DNS, -h: max hops, -w: per-probe timeout in milliseconds
            cmd = [
                "tracert", "-d",
                "-h", str(max_hops),
                "-w", str(max(1, int(timeout * 1000))),
                host,
            ]
        else:
            cmd = [
                "traceroute", "-n",
                "-m", str(max_hops),
                "-w", str(int(timeout)),
                host,
            ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=max(30, max_hops * timeout * 3),
        )
        return _parse_traceroute_output(proc.stdout or "", windows=windows)
    except (OSError, subprocess.TimeoutExpired):
        return []


def _parse_traceroute_output(text: str, windows: bool = False) -> List[dict]:
    """Parse Unix traceroute or Windows tracert stdout into hop dicts."""
    hops: List[dict] = []
    lines = text.splitlines()
    # Skip banner lines (traceroute to… / Tracing route to…)
    start = 0
    for i, line in enumerate(lines):
        if re.match(r"\s*\d+", line):
            start = i
            break
    for line in lines[start:]:
        m = re.match(r"\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        ttl = int(m.group(1))
        rest = m.group(2).strip()
        if windows:
            # "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            # "  2     *        *        *     Request timed out."
            rtts = [float(x) for x in re.findall(r"<?([\d.]+)\s*ms", rest, flags=re.I)]
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s*$", rest)
            timed_out = "request timed out" in rest.lower() or rest.lstrip().startswith("*")
            addr = None if timed_out or not ip_match else ip_match.group(1)
            if addr and addr.startswith("*"):
                addr = None
        else:
            m2 = re.match(r"(\S+)", rest)
            addr = m2.group(1) if m2 else None
            if addr and addr.startswith("*"):
                addr = None
            rtts = [float(x) for x in re.findall(r"([\d.]+)\s*ms", rest)]
        hops.append({
            "hop": ttl,
            "ip": addr,
            "avg_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
        })
    return hops


def port_scan(host: str, ports: List[int], timeout: float = 2.0,
              workers: int = 64) -> List[dict]:
    """Concurrent TCP connect scan. Only reports open/reachable state."""
    from concurrent.futures import ThreadPoolExecutor

    if not host or not ports:
        return []

    def probe(port: int) -> dict:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return {"port": port, "state": "open", "service": _SERVICE_HINTS.get(port, "unknown")}
        except OSError:
            return {"port": port, "state": "closed", "service": _SERVICE_HINTS.get(port, "unknown")}

    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        for r in pool.map(probe, ports):
            results.append(r)
    return results


def whois_lookup(ip: str, timeout: float = 6.0) -> Optional[str]:
    """Raw whois query (port 43) returning the most relevant summary lines."""
    server = _whois_server_for(ip)
    if not server:
        return None
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall(f"{ip}\r\n".encode())
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="replace"))
        raw = "".join(chunks)
        interesting = []
        for line in raw.splitlines():
            m = _WHOIS_SECTION_RE.match(line)
            if m:
                interesting.append(f"{m.group(1)}: {m.group(2).strip()}")
        return "\n".join(interesting) if interesting else raw[:1500]
    except OSError:
        return None


_RIR_HINTS = {
    "whois.arin.net": "38.",
    "whois.ripe.net": "185.",
    "whois.apnic.net": "1.",
    "whois.lacnic.net": "177.",
    "whois.afrinic.net": "105.",
}


def _whois_server_for(ip: str) -> Optional[str]:
    # First-octet heuristic per RIR. RIRs with specific /8 allocations are
    # matched BEFORE the broad legacy ranges: ARIN's 96-132 covers the
    # AFRINIC 105/8 and 102/8 blocks, APNIC's 101-105 covers 102/8, and
    # RIPE's 176-179 covers the LACNIC 177/8 and 179/8 blocks — checked
    # first, otherwise those allocations are silently shadowed.
    first = ip.split(".")[0] if "." in ip else None
    if first is None:
        return "whois.ripe.net"
    octet = int(first)
    # AFRINIC /8s: 41, 102, 105, 154, 196, 197
    if octet in (41, 102, 105, 154, 196, 197):
        return "whois.afrinic.net"
    # LACNIC /8s: 177, 179, 181, 186, 187, 189, 190, 191, 200, 201
    if octet in (177, 179, 181, 186, 187, 189, 190, 191, 200, 201):
        return "whois.lacnic.net"
    if octet in (31, 37, 46, 51, 62, 77, 78, 79, 80) or octet in range(81, 96) or octet in range(134, 136) or octet in range(141, 142) or octet in range(145, 148) or octet in range(151, 152) or octet in range(176, 180) or octet in range(185, 186) or octet in range(193, 195) or octet in (212, 213, 217):
        return "whois.ripe.net"
    if octet in range(1, 3) or octet in range(36, 40) or octet in range(58, 61) or octet in range(101, 106) or octet in range(110, 127) or octet in range(202, 204):
        return "whois.apnic.net"
    if octet in range(3, 32) or octet in range(63, 65) or octet in range(96, 133) or octet in range(140, 143) or octet in range(162, 163) or octet in range(192, 199) or octet in range(204, 210):
        return "whois.arin.net"
    return "whois.arin.net"


def tls_certificate(host: str, sni: Optional[str] = None, port: int = 443,
                    timeout: float = 5.0) -> Optional[dict]:
    """Fetch and summarise the X.509 certificate served on :443.

    Tries a verified connection first (when an SNI hostname is known), then
    falls back to an unverified one. Certificate fields are parsed directly
    from the DER encoding, so results work even for bare-IP connections.
    """
    der = None
    verified = False
    attempts = []
    if sni:
        attempts.append((ssl.create_default_context(), sni, True))
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    attempts.append((insecure, host if not _is_ip(host) else None, False))

    for ctx, server_hostname, is_verified in attempts:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
                    der = tls.getpeercert(binary_form=True)
                    verified = is_verified
            if der:
                break
        except (OSError, ssl.SSLError, ValueError):
            continue
    if not der:
        return None

    import hashlib

    fields = _parse_cert_der(der) or {}
    return {
        "subject_cn": fields.get("subject_cn"),
        "organization": fields.get("organization"),
        "issuer": fields.get("issuer"),
        "issued_on": fields.get("issued_on"),
        "expires_on": fields.get("expires_on"),
        "sha1": hashlib.sha1(der).hexdigest(),
        "sha256": hashlib.sha256(der).hexdigest(),
        "verified": verified,
    }


# ------------------------------------------------------------- X.509 (DER)


def _der_read_tlv(data: bytes, off: int):
    """Read one DER TLV, returning (tag, content, next_offset)."""
    if off >= len(data):
        raise ValueError("truncated DER")
    tag = data[off]
    off += 1
    length = data[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, data[off:off + length], off + length


def _der_children(blob: bytes):
    """Iterate the TLV children of a constructed DER element."""
    out = []
    off = 0
    while off < len(blob):
        tag, content, off = _der_read_tlv(blob, off)
        out.append((tag, content))
    return out


# DER-encoded OIDs of interest (2.5.4.x)
_OID_CN = bytes.fromhex("550403")
_OID_O = bytes.fromhex("55040a")


def _der_name(blob: bytes) -> dict:
    fields = {}
    for _tag, rdn in _der_children(blob):
        for _t, atv in _der_children(rdn):
            kids = _der_children(atv)
            if len(kids) < 2:
                continue
            oid, value = kids[0][1], kids[1][1]
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if oid == _OID_CN:
                fields.setdefault("cn", text)
            elif oid == _OID_O:
                fields.setdefault("o", text)
    return fields


def _parse_cert_der(der: bytes) -> Optional[dict]:
    """Extract subject/issuer/validity straight from the DER certificate."""
    try:
        _tag, cert_body, _ = _der_read_tlv(der, 0)
        _tag, tbs, _ = _der_read_tlv(cert_body, 0)
        children = _der_children(tbs)
        # validity = first SEQUENCE whose children are two TIME values
        idx = None
        validity = None
        for i, (t, content) in enumerate(children):
            if t != 0x30:
                continue
            kids = _der_children(content)
            if (len(kids) >= 2 and kids[0][0] in (0x17, 0x18)
                    and kids[1][0] in (0x17, 0x18)):
                idx, validity = i, kids
                break
        if idx is None or idx == 0 or idx + 1 >= len(children):
            return None
        issuer = _der_name(children[idx - 1][1])
        subject = _der_name(children[idx + 1][1])
        fmt = lambda b: b.decode("ascii", "replace")
        return {
            "subject_cn": subject.get("cn"),
            "organization": subject.get("o"),
            "issuer": issuer.get("o") or issuer.get("cn"),
            "issued_on": fmt(validity[0][1]),
            "expires_on": fmt(validity[1][1]),
        }
    except (ValueError, IndexError):
        return None


def _is_windows() -> bool:
    import os

    return os.name == "nt"
