"""TCP port discovery (active mode only).

Uses naabu (local or Docker) when available, otherwise a built-in asyncio
connect() scanner. IPs belonging to shared CDN/WAF networks are skipped:
scanning them maps the provider, not the target.
"""

from __future__ import annotations

import asyncio
import json
import re

from .tools import ToolRunner

SHARED_EDGE_AS = re.compile(
    r"cloudflare|akamai|fastly|incapsula|imperva|sucuri|stackpath|edgecast|cdn77|"
    r"limelight|edgio|bunny|cdnetworks|zscaler",
    re.I,
)


async def _connect(ip: str, port: int, timeout: float) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


async def builtin_scan(ips: list[str], ports: list[int], concurrency: int,
                       timeout: float = 2.0) -> dict[str, list[int]]:
    sem = asyncio.Semaphore(concurrency)
    found: dict[str, list[int]] = {ip: [] for ip in ips}

    async def one(ip: str, port: int):
        async with sem:
            if await _connect(ip, port, timeout):
                found[ip].append(port)

    await asyncio.gather(*(one(ip, p) for ip in ips for p in ports))
    return {ip: sorted(p) for ip, p in found.items() if p}


async def naabu_scan(runner: ToolRunner, ips: list[str], ports: list[int]) -> dict[str, list[int]]:
    res = await runner.run(
        "naabu",
        ["-list", "{input}", "-p", ",".join(map(str, ports)), "-json", "-silent",
         "-rate", "500", "-retries", "1"],
        stdin_lines=ips, timeout=3600, net_admin=True,
    )
    if not res.ok and not res.stdout:
        raise RuntimeError(res.stderr.strip()[-200:])
    found: dict[str, set[int]] = {}
    for line in res.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = row.get("ip") or row.get("host")
        if ip and row.get("port"):
            port = row["port"]["Port"] if isinstance(row["port"], dict) else int(row["port"])
            found.setdefault(ip, set()).add(port)
    return {ip: sorted(p) for ip, p in found.items()}


async def scan(runner: ToolRunner, ips: list[str], ports: list[int], concurrency: int, log) -> dict[str, list[int]]:
    if not ips:
        return {}
    if runner.available("naabu"):
        try:
            log(f"[ports] naabu ({runner.backend('naabu')}) on {len(ips)} IPs x {len(ports)} ports")
            return await naabu_scan(runner, ips, ports)
        except Exception as e:  # noqa: BLE001
            log(f"[ports] naabu failed ({e}); falling back to built-in scanner")
    log(f"[ports] built-in connect scan on {len(ips)} IPs x {len(ports)} ports")
    return await builtin_scan(ips, ports, concurrency)


async def nmap_services(runner: ToolRunner, targets: dict[str, list[int]], log) -> dict[str, dict[int, dict]]:
    """Service/version detection on already-open ports (much cheaper than a full -sV).

    Returns {ip: {port: {service, product, version, extra_info, tunnel, cpe, method, conf, summary}}}.
    `method` is "probed" when nmap matched a fingerprint, "table" when it only guessed from the port.
    """
    if not runner.available("nmap") or not targets:
        return {}
    all_ports = sorted({p for ps in targets.values() for p in ps})
    log(f"[ports] nmap -sV ({runner.backend('nmap')}) on {len(targets)} IPs")
    res = await runner.run(
        "nmap",
        ["-Pn", "-sV", "--version-light", "-T4", "-oX", "-", "-p", ",".join(map(str, all_ports)),
         "-iL", "{input}"],
        stdin_lines=list(targets), timeout=3600,
    )
    out = parse_nmap_xml(res.stdout)
    if not out:
        log(f"[ports] nmap returned no service data ({(res.stderr or '').strip()[-120:] or 'no output'})")
    # only keep ports the discovery scan reported, per IP (nmap scanned the union of ports)
    return {ip: {p: v for p, v in svcs.items() if p in targets.get(ip, [])} for ip, svcs in out.items()}


def parse_nmap_xml(xml: str) -> dict[str, dict[int, dict]]:
    import xml.etree.ElementTree as ET

    start = xml.find("<?xml")
    if start < 0:
        start = xml.find("<nmaprun")
    if start < 0:
        return {}
    try:
        root = ET.fromstring(xml[start:])
    except ET.ParseError:
        return {}
    out: dict[str, dict[int, dict]] = {}
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            a = svc.attrib if svc is not None else {}
            rec = {
                "protocol": port.get("protocol", "tcp"),
                "service": a.get("name"),
                "product": a.get("product"),
                "version": a.get("version"),
                "extra_info": a.get("extrainfo"),
                "tunnel": a.get("tunnel"),
                "os_type": a.get("ostype"),
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
                "method": a.get("method"),
                "conf": int(a["conf"]) if a.get("conf", "").isdigit() else None,
            }
            name = ("ssl/" if rec["tunnel"] == "ssl" else "") + (rec["service"] or "unknown")
            rec["summary"] = " ".join(x for x in (name, rec["product"], rec["version"],
                                                  f"({rec['extra_info']})" if rec["extra_info"] else None) if x)
            out.setdefault(addr, {})[int(port.get("portid"))] = rec
    return out
