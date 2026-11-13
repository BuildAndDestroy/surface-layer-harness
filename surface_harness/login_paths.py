"""Probe a small, fixed set of well-known remote-access login paths.

For hosts that already answered on 80/443 we additionally GET a handful of
standard gateway/VPN login pages and fingerprint the response. This is a plain
GET of published login pages for product identification only: it is NOT fuzzing,
NOT a credential attempt and NOT path brute forcing. The list is constant and
short, and every request is gated through the caller's semaphore.

Standard/active mode only (the caller gates on ``cfg.http_probe``).
"""

from __future__ import annotations

import asyncio
import re

import httpx

from .models import Finding, Host
from .probe import http_probe

# (path, product label, body/response marker). Markers are product-specific so a
# generic 404 page does not trip them. Matched case-insensitively against the body.
LOGIN_PATHS: list[tuple[str, str, str]] = [
    ("/remote/login", "Fortinet FortiGate SSL-VPN",
     r"fgt_lang|FortiGate|forticlient|sslvpn"),
    ("/vpn/index.html", "Citrix/NetScaler Gateway",
     r"Citrix Gateway|NetScaler|_ctxs|citrix"),
    ("/RDWeb/", "Microsoft RD Web Access",
     r"RD Web Access|RDWeb|Remote Desktop Services"),
    ("/+CSCOE+/logon.html", "Cisco ASA/AnyConnect",
     r"SSL VPN Service|webvpn|AnyConnect|Cisco Systems"),
    ("/adfs/ls/", "Microsoft ADFS",
     r"AD FS|Federation Service|SAMLRequest|MSISSamlRequest"),
    ("/owa/", "Microsoft Outlook Web App",
     r"Outlook Web App|Outlook on the web|owa/auth|X-OWA-Version"),
    ("/ecp/", "Microsoft Exchange ECP",
     r"Exchange Admin Center|Microsoft Exchange"),
    ("/global-protect/login.esp", "Palo Alto GlobalProtect",
     r"GlobalProtect|Palo Alto"),
]


def _base_scheme(h: Host) -> str | None:
    """Scheme of the host's first responsive probe, preferring https."""
    schemes = {svc.url.split("://", 1)[0] for svc in h.http if svc.status is not None}
    if "https" in schemes:
        return "https"
    if "http" in schemes:
        return "http"
    return None


async def scan_login_paths(client: httpx.AsyncClient, hosts: list[Host],
                           sem: asyncio.Semaphore, log) -> list[Finding]:
    """GET each known login path on responsive web hosts; fingerprint the reply."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # (host, label) de-dup

    async def one(h: Host, scheme: str, path: str, label: str, marker: re.Pattern[str]) -> None:
        url = f"{scheme}://{h.name}{path}"
        async with sem:
            svc, body = await http_probe(client, url)
        # A served login page returns a non-404 status; the marker confirms the product.
        if svc.status is None or svc.status in (400, 404):
            return
        if marker.search(body) or label.split()[0] in svc.tech:
            key = (h.name, label)
            if key in seen:
                return
            seen.add(key)
            findings.append(Finding(
                "low", "exposed-interface", svc.final_url or url,
                f"{label} login page reachable (HTTP {svc.status})"))

    tasks = []
    compiled = [(p, lbl, re.compile(mk, re.I)) for p, lbl, mk in LOGIN_PATHS]
    for h in hosts:
        scheme = _base_scheme(h)
        if not scheme:
            continue
        for path, label, marker in compiled:
            tasks.append(one(h, scheme, path, label, marker))
    if not tasks:
        return findings
    log(f"[login] probing {len(LOGIN_PATHS)} known login paths on {len(hosts)} web host(s)")
    await asyncio.gather(*tasks)
    if findings:
        log(f"[login] {len(findings)} remote-access login page(s) identified")
    return findings
