"""DNS-hygiene checks: zone transfer (AXFR), DNSSEC, CAA, and dangling delegation.

All lookups are standard DNS queries (AXFR included), so these run in every mode.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.query
import dns.zone

from .models import DnsHygiene, Finding

if TYPE_CHECKING:
    from .dns_ops import Dns

AXFR_TIMEOUT = 5.0


def _try_axfr(ns_ip: str, apex_name: str, timeout: float) -> int | None:
    """Attempt an AXFR against ``ns_ip``; return the record count on success, else None.

    A refused transfer (the normal, correctly-configured case) raises and yields None.
    """
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, apex_name, timeout=timeout, lifetime=timeout))
        return sum(len(node.rdatasets) for node in zone.nodes.values())
    except Exception:  # noqa: BLE001 - refused/failed transfer is expected; never a finding
        return None


async def audit_dns(dns_client: Dns, apex_name: str) -> tuple[DnsHygiene, list[Finding]]:
    """Audit DNS hygiene for ``apex_name``.

    Returns the structured :class:`DnsHygiene` record and the findings derived
    from it. Finding kinds: ``dns-axfr`` (high), ``dangling-ns`` (medium),
    ``dnssec-missing`` (info), ``caa-missing`` (info).
    """
    findings: list[Finding] = []
    nameservers = await dns_client.query(apex_name, "NS")
    record = DnsHygiene(domain=apex_name, nameservers=sorted(nameservers))

    # AXFR: try a zone transfer against the first address of each nameserver.
    for ns_name in nameservers:
        ips = await dns_client.query(ns_name, "A")
        if not ips:
            continue
        count = await asyncio.to_thread(_try_axfr, ips[0], apex_name, AXFR_TIMEOUT)
        if count is not None:
            record.axfr = True
            findings.append(Finding("high", "dns-axfr", apex_name,
                                    f"zone transfer (AXFR) allowed by {ns_name} ({ips[0]}); "
                                    f"{count} records exposed"))

    # Dangling delegation: a nameserver whose own name is NXDOMAIN is hijackable.
    for ns_name in nameservers:
        if await dns_client.exists(ns_name) == "nxdomain":
            record.dangling_ns.append(ns_name)
            findings.append(Finding("medium", "dangling-ns", apex_name,
                                    f"delegated nameserver {ns_name} does not resolve (NXDOMAIN); "
                                    "subdomain/zone-hijack risk"))

    dnskey, ds = await asyncio.gather(
        dns_client.query(apex_name, "DNSKEY"), dns_client.query(apex_name, "DS"))
    record.dnssec = bool(dnskey or ds)
    if not record.dnssec:
        findings.append(Finding("info", "dnssec-missing", apex_name,
                                "no DNSKEY/DS records; the zone is not DNSSEC-signed"))

    caa = await dns_client.query(apex_name, "CAA")
    record.caa = bool(caa)
    if not record.caa:
        findings.append(Finding("info", "caa-missing", apex_name,
                                "no CAA record; any certificate authority may issue for this domain"))

    return record, findings
