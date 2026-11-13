"""Network-range scope: expand CIDRs and ASNs into host IPs to seed the surface.

Input CIDRs are expanded to host addresses (bounded by a hard cap so a stray /8
can't trigger a runaway scan). Input ASNs are turned into announced prefixes via
RIPEstat (passive HTTP JSON, no API key) and then expanded the same way. The seeded
IPs flow through the pipeline's existing IP enrichment (ASN/PTR) and, in active mode,
port scanning.
"""

from __future__ import annotations

import ipaddress
import re

from .sources import get_json

# 4096 host addresses == a single IPv4 /20. Anything larger is refused (truncated)
# unless the caller raises Config.max_network_hosts explicitly.
MAX_NETWORK_HOSTS = 4096

ASN_RE = re.compile(r"^AS\d+$")


def normalize_asn(asn: str) -> str | None:
    """'as64500' / '64500' / 'AS64500' -> 'AS64500'; None if not AS<number>."""
    s = str(asn).strip().upper()
    if s.isdigit():
        s = "AS" + s
    return s if ASN_RE.match(s) else None


def validate_networks(networks) -> list[str]:
    """Return canonical CIDR strings, raising ValueError on anything malformed."""
    out: list[str] = []
    for n in networks or []:
        raw = str(n).strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            raise ValueError(f"invalid CIDR '{n}': {e}") from e
        out.append(str(net))
    return out


def validate_asns(asns) -> list[str]:
    """Return canonical 'AS<number>' strings, raising ValueError on bad input."""
    out: list[str] = []
    for a in asns or []:
        na = normalize_asn(a)
        if not na:
            raise ValueError(f"invalid ASN '{a}' (expected AS<number>, e.g. AS64500)")
        out.append(na)
    return out


def expand_networks(cidrs, cap: int = MAX_NETWORK_HOSTS) -> tuple[list[str], list[str]]:
    """Enumerate host IPs for the given CIDRs, de-duplicated and capped at ``cap``
    total addresses. Returns (ips, notes) where notes explain any cap that was hit."""
    ips: list[str] = []
    notes: list[str] = []
    seen: set[str] = set()
    for cidr in cidrs or []:
        raw = str(cidr).strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            notes.append(f"skipped invalid CIDR '{raw}'")
            continue
        if net.num_addresses > cap:
            notes.append(
                f"{net} has {net.num_addresses} addresses (> cap of {cap}); only the first "
                f"available addresses up to the cap are enumerated")
        for addr in net.hosts():
            if len(seen) >= cap:
                notes.append(f"host-address cap of {cap} reached; remaining ranges not expanded")
                return ips, notes
            s = str(addr)
            if s not in seen:
                seen.add(s)
                ips.append(s)
    return ips, notes


def parse_ripe_prefixes(data: dict) -> list[str]:
    """Pull announced prefixes out of a RIPEstat announced-prefixes JSON document."""
    prefixes: list[str] = []
    for row in (data or {}).get("data", {}).get("prefixes", []):
        p = row.get("prefix")
        if p:
            prefixes.append(p)
    return prefixes


async def asn_prefixes(client, asn: str, log=None) -> list[str]:
    """Announced prefixes for an ASN via RIPEstat (passive, no API key)."""
    na = normalize_asn(asn)
    if not na:
        return []
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={na}"
    try:
        data = await get_json(client, url)
    except Exception as e:  # noqa: BLE001 - a failed lookup must not sink the run
        if log:
            log(f"[network] RIPEstat prefix lookup for {na} failed: {type(e).__name__}: {e}")
        return []
    return parse_ripe_prefixes(data)
