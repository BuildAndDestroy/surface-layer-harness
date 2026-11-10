"""DNS operations: resolution, wildcard detection, brute force, record lookups,
and IP->ASN enrichment via Team Cymru's DNS interface."""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
from importlib import resources

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from .config import Config


class Dns:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.r = dns.asyncresolver.Resolver(configure=not cfg.resolvers)
        if cfg.resolvers:
            self.r.nameservers = cfg.resolvers
        self.r.timeout = cfg.dns_timeout
        self.r.lifetime = cfg.dns_timeout * 2
        self.sem = asyncio.Semaphore(cfg.concurrency * 2)
        self._wildcards: dict[str, set[str]] = {}

    async def query(self, name: str, rtype: str) -> list[str]:
        async with self.sem:
            try:
                ans = await self.r.resolve(name, rtype, raise_on_no_answer=False)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout,
                    dns.resolver.NoAnswer, dns.name.EmptyLabel, dns.name.LabelTooLong):
                return []
            except Exception:  # noqa: BLE001
                return []
            if ans.rrset is None:
                return []
            return [r.to_text().strip('"').rstrip(".") if rtype != "TXT" else
                    "".join(s.decode(errors="replace") for s in r.strings)
                    for r in ans.rrset]

    async def exists(self, name: str) -> str:
        """'nxdomain' | 'exists' | 'error' — used for dangling-CNAME checks."""
        async with self.sem:
            try:
                await self.r.resolve(name, "A")
                return "exists"
            except dns.resolver.NXDOMAIN:
                return "nxdomain"
            except dns.resolver.NoAnswer:
                return "exists"
            except Exception:  # noqa: BLE001
                return "error"

    async def resolve_host(self, name: str) -> dict[str, list[str]]:
        """Follow CNAME chain and return A/AAAA/CNAME."""
        cnames: list[str] = []
        cur = name
        for _ in range(8):
            c = await self.query(cur, "CNAME")
            if not c:
                break
            cur = c[0].lower()
            cnames.append(cur)
        a, aaaa = await asyncio.gather(self.query(name, "A"), self.query(name, "AAAA"))
        return {"a": sorted(set(a)), "aaaa": sorted(set(aaaa)), "cname": cnames}

    async def wildcard_ips(self, zone: str) -> set[str]:
        """IPs returned for random labels under ``zone`` (empty = no wildcard)."""
        if zone not in self._wildcards:
            ips: set[str] = set()
            for _ in range(2):
                probe = f"{secrets.token_hex(8)}.{zone}"
                ips |= set(await self.query(probe, "A"))
            self._wildcards[zone] = ips
        return self._wildcards[zone]

    async def brute(self, apex_name: str, words: list[str]) -> set[str]:
        wild = await self.wildcard_ips(apex_name)
        found: set[str] = set()

        async def one(w: str):
            name = f"{w}.{apex_name}"
            ips = await self.query(name, "A")
            if ips and not (wild and set(ips) <= wild):
                found.add(name)

        await asyncio.gather(*(one(w) for w in words))
        return found

    # -- enrichment ----------------------------------------------------------
    async def ptr(self, ip: str) -> str | None:
        res = await self.query(dns.reversename.from_address(ip).to_text(), "PTR")
        return res[0].lower() if res else None

    async def asn(self, ip: str) -> dict[str, str | None]:
        """Team Cymru IP->ASN via DNS (no API key, no rate-limited HTTP API)."""
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:
            nibbles = addr.exploded.replace(":", "")
            q = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
        txt = await self.query(q, "TXT")
        if not txt:
            return {}
        parts = [p.strip() for p in txt[0].split("|")]
        asn = parts[0].split()[0] if parts and parts[0] else None
        info: dict[str, str | None] = {
            "asn": asn,
            "prefix": parts[1] if len(parts) > 1 else None,
            "country": parts[2] if len(parts) > 2 else None,
        }
        if asn:
            name_txt = await self.query(f"AS{asn}.asn.cymru.com", "TXT")
            if name_txt:
                np = [p.strip() for p in name_txt[0].split("|")]
                info["as_name"] = np[-1] if np else None
        return info


def load_wordlist(path: str | None) -> list[str]:
    if path:
        with open(path) as fh:
            text = fh.read()
    else:
        text = resources.files("surface_harness.data").joinpath("subdomains.txt").read_text()
    return [w.strip().lower() for w in text.splitlines() if w.strip() and not w.startswith("#")]
