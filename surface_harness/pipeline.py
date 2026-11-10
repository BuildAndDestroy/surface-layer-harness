"""Orchestration.

  seeds ─► registrant data ─┐
                            ▼
   ┌──────────── round (repeats while new in-scope apexes appear, up to max_depth) ─┐
   │ passive subdomain enum (+ brute in active) ─► related-domain signals (CT, DNS,  │
   │ cert-org, reverse WHOIS) ─► RDAP verify ─► resolve ─► HTTP/TLS probe (redirects, │
   │ live cert SANs and O= feed back as new evidence / org names)                     │
   └───────────────────────────────────────────────────────────────────────────────┘
                            ▼
      IP enrichment (ASN/PTR) ─► takeover checks ─► port scan (active) ─► findings
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Callable

import httpx

from .company import Registries, candidate_names, site_identity
from .config import DEFAULT_PORTS, Config
from .dns_ops import Dns, load_wordlist
from .domains import apex, is_subdomain_of, normalize
from .models import ApexDomain, Finding, Host, IpInfo, Surface
from .ports import SHARED_EDGE_AS, nmap_services, scan
from .probe import http_probe, tls_grab
from .related import RelatedDiscovery
from .sources import UA, enumerate_passive
from .takeover import assess
from .tools import ToolRunner

SENSITIVE_PORTS = {
    23: ("high", "Telnet"), 445: ("high", "SMB"), 3389: ("medium", "RDP"), 5900: ("medium", "VNC"),
    2375: ("high", "Docker API (unauthenticated)"), 2376: ("medium", "Docker API (TLS)"),
    3306: ("high", "MySQL"), 5432: ("high", "PostgreSQL"), 1433: ("high", "MSSQL"),
    1521: ("high", "Oracle DB"), 6379: ("high", "Redis"), 27017: ("high", "MongoDB"),
    9200: ("high", "Elasticsearch"), 11211: ("high", "Memcached"), 5984: ("high", "CouchDB"),
    6443: ("medium", "Kubernetes API"), 10000: ("medium", "Webmin"), 21: ("low", "FTP"),
    5985: ("medium", "WinRM"), 5986: ("medium", "WinRM"), 15672: ("medium", "RabbitMQ mgmt"),
}
INTERESTING_TECH = {"Jenkins", "Grafana", "Kibana", "phpMyAdmin", "Swagger UI", "GitLab",
                    "Outlook Web App", "Citrix Gateway", "Palo Alto GlobalProtect", "Fortinet",
                    "Ivanti/Pulse VPN"}
NONPROD_RE = re.compile(r"(^|[.-])(dev|develop|staging|stage|stg|uat|qa|test|sandbox|preprod|internal)\d*([.-]|$)")
GENERIC_ORG_RE = re.compile(
    r"cloudflare|amazon|google|microsoft|akamai|fastly|let's encrypt|digicert|sectigo|"
    r"godaddy|automattic|shopify|github|heroku|salesforce|zendesk|wix|squarespace|hubspot|"
    r"incapsula|imperva|sucuri|vercel|netlify",
    re.I,
)
WEB_PORTS_TLS = {443, 4443, 7443, 8443, 9443}
WEB_PORTS_PLAIN = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}


class Pipeline:
    def __init__(self, cfg: Config, log: Callable[[str], None], checkpoint: Callable[[Surface], None]):
        self.cfg = cfg
        self._log = log
        self.checkpoint = checkpoint
        seeds = []
        for s in cfg.seeds:
            a = apex(s)
            if a and a not in seeds:
                seeds.append(a)
        if not seeds:
            raise ValueError("no valid seed domains")
        self.s = Surface(seeds=seeds, org_names=set(cfg.org_names))
        from . import __version__
        self.s.meta = {
            "harness_version": __version__,
            "engagement": cfg.engagement, "target_id": cfg.target_id,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "finished_at": None,
            "status": "running",
            "config": {"mode": cfg.mode, "depth": cfg.max_depth, "threshold": cfg.expand_threshold,
                       "max_apexes": cfg.max_apexes, "exclude": cfg.exclude, "org_names": cfg.org_names,
                       "sources": cfg.sources, "tools": cfg.tools,
                       "api_keys_present": sorted(k for k in cfg.keys if k != "contact")},
        }
        for sd in seeds:
            self.s.domains[sd] = ApexDomain(name=sd, seed=True, depth=0)
        self.runner = ToolRunner(cfg.tools, cfg.docker_image, log=self.log)
        self.dns = Dns(cfg)
        self.probed: set[str] = set()
        self.bodies: dict[str, list[str]] = {}
        self.sem = asyncio.Semaphore(cfg.concurrency)

    def log(self, msg: str) -> None:
        stamped = f"{time.strftime('%H:%M:%S')} {msg}"
        self.s.log.append(stamped)
        self._log(stamped)

    # -- helpers ----------------------------------------------------------------
    def excluded(self, name: str) -> bool:
        return any(name == x or name.endswith("." + x) for x in self.cfg.exclude)

    def in_scope_apex_of(self, host: str) -> ApexDomain | None:
        a = apex(host)
        d = self.s.domains.get(a) if a else None
        if d and d.confidence >= self.cfg.expand_threshold and not self.excluded(host):
            return d
        return None

    def add_hosts(self, names, source: str) -> int:
        n = 0
        for raw in names:
            h = normalize(raw)
            if not h or self.excluded(h):
                continue
            d = self.in_scope_apex_of(h)
            if not d:
                continue
            if h not in self.s.hosts:
                n += 1
            self.s.add_host(h, d.name, source)
        return n

    # -- stages ------------------------------------------------------------------
    async def enumerate_apex(self, d: ApexDomain, client: httpx.AsyncClient, rel: RelatedDiscovery) -> None:
        d.expanded = True
        self.log(f"[enum] {d.name} (depth {d.depth}, confidence {d.confidence})")
        self.s.add_host(d.name, d.name, "apex")
        results = await enumerate_passive(client, self.runner, d.name, self.cfg, self.log)
        for src, names in results.items():
            self.add_hosts(names, src)
        await asyncio.gather(rel.from_ct(d.name, d.depth), rel.from_dns(d.name, d.depth))
        if self.cfg.active:
            words = load_wordlist(self.cfg.wordlist)
            found = await self.dns.brute(d.name, words)
            self.log(f"[brute] {d.name}: {len(found)} names from {len(words)} words")
            self.add_hosts(found, "bruteforce")

    async def resolve_pending(self) -> None:
        pending = [h for h in self.s.hosts.values() if h.resolved is None]
        if not pending:
            return
        self.log(f"[dns] resolving {len(pending)} hosts")

        async def one(h: Host):
            r = await self.dns.resolve_host(h.name)
            h.a, h.aaaa, h.cnames = r["a"], r["aaaa"], r["cname"]
            h.resolved = bool(h.a or h.aaaa)
            if h.resolved and h.name != h.apex:
                wild = await self.dns.wildcard_ips(h.apex)
                h.wildcard = bool(wild) and set(h.a) <= wild and "bruteforce" not in h.sources
            for ip in h.a + h.aaaa:
                self.s.ips.setdefault(ip, IpInfo(ip=ip)).hosts.add(h.name)

        await asyncio.gather(*(one(h) for h in pending))
        live = sum(1 for h in pending if h.resolved)
        self.log(f"[dns] {live}/{len(pending)} resolve")

    async def probe_pending(self, client: httpx.AsyncClient, rel: RelatedDiscovery) -> None:
        todo = [h for h in self.s.hosts.values()
                if h.resolved and not h.wildcard and h.name not in self.probed]
        if not todo:
            return
        self.log(f"[http] probing {len(todo)} hosts")

        async def one(h: Host):
            self.probed.add(h.name)
            async with self.sem:
                tls = await tls_grab(h.name, 443, timeout=self.cfg.http_timeout)
                if tls.error is None or tls.subject:
                    h.tls.append(tls)
                for scheme in ("https", "http"):
                    svc, body = await http_probe(client, f"{scheme}://{h.name}/")
                    if svc.error and scheme == "https" and not tls.subject:
                        continue  # nothing on 443; try plain http
                    h.http.append(svc)
                    if body:
                        self.bodies.setdefault(h.name, []).append(body)
                    if svc.status is not None:
                        break
            depth = self.s.domains[h.apex].depth
            for svc in h.http:
                if svc.final_url:
                    rel.from_redirect(h.name, svc.final_url, depth)
                    final = normalize(svc.final_url)
                    if final:
                        self.add_hosts([final], "redirect")
            for body in self.bodies.get(h.name, []):
                rel.from_links(h.name, body, depth)
            for t in h.tls:
                rel.from_live_cert(h.name, t.sans, depth)
                self.add_hosts(t.sans, "tls-san")
                org = t.subject.get("O")
                if t.valid and org and not GENERIC_ORG_RE.search(org) and h.apex in self.s.seeds:
                    if org not in self.s.org_names:
                        self.log(f"[org] learned organisation name from TLS cert: '{org}'")
                    self.s.org_names.add(org)

        await asyncio.gather(*(one(h) for h in todo))

    async def company_intel(self, src_client: httpx.AsyncClient, probe_client: httpx.AsyncClient,
                            rel: RelatedDiscovery) -> None:
        """Identify the legal entity behind the seeds and feed what we learn back into
        related-domain discovery (org names for CT search, official/subsidiary websites)."""
        cfg = self.cfg
        idents = []
        if cfg.http_probe:  # fetching the target's own pages is not passive
            idents = list(await asyncio.gather(
                *(site_identity(probe_client, d, rel.seed_stems, self.log) for d in self.s.seeds)))
            for ident in idents:
                self.s.site_identity[ident.domain] = ident
                for e in sorted(ident.emails):
                    rel.add_candidate(e.split("@", 1)[1], "site-contact",
                                      f"contact email {e} published on {ident.domain}", 1)
                for s in sorted(ident.same_as):
                    rel.add_candidate(s, "site-sameas", f"schema.org sameAs on {ident.domain}: {s}", 1)
                for n in ident.legal_names:
                    self.s.org_names.add(n)

        names = candidate_names(cfg.org_names, sorted(self.s.org_names), idents)
        self.log(f"[company] registry lookups for: {names or '(no names; Wikidata by domain only)'}")
        records = await Registries(cfg, src_client, self.log).lookup(names, self.s.seeds)
        self.s.companies = records

        for c in records:
            if c.source != "wikidata":
                self.s.org_names.add(c.name)
                if c.source in ("gleif", "sec"):
                    self.s.org_names.update(c.former_names[:3])
            for w in c.websites:
                rel.add_candidate(w, "corp-website", f"official website of {c.name} ({c.source})", 1)
            for key, signal, label in (("subsidiary_sites", "corp-subsidiary", "subsidiary"),
                                       ("parent_sites", "corp-parent", "parent/owner")):
                for ent, sites in json.loads(c.identifiers.get(key, "{}")).items():
                    for site in sites:
                        rel.add_candidate(site, signal, f"website of {label} '{ent}' (wikidata)", 1)
            if cfg.pivot_subsidiaries:
                for sub in c.subsidiaries[:20]:
                    self.s.org_names.add(sub)
            if c.agent_commercial:
                self.log(f"[company] {c.name} ({c.source}): registered agent '{c.agent_name}' is a "
                         f"commercial agent service - recorded, not pivoted on")
        self.log(f"[company] {len(records)} entity record(s); org names now: {sorted(self.s.org_names)}")

    async def enrich_ips(self) -> None:
        ips = [i for i in self.s.ips.values() if i.asn is None]
        self.log(f"[ip] enriching {len(ips)} IPs (ASN/PTR)")

        async def one(info: IpInfo):
            a, p = await asyncio.gather(self.dns.asn(info.ip), self.dns.ptr(info.ip))
            info.asn, info.prefix = a.get("asn"), a.get("prefix")
            info.country, info.as_name = a.get("country"), a.get("as_name")
            info.ptr = p

        await asyncio.gather(*(one(i) for i in ips))
        # Organisation-owned network ranges are a strong pointer to more assets.
        org_tokens = {t.lower() for o in self.s.org_names for t in re.findall(r"[A-Za-z]{4,}", o)}
        org_tokens |= {d.split(".")[0] for d in self.s.seeds if len(d.split(".")[0]) >= 4}
        org_tokens -= {"corp", "corporation", "limited", "group", "holdings", "company", "global",
                       "international", "technologies", "services", "solutions"}
        seen = set()
        for info in self.s.ips.values():
            if info.as_name and info.asn not in seen and any(t in info.as_name.lower() for t in org_tokens):
                seen.add(info.asn)
                self.s.findings.append(Finding(
                    "info", "org-asn", f"AS{info.asn}",
                    f"{info.as_name} ({info.prefix}) looks organisation-owned; review its prefixes "
                    f"for additional hosts"))

    async def takeovers(self) -> None:
        cands = [h for h in self.s.hosts.values() if h.cnames]
        if not cands:
            return
        self.log(f"[takeover] checking {len(cands)} CNAME chains")

        async def one(h: Host):
            status = await self.dns.exists(h.cnames[-1])
            f = assess(h, status, self.bodies.get(h.name, []))
            if f:
                self.s.findings.append(f)

        await asyncio.gather(*(one(h) for h in cands))

    async def port_scan(self, client: httpx.AsyncClient) -> None:
        targets = sorted(ip for ip, info in self.s.ips.items()
                         if not (info.as_name and SHARED_EDGE_AS.search(info.as_name)))
        skipped = len(self.s.ips) - len(targets)
        if skipped:
            self.log(f"[ports] skipping {skipped} IPs on shared CDN/WAF networks")
        open_ports = await scan(self.runner, targets, self.cfg.ports or DEFAULT_PORTS,
                                self.cfg.concurrency * 4, self.log)
        services = await nmap_services(self.runner, open_ports, self.log)
        for ip, ports in open_ports.items():
            info = self.s.ips[ip]
            info.open_ports = sorted(set(info.open_ports) | set(ports))
            info.services = [{"port": p, **services[ip][p]} for p in sorted(services.get(ip, {}))]
            for hname in self.s.ips[ip].hosts:
                h = self.s.hosts[hname]
                h.open_ports = sorted(set(h.open_ports) | set(ports))
            for p in ports:
                if p in SENSITIVE_PORTS:
                    sev, label = SENSITIVE_PORTS[p]
                    svc = (services.get(ip, {}).get(p) or {}).get("summary", "")
                    hosts = ", ".join(sorted(self.s.ips[ip].hosts)[:3])
                    self.s.findings.append(Finding(sev, "exposed-service", f"{ip}:{p}",
                                                   f"{label} reachable from the internet "
                                                   f"({hosts}) {svc}".strip()))
        # HTTP on non-standard web ports
        extra = []
        for h in self.s.hosts.values():
            for p in h.open_ports:
                if p in WEB_PORTS_TLS - {443}:
                    extra.append((h, f"https://{h.name}:{p}/"))
                elif p in WEB_PORTS_PLAIN - {80}:
                    extra.append((h, f"http://{h.name}:{p}/"))

        async def one(h: Host, url: str):
            async with self.sem:
                svc, body = await http_probe(client, url)
            if svc.status is not None:
                h.http.append(svc)
                if body:
                    self.bodies.setdefault(h.name, []).append(body)

        if extra:
            self.log(f"[http] probing {len(extra)} non-standard web ports")
            await asyncio.gather(*(one(h, u) for h, u in extra))

    def derive_findings(self) -> None:
        for h in self.s.hosts.values():
            for svc in h.http:
                hits = INTERESTING_TECH.intersection(svc.tech)
                if hits and svc.status:
                    self.s.findings.append(Finding("low", "exposed-interface", svc.url,
                                                   f"{', '.join(sorted(hits))} exposed (HTTP {svc.status})"))
            for t in h.tls:
                if t.subject and not t.valid:
                    self.s.findings.append(Finding("low", "tls-invalid", f"{h.name}:{t.port}",
                                                   f"certificate fails validation: {t.error}"))
            if h.resolved and not h.wildcard and NONPROD_RE.search(h.name) and any(
                    s.status and s.status < 500 for s in h.http):
                self.s.findings.append(Finding("info", "non-production", h.name,
                                               "non-production environment reachable from the internet"))
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.s.findings.sort(key=lambda f: (order.get(f.severity, 9), f.kind, f.target))

    # -- main loop ------------------------------------------------------------------
    async def run(self) -> Surface:
        cfg = self.cfg
        self.log(f"[run] seeds={self.s.seeds} mode={cfg.mode} depth={cfg.max_depth} "
                 f"threshold={cfg.expand_threshold}")
        for t in ("subfinder", "naabu", "nmap"):
            backend = self.runner.backend(t) if cfg.tools != "none" else None
            self.log(f"[tools] {t}: {backend or 'unavailable (built-in fallback)'}")

        src_client = httpx.AsyncClient(headers={"User-Agent": UA}, timeout=60, follow_redirects=True)
        probe_client = httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=cfg.http_timeout,
            limits=httpx.Limits(max_connections=cfg.concurrency, max_keepalive_connections=0),
        )
        try:
            rel = RelatedDiscovery(self.s, cfg, src_client, self.dns, self.log)
            await rel.load_seed_registrants()
            if cfg.company_intel:
                await self.company_intel(src_client, probe_client, rel)
                self.checkpoint(self.s)
            if self.s.org_names:
                self.log(f"[org] organisation names: {sorted(self.s.org_names)}")

            expanded_count = 0
            for rnd in range(cfg.max_depth + 1):
                targets = [d for d in self.s.domains.values()
                           if not d.expanded and d.depth <= cfg.max_depth
                           and d.confidence >= cfg.expand_threshold and not self.excluded(d.name)]
                room = cfg.max_apexes - expanded_count
                if not targets or room <= 0:
                    break
                targets = sorted(targets, key=lambda d: (-d.confidence, d.name))[:room]
                expanded_count += len(targets)
                self.log(f"[round {rnd}] expanding {len(targets)} apex domain(s): "
                         f"{', '.join(d.name for d in targets)}")
                enum_sem = asyncio.Semaphore(3)

                async def enum(d: ApexDomain):
                    async with enum_sem:
                        await self.enumerate_apex(d, src_client, rel)

                await asyncio.gather(*(enum(d) for d in targets))

                for org in sorted(self.s.org_names):
                    await rel.from_cert_org(org, 0)
                    await rel.reverse_whois(org, 0)
                for email in sorted(rel.seed_registrants["email"]):
                    await rel.reverse_whois(email, 0)
                await rel.verify_by_registrant()

                await self.resolve_pending()
                if cfg.http_probe:
                    await self.probe_pending(probe_client, rel)
                    await self.resolve_pending()  # hosts learned from redirects / SANs
                    await self.probe_pending(probe_client, rel)
                self.checkpoint(self.s)

            # Hosts discovered after the last round for apexes that became in-scope late.
            for h in list(self.s.hosts.values()):
                if not is_subdomain_of(h.name, h.apex):
                    del self.s.hosts[h.name]

            await self.enrich_ips()
            await self.takeovers()
            if cfg.active:
                await self.port_scan(probe_client)
            self.derive_findings()
            self.checkpoint(self.s)
        finally:
            await src_client.aclose()
            await probe_client.aclose()
        self.s.meta.update(finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"), status="complete")
        self.log(f"[done] {len(self.s.in_scope_apexes(cfg.expand_threshold))} in-scope apex domains, "
                 f"{len(self.s.hosts)} hosts, {len(self.s.ips)} IPs, {len(self.s.findings)} findings")
        return self.s
