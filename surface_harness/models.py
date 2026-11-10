"""Core data model: everything discovered during a run lives in a Surface."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

RUN_SCHEMA_VERSION = "1.0"


@dataclass
class Evidence:
    """Why we believe a domain belongs to the target organisation."""

    signal: str  # e.g. "cert-san", "whois-org", "redirect"
    detail: str
    weight: float  # 0..1, independent probability-ish contribution


@dataclass
class ApexDomain:
    """A registrable domain (e.g. acme.com) that may belong to the target."""

    name: str
    seed: bool = False
    depth: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    whois: dict[str, Any] = field(default_factory=dict)
    expanded: bool = False  # subdomain enumeration was run against it

    @property
    def confidence(self) -> float:
        if self.seed:
            return 1.0
        # One contribution per signal type (its strongest instance), so e.g. ten
        # pages linking to a domain don't add up to "certainly ours".
        best: dict[str, float] = {}
        for e in self.evidence:
            best[e.signal] = max(best.get(e.signal, 0.0), max(0.0, min(1.0, e.weight)))
        miss = 1.0
        for w in best.values():
            miss *= 1.0 - w
        return round(1.0 - miss, 3)

    def add_evidence(self, signal: str, detail: str, weight: float) -> None:
        if any(e.signal == signal and e.detail == detail for e in self.evidence):
            return
        self.evidence.append(Evidence(signal, detail, weight))


@dataclass
class HttpService:
    url: str
    status: int | None = None
    final_url: str | None = None
    title: str | None = None
    server: str | None = None
    content_length: int | None = None
    tech: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class TlsInfo:
    port: int
    valid: bool
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    sans: list[str] = field(default_factory=list)
    not_after: str | None = None
    error: str | None = None


@dataclass
class Host:
    name: str
    apex: str
    sources: set[str] = field(default_factory=set)
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    resolved: bool | None = None  # None = not attempted
    wildcard: bool = False
    open_ports: list[int] = field(default_factory=list)
    http: list[HttpService] = field(default_factory=list)
    tls: list[TlsInfo] = field(default_factory=list)


@dataclass
class IpInfo:
    ip: str
    asn: str | None = None
    prefix: str | None = None
    country: str | None = None
    as_name: str | None = None
    ptr: str | None = None
    hosts: set[str] = field(default_factory=set)
    open_ports: list[int] = field(default_factory=list)
    # nmap -sV results, one dict per open port: {port, protocol, service, product, version, extra_info,
    # tunnel, os_type, cpe, method ("probed" = fingerprint match, "table" = guessed from port), conf, summary}
    services: list[dict] = field(default_factory=list)


@dataclass
class Finding:
    severity: str  # info | low | medium | high
    kind: str
    target: str
    detail: str


@dataclass
class Officer:
    name: str
    role: str = ""


@dataclass
class CompanyRecord:
    """A legal-entity record from a business registry or entity database."""

    source: str  # gleif | opencorporates | us-co | us-ny | us-or | sec | wikidata
    name: str
    match: str = "name"  # how it was tied to the target: name | domain | lei-relationship
    jurisdiction: str | None = None
    company_number: str | None = None
    status: str | None = None
    entity_type: str | None = None
    formed: str | None = None
    registered_address: str | None = None
    principal_address: str | None = None
    mailing_address: str | None = None
    agent_name: str | None = None
    agent_address: str | None = None
    agent_commercial: bool = False  # a registered-agent service, not the company itself
    address_notes: list[str] = field(default_factory=list)
    officers: list[Officer] = field(default_factory=list)
    identifiers: dict[str, str] = field(default_factory=dict)  # lei, cik, ein, wikidata, ...
    former_names: list[str] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    subsidiaries: list[str] = field(default_factory=list)
    websites: list[str] = field(default_factory=list)
    industry: str | None = None
    url: str | None = None  # link to the source record


@dataclass
class SiteIdentity:
    """What the organisation says about itself on its own website."""

    domain: str
    display_names: set[str] = field(default_factory=set)
    legal_names: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    addresses: set[str] = field(default_factory=set)
    same_as: set[str] = field(default_factory=set)
    security_txt: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)


@dataclass
class Surface:
    seeds: list[str]
    org_names: set[str] = field(default_factory=set)
    companies: list[CompanyRecord] = field(default_factory=list)
    site_identity: dict[str, SiteIdentity] = field(default_factory=dict)
    domains: dict[str, ApexDomain] = field(default_factory=dict)
    hosts: dict[str, Host] = field(default_factory=dict)
    ips: dict[str, IpInfo] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    # -- helpers -----------------------------------------------------------
    def in_scope_apexes(self, threshold: float) -> list[ApexDomain]:
        return [d for d in self.domains.values() if d.confidence >= threshold]

    def add_host(self, name: str, apex: str, source: str) -> Host:
        h = self.hosts.get(name)
        if h is None:
            h = self.hosts[name] = Host(name=name, apex=apex)
        h.sources.add(source)
        return h

    def to_dict(self) -> dict[str, Any]:
        def norm(o: Any) -> Any:
            if isinstance(o, set):
                return sorted(o)
            if isinstance(o, dict):
                return {k: norm(v) for k, v in o.items()}
            if isinstance(o, list):
                return [norm(v) for v in o]
            return o

        return {
            "schema": "surface-harness/run",
            "schema_version": RUN_SCHEMA_VERSION,
            "meta": self.meta,
            "seeds": self.seeds,
            "org_names": sorted(self.org_names),
            "companies": [norm(asdict(c)) for c in self.companies],
            "site_identity": {k: norm(asdict(v)) for k, v in sorted(self.site_identity.items())},
            "domains": {
                k: {**norm(asdict(v)), "confidence": v.confidence}
                for k, v in sorted(self.domains.items())
            },
            "hosts": {k: norm(asdict(v)) for k, v in sorted(self.hosts.items())},
            "ips": {k: norm(asdict(v)) for k, v in sorted(self.ips.items())},
            "findings": [asdict(f) for f in self.findings],
            "log": self.log,
        }
