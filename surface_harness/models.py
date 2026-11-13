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
class EmailSecurity:
    """Structured email-authentication posture for one apex domain."""

    domain: str
    spf: str | None = None            # raw v=spf1 record, if exactly one is published
    spf_all: str | None = None        # the 'all' qualifier: +all | ~all | -all | ?all | None
    spf_lookups: int | None = None    # count of DNS-lookup mechanisms (RFC 7208 §4.6.4)
    spf_records: int = 0              # how many v=spf1 records exist (>1 is a PermError)
    dmarc: str | None = None          # raw _dmarc record
    dmarc_policy: str | None = None   # none | quarantine | reject | None (no/invalid record)
    dmarc_pct: int = 100
    dmarc_rua: bool = False           # an aggregate-report address is configured
    dkim_selectors: list[str] = field(default_factory=list)  # common selectors found
    mta_sts: bool = False
    tls_rpt: bool = False


@dataclass
class DnsHygiene:
    """Structured DNS-hygiene posture for one apex domain."""

    domain: str
    nameservers: list[str] = field(default_factory=list)
    axfr: bool = False                # a nameserver allowed a zone transfer
    dnssec: bool = False              # DNSKEY/DS present
    caa: bool = False                 # a CAA record is published
    dangling_ns: list[str] = field(default_factory=list)  # delegated NS that is NXDOMAIN


@dataclass
class TlsConfig:
    """Structured TLS-configuration posture for one host:port."""

    host: str
    port: int
    weak_protocols: list[str] = field(default_factory=list)  # e.g. ["SSLv3", "TLSv1.0"]
    hsts: bool | None = None          # None = HTTPS not reached / not checked
    not_after: str | None = None
    expires_in_days: int | None = None


@dataclass
class CloudAsset:
    """A public cloud storage bucket that was found to exist."""

    name: str
    provider: str  # s3 | gcs | azure
    url: str
    state: str     # public (listable) | private (exists, access denied)


@dataclass
class M365Tenant:
    """A Microsoft 365 / Entra tenant backing one domain."""

    domain: str
    tenant_id: str | None = None
    namespace: str | None = None          # Managed | Federated
    federation_host: str | None = None    # IdP host when federated (ADFS / third-party)
    federation_brand: str | None = None


@dataclass
class BreachExposure:
    """Aggregated breach exposure for one domain (counts only, never credentials)."""

    domain: str
    accounts: int = 0        # distinct exposed accounts on the domain
    breach_count: int = 0
    breaches: list[dict] = field(default_factory=list)  # [{name, year, accounts}]


@dataclass
class EmailFormat:
    """Inferred corporate email format for one domain (no addresses retained)."""

    domain: str
    format: str              # e.g. "{first}.{last}@acme.com"
    template: str            # e.g. "{first}.{last}"
    samples: int = 0
    considered: int = 0


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
    # Structured posture captured alongside the findings (same data, queryable fields).
    email_security: dict[str, EmailSecurity] = field(default_factory=dict)
    dns_hygiene: dict[str, DnsHygiene] = field(default_factory=dict)
    tls_config: list[TlsConfig] = field(default_factory=list)
    cloud_assets: list[CloudAsset] = field(default_factory=list)
    m365_tenants: list[M365Tenant] = field(default_factory=list)
    breaches: list[BreachExposure] = field(default_factory=list)
    email_formats: list[EmailFormat] = field(default_factory=list)
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
            "email_security": {k: norm(asdict(v)) for k, v in sorted(self.email_security.items())},
            "dns_hygiene": {k: norm(asdict(v)) for k, v in sorted(self.dns_hygiene.items())},
            "tls_config": [norm(asdict(t)) for t in self.tls_config],
            "cloud_assets": [norm(asdict(c)) for c in self.cloud_assets],
            "m365_tenants": [norm(asdict(m)) for m in self.m365_tenants],
            "breaches": [norm(asdict(b)) for b in self.breaches],
            "email_formats": [norm(asdict(e)) for e in self.email_formats],
            "log": self.log,
        }
