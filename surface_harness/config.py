"""Run configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

MODES = ("passive", "standard", "active")


@dataclass
class Config:
    seeds: list[str]
    org_names: list[str] = field(default_factory=list)
    # Non-domain scope: IP ranges (CIDRs like "203.0.113.0/24") and ASNs ("AS64500").
    # Networks are expanded to host IPs and seeded for DNS/PTR enrichment (+ port scan in active).
    networks: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    # Cap on host addresses enumerated from CIDRs/ASN prefixes (4096 == a single /20).
    # Raise it to deliberately expand larger ranges.
    max_network_hosts: int = 4096
    # passive : only third-party data sources + DNS resolution of discovered names
    # standard: + HTTP(S) probing of live hosts on 80/443 and TLS cert collection
    # active  : + DNS brute force and TCP port scanning (requires --authorized)
    mode: str = "standard"
    authorized: bool = False
    max_depth: int = 1  # how many hops away from the seeds to auto-expand
    expand_threshold: float = 0.7  # min confidence to treat a related domain as in scope
    max_apexes: int = 25  # hard cap on auto-expanded apex domains
    exclude: list[str] = field(default_factory=list)  # hosts/apexes never to touch
    out_dir: str = "runs"
    concurrency: int = 50
    http_timeout: float = 10.0
    dns_timeout: float = 4.0
    resolvers: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    wordlist: str | None = None
    tools: str = "auto"  # auto | local | docker | none
    docker_image: str = "surface-tools:latest"
    sources: list[str] | None = None  # None = all available
    company_intel: bool = True  # website identity + business-registry lookups
    pivot_subsidiaries: bool = False  # search CT logs for subsidiaries' names too
    verbose: bool = False
    engagement: str | None = None  # set when run from an engagement scope
    target_id: str | None = None

    # Optional API keys, read from the environment.
    keys: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for env, name in (
            ("SECURITYTRAILS_API_KEY", "securitytrails"),
            ("VIRUSTOTAL_API_KEY", "virustotal"),
            ("WHOISXML_API_KEY", "whoisxml"),
            ("OTX_API_KEY", "otx"),
            ("CERTSPOTTER_API_KEY", "certspotter"),
            ("OPENCORPORATES_API_TOKEN", "opencorporates"),
            ("SEC_USER_AGENT", "sec_user_agent"),
            ("SURFACE_CONTACT", "contact"),  # email/URL for Wikimedia + SEC User-Agent policies  # e.g. "Acme Security research@acme.example"
        ):
            if os.environ.get(env) and name not in self.keys:
                self.keys[name] = os.environ[env]

    @property
    def http_probe(self) -> bool:
        return self.mode in ("standard", "active")

    @property
    def active(self) -> bool:
        return self.mode == "active"


DEFAULT_PORTS = [
    # Remote-access / VPN / admin ports folded into the sorted list below:
    #   1194 OpenVPN(TCP), 1494 Citrix ICA, 1723 PPTP, 2598 Citrix CGP,
    #   3389 RDP, 4433 alt-HTTPS/admin, 5985/5986 WinRM, 8834 Nessus, 10443 SSL-VPN.
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1080, 1194, 1433, 1494, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
    2375, 2376, 2598, 3000, 3128, 3306, 3389, 4433, 4443, 4848, 5000, 5432, 5601,
    5672, 5900, 5985, 5986, 6379, 6443, 7001, 7443, 8000, 8008, 8080, 8081, 8088,
    8443, 8834, 8888, 9000, 9090, 9200, 9300, 9443, 10000, 10443, 11211, 15672,
    27017, 50000,
]
