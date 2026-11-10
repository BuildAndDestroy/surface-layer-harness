"""Related-domain discovery: find *other* registrable domains owned by the same org.

Every candidate accumulates weighted Evidence; ApexDomain.confidence combines it
as 1 - prod(1 - w). Only candidates above Config.expand_threshold are treated as
in scope and get their own subdomain enumeration. Everything else is reported as
"needs review" so a human makes the scope call.

Signals (weights are deliberately conservative):
  cert-san        0.50  shares a TLS certificate (CT logs or live cert) with an in-scope domain
  cert-org        0.60  CT-logged cert whose Subject O= matches the org name
  rdap-org        0.60  RDAP/WHOIS registrant organisation matches a seed's
  rdap-email      0.70  RDAP/WHOIS registrant email matches a seed's
  reverse-whois   0.60  returned by reverse WHOIS on org name/email (WHOISXML_API_KEY)
  redirect        0.60  an in-scope web host redirects to it
  brand           0.40  apex label matches/contains the seed brand stem
  dns-ns          0.25  authoritative NS for an in-scope domain (self-hosted DNS)
  dns-mail        0.15  MX / SPF include / DMARC rua of an in-scope domain
  html-link       0.15  linked from an in-scope homepage
  corp-website    0.80  official website of the matched legal entity (Wikidata / SEC)
  corp-subsidiary 0.60  website of a subsidiary of the matched entity (Wikidata)
  corp-parent     0.50  website of the parent / owner of the matched entity (Wikidata)
  site-sameas     0.60  listed in the seed site's schema.org Organization sameAs
  site-contact    0.45  domain of a contact email published on the seed site

Registered-agent names/addresses and privacy-proxy registrants are never used as signals.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter

import httpx

from .company import is_commercial_agent, same_entity
from .config import Config
from .dns_ops import Dns
from .domains import apex, brand_stem, is_third_party, normalize, stem_similarity
from .models import ApexDomain, Surface
from .sources import crtsh_records, get_json

WEIGHTS = {
    "cert-san": 0.50,
    "cert-org": 0.60,
    "rdap-org": 0.60,
    "rdap-email": 0.70,
    "reverse-whois": 0.60,
    "redirect": 0.60,
    "brand": 0.40,
    "dns-ns": 0.25,
    "dns-mail": 0.15,
    "html-link": 0.15,
    "corp-website": 0.80,
    "corp-subsidiary": 0.60,
    "corp-parent": 0.50,
    "site-sameas": 0.60,
    "site-contact": 0.45,
}

REDACTED = re.compile(
    r"redacted|privacy|private|proxy|protected|withheld|not disclosed|data protected|"
    r"contact privacy|whoisguard|domains by proxy|perfect privacy|gdpr|statutory masking",
    re.I,
)

# Certificates covering more distinct apexes than this are shared hosting / CDN
# certs and say nothing about ownership.
MAX_APEXES_PER_CERT = 40


class RelatedDiscovery:
    def __init__(self, surface: Surface, cfg: Config, client: httpx.AsyncClient, dns: Dns, log):
        self.s = surface
        self.cfg = cfg
        self.client = client
        self.dns = dns
        self.log = log
        self.seed_stems = {brand_stem(d) for d in surface.seeds}
        self.seed_registrants: dict[str, set[str]] = {"org": set(), "email": set()}
        self._rdap_cache: dict[str, dict] = {}
        self._org_searched: set[str] = set()

    # -- candidate bookkeeping ------------------------------------------------
    def excluded(self, name: str) -> bool:
        return any(name == x or name.endswith("." + x) for x in self.cfg.exclude)

    def add_candidate(self, name: str, signal: str, detail: str, depth: int) -> ApexDomain | None:
        a = apex(name)
        if not a or is_third_party(a) or self.excluded(a):
            return None
        d = self.s.domains.get(a)
        if d is None:
            d = self.s.domains[a] = ApexDomain(name=a, depth=depth)
            m = stem_similarity(a, self.seed_stems)
            if m and a not in self.s.seeds:
                d.add_evidence("brand", f"label matches brand stem '{m}'", WEIGHTS["brand"])
        if d.seed:
            return d
        d.depth = min(d.depth, depth)
        d.add_evidence(signal, detail, WEIGHTS[signal])
        return d

    # -- signal: certificate transparency -------------------------------------
    async def from_ct(self, apex_name: str, depth: int) -> None:
        try:
            rows = await crtsh_records(self.client, apex_name)
        except Exception as e:  # noqa: BLE001
            self.log(f"[related:ct] {apex_name}: {e}")
            return
        seen_per_cert: dict[int, set[str]] = {}
        for r in rows:
            names = {apex(n) for n in re.split(r"\s+", r.get("name_value", "")) if n}
            seen_per_cert.setdefault(r.get("id", 0), set()).update(n for n in names if n)
        counts: Counter[str] = Counter()
        for apexes in seen_per_cert.values():
            if len(apexes) > MAX_APEXES_PER_CERT:
                continue
            for a in apexes:
                if a != apex_name:
                    counts[a] += 1
        for a, n in counts.items():
            self.add_candidate(a, "cert-san", f"shares {n} CT-logged cert(s) with {apex_name}", depth + 1)

    def from_live_cert(self, host: str, sans: list[str], depth: int) -> None:
        apexes = {apex(s) for s in sans} - {None}
        if len(apexes) > MAX_APEXES_PER_CERT:
            return
        for a in apexes:
            if a != apex(host):
                self.add_candidate(a, "cert-san", f"in live TLS cert SANs of {host}", depth + 1)

    async def from_cert_org(self, org: str, depth: int) -> None:
        """crt.sh search by certificate Subject Organisation (O=)."""
        key = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", "", org.lower())).strip()
        if key in self._org_searched or len(org) < 4 or len(self._org_searched) >= 12:
            return
        self._org_searched.add(key)
        try:
            rows = await get_json(self.client, "https://crt.sh/",
                                  params={"O": org, "output": "json"}, timeout=120, retries=2)
        except Exception as e:  # noqa: BLE001
            self.log(f"[related:cert-org] '{org}': {e}")
            return
        apexes = Counter()
        for r in rows or []:
            for n in re.split(r"\s+", r.get("name_value", "") + " " + r.get("common_name", "")):
                a = apex(n) if n else None
                if a:
                    apexes[a] += 1
        self.log(f"[related:cert-org] '{org}': {len(apexes)} apex domains")
        for a, n in apexes.items():
            self.add_candidate(a, "cert-org", f"{n} cert(s) issued to O='{org}'", depth + 1)

    # -- signal: DNS records ----------------------------------------------------
    async def from_dns(self, apex_name: str, depth: int) -> None:
        ns, mx, txt, dmarc = await asyncio.gather(
            self.dns.query(apex_name, "NS"), self.dns.query(apex_name, "MX"),
            self.dns.query(apex_name, "TXT"), self.dns.query(f"_dmarc.{apex_name}", "TXT"),
        )
        for n in ns:
            self.add_candidate(n, "dns-ns", f"NS of {apex_name}: {n}", depth + 1)
        for m in mx:
            host = m.split()[-1] if m else ""
            self.add_candidate(host, "dns-mail", f"MX of {apex_name}: {host}", depth + 1)
        for t in txt:
            if t.lower().startswith("v=spf1"):
                for inc in re.findall(r"(?:include|redirect|a|mx)[:=]([^\s]+)", t, re.I):
                    self.add_candidate(inc, "dns-mail", f"SPF of {apex_name}: {inc}", depth + 1)
        for t in dmarc:
            for addr in re.findall(r"mailto:[^@]+@([^,;\s!]+)", t, re.I):
                self.add_candidate(addr, "dns-mail", f"DMARC rua/ruf of {apex_name}: {addr}", depth + 1)

    # -- signal: HTTP ------------------------------------------------------------
    def from_redirect(self, src_host: str, final_url: str, depth: int) -> None:
        dst = normalize(final_url)
        if dst and apex(dst) != apex(src_host):
            self.add_candidate(dst, "redirect", f"{src_host} redirects to {dst}", depth + 1)

    def from_links(self, src_host: str, html: str, depth: int) -> None:
        hosts = set(re.findall(r"""(?:href|src)=["']https?://([^/"':]+)""", html, re.I))
        src_apex = apex(src_host)
        for h in hosts:
            a = apex(h)
            if a and a != src_apex:
                # Weak alone; mostly useful combined with the brand signal.
                d = self.s.domains.get(a)
                if d is None and not stem_similarity(a, self.seed_stems):
                    continue  # don't create noise candidates from arbitrary outbound links
                self.add_candidate(h, "html-link", f"linked from https://{src_host}/", depth + 1)

    # -- signal: registration data -------------------------------------------------
    async def rdap(self, domain: str) -> dict:
        if domain in self._rdap_cache:
            return self._rdap_cache[domain]
        info: dict = {}
        try:
            data = await get_json(self.client, f"https://rdap.org/domain/{domain}",
                                  timeout=30, retries=1, follow_redirects=True)
            info = _parse_rdap(data)
        except Exception as e:  # noqa: BLE001
            info = {"error": str(e)[:120]}
        self._rdap_cache[domain] = info
        return info

    async def load_seed_registrants(self) -> None:
        for seed in self.s.seeds:
            info = await self.rdap(seed)
            self.s.domains[seed].whois = info
            if info.get("org") and not is_commercial_agent(info["org"]):
                self.seed_registrants["org"].add(info["org"].lower())
                self.s.org_names.add(info["org"])
            if info.get("email"):
                self.seed_registrants["email"].add(info["email"].lower())

    async def verify_by_registrant(self, min_conf: float = 0.15, limit: int = 150) -> None:
        """RDAP-check plausible candidates and add evidence when registrants match."""
        if not (self.seed_registrants["org"] or self.seed_registrants["email"]):
            # Still record registration data for the report.
            pass
        cands = sorted(
            (d for d in self.s.domains.values() if not d.seed and not d.whois and d.confidence >= min_conf),
            key=lambda d: -d.confidence,
        )[:limit]
        sem = asyncio.Semaphore(5)  # rdap.org is shared infrastructure; be gentle

        async def one(d: ApexDomain):
            async with sem:
                d.whois = await self.rdap(d.name)
            org = (d.whois.get("org") or "").lower()
            email = (d.whois.get("email") or "").lower()
            known = self.seed_registrants["org"] | {o.lower() for o in self.s.org_names}
            if org and not is_commercial_agent(org) and any(same_entity(org, k) for k in known):
                d.add_evidence("rdap-org", f"registrant org '{d.whois['org']}' matches seed", WEIGHTS["rdap-org"])
            if email and email in self.seed_registrants["email"]:
                d.add_evidence("rdap-email", f"registrant email '{email}' matches seed", WEIGHTS["rdap-email"])

        await asyncio.gather(*(one(d) for d in cands))

    async def reverse_whois(self, term: str, depth: int) -> None:
        key = self.cfg.keys.get("whoisxml")
        if not key:
            return
        try:
            r = await self.client.post(
                "https://reverse-whois.whoisxmlapi.com/api/v2",
                json={"apiKey": key, "searchType": "current", "mode": "purchase",
                      "basicSearchTerms": {"include": [term]}},
                timeout=90,
            )
            r.raise_for_status()
            names = r.json().get("domainsList", [])
        except Exception as e:  # noqa: BLE001
            self.log(f"[related:reverse-whois] '{term}': {e}")
            return
        self.log(f"[related:reverse-whois] '{term}': {len(names)} domains")
        for n in names:
            self.add_candidate(n, "reverse-whois", f"reverse WHOIS on '{term}'", depth + 1)


def _parse_rdap(data: dict) -> dict:
    out: dict = {"registrar": None, "org": None, "name": None, "email": None,
                 "created": None, "expires": None, "nameservers": []}
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            out["created"] = ev.get("eventDate")
        elif ev.get("eventAction") == "expiration":
            out["expires"] = ev.get("eventDate")
    out["nameservers"] = [n.get("ldhName", "").lower() for n in data.get("nameservers", [])]

    def walk(entities):
        for ent in entities or []:
            yield ent
            yield from walk(ent.get("entities"))

    for ent in walk(data.get("entities")):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
        fields = {}
        for item in vcard:
            if len(item) >= 4 and item[0] in ("fn", "org", "email"):
                val = item[3]
                if isinstance(val, list):
                    val = " ".join(str(v) for v in val if v)
                fields[item[0]] = str(val).strip()
        if "registrar" in roles and fields.get("fn"):
            out["registrar"] = fields["fn"]
        if "registrant" in roles:
            org = fields.get("org") or fields.get("fn")
            if org and not REDACTED.search(org):
                out["org"] = org
            if fields.get("fn") and not REDACTED.search(fields["fn"]):
                out["name"] = fields["fn"]
            em = fields.get("email")
            if em and "@" in em and not REDACTED.search(em):
                out["email"] = em
    return out
