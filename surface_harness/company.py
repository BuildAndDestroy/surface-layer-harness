"""Company / legal-entity intelligence.

Answers "who is the organisation behind these domains?":
  1. Website self-disclosure (standard/active modes): schema.org JSON-LD, copyright and
     legal-entity strings, contact emails/phones, sameAs links, security.txt.
  2. Registries and entity databases (third-party, allowed in passive mode):
       GLEIF LEI          free; legal/HQ address, registration number, parent/child entities
       Wikidata           free; looked up by official website; parent/subsidiaries + their sites
       Colorado/NY/Oregon free state open-data registries incl. registered agent & officers
       OpenCorporates     OPENCORPORATES_API_TOKEN; ~all US states + 140 jurisdictions, agents, officers
       SEC EDGAR          SEC_USER_AGENT ("Name contact@example.com"); public companies

Registered agents: many companies list a commercial registered agent (Northwest
Registered Agent, CT Corporation, CSC, ...) as their registered office. That agent
fronts thousands of unrelated companies, so it is recorded and flagged but NEVER used
as a pivot for finding related domains or entities.
"""

from __future__ import annotations

import asyncio
import hashlib
import html as htmllib
import json
import re
from urllib.parse import quote

import httpx

from .config import Config
from .domains import apex, brand_stem, normalize
from .models import CompanyRecord, Officer, SiteIdentity

# ---------------------------------------------------------------------------
# Name handling

_SUFFIXES = (
    r"l\.?\s?l\.?\s?c\.?|l\.?\s?l\.?\s?p\.?|l\.?\s?p\.?|inc\.?|incorporated|corp\.?|corporation|"
    r"co\.?|company|ltd\.?|limited|plc|p\.?l\.?c\.?|gmbh|ag|s\.?a\.?|s\.?a\.?s\.?|b\.?v\.?|n\.?v\.?|"
    r"pty\.?(?:\s+ltd\.?)?|s\.?r\.?l\.?|oy|ab|as|a/s|kk|pte\.?(?:\s+ltd\.?)?|pllc|pc|lllp"
)
SUFFIX_RE = re.compile(rf"(?:,?\s+(?:{_SUFFIXES}))+\s*$", re.I)
ENTITY_RE = re.compile(
    r"\b((?:[A-Z][A-Za-z0-9&'’.-]*\s+){0,6}?[A-Z][A-Za-z0-9&'’.-]*),?\s+"
    r"(LLC|L\.L\.C\.|LLP|Inc\.?|Incorporated|Corp\.?|Corporation|Ltd\.?|Limited|GmbH|PLC|"
    r"B\.V\.|S\.A\.|Pty\.? Ltd\.?|S\.r\.l\.|AG)(?![A-Za-z])"
)
COPYRIGHT_RE = re.compile(
    r"(?:©|\(c\)|copyright)\s*(?:\d{4}\s*(?:[-–—]\s*\d{2,4})?\s*,?\s*)?(?:by\s+)?"
    r"([A-Z][A-Za-z0-9&'’., -]{2,80}?)\s*(?:\.\s|\s*All rights|\s*\||\s*$|\s*-\s)",
    re.I,
)


def core_name(name: str) -> str:
    """'Harvest Range Labs, LLC' -> 'harvest range labs' (suffixes/punctuation removed)."""
    n = htmllib.unescape(name).strip()
    n = re.split(r",\s*(?:dissolved|delinquent|administratively|voluntarily)\b", n, flags=re.I)[0]
    n = re.sub(r"^the\s+", "", n, flags=re.I)
    n = SUFFIX_RE.sub("", n)
    n = re.sub(r"[^\w\s&]", " ", n.lower())
    return re.sub(r"\s+", " ", n).strip()


def squash(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", core_name(name).replace("&", "and"))


def same_entity(a: str, b: str) -> bool:
    sa, sb = squash(a), squash(b)
    return bool(sa) and sa == sb


def trim_to_brand(name: str, stems: set[str]) -> str | None:
    """'Privacy Team HackerOne Inc.' -> 'HackerOne Inc.': drop leading words until the
    shortest trailing phrase that still contains the brand stem."""
    name = re.sub(r"\s+", " ", name).strip(" ,-").lstrip(".")
    m = SUFFIX_RE.search(name)
    core, suffix = (name[:m.start()], name[m.start():]) if m else (name, "")
    words = core.split()
    keys = [s.replace("-", "") for s in stems if len(s) >= 3]
    for i in range(len(words) - 1, -1, -1):
        cand = (" ".join(words[i:]) + suffix).strip(" ,")
        if any(k in squash(cand) for k in keys):
            return cand
    return name if relates_to_brand(name, stems) else None


def relates_to_brand(name: str, stems: set[str]) -> bool:
    s = squash(name)
    if len(s) < 3:
        return False
    for st in stems:
        st = st.replace("-", "")
        if s == st or (len(st) >= 5 and (st in s or s in st and len(s) >= 5)):
            return True
    return False


# ---------------------------------------------------------------------------
# Registered agents / mail drops

COMMERCIAL_AGENTS = [
    "northwest registered agent", "registered agents inc", "registered agents legal services",
    "ct corporation", "c t corporation", "corporation trust company", "corporation service company",
    "csc lawyers incorporating", "cogency global", "national registered agents", "nrai services",
    "incorp services", "legalinc corporate services", "legalzoom", "harbor compliance",
    "zenbusiness", "united states corporation agents", "registered agent solutions",
    "a registered agent inc", "business filings incorporated", "vcorp services", "vcorp agent",
    "spiegel utrera", "sundoc filings", "wyoming registered agent", "wyoming agents",
    "incfile", "bizee", "swyft filings", "corporate creations", "paracorp", "capitol services",
    "delaware registered agent", "the company corporation", "agents and corporations inc",
    "delaware intercorp", "american incorporators", "unisearch", "corporate agents inc",
    "registered agent llc", "republic registered agent", "inc authority", "mycorporation",
    "cscglobal", "lexisnexis document solutions", "firstbase agent", "stripe atlas",
    "clerky", "doola", "corpnet", "registered agents of", "corporation guarantee and trust",
]
_AGENT_SQ = [re.sub(r"[^a-z0-9]", "", a) for a in COMMERCIAL_AGENTS]
MAIL_DROP_RE = re.compile(r"\bPMB\b|private mail\s?box|\bUPS Store\b|\bP\.?\s?O\.?\s?Box\b|virtual office", re.I)
CARE_OF_RE = re.compile(r"\b(?:c/o|care of)\s+([^,\n]+)", re.I)


def is_commercial_agent(name: str | None) -> bool:
    if not name:
        return False
    s = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(a in s for a in _AGENT_SQ)


def address_notes(addr: str | None) -> list[str]:
    notes: list[str] = []
    if not addr:
        return notes
    m = CARE_OF_RE.search(addr)
    if m:
        who = m.group(1).strip()
        notes.append(f"'c/o {who}'" + (" is a commercial registered agent" if is_commercial_agent(who) else
                                         " - address belongs to a third party"))
    if MAIL_DROP_RE.search(addr):
        notes.append("mail drop / PO box / private mailbox, not a physical office")
    return notes


def finalize(rec: CompanyRecord) -> CompanyRecord:
    if rec.agent_name and is_commercial_agent(rec.agent_name):
        rec.agent_commercial = True
    for label, addr in (("registered", rec.registered_address), ("principal", rec.principal_address),
                        ("mailing", rec.mailing_address)):
        for n in address_notes(addr):
            if "commercial registered agent" in n:
                rec.agent_commercial = True
                if not rec.agent_name:
                    rec.agent_name = CARE_OF_RE.search(addr).group(1).strip()  # type: ignore[union-attr]
            rec.address_notes.append(f"{label} address: {n}")
    if rec.agent_commercial:
        agent_sq = re.sub(r"[^a-z0-9]", "", (rec.agent_name or "").lower())
        agent_addr_sq = _addr_key(rec.agent_address)
        for label, addr in (("principal", rec.principal_address), ("mailing", rec.mailing_address),
                            ("registered", rec.registered_address)):
            if not addr:
                continue
            a_sq = re.sub(r"[^a-z0-9]", "", addr.lower())
            if (agent_addr_sq and _addr_key(addr) == agent_addr_sq) or (agent_sq and agent_sq in a_sq):
                rec.address_notes.append(f"{label} address is the registered agent's address, "
                                         f"not a company location")
        rec.address_notes.append(
            f"registered agent '{rec.agent_name}' is a commercial agent service: its address is not "
            f"the company's location and it is shared by many unrelated companies (not used for pivoting)")
    rec.address_notes = list(dict.fromkeys(rec.address_notes))
    return rec


def _addr_key(addr: str | None) -> str:
    """Street line + postcode, normalised, for 'same address' comparisons."""
    if not addr:
        return ""
    first = re.sub(r"[^a-z0-9]", "", addr.split(",")[0].lower())
    zips = re.findall(r"\b\d{5}\b", addr)
    return first + (zips[-1] if zips else "")


def _join(*parts) -> str | None:
    s = ", ".join(str(p).strip() for p in parts if p and str(p).strip())
    return s or None


# ---------------------------------------------------------------------------
# Website self-disclosure

SITE_PATHS = ["/", "/about", "/about-us", "/company", "/contact", "/contact-us", "/legal",
              "/imprint", "/impressum", "/privacy", "/privacy-policy", "/terms", "/terms-of-service",
              "/.well-known/security.txt"]
LDJSON_RE = re.compile(r"<script[^>]+application/ld\+json[^>]*>(.*?)</script>", re.I | re.S)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
TEL_RE = re.compile(r"""href=["']tel:([+\d][\d\s().-]{6,})["']""", re.I)
SITE_NAME_RE = re.compile(r"""<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']+)""", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
ORG_TYPES = ("organization", "corporation", "localbusiness", "company", "ngo", "professionalservice",
             "educationalorganization", "governmentorganization", "onlinebusiness", "store")


def _text(html: str) -> str:
    t = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", html, flags=re.I | re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", htmllib.unescape(t))


def _walk_ld(obj):
    if isinstance(obj, list):
        for o in obj:
            yield from _walk_ld(o)
    elif isinstance(obj, dict):
        yield obj
        for k in ("@graph", "publisher", "author", "provider", "parentOrganization",
                  "subOrganization", "brand", "creator", "seller"):
            if k in obj:
                yield from _walk_ld(obj[k])


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _postal(a) -> str | None:
    if isinstance(a, str):
        return a.strip() or None
    if isinstance(a, dict):
        country = a.get("addressCountry")
        if isinstance(country, dict):
            country = country.get("name")
        return _join(a.get("streetAddress"), a.get("addressLocality"), a.get("addressRegion"),
                     a.get("postalCode"), country)
    return None


def parse_site_page(ident: SiteIdentity, url: str, body: str, stems: set[str]) -> None:
    if url.endswith("security.txt"):
        if "contact:" in body.lower():
            ident.security_txt = [l.strip() for l in body.splitlines()
                                  if re.match(r"\s*(contact|policy|hiring|canonical|acknowledgments?):", l, re.I)]
            for line in ident.security_txt:
                for m in EMAIL_RE.finditer(line):
                    ident.emails.add(m.group(0).lower())
        return

    # schema.org JSON-LD
    for block in LDJSON_RE.findall(body):
        try:
            data = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        for node in _walk_ld(data):
            types = " ".join(str(t) for t in _as_list(node.get("@type"))).lower()
            if not any(t in types for t in ORG_TYPES):
                continue
            for n in _as_list(node.get("name")) + _as_list(node.get("alternateName")):
                if isinstance(n, str) and relates_to_brand(n, stems):
                    ident.display_names.add(n.strip())
            for n in _as_list(node.get("legalName")):
                if isinstance(n, str):
                    ident.legal_names.add(n.strip())
            for e in _as_list(node.get("email")):
                if isinstance(e, str):
                    ident.emails.add(e.replace("mailto:", "").strip().lower())
            for t in _as_list(node.get("telephone")):
                if isinstance(t, str):
                    ident.phones.add(t.strip())
            for a in _as_list(node.get("address")):
                if (p := _postal(a)):
                    ident.addresses.add(p)
            for s in _as_list(node.get("sameAs")):
                if isinstance(s, str):
                    ident.same_as.add(s.strip())

    # <title> / og:site_name -> display name only when it *is* the brand
    for m in [*SITE_NAME_RE.findall(body), *TITLE_RE.findall(body)[:1]]:
        for part in re.split(r"\s+[|–—:·-]\s+", htmllib.unescape(m).strip()):
            if squash(part) and any(squash(part) == s.replace("-", "") for s in stems):
                ident.display_names.add(part.strip())

    text = _text(body)
    for m in COPYRIGHT_RE.finditer(text):
        cand = m.group(1).strip(" .,-")
        if SUFFIX_RE.search(cand) and (trimmed := trim_to_brand(cand, stems)):
            ident.legal_names.add(trimmed)
    for m in ENTITY_RE.finditer(text):
        if (trimmed := trim_to_brand(f"{m.group(1).strip()} {m.group(2)}", stems)):
            ident.legal_names.add(trimmed)
    for m in EMAIL_RE.finditer(text + " " + " ".join(re.findall(r"mailto:([^\"'?]+)", body))):
        e = m.group(0).lower()
        if not re.search(r"\.(png|jpe?g|gif|svg|webp)$", e) and "example" not in e and len(e) < 80:
            ident.emails.add(e)
    for t in TEL_RE.findall(body):
        ident.phones.add(re.sub(r"\s+", " ", t).strip())


async def site_identity(client: httpx.AsyncClient, domain: str, stems: set[str], log) -> SiteIdentity:
    ident = SiteIdentity(domain=domain)
    seen: set[str] = set()
    sem = asyncio.Semaphore(4)

    async def fetch(path: str):
        url = f"https://{domain}{path}"
        async with sem:
            try:
                r = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; surface-harness/0.1)"})
            except Exception:  # noqa: BLE001
                return None
        if r.status_code != 200:
            return None
        ctype = r.headers.get("content-type", "")
        if path.endswith("security.txt") and "html" in ctype:
            return None
        body = r.text[:1_000_000]
        digest = hashlib.sha1(body.encode(errors="ignore")).hexdigest()
        if digest in seen:  # SPA catch-all returning the same page for every path
            return None
        seen.add(digest)
        return str(r.url), body

    results = await asyncio.gather(*(fetch(p) for p in SITE_PATHS))
    for res in results:
        if res:
            url, body = res
            ident.pages.append(url)
            parse_site_page(ident, url, body, stems)
    log(f"[company:site] {domain}: {len(ident.pages)} pages, names={sorted(ident.display_names | ident.legal_names)}")
    return ident


# ---------------------------------------------------------------------------
# Registries

class Registries:
    def __init__(self, cfg: Config, client: httpx.AsyncClient, log):
        self.cfg = cfg
        self.client = client
        self.log = log

    async def _get(self, url: str, **kw):
        r = await self.client.get(url, timeout=kw.pop("timeout", 45), **kw)
        r.raise_for_status()
        return r.json()

    # -- GLEIF --------------------------------------------------------------------
    async def gleif(self, name: str) -> list[CompanyRecord]:
        data = await self._get("https://api.gleif.org/api/v1/lei-records",
                               params={"filter[fulltext]": name, "page[size]": "20"})
        out = []
        for rec in data.get("data", []):
            ent = rec["attributes"]["entity"]
            legal = ent["legalName"]["name"]
            others = [o.get("name") for o in ent.get("otherNames", []) if o.get("name")]
            if not any(same_entity(n, name) for n in [legal, *others]):
                continue
            out.append(await self._gleif_record(rec, "name"))
        return out

    def _gleif_addr(self, a: dict | None) -> str | None:
        if not a:
            return None
        return _join(*a.get("addressLines", []), a.get("city"), a.get("region"), a.get("postalCode"),
                     a.get("country"))

    async def _gleif_record(self, rec: dict, match: str, relations: bool = True) -> CompanyRecord:
        a = rec["attributes"]
        ent = a["entity"]
        lei = a["lei"]
        c = CompanyRecord(
            source="gleif", name=ent["legalName"]["name"], match=match,
            jurisdiction=ent.get("jurisdiction"), company_number=ent.get("registeredAs"),
            status=ent.get("status"),
            entity_type=f"ISO 20275 code {(ent.get('legalForm') or {}).get('id')}",
            formed=(ent.get("creationDate") or "")[:10] or None,
            registered_address=self._gleif_addr(ent.get("legalAddress")),
            principal_address=self._gleif_addr(ent.get("headquartersAddress")),
            identifiers={"lei": lei, "registration_authority": (ent.get("registeredAt") or {}).get("id") or ""},
            former_names=[o["name"] for o in ent.get("otherNames", []) if o.get("name")],
            url=f"https://search.gleif.org/#/record/{lei}",
        )
        if relations:
            base = f"https://api.gleif.org/api/v1/lei-records/{lei}"
            for rel in ("direct-parent", "ultimate-parent"):
                try:
                    d = await self._get(f"{base}/{rel}")
                    pname = d["data"]["attributes"]["entity"]["legalName"]["name"]
                    if pname not in c.parents:
                        c.parents.append(pname)
                except Exception:  # noqa: BLE001 - 404 = no reported parent
                    pass
            try:
                d = await self._get(f"{base}/direct-children", params={"page[size]": "100"})
                c.subsidiaries = [x["attributes"]["entity"]["legalName"]["name"] for x in d.get("data", [])]
            except Exception:  # noqa: BLE001
                pass
        return finalize(c)

    # -- OpenCorporates (token) ------------------------------------------------------
    async def opencorporates(self, name: str) -> list[CompanyRecord]:
        token = self.cfg.keys.get("opencorporates")
        if not token:
            return []
        base = "https://api.opencorporates.com/v0.4"
        data = await self._get(f"{base}/companies/search",
                               params={"q": name, "api_token": token, "per_page": "50"})
        hits = [c["company"] for c in data["results"]["companies"]
                if same_entity(c["company"]["name"], name)][:8]
        out = []
        for h in hits:
            try:
                d = (await self._get(f"{base}/companies/{h['jurisdiction_code']}/{quote(h['company_number'])}",
                                     params={"api_token": token}))["results"]["company"]
            except Exception:  # noqa: BLE001
                d = h
            c = CompanyRecord(
                source="opencorporates", name=d["name"], jurisdiction=d.get("jurisdiction_code"),
                company_number=d.get("company_number"), status=d.get("current_status"),
                entity_type=d.get("company_type"), formed=d.get("incorporation_date"),
                registered_address=d.get("registered_address_in_full"),
                agent_name=d.get("agent_name"), agent_address=d.get("agent_address"),
                former_names=[p.get("company_name") for p in d.get("previous_names") or [] if p.get("company_name")],
                url=d.get("opencorporates_url"), identifiers={"registry_url": d.get("registry_url") or ""},
            )
            for o in d.get("officers") or []:
                o = o.get("officer", o)
                if o.get("end_date"):
                    continue
                c.officers.append(Officer(o.get("name", ""), o.get("position", "")))
            out.append(finalize(c))
        return out

    # -- US state open-data registries (Socrata) --------------------------------------
    @staticmethod
    def _soql_prefix(field: str, name: str) -> str:
        core = core_name(name).upper().replace("'", "''")
        return f"upper({field}) like '{core}%'"

    async def colorado(self, name: str) -> list[CompanyRecord]:
        rows = await self._get("https://data.colorado.gov/resource/4ykn-tg5h.json",
                               params={"$where": self._soql_prefix("entityname", name), "$limit": "50"})
        out = []
        for r in rows:
            if not same_entity(r.get("entityname", ""), name):
                continue
            agent = r.get("agentorganizationname") or _join(
                r.get("agentfirstname"), r.get("agentmiddlename"), r.get("agentlastname"))
            out.append(finalize(CompanyRecord(
                source="us-co", name=r["entityname"], jurisdiction=f"CO (formed in {r.get('jurisdictonofformation')})",
                company_number=r.get("entityid"), status=r.get("entitystatus"), entity_type=r.get("entitytype"),
                formed=(r.get("entityformdate") or "")[:10] or None,
                principal_address=_join(r.get("principaladdress1"), r.get("principaladdress2"),
                                        r.get("principalcity"), r.get("principalstate"),
                                        r.get("principalzipcode"), r.get("principalcountry")),
                mailing_address=_join(r.get("mailingaddress1"), r.get("mailingaddress2"), r.get("mailingcity"),
                                      r.get("mailingstate"), r.get("mailingzipcode")),
                agent_name=agent and re.sub(r"\s+", " ", agent),
                agent_address=_join(r.get("agentprincipaladdress1"), r.get("agentprincipaladdress2"),
                                    r.get("agentprincipalcity"), r.get("agentprincipalstate"),
                                    r.get("agentprincipalzipcode")),
                url=f"https://www.coloradosos.gov/biz/BusinessEntityDetail.do?masterFileId={r.get('entityid')}",
            )))
        return out

    async def new_york(self, name: str) -> list[CompanyRecord]:
        rows = await self._get("https://data.ny.gov/resource/n9v6-gdp6.json",
                               params={"$where": self._soql_prefix("current_entity_name", name), "$limit": "50"})
        out = []
        for r in rows:
            if not same_entity(r.get("current_entity_name", ""), name):
                continue
            c = CompanyRecord(
                source="us-ny", name=r["current_entity_name"], jurisdiction=f"NY (formed in {r.get('jurisdiction')})",
                company_number=r.get("dos_id"), entity_type=r.get("entity_type"),
                formed=(r.get("initial_dos_filing_date") or "")[:10] or None, status="active",
                principal_address=_join(r.get("location_address_1"), r.get("location_address_2"),
                                        r.get("location_city"), r.get("location_state"), r.get("location_zip")),
                mailing_address=_join(r.get("dos_process_name"), r.get("dos_process_address_1"),
                                      r.get("dos_process_city"), r.get("dos_process_state"), r.get("dos_process_zip")),
                agent_name=r.get("registered_agent_name") or (
                    r.get("dos_process_name") if is_commercial_agent(r.get("dos_process_name")) else None),
                agent_address=_join(r.get("registered_agent_address_1"), r.get("registered_agent_city"),
                                    r.get("registered_agent_state"), r.get("registered_agent_zip")),
                url="https://apps.dos.ny.gov/publicInquiry/",
            )
            if r.get("chairman_name"):
                c.officers.append(Officer(r["chairman_name"], "chairman/CEO"))
            out.append(finalize(c))
        return out

    async def oregon(self, name: str) -> list[CompanyRecord]:
        rows = await self._get("https://data.oregon.gov/resource/tckn-sxa6.json",
                               params={"$where": self._soql_prefix("business_name", name), "$limit": "200"})
        by_reg: dict[str, CompanyRecord] = {}
        for r in rows:
            if not same_entity(r.get("business_name", ""), name):
                continue
            reg = r["registry_number"]
            c = by_reg.get(reg)
            if c is None:
                c = by_reg[reg] = CompanyRecord(
                    source="us-or", name=r["business_name"], jurisdiction=f"OR (formed in {r.get('jurisdiction')})",
                    company_number=reg, entity_type=r.get("entity_type"), status="active",
                    formed=(r.get("registry_date") or "")[:10] or None,
                    url=(r.get("business_details") or {}).get("url"))
            kind = (r.get("associated_name_type") or "").upper()
            who = r.get("entity_of_record_name") or _join(r.get("first_name"), r.get("last_name"))
            addr = _join(r.get("address"), r.get("city"), r.get("state"), r.get("zip"))
            if kind == "REGISTERED AGENT":
                c.agent_name, c.agent_address = who, addr
            elif kind == "PRINCIPAL PLACE OF BUSINESS":
                c.principal_address = addr
            elif kind == "MAILING ADDRESS":
                c.mailing_address = addr
            elif who:
                c.officers.append(Officer(who.replace(",", " ").strip(), kind.lower()))
        return [finalize(c) for c in by_reg.values()]

    # -- SEC EDGAR (needs declared User-Agent) ------------------------------------------
    async def sec(self, name: str) -> list[CompanyRecord]:
        ua = self.cfg.keys.get("sec_user_agent") or (
            f"surface-harness/0.1 {self.cfg.keys['contact']}" if self.cfg.keys.get("contact") else None)
        if not ua:
            return []
        hdr = {"User-Agent": ua}
        r = await self.client.get("https://www.sec.gov/cgi-bin/browse-edgar",
                                  params={"action": "getcompany", "company": core_name(name),
                                          "output": "atom", "count": "40"}, headers=hdr, timeout=45)
        ciks = set()
        for m in re.finditer(r"<entry>.*?</entry>", r.text, re.S):
            ent = m.group(0)
            nm = re.search(r"<title>(.*?)</title>", ent, re.S)
            ck = re.search(r"CIK=(\d+)|<cik>(\d+)</cik>", ent)
            if nm and ck and same_entity(re.sub(r"\s*\(.*$", "", htmllib.unescape(nm.group(1))), name):
                ciks.add((ck.group(1) or ck.group(2)).zfill(10))
        cikm = re.search(r"<cik>(\d+)</cik>", r.text)  # exact single-company response
        if cikm and not ciks:
            ciks.add(cikm.group(1).zfill(10))
        out = []
        for cik in list(ciks)[:3]:
            d = (await self.client.get(f"https://data.sec.gov/submissions/CIK{cik}.json",
                                       headers=hdr, timeout=45)).json()
            if not same_entity(d.get("name", ""), name):
                continue
            ad = d.get("addresses", {})

            def fmt(a):
                return _join(a.get("street1"), a.get("street2"), a.get("city"),
                             a.get("stateOrCountry"), a.get("zipCode")) if a else None

            out.append(finalize(CompanyRecord(
                source="sec", name=d["name"], jurisdiction=d.get("stateOfIncorporation"),
                company_number=cik, entity_type=d.get("entityType"), industry=d.get("sicDescription"),
                principal_address=fmt(ad.get("business")), mailing_address=fmt(ad.get("mailing")),
                former_names=[f.get("name") for f in d.get("formerNames", []) if f.get("name")],
                identifiers={"cik": cik, "ein": d.get("ein") or "",
                             "tickers": ",".join(d.get("tickers", []))},
                websites=[w for w in [d.get("website")] if w],
                url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
            )))
        return out

    # -- Wikidata ------------------------------------------------------------------------
    def _wm_ua(self) -> str:
        return f"surface-harness/0.1 ({self.cfg.keys['contact']})"

    async def _sparql(self, query: str) -> list[dict]:
        r = await self.client.get("https://query.wikidata.org/sparql", params={"query": query},
                                  headers={"Accept": "application/sparql-results+json",
                                           "User-Agent": self._wm_ua()},
                                  timeout=60)
        r.raise_for_status()
        return r.json()["results"]["bindings"]

    async def wikidata(self, domains: list[str], names: list[str]) -> list[CompanyRecord]:
        variants = []
        for d in domains:
            for scheme in ("https", "http"):
                for host in (d, f"www.{d}"):
                    variants += [f"<{scheme}://{host}/>", f"<{scheme}://{host}>"]
        rows = await self._sparql(
            f"SELECT DISTINCT ?item WHERE {{ VALUES ?site {{ {' '.join(variants)} }} ?item wdt:P856 ?site . }}")
        qids = {row["item"]["value"].rsplit("/", 1)[-1]: "domain" for row in rows}
        if not qids:
            for n in names[:3]:
                r = await self.client.get("https://www.wikidata.org/w/api.php", params={
                    "action": "wbsearchentities", "search": n, "language": "en", "format": "json", "limit": "5"},
                    headers={"User-Agent": self._wm_ua()}, timeout=30)
                for hit in r.json().get("search", []):
                    if same_entity(hit.get("label", ""), n):
                        qids.setdefault(hit["id"], "name")
        out = []
        for qid, match in list(qids.items())[:5]:
            out.append(await self._wikidata_item(qid, match, domains))
        return [c for c in out if c]

    async def _wikidata_item(self, qid: str, match: str, domains: list[str]) -> CompanyRecord | None:
        rows = await self._sparql(f"""
SELECT ?label ?official ?site ?countryLabel ?inception ?hqLabel ?industryLabel
       ?parentLabel ?parentSite ?subLabel ?subSite ?ownerLabel WHERE {{
  BIND(wd:{qid} AS ?i)
  ?i rdfs:label ?label FILTER(lang(?label)="en")
  OPTIONAL {{ ?i wdt:P1448 ?official }}
  OPTIONAL {{ ?i wdt:P856 ?site }}
  OPTIONAL {{ ?i wdt:P17 ?country }}
  OPTIONAL {{ ?i wdt:P571 ?inception }}
  OPTIONAL {{ ?i wdt:P159 ?hq }}
  OPTIONAL {{ ?i wdt:P452 ?industry }}
  OPTIONAL {{ ?i wdt:P749 ?parent OPTIONAL {{ ?parent wdt:P856 ?parentSite }} }}
  OPTIONAL {{ ?i wdt:P355 ?sub OPTIONAL {{ ?sub wdt:P856 ?subSite }} }}
  OPTIONAL {{ ?i wdt:P127 ?owner }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}} LIMIT 2000""")
        if not rows:
            return None
        v = lambda row, k: row.get(k, {}).get("value")  # noqa: E731
        c = CompanyRecord(source="wikidata", name=v(rows[0], "label"), match=match,
                          identifiers={"wikidata": qid}, url=f"https://www.wikidata.org/wiki/{qid}")
        sub_sites: dict[str, set[str]] = {}
        parent_sites: dict[str, set[str]] = {}
        for row in rows:
            if v(row, "official") and v(row, "official") not in c.former_names and v(row, "official") != c.name:
                c.former_names.append(v(row, "official"))
            if v(row, "site") and v(row, "site") not in c.websites:
                c.websites.append(v(row, "site"))
            c.jurisdiction = c.jurisdiction or v(row, "countryLabel")
            c.formed = c.formed or (v(row, "inception") or "")[:10] or None
            c.principal_address = c.principal_address or v(row, "hqLabel")
            c.industry = c.industry or v(row, "industryLabel")
            for key, sites, lst in (("parentLabel", parent_sites, c.parents), ("ownerLabel", None, c.parents),
                                    ("subLabel", sub_sites, c.subsidiaries)):
                n = v(row, key)
                if n and not re.fullmatch(r"Q\d+", n):
                    if n not in lst:
                        lst.append(n)
                    site_key = {"parentLabel": "parentSite", "subLabel": "subSite"}.get(key)
                    if sites is not None and site_key and v(row, site_key):
                        sites.setdefault(n, set()).add(v(row, site_key))
        c.identifiers["subsidiary_sites"] = json.dumps({k: sorted(s) for k, s in sub_sites.items()})
        c.identifiers["parent_sites"] = json.dumps({k: sorted(s) for k, s in parent_sites.items()})
        if match == "name" and not any(apex(w) in domains for w in c.websites):
            # Name-only match whose official site isn't one of ours: too risky to attribute.
            return None
        return c

    # -- fan-out -----------------------------------------------------------------------
    async def lookup(self, names: list[str], domains: list[str]) -> list[CompanyRecord]:
        tasks = {}
        queries, seen_q = [], set()
        for n in names:
            q = core_name(n)
            if q and squash(q) not in seen_q:
                seen_q.add(squash(q))
                queries.append(q)
        for n in queries:
            for src, fn in (("gleif", self.gleif), ("opencorporates", self.opencorporates),
                            ("us-co", self.colorado), ("us-ny", self.new_york), ("us-or", self.oregon),
                            ("sec", self.sec)):
                tasks[(src, n)] = fn(n)
        if self.cfg.keys.get("contact"):
            tasks[("wikidata", ",".join(domains))] = self.wikidata(domains, queries)
        else:
            self.log("[company] SURFACE_CONTACT not set: skipping Wikidata and SEC (their usage policies "
                     "require contact info in the User-Agent)")
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        out: list[CompanyRecord] = []
        seen = set()
        for (src, n), res in zip(tasks, results):
            if isinstance(res, BaseException):
                self.log(f"[company:{src}] '{n}': {type(res).__name__}: {str(res)[:120]}")
                continue
            if res:
                self.log(f"[company:{src}] '{n}': {len(res)} record(s)")
            for c in res:
                key = (c.source, c.company_number or c.identifiers.get("wikidata") or c.name)
                if key not in seen:
                    seen.add(key)
                    out.append(c)
        if not self.cfg.keys.get("opencorporates"):
            self.log("[company] OPENCORPORATES_API_TOKEN not set: registry coverage limited to "
                     "GLEIF, Wikidata and CO/NY/OR open data")
        return out


def candidate_names(cfg_orgs, rdap_orgs, idents: list[SiteIdentity], limit: int = 6) -> list[str]:
    """Names to search registries for, best first, de-duplicated by core name."""
    ordered = list(cfg_orgs)
    for i in idents:
        ordered += sorted(i.legal_names)
    ordered += [o for o in rdap_orgs if not is_commercial_agent(o)]
    for i in idents:
        ordered += sorted(i.display_names)
    out, seen = [], set()
    for n in ordered:
        k = squash(n)
        if k and k not in seen and len(k) >= 3:
            seen.add(k)
            out.append(n.strip())
    return out[:limit]


def website_domains(urls) -> set[str]:
    out = set()
    for u in urls:
        a = apex(normalize(u) or "")
        if a:
            out.add(a)
    return out


__all__ = [
    "Registries", "site_identity", "candidate_names", "is_commercial_agent", "same_entity",
    "core_name", "relates_to_brand", "website_domains", "brand_stem",
]
