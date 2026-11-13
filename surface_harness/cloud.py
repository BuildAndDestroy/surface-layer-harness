"""Passive cloud-asset discovery: public storage buckets and Microsoft 365 tenants.

Everything here reads only public, unauthenticated metadata:
  * storage buckets  - a single HEAD/GET of the public endpoint tells us whether a
    guessed bucket name exists and whether it is world-listable. We never download
    objects or walk contents beyond that one listing request.
  * Microsoft 365    - the tenant OpenID configuration and the getuserrealm endpoint
    reveal the tenant id and whether sign-in is Managed or Federated (ADFS / third-party
    IdP). No login attempts, no user enumeration beyond the domain realm check itself.
"""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from .domains import brand_stem
from .models import Finding
from .probe import UA

# Tokens that are too generic to make a useful bucket/brand stem on their own.
GENERIC_STEMS = {
    "corp", "corporation", "limited", "group", "holdings", "company", "global", "the",
    "international", "technologies", "technology", "services", "solutions", "systems",
    "software", "digital", "online", "cloud", "labs", "inc", "llc", "ltd", "plc", "gmbh",
}

# Bucket-name permutations. Kept small and bounded so discovery stays passive and cheap.
BUCKET_SUFFIXES = [
    "", "-prod", "-production", "-dev", "-staging", "-test", "-backup", "-backups",
    "-assets", "-static", "-media", "-data", "-files", "-uploads", "-public", "-private",
    "-cdn", "-logs", "-www", "-app",
]

# (provider label, URL template). A single GET of each tells us exists/public/private.
BUCKET_PROVIDERS = [
    ("s3", "https://{name}.s3.amazonaws.com"),
    ("gcs", "https://storage.googleapis.com/{name}"),
    ("azure", "https://{name}.blob.core.windows.net/?comp=list"),
]

MS_LOGIN = "https://login.microsoftonline.com"


# -- brand stems -------------------------------------------------------------
def brand_stems(seeds, org_names) -> list[str]:
    """Candidate name stems for bucket guessing: seed apex labels + org-name tokens."""
    stems: set[str] = set()
    for s in seeds:
        st = brand_stem(s)
        if st and len(st) >= 3:
            stems.add(st.lower())
    for o in org_names:
        for tok in re.findall(r"[a-z0-9]{3,}", str(o).lower()):
            if tok not in GENERIC_STEMS:
                stems.add(tok)
    return sorted(stems)


# -- storage buckets ---------------------------------------------------------
def bucket_candidates(stems, limit: int = 20) -> list[str]:
    """Generate bounded, DNS-valid bucket name candidates from brand stems."""
    names: list[str] = []
    seen: set[str] = set()
    for stem in stems:
        base = re.sub(r"[^a-z0-9-]", "", str(stem).lower()).strip("-")
        if len(base) < 3:
            continue
        variants = {base}
        if "-" in base:
            variants.add(base.replace("-", ""))
        for v in sorted(variants):
            for suf in BUCKET_SUFFIXES:
                name = f"{v}{suf}"
                if 3 <= len(name) <= 63 and name not in seen:
                    seen.add(name)
                    names.append(name)
                    if len(names) >= limit:
                        return names
    return names


def classify_bucket(status: int) -> str | None:
    """HTTP status -> 'public' (listable), 'private' (exists, denied), or None (absent)."""
    if status == 200:
        return "public"
    if status in (401, 403):
        return "private"
    return None


async def discover_buckets(client, stems, log, max_requests: int = 60) -> list[Finding]:
    """Check guessed bucket names across S3/GCS/Azure. Bounded to ~max_requests GETs."""
    per_provider = max(1, max_requests // len(BUCKET_PROVIDERS))
    names = bucket_candidates(stems, limit=per_provider)
    jobs = [(name, provider, tmpl.format(name=name))
            for name in names for provider, tmpl in BUCKET_PROVIDERS][:max_requests]
    if not jobs:
        return []
    log(f"[cloud] checking {len(names)} bucket name(s) across S3/GCS/Azure ({len(jobs)} requests)")
    findings: list[Finding] = []
    sem = asyncio.Semaphore(10)

    async def check(name: str, provider: str, url: str):
        async with sem:
            try:
                r = await client.get(url, headers={"User-Agent": UA}, timeout=10.0)
            except Exception:  # noqa: BLE001 - connection/DNS failure == bucket not found
                return
        cat = classify_bucket(r.status_code)
        if cat == "public":
            findings.append(Finding("medium", "cloud-bucket", url,
                                    f"{provider} bucket '{name}' is publicly listable"))
        elif cat == "private":
            findings.append(Finding("info", "cloud-bucket", url,
                                    f"{provider} bucket '{name}' exists but access is denied"))

    await asyncio.gather(*(check(n, p, u) for n, p, u in jobs))
    return findings


# -- Microsoft 365 / Entra ---------------------------------------------------
_GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def parse_openid_config(data: dict) -> str | None:
    """Extract the tenant GUID from a tenant OpenID configuration document."""
    for key in ("issuer", "token_endpoint", "authorization_endpoint", "jwks_uri"):
        m = _GUID_RE.search(str((data or {}).get(key, "")))
        if m:
            return m.group(0).lower()
    return None


def parse_userrealm(xml_text: str) -> dict:
    """Parse a getuserrealm XML response into a flat dict of its fields + attributes."""
    out: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - Microsoft login response over HTTPS
    except ET.ParseError:
        return out
    out.update({k: v for k, v in root.attrib.items()})
    for child in root:
        tag = child.tag.split("}")[-1]
        if child.text and child.text.strip():
            out[tag] = child.text.strip()
    return out


async def _userrealm(client, domain: str) -> dict:
    url = f"{MS_LOGIN}/getuserrealm.srv?login=user@{domain}&xml=1"
    try:
        r = await client.get(url, headers={"User-Agent": UA}, timeout=10.0)
    except Exception:  # noqa: BLE001
        return {}
    if r.status_code != 200:
        return {}
    return parse_userrealm(r.text)


async def _openid_tenant(client, domain: str) -> str | None:
    url = f"{MS_LOGIN}/{domain}/.well-known/openid-configuration"
    try:
        r = await client.get(url, headers={"User-Agent": UA}, timeout=10.0)
    except Exception:  # noqa: BLE001
        return None
    if r.status_code != 200:
        return None
    try:
        return parse_openid_config(r.json())
    except Exception:  # noqa: BLE001
        return None


async def discover_m365(client, domains, log) -> list[Finding]:
    """Passive M365/Entra tenant recon for each candidate mail domain."""
    findings: list[Finding] = []
    checked = [d for d in dict.fromkeys(domains) if d]
    if not checked:
        return findings
    log(f"[cloud] Microsoft 365 tenant check for {len(checked)} domain(s)")

    async def one(domain: str):
        realm = await _userrealm(client, domain)
        ns = (realm.get("NameSpaceType") or "").strip()
        if ns.lower() in ("", "unknown"):
            return  # domain is not backed by an Entra/M365 tenant
        tenant = await _openid_tenant(client, domain)
        if tenant:
            findings.append(Finding("info", "m365-tenant", domain,
                                    f"Microsoft 365 / Entra tenant {tenant} ({ns} namespace)"))
        else:
            findings.append(Finding("info", "m365-tenant", domain,
                                    f"Microsoft 365 / Entra domain ({ns} namespace)"))
        if ns.lower() == "federated":
            host = urlparse(realm.get("AuthURL") or "").hostname
            brand = realm.get("FederationBrandName") or ""
            label = host or brand or "unknown IdP"
            detail = f"federated identity provider: {label}"
            if brand and host:
                detail += f" (brand '{brand}')"
            findings.append(Finding("info", "m365-federation", domain, detail))

    await asyncio.gather(*(one(d) for d in checked))
    return findings
