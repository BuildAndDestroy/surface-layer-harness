"""Domain-name utilities: normalisation, apex extraction, brand heuristics."""

from __future__ import annotations

import re

import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with tldextract,
# so runs are deterministic and don't fetch the PSL on every start.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

# Big shared providers that show up in SPF/MX/NS/links/cert SANs but are
# never "the company's own" domain. Matched against the apex.
THIRD_PARTY_APEXES = frozenset(
    """
    google.com googleapis.com gstatic.com googleusercontent.com googlemail.com gmail.com
    youtube.com doubleclick.net googletagmanager.com google-analytics.com
    microsoft.com outlook.com office.com office365.com live.com microsoftonline.com
    windows.net azure.com azurewebsites.net azureedge.net msecnd.net sharepoint.com
    amazonaws.com amazon.com cloudfront.net awsdns.com awsdns.net awsdns.org awsdns.co.uk
    cloudflare.com cloudflare.net cloudflare-dns.com akamai.net akamaiedge.net akamaihd.net
    akamaitechnologies.com edgekey.net edgesuite.net fastly.net fastlylb.net
    facebook.com fbcdn.net instagram.com twitter.com x.com linkedin.com licdn.com
    apple.com icloud.com github.com github.io githubusercontent.com gitlab.com
    mailchimp.com mcsv.net mandrillapp.com sendgrid.net sendgrid.com mailgun.org
    mailgun.net sparkpostmail.com amazonses.com mimecast.com pphosted.com
    protection.outlook.com zendesk.com salesforce.com force.com hubspot.com
    hubspotemail.net hs-analytics.net marketo.com mktoweb.com shopify.com myshopify.com
    wordpress.com wp.com squarespace.com wixsite.com wix.com godaddy.com domaincontrol.com
    secureserver.net registrar-servers.com dnsmadeeasy.com ultradns.com ultradns.net
    nsone.net dynect.net digicert.com letsencrypt.org sectigo.com globalsign.com
    jsdelivr.net unpkg.com cdnjs.cloudflare.com bootstrapcdn.com fontawesome.com
    typekit.net hotjar.com segment.com segment.io intercom.io optimizely.com
    vimeo.com wistia.com cookielaw.org onetrust.com trustarc.com
    dmarcian.com dmarcian.eu valimail.com agari.com ondmarc.com proofpoint.com mktomail.com
    registrarmail.net emailsrvr.com zoho.com zohomail.com messagelabs.com barracudanetworks.com
    medium.com crunchbase.com wikipedia.org wikidata.org glassdoor.com tiktok.com reddit.com
    discord.gg discord.com t.me telegram.me mastodon.social bsky.app threads.net pinterest.com
    bitbucket.org npmjs.com pypi.org hub.docker.com docker.com stackoverflow.com angel.co wellfound.com
    w3.org schema.org example.com example.org example.net
    """.split()
)


def normalize(name: str) -> str | None:
    """Lower-case, strip wildcards/trailing dots/ports/schemes. None if invalid."""
    if not name:
        return None
    n = name.strip().lower()
    n = re.sub(r"^[a-z]+://", "", n)
    n = n.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    n = n.strip(".")
    while n.startswith("*."):
        n = n[2:]
    if not _HOST_RE.match(n):
        return None
    return n


def apex(name: str) -> str | None:
    """Registrable domain (eTLD+1) of a host name."""
    n = normalize(name)
    if not n:
        return None
    ext = _extract(n)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def brand_stem(domain: str) -> str:
    """'acme-corp.co.uk' -> 'acme-corp'."""
    return _extract(domain).domain


def is_subdomain_of(host: str, apex_name: str) -> bool:
    return host == apex_name or host.endswith("." + apex_name)


def is_third_party(apex_name: str) -> bool:
    return apex_name in THIRD_PARTY_APEXES


def stem_similarity(candidate: str, seed_stems: set[str]) -> str | None:
    """Return the matching seed stem if the candidate apex looks brand-related."""
    cs = brand_stem(candidate)
    if not cs:
        return None
    for s in seed_stems:
        if len(s) < 4:
            # short stems (e.g. "ibm") only count on an exact stem match
            if cs == s:
                return s
            continue
        if cs == s or s in cs.replace("-", "") or cs in s and len(cs) >= 5:
            return s
    return None
