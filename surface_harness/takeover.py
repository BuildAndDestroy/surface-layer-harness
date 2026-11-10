"""Subdomain-takeover candidate detection.

A host is a candidate when its CNAME chain ends at a third-party service and
either the target no longer exists (NXDOMAIN) or the service's "unclaimed"
page is served. These are *candidates* — always confirm manually.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Host


@dataclass(frozen=True)
class Fingerprint:
    service: str
    cname_suffixes: tuple[str, ...]
    body: tuple[str, ...]
    nxdomain_vulnerable: bool  # NXDOMAIN on the CNAME target alone suggests takeover


FINGERPRINTS = [
    Fingerprint("AWS S3", ("s3.amazonaws.com", "s3-website", ".s3."), ("NoSuchBucket",), False),
    Fingerprint("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), (), True),
    Fingerprint("Azure", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                          "trafficmanager.net", "blob.core.windows.net", "azureedge.net",
                          "azure-api.net", "azurefd.net", "azurecontainer.io",
                          "azurestaticapps.net"), (), True),
    Fingerprint("GitHub Pages", ("github.io",),
                ("There isn't a GitHub Pages site here",), False),
    Fingerprint("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
                ("No such app", "herokucdn.com/error-pages/no-such-app"), False),
    Fingerprint("Netlify", ("netlify.app", "netlify.com"), ("Not Found - Request ID",), False),
    Fingerprint("Vercel", ("vercel.app", "now.sh"), ("DEPLOYMENT_NOT_FOUND",), False),
    Fingerprint("Shopify", ("myshopify.com",),
                ("Sorry, this shop is currently unavailable",), False),
    Fingerprint("Fastly", ("fastly.net",), ("Fastly error: unknown domain",), False),
    Fingerprint("Pantheon", ("pantheonsite.io",), ("The gods are wise",), False),
    Fingerprint("Zendesk", ("zendesk.com",), ("Help Center Closed",), False),
    Fingerprint("Ghost", ("ghost.io",),
                ("Domain error", "The thing you were looking for is no longer here"), False),
    Fingerprint("Surge.sh", ("surge.sh",), ("project not found",), False),
    Fingerprint("Bitbucket", ("bitbucket.io",), ("Repository not found",), False),
    Fingerprint("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"),
                ("The page you are looking for doesn't exist or has been moved",), False),
    Fingerprint("Readme.io", ("readme.io",), ("Project doesnt exist... yet!",), False),
    Fingerprint("Unbounce", ("unbouncepages.com",), ("The requested URL was not found on this server",), False),
    Fingerprint("Tilda", ("tilda.ws",), ("Please renew your subscription",), False),
    Fingerprint("Fly.io", ("fly.dev",), ("404 Not Found",), True),
    Fingerprint("Google Cloud Storage", ("c.storage.googleapis.com",), ("NoSuchBucket",), False),
    Fingerprint("Help Scout", ("helpscoutdocs.com",), ("No settings were found for this company",), False),
]


def match_service(cnames: list[str]) -> Fingerprint | None:
    for c in reversed(cnames):  # terminal CNAME is most specific
        for fp in FINGERPRINTS:
            if any(c.endswith(s) or s in c for s in fp.cname_suffixes):
                return fp
    return None


def assess(host: Host, cname_target_status: str | None, bodies: list[str]) -> Finding | None:
    """cname_target_status: 'nxdomain' | 'exists' | 'error' | None for the last CNAME."""
    if not host.cnames:
        return None
    fp = match_service(host.cnames)
    target = host.cnames[-1]
    if fp:
        if any(sig in b for b in bodies for sig in fp.body):
            return Finding("high", "takeover-candidate", host.name,
                           f"CNAME -> {target} ({fp.service}) serves an 'unclaimed' fingerprint")
        if cname_target_status == "nxdomain":
            sev = "high" if fp.nxdomain_vulnerable else "medium"
            return Finding(sev, "takeover-candidate", host.name,
                           f"CNAME -> {target} ({fp.service}) does not resolve (NXDOMAIN)")
        return None
    if cname_target_status == "nxdomain":
        return Finding("medium", "dangling-cname", host.name,
                       f"CNAME -> {target} returns NXDOMAIN; check whether the target "
                       f"domain/resource can be registered or claimed")
    return None
