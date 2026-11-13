"""Email-security posture grading (SPF / DMARC / DKIM / MTA-STS / TLS-RPT).

All checks are passive DNS lookups against the apex, so they run in every mode.
The parsing/grading logic is factored into pure synchronous helpers
(``grade_spf`` / ``grade_dmarc``) so it can be unit tested without the network.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from .models import EmailSecurity, Finding

if TYPE_CHECKING:
    from .dns_ops import Dns

# Mechanisms/modifiers that each cost a DNS lookup (RFC 7208 §4.6.4). More than
# ten of these across the whole evaluation is a PermError.
SPF_DNS_LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists", "redirect")
SPF_MAX_DNS_LOOKUPS = 10

# A small, common set of DKIM selectors. DKIM can never be proven absent (the
# selector namespace is unbounded), so a miss here is informational only.
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "dkim", "mail")


def _strip_qualifier(term: str) -> tuple[str, str]:
    """Split an SPF term into (qualifier, mechanism). Bare mechanisms are '+'."""
    if term and term[0] in "+-~?":
        return term[0], term[1:]
    return "+", term


def _spf_all_qualifier(terms: list[str]) -> str | None:
    """Qualifier on the ``all`` mechanism ('+', '-', '~', '?'), or None if absent."""
    for term in terms:
        qual, mech = _strip_qualifier(term)
        if mech.lower() == "all":
            return qual
    return None


def _spf_dns_lookups(terms: list[str]) -> int:
    count = 0
    for term in terms:
        _qual, mech = _strip_qualifier(term)
        name = mech.split(":", 1)[0].split("=", 1)[0].lower()
        if name in SPF_DNS_LOOKUP_TERMS:
            count += 1
    return count


def grade_spf(apex_name: str, txt_records: list[str]) -> list[Finding]:
    """Grade the apex ``v=spf1`` TXT record(s). Pure function for unit testing."""
    findings: list[Finding] = []
    spf = [t for t in txt_records if t.strip().lower().startswith("v=spf1")]
    if not spf:
        return [Finding("medium", "email-spf", apex_name,
                        "no SPF record (v=spf1) published; sender spoofing is unconstrained")]
    if len(spf) > 1:
        findings.append(Finding("medium", "email-spf", apex_name,
                                f"{len(spf)} SPF records published; RFC 7208 permits exactly one (PermError)"))
    terms = spf[0].split()
    qual = _spf_all_qualifier(terms)
    if qual is None:
        findings.append(Finding("low", "email-spf", apex_name,
                                "SPF record has no 'all' mechanism; it is not authoritative (implicit neutral)"))
    elif qual == "+":
        findings.append(Finding("high", "email-spf", apex_name,
                                "SPF ends with +all; any host may send as this domain (no protection)"))
    elif qual == "?":
        findings.append(Finding("low", "email-spf", apex_name,
                                "SPF ends with ?all (neutral); senders are not constrained"))
    # '~all' (softfail) is acceptable and '-all' (hardfail) is ideal: no finding.
    lookups = _spf_dns_lookups(terms)
    if lookups > SPF_MAX_DNS_LOOKUPS:
        findings.append(Finding("medium", "email-spf", apex_name,
                                f"SPF needs {lookups} DNS-lookup mechanisms (>{SPF_MAX_DNS_LOOKUPS}); "
                                "RFC 7208 PermError, SPF may be ignored"))
    return findings


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    return tags


def grade_dmarc(apex_name: str, txt_records: list[str]) -> list[Finding]:
    """Grade the ``_dmarc`` ``v=DMARC1`` TXT record. Pure function for unit testing."""
    dmarc = [t for t in txt_records if t.strip().lower().startswith("v=dmarc1")]
    if not dmarc:
        return [Finding("medium", "email-dmarc", apex_name,
                        "no DMARC record at _dmarc; spoofed mail is neither reported nor rejected")]
    findings: list[Finding] = []
    tags = _parse_dmarc_tags(dmarc[0])
    policy = tags.get("p", "").lower()
    if not policy:
        findings.append(Finding("medium", "email-dmarc", apex_name,
                                "DMARC record present but missing the p= policy tag (invalid)"))
    elif policy == "none":
        findings.append(Finding("low", "email-dmarc", apex_name,
                                "DMARC policy is p=none (monitor only); spoofed mail is not quarantined or rejected"))
    # p=quarantine / p=reject are enforced: no finding.
    pct = tags.get("pct", "")
    if pct.isdigit() and int(pct) < 100:
        findings.append(Finding("info", "email-dmarc", apex_name,
                                f"DMARC pct={pct}; the policy is applied to only {pct}% of mail"))
    if "rua" not in tags:
        findings.append(Finding("low", "email-dmarc", apex_name,
                                "DMARC has no rua= aggregate-report address; abuse goes unobserved"))
    return findings


def _email_record(apex_name: str, apex_txt: list[str], dmarc_txt: list[str],
                  dkim_selectors: list[str], mta_sts: bool, tls_rpt: bool) -> EmailSecurity:
    """Build the structured EmailSecurity posture from the raw DNS answers."""
    rec = EmailSecurity(domain=apex_name, dkim_selectors=dkim_selectors,
                        mta_sts=mta_sts, tls_rpt=tls_rpt)
    spf = [t for t in apex_txt if t.strip().lower().startswith("v=spf1")]
    rec.spf_records = len(spf)
    if spf:
        rec.spf = spf[0]
        terms = spf[0].split()
        qual = _spf_all_qualifier(terms)
        rec.spf_all = f"{qual}all" if qual else None
        rec.spf_lookups = _spf_dns_lookups(terms)
    dmarc = [t for t in dmarc_txt if t.strip().lower().startswith("v=dmarc1")]
    if dmarc:
        rec.dmarc = dmarc[0]
        tags = _parse_dmarc_tags(dmarc[0])
        rec.dmarc_policy = (tags.get("p") or "").lower() or None
        pct = tags.get("pct", "")
        rec.dmarc_pct = int(pct) if pct.isdigit() else 100
        rec.dmarc_rua = "rua" in tags
    return rec


async def assess_email_security(dns: Dns, apex_name: str) -> tuple[EmailSecurity, list[Finding]]:
    """Assess email-authentication posture for ``apex_name`` via DNS lookups.

    Returns the structured :class:`EmailSecurity` record and the findings derived
    from it.
    """
    findings: list[Finding] = []

    apex_txt = await dns.query(apex_name, "TXT")
    findings += grade_spf(apex_name, apex_txt)

    dmarc_txt = await dns.query(f"_dmarc.{apex_name}", "TXT")
    findings += grade_dmarc(apex_name, dmarc_txt)

    # DKIM: probe a handful of common selectors (TXT or CNAME counts as present).
    async def _selector(sel: str) -> str | None:
        name = f"{sel}._domainkey.{apex_name}"
        txt, cname = await asyncio.gather(dns.query(name, "TXT"), dns.query(name, "CNAME"))
        return sel if (txt or cname) else None

    present = [s for s in await asyncio.gather(*(_selector(s) for s in COMMON_DKIM_SELECTORS)) if s]
    if present:
        findings.append(Finding("info", "email-dkim", apex_name,
                                f"DKIM selectors published: {', '.join(present)} "
                                "(other selectors cannot be ruled out)"))
    else:
        findings.append(Finding("info", "email-dkim", apex_name,
                                f"no DKIM key for common selectors ({', '.join(COMMON_DKIM_SELECTORS)}); "
                                "DKIM cannot be proven absent"))

    mta_sts_txt = await dns.query(f"_mta-sts.{apex_name}", "TXT")
    mta_sts = any(t.lower().startswith("v=stsv1") for t in mta_sts_txt)
    if mta_sts:
        findings.append(Finding("info", "email-mta-sts", apex_name,
                                "MTA-STS policy record published (good)"))
    else:
        findings.append(Finding("info", "email-mta-sts", apex_name,
                                "no MTA-STS policy record; inbound SMTP is open to TLS-downgrade attacks"))

    tls_rpt_txt = await dns.query(f"_smtp._tls.{apex_name}", "TXT")
    tls_rpt = any(t.lower().startswith("v=tlsrptv1") for t in tls_rpt_txt)
    if tls_rpt:
        findings.append(Finding("info", "email-tls-rpt", apex_name,
                                "SMTP TLS-RPT reporting published (good)"))
    else:
        findings.append(Finding("info", "email-tls-rpt", apex_name,
                                "no SMTP TLS-RPT record; inbound TLS failures are not reported"))

    record = _email_record(apex_name, apex_txt, dmarc_txt, present, mta_sts, tls_rpt)
    return record, findings
