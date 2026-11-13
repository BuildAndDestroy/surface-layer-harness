"""Unit tests for protocol-hygiene grading (no network calls)."""

import asyncio

from surface_harness.dns_audit import audit_dns
from surface_harness.email_sec import (
    assess_email_security,
    grade_dmarc,
    grade_spf,
)
from surface_harness.models import Finding


def _by_kind(findings, kind):
    return [f for f in findings if f.kind == kind]


# -- SPF -------------------------------------------------------------------

def test_spf_missing_is_medium():
    f = grade_spf("acme.com", ["some other txt", "google-site-verification=x"])
    assert len(f) == 1
    assert f[0].severity == "medium" and f[0].kind == "email-spf"


def test_spf_hardfail_is_clean():
    assert grade_spf("acme.com", ["v=spf1 include:_spf.google.com -all"]) == []


def test_spf_softfail_is_acceptable():
    assert grade_spf("acme.com", ["v=spf1 mx ~all"]) == []


def test_spf_plus_all_is_high():
    f = grade_spf("acme.com", ["v=spf1 +all"])
    assert any(x.severity == "high" for x in f)


def test_spf_neutral_all_is_low():
    f = grade_spf("acme.com", ["v=spf1 include:example.com ?all"])
    assert f and f[0].severity == "low"


def test_spf_no_all_mechanism_is_low():
    f = grade_spf("acme.com", ["v=spf1 include:example.com"])
    assert any(x.severity == "low" and "no 'all'" in x.detail for x in f)


def test_spf_multiple_records_is_permerror():
    f = grade_spf("acme.com", ["v=spf1 -all", "v=spf1 include:x.com ~all"])
    assert any("exactly one" in x.detail and x.severity == "medium" for x in f)


def test_spf_too_many_dns_lookups():
    terms = " ".join(f"include:z{i}.example.com" for i in range(11))
    f = grade_spf("acme.com", [f"v=spf1 {terms} -all"])
    assert any(">10" in x.detail and x.severity == "medium" for x in f)
    # exactly 10 lookups is still within the limit
    terms10 = " ".join(f"include:z{i}.example.com" for i in range(10))
    assert all(">10" not in x.detail for x in grade_spf("acme.com", [f"v=spf1 {terms10} -all"]))


def test_spf_counts_a_mx_redirect_as_lookups():
    # 9 includes + a + mx + redirect = 12 lookups -> PermError
    terms = " ".join(f"include:z{i}.example.com" for i in range(9))
    rec = f"v=spf1 {terms} a mx redirect=_spf.example.com"
    assert any(">10" in x.detail for x in grade_spf("acme.com", [rec]))


# -- DMARC -----------------------------------------------------------------

def test_dmarc_missing_is_medium():
    f = grade_dmarc("acme.com", [])
    assert len(f) == 1 and f[0].severity == "medium" and f[0].kind == "email-dmarc"


def test_dmarc_reject_with_rua_is_clean():
    assert grade_dmarc("acme.com", ["v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"]) == []


def test_dmarc_quarantine_is_clean():
    assert grade_dmarc("acme.com", ["v=DMARC1; p=quarantine; rua=mailto:r@acme.com"]) == []


def test_dmarc_p_none_is_low():
    f = grade_dmarc("acme.com", ["v=DMARC1; p=none; rua=mailto:r@acme.com"])
    assert any(x.severity == "low" and "p=none" in x.detail for x in f)


def test_dmarc_missing_rua_is_low():
    f = grade_dmarc("acme.com", ["v=DMARC1; p=reject"])
    assert any(x.severity == "low" and "rua" in x.detail for x in f)


def test_dmarc_pct_below_100_is_noted():
    f = grade_dmarc("acme.com", ["v=DMARC1; p=reject; pct=20; rua=mailto:r@acme.com"])
    noted = [x for x in f if "pct" in x.detail]
    assert noted and noted[0].severity == "info"


def test_dmarc_missing_policy_tag_is_medium():
    f = grade_dmarc("acme.com", ["v=DMARC1; rua=mailto:r@acme.com"])
    assert any(x.severity == "medium" for x in f)


# -- async assess_email_security with a fake DNS client --------------------

class FakeDns:
    """Minimal stand-in for Dns: query() returns canned records, exists() canned status."""

    def __init__(self, records=None, exists_map=None):
        self.records = records or {}
        self.exists_map = exists_map or {}

    async def query(self, name, rtype):
        return list(self.records.get((name, rtype), []))

    async def exists(self, name):
        return self.exists_map.get(name, "exists")


def test_assess_email_security_full_posture():
    recs = {
        ("acme.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_dmarc.acme.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"],
        ("google._domainkey.acme.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGf..."],
        ("_mta-sts.acme.com", "TXT"): ["v=STSv1; id=20240101"],
        ("_smtp._tls.acme.com", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@acme.com"],
    }
    email, findings = asyncio.run(assess_email_security(FakeDns(recs), "acme.com"))
    assert email.spf_all == "-all" and email.dmarc_policy == "reject" and email.dmarc_rua
    assert email.dkim_selectors == ["google"] and email.mta_sts and email.tls_rpt
    assert _by_kind(findings, "email-spf") == []  # -all is clean
    assert _by_kind(findings, "email-dmarc") == []  # p=reject + rua is clean
    dkim = _by_kind(findings, "email-dkim")
    assert dkim and "google" in dkim[0].detail
    mta = _by_kind(findings, "email-mta-sts")
    assert mta and "good" in mta[0].detail
    tlsrpt = _by_kind(findings, "email-tls-rpt")
    assert tlsrpt and "good" in tlsrpt[0].detail
    assert all(isinstance(f, Finding) for f in findings)


def test_assess_email_security_empty_domain():
    email, findings = asyncio.run(assess_email_security(FakeDns({}), "bare.example"))
    assert email.spf is None and email.dmarc_policy is None and not email.mta_sts
    # missing SPF (medium), missing DMARC (medium), plus info DKIM/MTA-STS/TLS-RPT
    assert _by_kind(findings, "email-spf")[0].severity == "medium"
    assert _by_kind(findings, "email-dmarc")[0].severity == "medium"
    assert _by_kind(findings, "email-dkim")[0].severity == "info"
    assert _by_kind(findings, "email-mta-sts")[0].severity == "info"
    assert _by_kind(findings, "email-tls-rpt")[0].severity == "info"


def test_assess_email_security_dkim_via_cname():
    recs = {("selector1._domainkey.acme.com", "CNAME"): ["selector1.acme._domainkey.example.net"]}
    email, findings = asyncio.run(assess_email_security(FakeDns(recs), "acme.com"))
    assert email.dkim_selectors == ["selector1"]
    dkim = _by_kind(findings, "email-dkim")
    assert dkim and "selector1" in dkim[0].detail


# -- async audit_dns with a fake DNS client (AXFR/xfr not exercised) -------

def test_audit_dns_missing_dnssec_and_caa():
    # NS present but resolves, no DNSKEY/DS, no CAA -> two info findings.
    dns = FakeDns(
        records={("acme.com", "NS"): ["ns1.acme.com"], ("ns1.acme.com", "A"): []},
        exists_map={"ns1.acme.com": "exists"},
    )
    dns_rec, findings = asyncio.run(audit_dns(dns, "acme.com"))
    assert not dns_rec.dnssec and not dns_rec.caa and dns_rec.nameservers == ["ns1.acme.com"]
    kinds = {f.kind for f in findings}
    assert "dnssec-missing" in kinds and "caa-missing" in kinds
    assert all(f.severity == "info" for f in findings)


def test_audit_dns_dangling_nameserver():
    dns = FakeDns(
        records={("acme.com", "NS"): ["ns-gone.acme.com"], ("ns-gone.acme.com", "A"): []},
        exists_map={"ns-gone.acme.com": "nxdomain"},
    )
    dns_rec, findings = asyncio.run(audit_dns(dns, "acme.com"))
    assert dns_rec.dangling_ns == ["ns-gone.acme.com"]
    dangling = _by_kind(findings, "dangling-ns")
    assert dangling and dangling[0].severity == "medium"


def test_audit_dns_signed_zone_with_caa_is_quiet():
    dns = FakeDns(
        records={
            ("acme.com", "NS"): ["ns1.acme.com"],
            ("ns1.acme.com", "A"): [],
            ("acme.com", "DNSKEY"): ["256 3 13 abc..."],
            ("acme.com", "CAA"): ['0 issue "letsencrypt.org"'],
        },
        exists_map={"ns1.acme.com": "exists"},
    )
    dns_rec, findings = asyncio.run(audit_dns(dns, "acme.com"))
    assert dns_rec.dnssec and dns_rec.caa
    assert findings == []
