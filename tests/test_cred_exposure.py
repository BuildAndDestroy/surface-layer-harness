import asyncio
import json

from surface_harness.config import Config
from surface_harness.cred_exposure import (
    breach_exposure_findings,
    breach_finding,
    collect,
    email_format_finding,
    infer_email_format,
    known_repos,
    parse_gitleaks_findings,
    repo_secret_findings,
    summarize_breached_domain,
)
from surface_harness.models import CompanyRecord, Officer, SiteIdentity, Surface

# A credential-looking sentinel that must never leak into any Finding.detail.
SECRET = "hunter2-SUPERSECRET-passwordhash-deadbeef"


# ---------------------------------------------------------------------------
# HIBP breach-by-domain parsing

def _meta():
    return {
        "Adobe": {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04"},
        "LinkedIn": {"Name": "LinkedIn", "Title": "LinkedIn", "BreachDate": "2012-05-05"},
        "Canva": {"Name": "Canva", "Title": "Canva", "BreachDate": "2019-05-24"},
    }


def test_summarize_counts_only():
    # alias -> breaches. Aliases are PII and must never appear in output.
    breached = {
        "jdoe": ["Adobe", "LinkedIn"],
        "asmith": ["Adobe"],
        "bob": ["Adobe", "Canva"],
    }
    summary = summarize_breached_domain(breached, _meta())
    assert summary["accounts"] == 3  # distinct accounts
    assert summary["breach_count"] == 3
    top = summary["breaches"][0]
    assert top["name"] == "Adobe" and top["accounts"] == 3 and top["year"] == "2013"


def test_breach_finding_severity_and_redaction():
    # magnitude scales severity: info / low / medium
    small = breach_finding("a.com", {"accounts": 10, "breach_count": 1,
                                      "breaches": [{"name": "Adobe", "year": "2013", "accounts": 10}]})
    assert small.severity == "info" and small.kind == "breach-exposure" and small.target == "a.com"

    mid = breach_finding("b.com", {"accounts": 80, "breach_count": 1,
                                   "breaches": [{"name": "Adobe", "year": "2013", "accounts": 80}]})
    assert mid.severity == "low"

    big = breach_finding("acme.com", {"accounts": 1240, "breach_count": 3, "breaches": [
        {"name": "Adobe", "year": "2013", "accounts": 900},
        {"name": "LinkedIn", "year": "2012", "accounts": 300},
        {"name": "Canva", "year": "2019", "accounts": 40},
    ]})
    assert big.severity == "medium"
    assert "1,240" in big.detail and "Adobe 2013" in big.detail

    assert breach_finding("none.com", {"accounts": 0, "breach_count": 0, "breaches": []}) is None


def test_breach_finding_never_contains_aliases_or_secrets():
    breached = {
        f"jdoe-{SECRET}": ["Adobe"],
        "password-" + SECRET: ["LinkedIn"],
    }
    summary = summarize_breached_domain(breached, _meta())
    f = breach_finding("acme.com", summary)
    assert SECRET not in f.detail
    assert "jdoe" not in f.detail and "password" not in f.detail


def test_breach_exposure_skips_without_key():
    out = asyncio.run(breach_exposure_findings(client=None, domains=["acme.com"], api_key="", log=lambda m: None))
    assert out == []


# ---------------------------------------------------------------------------
# Email / username format inference

def test_infer_format_with_names():
    emails = ["john.doe@acme.com", "jane.smith@acme.com", "info@acme.com",
              "security@acme.com", "bob.jones@other.com"]
    names = ["John Doe", "Jane Smith"]
    got = infer_email_format(emails, "acme.com", names)
    assert got["template"] == "{first}.{last}"
    assert got["format"] == "{first}.{last}@acme.com"
    assert got["samples"] == 2  # role addrs and other-domain addr excluded

    f = email_format_finding(got)
    assert f.kind == "email-format" and f.severity == "info" and f.target == "acme.com"
    # no raw address leaks into the detail
    assert "@acme.com" in f.detail and "john.doe@acme.com" not in f.detail


def test_infer_format_initial_last():
    emails = ["jdoe@acme.com", "asmith@acme.com"]
    names = ["John Doe", "Alice Smith"]
    got = infer_email_format(emails, "acme.com", names)
    assert got["template"] == "{f}{last}"


def test_infer_format_without_names_defaults_first_last():
    # two plain tokens joined by a dot -> first.last by convention
    got = infer_email_format(["a.bcd@acme.com", "ef.ghi@acme.com"], "acme.com", None)
    assert got["template"] == "{first}.{last}"


def test_infer_format_none_when_only_role_addresses():
    assert infer_email_format(["info@acme.com", "security@acme.com"], "acme.com", None) is None
    assert infer_email_format([], "acme.com", None) is None


# ---------------------------------------------------------------------------
# gitleaks public-repo secret scanning

def test_known_repos_from_site_identity():
    s = Surface(seeds=["acme.com"])
    ident = SiteIdentity(domain="acme.com")
    ident.same_as = {
        "https://github.com/acme/webapp",
        "https://github.com/acme",          # bare org profile, not a repo
        "https://twitter.com/acme",         # not a code host
        "https://gitlab.com/acme/infra/",
    }
    s.site_identity["acme.com"] = ident
    repos = known_repos(s)
    assert "https://github.com/acme/webapp" in repos
    assert "https://gitlab.com/acme/infra" in repos
    assert "https://github.com/acme" not in repos
    assert not any("twitter" in r for r in repos)


def test_parse_gitleaks_redacts_secret_value():
    report = json.dumps([
        {"RuleID": "aws-access-key", "File": "src/config.py", "StartLine": 12,
         "Secret": SECRET, "Match": "aws_key=" + SECRET},
        {"RuleID": "generic-api-key", "File": "deploy/.env", "StartLine": 3,
         "Secret": SECRET, "Match": SECRET},
        {"RuleID": "aws-access-key", "File": "src/other.py", "Secret": SECRET},
    ])
    findings = parse_gitleaks_findings(report, "https://github.com/acme/webapp")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high" and f.kind == "secret-exposure"
    assert SECRET not in f.detail
    assert "aws-access-key x2" in f.detail and "generic-api-key x1" in f.detail
    assert "src/config.py" in f.detail and "deploy/.env" in f.detail


def test_parse_gitleaks_empty_report():
    assert parse_gitleaks_findings("[]", "https://github.com/acme/webapp") == []
    assert parse_gitleaks_findings("not json", "https://github.com/acme/webapp") == []


def test_repo_secret_scan_skips_when_gitleaks_absent():
    class NoTools:
        def available(self, tool):
            return False

        def backend(self, tool):
            return None

    out = asyncio.run(repo_secret_findings(NoTools(), ["https://github.com/acme/webapp"], lambda m: None))
    assert out == []
    # no repos -> no-op even if a tool existed
    assert asyncio.run(repo_secret_findings(NoTools(), [], lambda m: None)) == []


# ---------------------------------------------------------------------------
# End-to-end collect() with no keys/tools: must skip cleanly, never crash

def test_collect_graceful_without_keys_or_tools():
    class NoTools:
        def available(self, tool):
            return False

        def backend(self, tool):
            return None

    s = Surface(seeds=["acme.com"])
    from surface_harness.models import ApexDomain
    s.domains["acme.com"] = ApexDomain("acme.com", seed=True)
    ident = SiteIdentity(domain="acme.com")
    ident.emails = {"john.doe@acme.com", "jane.roe@acme.com", "info@acme.com"}
    s.site_identity["acme.com"] = ident
    s.companies = [CompanyRecord(source="us-co", name="Acme LLC",
                                 officers=[Officer("John Doe", "CEO"), Officer("Jane Roe", "CTO")])]

    cfg = Config(seeds=["acme.com"])  # no HIBP key
    findings = asyncio.run(collect(s, cfg, client=None, runner=NoTools(), log=lambda m: None))
    # HIBP + gitleaks skip; only the email-format finding is produced.
    kinds = {f.kind for f in findings}
    assert kinds == {"email-format"}
    assert all(SECRET not in f.detail for f in findings)
