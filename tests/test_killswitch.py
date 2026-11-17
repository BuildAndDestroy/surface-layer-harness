"""Third-party protection: scoring gate, registrant veto, cleared-host filter, tripwire,
redirects that leave scope, and the dated run-directory layout / report.html."""

import asyncio
import json

import httpx
import pytest

from surface_harness.config import Config
from surface_harness.engagement import write_merged
from surface_harness.models import ASSOCIATION_CAP, ApexDomain, Finding, Host, Surface
from surface_harness.pipeline import KillSwitch, Pipeline
from surface_harness.probe import http_probe
from surface_harness.related import RelatedDiscovery
from surface_harness.report import write_all
from surface_harness.scope import ScopeError, load_scope, run_names


def _pipe(seeds=("platform.com",), **kw) -> Pipeline:
    return Pipeline(Config(seeds=list(seeds), tools="none", **kw), log=lambda m: None, checkpoint=lambda s: None)


def _rel(pipe: Pipeline) -> RelatedDiscovery:
    return RelatedDiscovery(pipe.s, pipe.cfg, client=None, dns=None, log=lambda m: None)


def test_association_evidence_alone_never_reaches_scope():
    # The customer-tenant case: a tenant host redirects to the customer and shares a cert with it.
    d = ApexDomain("customer.com")
    d.add_evidence("redirect", "tenant.platform.com redirects to sso.customer.com", 0.6)
    d.add_evidence("cert-san", "in live TLS cert SANs of tenant.platform.com", 0.5)
    d.add_evidence("html-link", "linked", 0.15)
    d.add_evidence("dns-mail", "mx", 0.15)
    assert d.raw_confidence > 0.8
    assert d.confidence == ASSOCIATION_CAP and not d.ownership
    assert "no ownership evidence" in d.blocked
    d.add_evidence("cert-org", "cert issued to O='Platform Inc'", 0.6)  # real ownership evidence
    assert d.ownership and d.confidence == d.raw_confidence and not d.blocked


def test_live_cert_must_cover_the_host():
    rel = _rel(_pipe())
    # Tenant presents the customer's own certificate: it does not name the platform at all.
    rel.from_live_cert("tenant.platform.com", ["www.customer.com", "customer.org"], 0)
    assert "customer.com" not in rel.s.domains
    # A certificate shared between the platform and another name does link them.
    rel.from_live_cert("www.platform.com", ["platform.com", "platform-cdn.net"], 0)
    assert "platform-cdn.net" in rel.s.domains


def test_registrant_veto_beats_all_other_evidence():
    pipe = _pipe(seeds=("acme.com",))
    pipe.s.org_names.add("Acme Inc.")
    rel = _rel(pipe)
    theirs = rel.add_candidate("acme-rewards.com", "cert-san", "shared cert", 1)   # brand + cert-san = 0.7
    ours = rel.add_candidate("acme-labs.com", "cert-san", "shared cert", 1)
    redacted = rel.add_candidate("acme-shop.com", "cert-san", "shared cert", 1)
    answers = {"acme-rewards.com": {"org": "Loyalty Partners GmbH", "registrar": "Some Registrar"},
               "acme-labs.com": {"org": "ACME, Inc", "registrar": "Some Registrar"},
               "acme-shop.com": {"registrar": "Some Registrar"}}

    async def rdap(name):
        return answers[name]

    rel.rdap = rdap
    asyncio.run(rel.verify_by_registrant())
    assert theirs.third_party and theirs.confidence <= 0.2 and pipe.cleared("www.acme-rewards.com") is None
    assert not ours.third_party and pipe.cleared("www.acme-labs.com") is ours
    assert not redacted.third_party and pipe.cleared("acme-shop.com") is redacted


def test_nothing_is_cleared_before_registration_is_checked():
    pipe = _pipe(seeds=("acme.com",))
    d = _rel(pipe).add_candidate("acme.io", "cert-san", "shared cert", 1)
    assert d.confidence >= 0.7 and pipe.in_scope_apex_of("x.acme.io") is d
    assert not pipe.allowed("x.acme.io")  # not vetted yet
    d.vetted = True
    assert pipe.allowed("x.acme.io")
    assert pipe.allowed("www.acme.com") and not pipe.allowed("www.someone-else.com")
    pipe.cfg.exclude = ["acme.io"]
    assert not pipe.allowed("x.acme.io")


def test_resolve_skips_uncleared_hosts_and_guard_kills():
    pipe = _pipe()
    cust = ApexDomain("customer.com")
    cust.add_evidence("redirect", "r", 0.6)
    cust.add_evidence("cert-san", "c", 0.5)
    pipe.s.domains["customer.com"] = cust
    pipe.s.hosts["sso.customer.com"] = Host("sso.customer.com", "customer.com")
    pipe.s.hosts["www.platform.com"] = Host("www.platform.com", "platform.com")
    asked = []

    async def resolve_host(name):
        asked.append(name)
        return {"a": ["192.0.2.1"], "aaaa": [], "cname": []}

    async def wildcard_ips(apex_name):
        return set()

    pipe.dns.resolve_host, pipe.dns.wildcard_ips = resolve_host, wildcard_ips
    asyncio.run(pipe.resolve_pending())
    assert asked == ["www.platform.com"]
    assert pipe.s.hosts["sso.customer.com"].resolved is None

    pipe.guard("www.platform.com", "probe")  # cleared: no exception
    with pytest.raises(KillSwitch, match=r"sso\.customer\.com.*no ownership evidence"):
        pipe.guard("sso.customer.com", "probe")
    assert pipe.killed
    with pytest.raises(KillSwitch):  # once tripped, every further request is refused
        pipe.guard("www.platform.com", "probe")
    pipe.report_blocked()
    assert [b["domain"] for b in pipe.s.meta["third_party_blocked"]] == ["customer.com"]


def test_probe_does_not_follow_redirects_out_of_scope():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.host)
        if req.url.host == "tenant.platform.com":
            return httpx.Response(302, headers={"location": "https://www.platform.com/start"})
        if req.url.host == "www.platform.com":
            return httpx.Response(302, headers={"location": "https://sso.customer.com/login?x=1"})
        return httpx.Response(200, text="<title>Customer SSO</title>")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as c:
            return await http_probe(c, "https://tenant.platform.com/", lambda h: h.endswith("platform.com"))

    svc, _body = asyncio.run(go())
    assert seen == ["tenant.platform.com", "www.platform.com"]  # the customer was never contacted
    assert svc.offscope_redirect == "https://sso.customer.com/login?x=1"
    assert svc.status == 302 and svc.final_url == "https://www.platform.com/start"


def test_threshold_cannot_be_lowered_into_association_range(tmp_path):
    with pytest.raises(ValueError, match="threshold"):
        _pipe(expand_threshold=ASSOCIATION_CAP)
    (tmp_path / "scope.yaml").write_text(SCOPE.replace("threshold: 0.7", "threshold: 0.4"))
    sc = load_scope(tmp_path)
    with pytest.raises(ScopeError, match="threshold"):
        sc.config_for(sc.target("acme"))


def test_urls_txt_and_report_exclude_third_parties(tmp_path):
    s = Surface(seeds=["platform.com"])
    s.domains["platform.com"] = ApexDomain("platform.com", seed=True)
    h = Host("t.platform.com", "platform.com", resolved=True)
    from surface_harness.models import HttpService
    h.http = [HttpService(url="https://t.platform.com/", status=200, final_url="https://sso.customer.com/x"),
              HttpService(url="https://t.platform.com/a", status=200, final_url="https://www.platform.com/a")]
    s.hosts[h.name] = h
    s.meta = {"status": "killed", "kill_switch": {"reason": "refused to probe sso.customer.com"},
              "third_party_blocked": [{"domain": "customer.com", "evidence_score": 0.83, "reason": "no ownership evidence"}]}
    write_all(s, tmp_path, 0.7)
    assert (tmp_path / "urls.txt").read_text().split() == ["https://www.platform.com/a"]
    rep = (tmp_path / "report.md").read_text()
    assert "KILL-SWITCH: run stopped." in rep and "| customer.com | 0.83 |" in rep


SCOPE = """
engagement: test-eng
client: "Test Client"
authorization: {reference: "SOW-1", active_testing: false}
defaults: {mode: standard, depth: 1, threshold: 0.7}
targets:
  - id: acme
    domains: [acme.com]
"""


def _surface(detail: str, status: str = "complete") -> Surface:
    s = Surface(seeds=["acme.com"])
    s.meta = {"status": status, "started_at": "2026-11-16T10:00:00", "config": {"threshold": 0.7}}
    if status == "killed":
        s.meta["kill_switch"] = {"reason": "refused to probe sso.customer.com"}
        s.meta["third_party_blocked"] = [{"domain": "customer.com", "evidence_score": 0.83, "reason": "no ownership evidence"}]
    s.domains["acme.com"] = ApexDomain("acme.com", seed=True)
    s.findings.append(Finding("medium", "email-dmarc", "acme.com", detail))
    return s


def test_each_engagement_run_gets_its_own_directory(tmp_path):
    (tmp_path / "scope.yaml").write_text(SCOPE)
    sc = load_scope(tmp_path)
    assert sc.run is None and sc.out_root == tmp_path
    first = sc.new_run()
    assert first.parent == tmp_path and (first / "scope.yaml").read_text() == SCOPE
    assert sc.target_dir("acme") == first / "targets" / "acme"
    write_all(_surface("first run"), sc.target_dir("acme") / "runs" / "20261116-100000", 0.7)
    (first / "summary.md").write_text("# Executive summary\n\nFirst.\n")
    (sc.target_dir("acme") / "analysis.json").write_text(json.dumps({
        "schema": "surface-harness/analysis", "target_id": "acme",
        "scope_decisions": [{"domain": "acme.io", "decision": "needs-client-confirmation", "rationale": "redacted"}],
        "findings": [{"ref": "email-dmarc:acme.com", "asset": "acme.com", "severity": "medium", "status": "confirmed",
                      "title": "No DMARC </script><script>alert(1)</script>", "evidence": "dig", "recommendation": "Publish DMARC"}]}))
    write_merged(sc)

    # The scope changes and a second run happens: nothing from the first run is touched.
    (tmp_path / "scope.yaml").write_text(SCOPE.replace("Test Client", "Renamed Client"))
    sc2 = load_scope(tmp_path)
    second = sc2.new_run()
    assert second != first and run_names(tmp_path) == [first.name, second.name]
    write_all(_surface("second run", status="killed"), sc2.target_dir("acme") / "runs" / "20261116-110000", 0.7)
    doc2 = write_merged(sc2)
    assert doc2["run"] == second.name and doc2["targets"][0]["status"] == "killed"
    assert doc2["targets"][0]["analysis"] is None  # the first run's analysis does not leak into the second

    doc1 = json.loads((first / "engagement.json").read_text())
    assert doc1["run"] == first.name and doc1["engagement"]["client"] == "Test Client"
    assert doc1["targets"][0]["surface"]["findings"][0]["detail"] == "first run"
    assert "First." in (first / "report.md").read_text()
    assert not (tmp_path / "engagement.json").exists() and not (tmp_path / "targets").exists()
    assert (tmp_path / "latest").resolve() == second.resolve()

    # merge with no run named -> latest; naming a run directory -> that run, with its own scope.
    assert load_scope(tmp_path, read_only=True).run == second.name
    old = load_scope(first, read_only=True)
    assert old.run == first.name and old.client == "Test Client" and old.root == tmp_path
    assert load_scope(first).client == "Renamed Client"  # running into an existing run uses the live scope

    for run_dir, needle in ((first, "Publish DMARC"), (second, "refused to probe sso.customer.com")):
        html = (run_dir / "report.html").read_text()
        assert needle in html and html.count("</script>") == 2  # scan data cannot close the data block
    data = json.loads((second / "report.html").read_text().split('type="application/json">')[1].split("</script>")[0])
    assert data["blocked"][0]["domain"] == "customer.com" and data["targets"][0]["kill"]
    assert data["playbook"]["email-dmarc"]
    assert "KILL-SWITCH: target `acme` was stopped." in (second / "report.md").read_text()


def test_graphql_serves_latest_run(tmp_path):
    from surface_harness import gql

    (tmp_path / "scope.yaml").write_text(SCOPE)
    sc = load_scope(tmp_path)
    sc.new_run()
    write_all(_surface("only run"), sc.target_dir("acme") / "runs" / "20261116-100000", 0.7)
    write_merged(sc)
    gql.load(tmp_path)
    r = gql.schema.execute_sync("{ targets { id status } }")
    assert r.errors is None and r.data["targets"] == [{"id": "acme", "status": "complete"}]
