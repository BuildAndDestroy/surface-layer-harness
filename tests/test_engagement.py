import json
from pathlib import Path

import pytest

from surface_harness.engagement import write_merged
from surface_harness.models import (
    ApexDomain,
    BreachExposure,
    CloudAsset,
    CompanyRecord,
    DnsHygiene,
    EmailFormat,
    EmailSecurity,
    Finding,
    Host,
    HttpService,
    IpInfo,
    M365Tenant,
    Officer,
    SiteIdentity,
    Surface,
    TlsConfig,
)
from surface_harness.report import write_all
from surface_harness.scope import ScopeError, load_scope

SCOPE = """
engagement: test-eng
client: "Test Client"
authorization: {reference: "SOW-1", active_testing: false}
defaults: {mode: standard, depth: 1, threshold: 0.7}
exclude: [vendor.com]
targets:
  - id: acme
    name: Acme Inc.
    domains: [acme.com]
    org: ["Acme Inc."]
  - id: beta
    name: Beta LLC
    domains: [beta.io]
  - id: never-run
    domains: [gamma.net]
"""


def fake_surface(seed: str, shared_ip: str, tid: str) -> Surface:
    s = Surface(seeds=[seed])
    s.meta = {"status": "complete", "started_at": "2026-11-09T10:00:00", "target_id": tid,
              "config": {"threshold": 0.7}}
    s.domains[seed] = ApexDomain(seed, seed=True)
    cand = ApexDomain("cand-" + seed)
    cand.add_evidence("cert-san", "shares cert", 0.5)
    s.domains[cand.name] = cand
    h = Host(f"www.{seed}", seed, sources={"crtsh"}, a=[shared_ip], resolved=True, cnames=[],
             http=[HttpService(url=f"https://www.{seed}/", status=200, title="Home", tech=["Jenkins"])],
             open_ports=[443, 6379])
    s.hosts[h.name] = h
    s.ips[shared_ip] = IpInfo(shared_ip, asn="13335", as_name="CLOUDFLARENET", hosts={h.name},
                              open_ports=[443, 6379],
                              services=[{"port": 6379, "protocol": "tcp", "service": "redis", "product": "Redis key-value store",
                                         "version": "7.2.4", "extra_info": None, "tunnel": None, "os_type": None,
                                         "cpe": ["cpe:/a:redis:redis:7.2.4"], "method": "probed", "conf": 10,
                                         "summary": "redis Redis key-value store 7.2.4"}])
    s.findings.append(Finding("low", "exposed-interface", f"https://www.{seed}/", "Jenkins exposed"))
    s.companies.append(CompanyRecord(source="us-co", name=f"{seed} Inc", company_number="123" + tid,
                                     agent_name="Northwest Registered Agent, LLC", agent_commercial=True,
                                     officers=[Officer("Jane Doe", "manager")]))
    s.site_identity[seed] = SiteIdentity(seed, same_as={"https://github.com/" + tid})
    # structured posture records
    s.email_security[seed] = EmailSecurity(domain=seed, spf="v=spf1 -all", spf_all="-all",
                                           spf_lookups=1, spf_records=1, dmarc_policy="none",
                                           dmarc_rua=True, dkim_selectors=["google"], mta_sts=True)
    s.dns_hygiene[seed] = DnsHygiene(domain=seed, nameservers=[f"ns1.{seed}"], dnssec=False, caa=True)
    s.tls_config.append(TlsConfig(host=f"www.{seed}", port=443, weak_protocols=["TLSv1.0"],
                                  hsts=False, not_after="2027-01-01T00:00:00", expires_in_days=400))
    s.m365_tenants.append(M365Tenant(domain=seed, tenant_id="11111111-2222-3333-4444-555555555555",
                                     namespace="Federated", federation_host="adfs." + seed))
    s.cloud_assets.append(CloudAsset(name=tid + "-backup", provider="s3",
                                     url=f"https://{tid}-backup.s3.amazonaws.com", state="public"))
    s.breaches.append(BreachExposure(domain=seed, accounts=1200, breach_count=2,
                                     breaches=[{"name": "Adobe", "year": "2013", "accounts": 1000}]))
    s.email_formats.append(EmailFormat(domain=seed, format="{first}.{last}@" + seed,
                                       template="{first}.{last}", samples=3, considered=5))
    return s


@pytest.fixture
def eng(tmp_path: Path):
    (tmp_path / "scope.yaml").write_text(SCOPE)
    for tid, seed in (("acme", "acme.com"), ("beta", "beta.io")):
        write_all(fake_surface(seed, "1.1.1.1", tid), tmp_path / "targets" / tid / "runs" / "20261109-100000", 0.7)
    (tmp_path / "targets" / "acme" / "analysis.json").write_text(json.dumps({
        "schema": "surface-harness/analysis", "schema_version": "1.0", "target_id": "acme",
        "summary": "ok", "scope_decisions": [{"domain": "cand-acme.com", "decision": "in-scope", "rationale": "x"}],
        "findings": [{"severity": "high", "status": "confirmed", "title": "Takeover", "asset": "www.acme.com"}]}))
    (tmp_path / "targets" / "acme" / "analysis.md").write_text("# Acme analysis\n\n## Detail\nlooks fine\n")
    (tmp_path / "summary.md").write_text("# Executive summary\n\nTwo targets reviewed.\n")
    return tmp_path


def test_scope_validation(tmp_path):
    (tmp_path / "scope.yaml").write_text(SCOPE.replace('reference: "SOW-1", ', ""))
    with pytest.raises(ScopeError, match=r"authorization\.reference"):
        load_scope(tmp_path)
    (tmp_path / "scope.yaml").write_text(SCOPE)
    sc = load_scope(tmp_path)
    cfg = sc.config_for(sc.target("acme"))
    assert cfg.exclude == ["vendor.com"] and cfg.out_dir.endswith("targets/acme/runs")
    with pytest.raises(ScopeError, match="active_testing"):
        sc.config_for(sc.target("acme"), mode="active")


def test_merge_report_graph(eng):
    sc = load_scope(eng)
    doc = write_merged(sc)
    assert doc["schema"] == "surface-harness/engagement"
    st = {t["id"]: t["status"] for t in doc["targets"]}
    assert st == {"acme": "complete", "beta": "complete", "never-run": "missing"}
    acme = doc["targets"][0]
    assert acme["summary"]["live_hosts"] == 1 and acme["analysis_warnings"] == []
    assert doc["cross_target"]["shared_ips"] == {"1.1.1.1": ["acme", "beta"]}

    report = (eng / "report.md").read_text()
    assert report.startswith("# Attack surface assessment: Test Client")
    assert "## Executive summary" in report and "Two targets reviewed." in report
    assert "| high | `acme` | confirmed | Takeover |" in report
    assert "### Analyst notes" in report and "#### Detail" in report  # demoted headings
    assert "### Company" in report  # run report demoted under target heading
    assert "_No harness run found for this target._" in report

    g = json.loads((eng / "graph.json").read_text())
    ids = {n["id"] for n in g["nodes"]}
    assert {"ip:1.1.1.1", "agent:northwestregisteredagentllc", "target:acme", "domain:acme.com"} <= ids
    ip = next(n for n in g["nodes"] if n["id"] == "ip:1.1.1.1")
    assert sorted(ip["targets"]) == ["acme", "beta"]
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    port = next(n for n in g["nodes"] if n["id"] == "port:1.1.1.1:6379")
    assert port["type"] == "Port" and port["label"] == "6379/tcp redis · Redis key-value store 7.2.4"
    assert port["props"]["cpe"] == ["cpe:/a:redis:redis:7.2.4"]
    assert any(e["source"] == "ip:1.1.1.1" and e["target"] == "port:1.1.1.1:443" and e["type"] == "HAS_PORT"
               for e in g["edges"])
    cy = (eng / "graph.cypher").read_text()
    assert "MERGE (n:IP {id: \"ip:1.1.1.1\"})" in cy
    assert "<\\/" in (eng / "graph.html").read_text() or "</script>" in (eng / "graph.html").read_text()


def test_graphql(eng):
    from surface_harness import gql

    write_merged(load_scope(eng))
    gql.load(eng)
    r = gql.schema.execute_sync("""{
      engagement { client authorization }
      targets { id status summary findings(minSeverity: "high") { origin severity detail }
                entities { name agentName agentCommercial officers { name role } } }
      hosts(tech: "jenkins") { name targetId http { status title } }
      domains(inScopeOnly: true) { name confidence }
      findings(minSeverity: "low") { targetId severity origin }
      byKind: findings(kind: "exposed-interface") { targetId kind origin }
      emailSecurity(targetId: "acme") { domain spfAll dmarcPolicy dkimSelectors mtaSts }
      dnsHygiene(targetId: "acme") { domain caa dnssec nameservers }
      tlsConfig(weakOnly: true) { host port weakProtocols hsts }
      m365Tenants(targetId: "acme") { domain tenantId namespace federationHost }
      cloudAssets(provider: "s3") { name provider state url }
      breaches(targetId: "acme") { domain accounts breachCount breaches { name year accounts } }
      emailFormats(targetId: "acme") { domain format template samples }
      ports(service: "https") { targetId ip port hosts web { status url } }
      ips(targetId: "acme") { ip openPorts }
      redis: ports(port: 6379, targetId: "beta") { hosts product version cpe detection nmap }
      byProduct: ports(product: "redis") { targetId }
    }""")
    assert r.errors is None, r.errors
    d = r.data
    assert d["engagement"]["client"] == "Test Client"
    acme = d["targets"][0]
    assert acme["findings"] == [{"origin": "analyst", "severity": "high", "detail": "Takeover"}]
    assert acme["entities"][0]["agentCommercial"] is True
    assert {h["name"] for h in d["hosts"]} == {"www.acme.com", "www.beta.io"}
    assert {x["name"] for x in d["domains"]} == {"acme.com", "beta.io"}
    assert d["findings"][0]["severity"] == "high"
    assert d["byKind"] and all(f["kind"] == "exposed-interface" and f["origin"] == "harness"
                               for f in d["byKind"])
    assert d["emailSecurity"] == [{"domain": "acme.com", "spfAll": "-all", "dmarcPolicy": "none",
                                   "dkimSelectors": ["google"], "mtaSts": True}]
    assert d["dnsHygiene"] == [{"domain": "acme.com", "caa": True, "dnssec": False,
                                "nameservers": ["ns1.acme.com"]}]
    assert d["tlsConfig"] == [{"host": "www.acme.com", "port": 443, "weakProtocols": ["TLSv1.0"],
                               "hsts": False}, {"host": "www.beta.io", "port": 443,
                               "weakProtocols": ["TLSv1.0"], "hsts": False}]
    assert d["m365Tenants"][0]["namespace"] == "Federated" and d["m365Tenants"][0]["federationHost"] == "adfs.acme.com"
    assert {a["name"] for a in d["cloudAssets"]} == {"acme-backup", "beta-backup"}
    assert d["breaches"] == [{"domain": "acme.com", "accounts": 1200, "breachCount": 2,
                              "breaches": [{"name": "Adobe", "year": "2013", "accounts": 1000}]}]
    assert d["emailFormats"] == [{"domain": "acme.com", "format": "{first}.{last}@acme.com",
                                  "template": "{first}.{last}", "samples": 3}]
    assert {(p["targetId"], p["port"]) for p in d["ports"]} == {("acme", 443), ("beta", 443)}
    assert d["ports"][0]["web"] == [{"status": 200, "url": "https://www.acme.com/"}]
    assert d["ips"] == [{"ip": "1.1.1.1", "openPorts": [443, 6379]}]
    assert d["redis"] == [{"hosts": ["www.beta.io"], "product": "Redis key-value store", "version": "7.2.4",
                           "cpe": ["cpe:/a:redis:redis:7.2.4"], "detection": "probed",
                           "nmap": "redis Redis key-value store 7.2.4"}]
    assert len(d["byProduct"]) == 2
    rep = (eng / "targets" / "acme" / "runs" / "20261109-100000" / "report.md").read_text()
    assert "## Open ports and services" in rep and "| 1.1.1.1 | 6379/tcp | redis | Redis key-value store | 7.2.4 |" in rep
