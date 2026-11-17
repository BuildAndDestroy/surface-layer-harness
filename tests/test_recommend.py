import json

from test_engagement import eng, fake_surface  # noqa: F401 - pytest fixture

from surface_harness.cli import main
from surface_harness.engagement import _validate_analysis, write_merged
from surface_harness.recommend import CATALOG, coverage_gaps, recommend_for_engagement, recommend_for_run
from surface_harness.scope import load_scope

ALL_TOOLS = {"subfinder": "docker", "naabu": "docker", "nmap": "docker", "gitleaks": "local", "git": "local"}
ALL_KEYS = ["certspotter", "hibp", "opencorporates", "otx", "securitytrails", "virustotal", "whoisxml"]


def ids(recs):
    return {r["id"] if isinstance(r, dict) else r.tool for r in recs}


def test_coverage_gaps_from_capabilities():
    full = {"keys": ALL_KEYS, "contact": True, "tools": ALL_TOOLS}
    assert ids(coverage_gaps(full, "active", True)) == set()
    assert ids(coverage_gaps(full, "standard", True)) == {"active-mode"}
    gaps = coverage_gaps({"keys": [], "contact": False, "tools": {}}, "passive", False)
    assert {"whoisxml", "opencorporates", "contact", "standard-mode", "active-mode"} <= ids(gaps)
    assert "hibp" not in ids(gaps)  # HIBP only runs in standard/active
    active = next(r for r in gaps if r.tool == "active-mode")
    assert "does not authorise active testing" in active.reason
    no_bins = coverage_gaps({"keys": ALL_KEYS, "contact": True, "tools": dict.fromkeys(ALL_TOOLS)}, "active", True)
    assert ids(no_bins) == {"subfinder", "naabu-nmap", "gitleaks"}
    assert all(r.tool in CATALOG for r in gaps + no_bins)


def test_run_recommendations_follow_findings():
    run = fake_surface("acme.com", "1.1.1.1", "acme").to_dict()
    run["meta"]["config"].update(mode="standard", api_keys_present=[])
    recs = {r["id"]: r for r in recommend_for_run(run, active_allowed=False)}
    # complementary tools triggered by what was found
    assert {"gowitness", "nuclei", "testssl", "dnstwist", "cloud-posture", "m365-posture",
            "web-app-testing", "code-search"} <= set(recs)
    assert recs["testssl"]["priority"] == "medium"  # weak TLS protocol in the fake run
    assert "federated" in recs["m365-posture"]["reasons"][0]
    assert recs["code-search"]["priority"] == "medium"  # github sameAs link
    # coverage gaps come first in the ordering
    ordered = recommend_for_run(run)
    kinds = [r["kind"] for r in ordered]
    assert kinds == sorted(kinds, key=lambda k: k != "coverage-gap")
    # no capabilities recorded (older run): binary gaps aren't guessed
    assert "subfinder" not in recs


def test_engagement_merges_analyst_recommendations():
    targets = [
        {"id": "a", "recommendations": recommend_for_run(fake_surface("a.com", "1.1.1.1", "a").to_dict()),
         "analysis": {"tool_recommendations": [
             {"tool": "Nuclei", "priority": "high", "reason": "Jenkins 2.1 exposed"},
             {"tool": "BloodHound CE", "reason": "AD exposure suspected", "area": "Identity"}]}},
        {"id": "b", "recommendations": recommend_for_run(fake_surface("b.com", "1.1.1.1", "b").to_dict())},
    ]
    recs = {r["id"]: r for r in recommend_for_engagement(targets, False)}
    assert recs["nuclei"]["priority"] == "high" and recs["nuclei"]["targets"] == ["a", "b"]
    assert "[a] analyst: Jenkins 2.1 exposed" in recs["nuclei"]["reasons"]
    # the same generic reason for both targets is listed once, tagged with both
    assert any(r.startswith("[a, b] ") for r in recs["nuclei"]["reasons"])
    assert recs["BloodHound CE"]["kind"] == "analyst" and recs["BloodHound CE"]["area"] == "Identity"


def test_merge_report_and_graphql(eng):  # noqa: F811
    a = json.loads((eng / "targets" / "acme" / "analysis.json").read_text())
    a["tool_recommendations"] = [{"tool": "dnstwist", "priority": "high", "reason": "phishing seen"}]
    (eng / "targets" / "acme" / "analysis.json").write_text(json.dumps(a))

    doc = write_merged(load_scope(eng))
    assert doc["schema_version"] == "1.2"
    recs = {r["id"]: r for r in doc["tool_recommendations"]}
    assert recs["dnstwist"]["priority"] == "high"
    assert doc["targets"][0]["analysis_warnings"] == []
    report = (eng / "report.md").read_text()
    assert report.count("## Recommended tools for a complete picture") == 1  # not repeated per target
    assert "### Complementary tools (outside the harness)" in report and "[dnstwist](" in report
    run_md = next((eng / "targets" / "acme" / "runs").glob("*/report.md")).read_text()
    assert run_md.rstrip().endswith("|") and "## Recommended tools for a complete picture" in run_md
    assert (run_md.split("## Recommended tools")[1]).count("\n## ") == 0  # last section

    from surface_harness import gql
    gql.load(eng)
    r = gql.schema.execute_sync('{ toolRecommendations(minPriority: "medium", kind: "complementary") '
                                '{ id priority targets reasons needs } }')
    assert r.errors is None, r.errors
    got = {x["id"]: x for x in r.data["toolRecommendations"]}
    assert "dnstwist" in got and "mobile-apps" not in got  # low priority filtered out
    assert got["nuclei"]["targets"] == ["acme", "beta"]


def test_analysis_validation():
    base = {"schema": "surface-harness/analysis", "target_id": "acme"}
    assert _validate_analysis({**base, "tool_recommendations": [{"tool": "nuclei", "reason": "x"}]}, "acme") == []
    assert _validate_analysis({**base, "tool_recommendations": [{"tool": "nuclei"}]}, "acme") == [
        "tool_recommendations[0] needs 'tool' and 'reason'"]
    assert _validate_analysis({**base, "tool_recommendations": "nuclei"}, "acme") == [
        "tool_recommendations should be a list"]


def test_doctor_cli(eng, capsys):  # noqa: F811
    assert main(["doctor", str(eng), "--tools", "none", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["modes"] == ["standard"] and out["active_allowed"] is False
    assert "active-mode" in ids(out["coverage_gaps"]) and "subfinder" in ids(out["coverage_gaps"])
