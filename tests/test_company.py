from surface_harness.company import (
    candidate_names,
    core_name,
    finalize,
    is_commercial_agent,
    parse_site_page,
    relates_to_brand,
    same_entity,
)
from surface_harness.models import CompanyRecord, SiteIdentity


def test_core_name_and_matching():
    assert core_name("Harvest Range Labs, LLC") == "harvest range labs"
    assert core_name("HACKERONE INC.") == "hackerone"
    assert core_name("Complete Mechanical Co., Inc, Dissolved November 16, 2020") == "complete mechanical"
    assert same_entity("Harvest Range Labs L.L.C.", "harvest range labs")
    assert same_entity("HackerOne Inc.", "HACKERONE, INC")
    assert not same_entity("Harvest Range", "Harvest Range Labs")


def test_brand_relation():
    stems = {"harvestrangelabs"}
    assert relates_to_brand("Harvest Range Labs", stems)
    assert relates_to_brand("Harvest Range Labs LLC", stems)
    assert not relates_to_brand("Google LLC", stems)


def test_commercial_agents():
    assert is_commercial_agent("Northwest Registered  Agent, LLC")
    assert is_commercial_agent("NORTHWEST REGISTERED AGENT LLC")
    assert is_commercial_agent("C T Corporation System")
    assert is_commercial_agent("Corporation Service Company")
    assert not is_commercial_agent("Jane Smith")
    assert not is_commercial_agent("Harvest Range Labs LLC")


def test_finalize_flags_agent_and_mail_drops():
    c = finalize(CompanyRecord(source="us-co", name="Harvest Range Labs LLC",
                               agent_name="Northwest Registered Agent, LLC",
                               agent_address="1500 N. Grant Street, Suite N, Denver, CO"))
    assert c.agent_commercial
    assert any("not used for pivoting" in n for n in c.address_notes)

    g = finalize(CompanyRecord(source="gleif", name="HACKERONE INC.",
                               registered_address="C/O BUSINESS FILINGS INCORPORATED, 108 WEST 13TH ST, WILMINGTON",
                               principal_address="548 MARKET STREET, PMB 24734, SAN FRANCISCO"))
    assert g.agent_commercial and g.agent_name.upper().startswith("BUSINESS FILINGS")
    assert any("mail drop" in n for n in g.address_notes)


def test_parse_site_identity():
    html = """<html><head><title>Harvest Range Labs — Adversary Simulation</title>
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization",
      "name":"Harvest Range Labs","legalName":"Harvest Range Labs LLC","email":"hello@harvestrangelabs.com",
      "address":{"@type":"PostalAddress","addressLocality":"Denver","addressRegion":"CO"},
      "sameAs":["https://github.com/BuildAndDestroy"]}</script></head>
    <body><a href="tel:+1 555 010 0000">call</a> Uses Google LLC analytics.
    <footer>© 2026 Harvest Range Labs, LLC. All rights reserved.</footer></body></html>"""
    i = SiteIdentity(domain="harvestrangelabs.com")
    parse_site_page(i, "https://harvestrangelabs.com/", html, {"harvestrangelabs"})
    assert "Harvest Range Labs" in i.display_names
    assert "Harvest Range Labs LLC" in i.legal_names
    assert not any("Google" in n for n in i.legal_names)
    assert "hello@harvestrangelabs.com" in i.emails
    assert "https://github.com/BuildAndDestroy" in i.same_as
    assert "Denver, CO" in i.addresses
    assert i.phones == {"+1 555 010 0000"}

    names = candidate_names([], ["Northwest Registered Agent LLC"], [i])
    assert names[0] in ("Harvest Range Labs LLC", "Harvest Range Labs, LLC")
    assert not any("Northwest" in n for n in names)
    assert len(names) == 1  # all variants collapse to one core name


def test_security_txt():
    i = SiteIdentity(domain="acme.com")
    parse_site_page(i, "https://acme.com/.well-known/security.txt",
                    "Contact: mailto:security@acme.com\nPolicy: https://acme.com/vdp\nExpires: 2027", {"acme"})
    assert "security@acme.com" in i.emails
    assert len(i.security_txt) == 2


def test_trim_noisy_entity_names():
    from surface_harness.company import trim_to_brand
    assert trim_to_brand("Privacy Team HackerOne Inc.", {"hackerone"}) == "HackerOne Inc."
    assert trim_to_brand("Commerce. HackerOne Inc.", {"hackerone"}) == "HackerOne Inc."
    assert trim_to_brand("Contact Harvest Range Labs, LLC", {"harvestrangelabs"}) == "Harvest Range Labs, LLC"
    assert trim_to_brand("Google LLC", {"hackerone"}) is None


def test_title_requires_exact_brand():
    i = SiteIdentity(domain="hackerone.com")
    parse_site_page(i, "https://hackerone.com/privacy", "<title>HackerOne Privacy Policy | HackerOne</title>",
                    {"hackerone"})
    assert i.display_names == {"HackerOne"}


def test_principal_address_is_agent_address():
    c = finalize(CompanyRecord(source="us-or", name="HACKERONE INC.", agent_name="REGISTERED AGENTS INC",
                               agent_address="5441 S MACADAM AVE, PORTLAND, OR, 97239",
                               principal_address="5441 S MACADAM AVE, PORTLAND, OR, 97239"))
    assert any("principal address is the registered agent" in n for n in c.address_notes)
    ny = finalize(CompanyRecord(source="us-ny", name="X", agent_name="REGISTERED AGENTS INC.",
                                mailing_address="REGISTERED AGENTS INC., 418 Broadway STE R, Albany, NY, 12207"))
    assert any("mailing address is the registered agent" in n for n in ny.address_notes)


def test_wikidata_item_parsing():
    import asyncio
    import json

    from surface_harness.company import Registries
    from surface_harness.config import Config

    def b(**kw):
        return {k: {"value": v} for k, v in kw.items()}

    rows = [
        b(label="Acme", official="Acme Corporation", site="https://acme.com/", countryLabel="United States",
          inception="1999-01-01T00:00:00Z", parentLabel="Acme Holdings", parentSite="https://acmeholdings.com/",
          subLabel="Acme Cloud", subSite="https://acmecloud.io/"),
        b(label="Acme", subLabel="Q12345"),  # unlabeled item is ignored
    ]
    cfg = Config(seeds=["acme.com"], keys={"contact": "test"})
    r = Registries(cfg, client=None, log=lambda m: None)

    async def fake_sparql(q):
        return rows
    r._sparql = fake_sparql
    c = asyncio.run(r._wikidata_item("Q1", "domain", ["acme.com"]))
    assert c.name == "Acme" and c.former_names == ["Acme Corporation"]
    assert c.parents == ["Acme Holdings"] and c.subsidiaries == ["Acme Cloud"]
    assert json.loads(c.identifiers["subsidiary_sites"]) == {"Acme Cloud": ["https://acmecloud.io/"]}
    # name-only match whose website isn't ours is rejected
    rows[0]["site"]["value"] = "https://other.com/"
    assert asyncio.run(r._wikidata_item("Q1", "name", ["acme.com"])) is None
