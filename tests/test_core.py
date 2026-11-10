
from surface_harness.config import Config
from surface_harness.domains import apex, normalize, stem_similarity
from surface_harness.models import ApexDomain, Host, Surface
from surface_harness.related import RelatedDiscovery, _parse_rdap
from surface_harness.sources import _filter
from surface_harness.takeover import assess


def test_normalize():
    assert normalize("*.Foo.Example.COM.") == "foo.example.com"
    assert normalize("https://a.b.com:8443/path") == "a.b.com"
    assert normalize("user@mail.acme.com") == "mail.acme.com"
    assert normalize("not a domain") is None
    assert normalize("-bad.com") is None


def test_apex_multi_part_suffix():
    assert apex("a.b.acme.co.uk") == "acme.co.uk"
    assert apex("www.acme.com") == "acme.com"
    assert apex("co.uk") is None


def test_stem_similarity():
    stems = {"acme"}
    assert stem_similarity("acme.io", stems) == "acme"
    assert stem_similarity("acmecorp.com", stems) == "acme"
    assert stem_similarity("acme-cloud.net", stems) == "acme"
    assert stem_similarity("unrelated.com", stems) is None
    # short stems only match exactly
    assert stem_similarity("ibmcloud.com", {"ibm"}) is None
    assert stem_similarity("ibm.net", {"ibm"}) == "ibm"


def test_filter_keeps_only_subdomains():
    got = _filter(["a.acme.com\n*.b.acme.com", "evil-acme.com", "x.notacme.com", "ACME.COM"], "acme.com")
    assert got == {"a.acme.com", "b.acme.com", "acme.com"}


def test_confidence_combination():
    d = ApexDomain("acme.io")
    d.add_evidence("cert-san", "x", 0.5)
    d.add_evidence("brand", "y", 0.4)
    assert d.confidence == 0.7
    d.add_evidence("brand", "y", 0.4)  # duplicate evidence ignored
    assert d.confidence == 0.7
    assert ApexDomain("acme.com", seed=True).confidence == 1.0


def _rel(seeds=("acme.com",)):
    s = Surface(seeds=list(seeds))
    for sd in seeds:
        s.domains[sd] = ApexDomain(sd, seed=True)
    return s, RelatedDiscovery(s, Config(seeds=list(seeds)), client=None, dns=None, log=lambda m: None)


def test_candidates_skip_third_party_and_exclusions():
    _s, rel = _rel()
    rel.cfg.exclude = ["acme-legacy.com"]
    assert rel.add_candidate("aspmx.l.google.com", "dns-mail", "mx", 1) is None
    assert rel.add_candidate("x.acme-legacy.com", "cert-san", "c", 1) is None
    d = rel.add_candidate("www.acme.io", "cert-san", "shared cert", 1)
    assert d.name == "acme.io"
    assert {e.signal for e in d.evidence} == {"brand", "cert-san"}
    assert d.confidence >= 0.7


def test_redirect_and_unrelated_links():
    s, rel = _rel()
    rel.from_redirect("www.acme.com", "https://www.acmegroup.com/en", 0)
    assert "acmegroup.com" in s.domains
    rel.from_links("www.acme.com", '<a href="https://random-site.org/x">', 0)
    assert "random-site.org" not in s.domains


def test_rdap_parse_redaction():
    data = {
        "events": [{"eventAction": "registration", "eventDate": "2001-01-01"}],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Inc"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                ["org", {}, "text", "Acme Corporation"],
                ["email", {}, "text", "hostmaster@acme.com"]]]},
        ],
    }
    p = _parse_rdap(data)
    assert p["org"] == "Acme Corporation"
    assert p["name"] is None
    assert p["email"] == "hostmaster@acme.com"
    assert p["registrar"] == "Registrar Inc"


def test_takeover_assessment():
    h = Host("docs.acme.com", "acme.com", cnames=["acme.github.io"])
    f = assess(h, "exists", ["There isn't a GitHub Pages site here."])
    assert f and f.severity == "high"
    h2 = Host("old.acme.com", "acme.com", cnames=["acme-old.azurewebsites.net"])
    assert assess(h2, "nxdomain", []).severity == "high"
    h3 = Host("x.acme.com", "acme.com", cnames=["gone.example-vendor.com"])
    assert assess(h3, "nxdomain", []).kind == "dangling-cname"
    assert assess(h3, "exists", []) is None


def test_active_requires_authorization():
    import pytest

    from surface_harness.cli import parse_args
    with pytest.raises(SystemExit):
        parse_args(["-m", "active", "acme.com"])
    cfg = parse_args(["-m", "active", "--authorized", "acme.com"])
    assert cfg.active


def test_repeated_signal_counts_once():
    d = ApexDomain("acme-partners.com")
    d.add_evidence("brand", "b", 0.4)
    for i in range(10):
        d.add_evidence("html-link", f"linked from page {i}", 0.15)
    assert d.confidence == round(1 - 0.6 * 0.85, 3)


NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV">
<host><status state="up"/><address addr="203.0.113.7" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/></port>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain" method="table" conf="3"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp" method="table" conf="3"/></port>
</ports></host></nmaprun>
"""


def test_parse_nmap_xml():
    from surface_harness.ports import parse_nmap_xml

    out = parse_nmap_xml("Starting Nmap...\n" + NMAP_XML)
    svcs = out["203.0.113.7"]
    assert set(svcs) == {22, 443, 53}  # filtered port dropped
    assert svcs[22]["product"] == "OpenSSH" and svcs[22]["version"].startswith("9.6p1")
    assert svcs[22]["cpe"] == ["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]
    assert svcs[22]["summary"] == "ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)"
    assert svcs[443]["summary"] == "ssl/http nginx"
    assert svcs[53]["method"] == "table"
    assert parse_nmap_xml("garbage") == {}
