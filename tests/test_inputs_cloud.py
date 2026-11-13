"""CIDR/ASN scope input + passive cloud discovery. No live network."""

import pytest

from surface_harness.cloud import (
    brand_stems,
    bucket_candidates,
    classify_bucket,
    parse_openid_config,
    parse_userrealm,
)
from surface_harness.networks import (
    MAX_NETWORK_HOSTS,
    expand_networks,
    normalize_asn,
    parse_ripe_prefixes,
    validate_asns,
    validate_networks,
)


# -- CIDR parsing / validation ------------------------------------------------
def test_validate_networks_ok_and_canonical():
    assert validate_networks(["203.0.113.0/24", "10.0.0.5/32"]) == ["203.0.113.0/24", "10.0.0.5/32"]
    # host bits set + strict=False -> canonical network address
    assert validate_networks(["203.0.113.7/24"]) == ["203.0.113.0/24"]


def test_validate_networks_rejects_malformed():
    with pytest.raises(ValueError, match="invalid CIDR"):
        validate_networks(["not-a-cidr"])
    with pytest.raises(ValueError, match="invalid CIDR"):
        validate_networks(["203.0.113.0/33"])


def test_expand_small_network():
    ips, notes = expand_networks(["203.0.113.0/30"])
    # /30 host addresses exclude network + broadcast -> .1 and .2
    assert ips == ["203.0.113.1", "203.0.113.2"]
    assert notes == []


def test_expand_single_host():
    ips, notes = expand_networks(["198.51.100.9/32"])
    assert ips == ["198.51.100.9"]
    assert notes == []


def test_expand_dedupes_overlapping_ranges():
    ips, _ = expand_networks(["203.0.113.0/30", "203.0.113.0/29"])
    assert len(ips) == len(set(ips))
    assert ips.count("203.0.113.1") == 1


def test_expand_cap_truncates_large_network():
    # /16 == 65536 addresses; capped well below that.
    ips, notes = expand_networks(["10.0.0.0/16"], cap=50)
    assert len(ips) == 50
    assert any("cap" in n for n in notes)


def test_default_cap_is_a_slash_20():
    assert MAX_NETWORK_HOSTS == 4096  # one IPv4 /20


def test_expand_skips_invalid_cidr_with_note():
    ips, notes = expand_networks(["garbage", "198.51.100.0/31"])
    assert ips == ["198.51.100.0", "198.51.100.1"]
    assert any("skipped invalid" in n for n in notes)


# -- ASN validation -----------------------------------------------------------
def test_normalize_asn():
    assert normalize_asn("AS64500") == "AS64500"
    assert normalize_asn("as64500") == "AS64500"
    assert normalize_asn("64500") == "AS64500"
    assert normalize_asn("AS64 500") is None
    assert normalize_asn("ASN64500") is None
    assert normalize_asn("") is None


def test_validate_asns_ok_and_bad():
    assert validate_asns(["AS64500", "64501"]) == ["AS64500", "AS64501"]
    with pytest.raises(ValueError, match="invalid ASN"):
        validate_asns(["AS64500", "notanasn"])


def test_parse_ripe_prefixes():
    data = {"data": {"prefixes": [
        {"prefix": "203.0.113.0/24", "timelines": []},
        {"prefix": "2001:db8::/32"},
        {"nope": "x"},
    ]}}
    assert parse_ripe_prefixes(data) == ["203.0.113.0/24", "2001:db8::/32"]
    assert parse_ripe_prefixes({}) == []


# -- bucket-name generation ---------------------------------------------------
def test_brand_stems_from_seeds_and_orgs():
    stems = brand_stems(["acme.com", "acme.io"], {"Acme Corporation", "Globex Holdings"})
    assert "acme" in stems
    assert "globex" in stems
    # generic org tokens are dropped
    assert "corporation" not in stems and "holdings" not in stems


def test_bucket_candidates_permutations_and_bounds():
    names = bucket_candidates(["acme"], limit=20)
    assert "acme" in names
    assert "acme-prod" in names
    assert "acme-backup" in names
    assert len(names) <= 20
    # all are DNS-valid bucket lengths
    assert all(3 <= len(n) <= 63 for n in names)


def test_bucket_candidates_strips_hyphen_variant():
    names = bucket_candidates(["acme-corp"], limit=40)
    assert "acme-corp" in names
    assert "acmecorp" in names  # hyphen-free variant also generated


def test_bucket_candidates_skips_short_stems():
    assert bucket_candidates(["ab"], limit=20) == []


def test_classify_bucket():
    assert classify_bucket(200) == "public"
    assert classify_bucket(403) == "private"
    assert classify_bucket(401) == "private"
    assert classify_bucket(404) is None
    assert classify_bucket(301) is None


# -- Microsoft 365 parsing ----------------------------------------------------
OPENID = {
    "token_endpoint": "https://login.microsoftonline.com/"
                      "72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token",
    "issuer": "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
}

USERREALM_MANAGED = """<?xml version="1.0" encoding="utf-8"?>
<RealmInfo Success="True">
  <State>3</State>
  <UserState>2</UserState>
  <Login>user@contoso.com</Login>
  <NameSpaceType>Managed</NameSpaceType>
  <DomainName>contoso.com</DomainName>
  <IsFederatedNS>false</IsFederatedNS>
  <FederationBrandName>Contoso</FederationBrandName>
  <CloudInstanceName>microsoftonline.com</CloudInstanceName>
</RealmInfo>"""

USERREALM_FEDERATED = """<?xml version="1.0" encoding="utf-8"?>
<RealmInfo Success="True">
  <State>4</State>
  <NameSpaceType>Federated</NameSpaceType>
  <DomainName>fabrikam.com</DomainName>
  <AuthURL>https://sts.fabrikam.com/adfs/ls/?wa=wsignin1.0</AuthURL>
  <IsFederatedNS>true</IsFederatedNS>
  <FederationBrandName>Fabrikam</FederationBrandName>
</RealmInfo>"""

USERREALM_UNKNOWN = """<?xml version="1.0" encoding="utf-8"?>
<RealmInfo Success="True"><NameSpaceType>Unknown</NameSpaceType></RealmInfo>"""


def test_parse_openid_config_extracts_tenant():
    assert parse_openid_config(OPENID) == "72f988bf-86f1-41af-91ab-2d7cd011db47"
    assert parse_openid_config({"issuer": "https://example.com/no-guid"}) is None
    assert parse_openid_config({}) is None


def test_parse_userrealm_managed():
    d = parse_userrealm(USERREALM_MANAGED)
    assert d["NameSpaceType"] == "Managed"
    assert d["DomainName"] == "contoso.com"
    assert d["Success"] == "True"  # root attribute captured
    assert "AuthURL" not in d


def test_parse_userrealm_federated():
    d = parse_userrealm(USERREALM_FEDERATED)
    assert d["NameSpaceType"] == "Federated"
    assert d["AuthURL"].startswith("https://sts.fabrikam.com/adfs/ls/")
    assert d["FederationBrandName"] == "Fabrikam"


def test_parse_userrealm_unknown_and_garbage():
    assert parse_userrealm(USERREALM_UNKNOWN)["NameSpaceType"] == "Unknown"
    assert parse_userrealm("not xml at all") == {}
