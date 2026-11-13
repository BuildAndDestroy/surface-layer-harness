"""Unit tests for remote-access detection: fingerprints, ports, probe payloads.

No network calls: fingerprints are fed synthetic responses, UDP payloads are
only shape-checked.
"""

import re
import struct

import httpx

from surface_harness.config import DEFAULT_PORTS
from surface_harness.login_paths import LOGIN_PATHS
from surface_harness.pipeline import INTERESTING_TECH, SENSITIVE_PORTS
from surface_harness.probe import detect_tech
from surface_harness.udp_probe import (
    _isakmp_sa_proposal,
    _openvpn_reset,
    _wireguard_init,
    udp_vpn_scan,
)


def _tech(body="", headers=None):
    resp = httpx.Response(200, headers=headers or {})
    return detect_tech(resp, body)


# --- product fingerprints (probe.TECH_HINTS via detect_tech) ---------------------

def test_fingerprint_cisco_asa():
    assert "Cisco AnyConnect/ASA" in _tech("<a href='/+CSCOE+/logon.html'>login</a>")
    assert "Cisco AnyConnect/ASA" in _tech("<title>SSL VPN Service</title>")


def test_fingerprint_sonicwall():
    assert "SonicWall SSL-VPN" in _tech("Powered by SonicWall SSL-VPN")


def test_fingerprint_checkpoint():
    assert "Check Point Mobile Access" in _tech("Check Point Mobile Access portal")


def test_fingerprint_f5_bigip_body_and_cookie():
    assert "F5 BIG-IP" in _tech("Served by BIG-IP")
    assert "F5 BIG-IP" in _tech("F5 Networks appliance")
    cookie = _tech("", headers=[("set-cookie", "TS01abc123=deadbeef; path=/")])
    assert "F5 BIG-IP" in cookie
    assert "F5 BIG-IP" in _tech("", headers=[("set-cookie", "BIGipServerpool=123.456")])


def test_fingerprint_vmware_horizon():
    assert "VMware Horizon" in _tech("<title>VMware Horizon</title>")


def test_fingerprint_rdweb():
    assert "Microsoft RD Web" in _tech("<form action='/RDWeb/Pages/login.aspx'>")
    assert "Microsoft RD Web" in _tech("RD Web Access")


def test_fingerprint_exchange_ecp():
    assert "Exchange ECP" in _tech("redirect to /ecp/ here")
    assert "Exchange ECP" in _tech("Exchange Admin Center")


def test_fingerprint_adfs():
    assert "ADFS" in _tech("GET /adfs/ls/?wa=wsignin1.0")


def test_fingerprint_okta():
    assert "Okta" in _tech("<div class='okta-sign-in'>")


def test_fingerprints_do_not_match_generic_page():
    tech = _tech("<html><body>Welcome to our marketing homepage</body></html>")
    for label in ("Cisco AnyConnect/ASA", "SonicWall SSL-VPN", "F5 BIG-IP", "ADFS",
                  "Okta", "VMware Horizon", "Microsoft RD Web", "Exchange ECP"):
        assert label not in tech


def test_new_fingerprints_are_interesting_tech():
    for label in ("Cisco AnyConnect/ASA", "SonicWall SSL-VPN", "Check Point Mobile Access",
                  "F5 BIG-IP", "VMware Horizon", "Microsoft RD Web", "Exchange ECP",
                  "ADFS", "Okta"):
        assert label in INTERESTING_TECH


# --- port coverage ---------------------------------------------------------------

def test_default_ports_sorted_and_deduped():
    assert sorted(DEFAULT_PORTS) == DEFAULT_PORTS
    assert len(DEFAULT_PORTS) == len(set(DEFAULT_PORTS))


def test_default_ports_added():
    for p in (1194, 1494, 2598, 4433, 8834, 10443):
        assert p in DEFAULT_PORTS, p
    # these were required to already be present
    for p in (5985, 5986):
        assert p in DEFAULT_PORTS


def test_sensitive_ports_additions():
    for p, label in ((1194, "OpenVPN"), (1494, "Citrix"), (1723, "PPTP"),
                     (2598, "Citrix"), (8834, "Nessus"), (10443, "SSL-VPN")):
        assert p in SENSITIVE_PORTS, p
        sev, text = SENSITIVE_PORTS[p]
        assert sev in ("low", "medium", "high")
        assert label.lower() in text.lower()


# --- UDP probe payloads (shape only, no sockets) ---------------------------------

def test_isakmp_payload_shape():
    pkt = _isakmp_sa_proposal()
    # ISAKMP header (28) + SA(12) + proposal(8) + transform(8) + 6*4 attrs(24) = 80
    assert len(pkt) == 80
    # length field in the ISAKMP header (bytes 24..28) matches the packet length
    assert struct.unpack(">I", pkt[24:28])[0] == len(pkt)
    # next-payload after the cookies is SA (1); version byte is 0x10
    assert pkt[16] == 1
    assert pkt[17] == 0x10


def test_openvpn_payload_shape():
    pkt = _openvpn_reset()
    assert len(pkt) == 14
    assert pkt[0] == (7 << 3)  # P_CONTROL_HARD_RESET_CLIENT_V2 opcode


def test_wireguard_payload_shape():
    pkt = _wireguard_init()
    assert len(pkt) == 148
    assert struct.unpack("<I", pkt[:4])[0] == 1  # handshake initiation type


def test_udp_vpn_scan_empty_is_noop():
    import asyncio

    assert asyncio.run(udp_vpn_scan([], lambda *_: None)) == []


# --- login-path fingerprints (compile + sample matches) --------------------------

def test_login_paths_small_and_markers_compile():
    assert 1 <= len(LOGIN_PATHS) <= 12
    samples = {
        "/remote/login": "var fgt_lang = 'en';",
        "/vpn/index.html": "Citrix Gateway login",
        "/RDWeb/": "RD Web Access",
        "/+CSCOE+/logon.html": "SSL VPN Service",
        "/adfs/ls/": "AD FS sign in",
        "/owa/": "Outlook Web App",
        "/ecp/": "Exchange Admin Center",
        "/global-protect/login.esp": "GlobalProtect Portal",
    }
    for path, _label, marker in LOGIN_PATHS:
        rx = re.compile(marker, re.I)  # must compile
        assert rx.search(samples[path]), path
