"""Lightweight UDP presence probes for VPN endpoints (active mode only).

Detection / fingerprinting only: each endpoint is sent exactly ONE small probe
packet and we treat *any* reply as "service present". No handshake is completed,
no credentials are sent and no payload beyond the single detection packet is
emitted. Silence is the normal case (firewalls drop, servers with tls-auth or
cookie-based anti-DoS stay quiet), so every error is swallowed.

Only non-CDN target IPs should be passed in by the caller.
"""

from __future__ import annotations

import asyncio
import os
import struct

from .models import Finding


def _isakmp_sa_proposal() -> bytes:
    """A minimal IKEv1 (ISAKMP) Main-Mode Security Association proposal.

    One proposal, one transform (3DES / SHA1 / PSK / MODP-1024), mirroring the
    classic ``ike-scan`` default. A VPN endpoint on UDP/500 answers with its own
    SA payload (or a NOTIFY); either way a datagram comes back and that is all we
    look for. We never read or act on the response contents.
    """
    # Transform payload: basic (TLV, 4-byte) attributes.
    attrs = b"".join(struct.pack(">HH", 0x8000 | t, v) for t, v in (
        (1, 5),       # Encryption Algorithm = 3DES-CBC
        (2, 2),       # Hash Algorithm = SHA1
        (3, 1),       # Authentication Method = pre-shared key
        (4, 2),       # Group Description = MODP-1024
        (11, 1),      # Life Type = seconds
        (12, 28800),  # Life Duration = 28800s
    ))
    transform = struct.pack(">BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa_body = struct.pack(">II", 1, 1) + proposal  # DOI = IPSEC, situation = identity
    sa = struct.pack(">BBH", 0, 0, 4 + len(sa_body)) + sa_body
    # ISAKMP header: random initiator cookie, zero responder cookie, next=SA(1),
    # version 1.0, exchange type = Identity Protection / Main Mode (2).
    init_cookie = os.urandom(8)
    header = init_cookie + b"\x00" * 8 + struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa))
    return header + sa


def _openvpn_reset() -> bytes:
    """OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 over UDP.

    One byte opcode/key-id (opcode 7 << 3), 8-byte random session id, a zero-length
    ACK array and a 4-byte packet-id. A server without ``tls-auth``/``tls-crypt``
    replies with a server reset; hardened servers stay silent (best effort).
    """
    opcode = 7 << 3  # P_CONTROL_HARD_RESET_CLIENT_V2
    return bytes([opcode]) + os.urandom(8) + b"\x00" + struct.pack(">I", 0)


def _wireguard_init() -> bytes:
    """WireGuard handshake-initiation shaped packet (type 1, 148 bytes).

    WireGuard silently drops anything it cannot cryptographically verify, so a
    reply is not expected; included only for completeness / best effort.
    """
    return struct.pack("<I", 1) + b"\x00" * 144


# (port, payload, severity, label). Payload builders are called per probe so the
# ISAKMP initiator cookie / OpenVPN session id are fresh each time.
_PROBES: list[tuple[int, bytes, str, str]] = []


def _build_probes() -> list[tuple[int, bytes, str, str]]:
    sa = _isakmp_sa_proposal()
    return [
        (500, sa, "medium", "IKE/IPsec VPN"),
        # NAT-T traffic is prefixed with a 4-byte non-ESP marker before the ISAKMP header.
        (4500, b"\x00\x00\x00\x00" + sa, "medium", "IKE/IPsec VPN (NAT-T)"),
        (1194, _openvpn_reset(), "medium", "OpenVPN"),
        (51820, _wireguard_init(), "medium", "WireGuard VPN"),
    ]


async def _udp_responds(ip: str, port: int, payload: bytes, timeout: float) -> bool:
    """Send one datagram; return True iff any reply arrives before ``timeout``."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr) -> None:
            if not fut.done():
                fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            # ICMP port-unreachable etc. -> treat as "no VPN here", not an error.
            if not fut.done():
                fut.set_exception(exc)

    try:
        transport, _ = await loop.create_datagram_endpoint(_Proto, remote_addr=(ip, port))
    except Exception:  # noqa: BLE001
        return False
    try:
        transport.sendto(payload)
        await asyncio.wait_for(fut, timeout)
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        transport.close()


async def udp_vpn_scan(ips: list[str], log, concurrency: int = 100,
                       timeout: float = 2.5) -> list[Finding]:
    """Probe each IP for common UDP VPN endpoints. Returns ``exposed-service`` findings.

    Active mode only (gated by the caller). Best effort: no reply is the norm.
    """
    if not ips:
        return []
    probes = _build_probes()
    log(f"[udp] VPN probes on {len(ips)} IPs x {len(probes)} ports")
    sem = asyncio.Semaphore(concurrency)
    findings: list[Finding] = []

    async def one(ip: str, port: int, payload: bytes, sev: str, label: str) -> None:
        async with sem:
            if await _udp_responds(ip, port, payload, timeout):
                findings.append(Finding(
                    sev, "exposed-service", f"{ip}:{port}/udp",
                    f"{label} responded to a UDP presence probe on {port}/udp"))

    await asyncio.gather(*(one(ip, port, payload, sev, label)
                           for ip in ips for port, payload, sev, label in probes))
    if findings:
        log(f"[udp] {len(findings)} VPN endpoint(s) responded")
    return findings
