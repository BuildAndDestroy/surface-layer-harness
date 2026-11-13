"""Light TLS-configuration audit: legacy protocol support, near/expired certs,
and missing HSTS. One short handshake per legacy protocol version (no cipher
enumeration). Runs only in standard/active mode (cfg.http_probe)."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from datetime import UTC, datetime

import httpx

from .models import Finding, TlsConfig
from .probe import UA, tls_grab

# Legacy protocols to probe for, with the severity if the server accepts one.
WEAK_PROTOCOLS: list[tuple[str, ssl.TLSVersion, str]] = [
    ("SSLv3", ssl.TLSVersion.SSLv3, "high"),
    ("TLSv1.0", ssl.TLSVersion.TLSv1, "medium"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "medium"),
]
EXPIRY_WARN_DAYS = 21


async def _version_accepted(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    """True if ``host:port`` completes a handshake pinned to exactly ``version``."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we test protocol support, not cert validity
        ctx.minimum_version = version
        ctx.maximum_version = version
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # allow the weak ciphers legacy protocols need
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    except Exception:  # noqa: BLE001 - any failure means the version is not usable
        return False


async def _check_hsts(host: str, port: int, timeout: float,
                      http_client: httpx.AsyncClient | None) -> bool | None:
    """Return True/False for HSTS presence, or None if no HTTPS response was reached."""
    url = f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    try:
        if http_client is not None:
            resp = await http_client.get(url, headers={"User-Agent": UA})
        else:
            # Verify certs here: a browser ignores HSTS on an untrusted cert, so a
            # missing-HSTS finding is only meaningful when the cert validates. Hosts
            # with invalid/weak certs are already covered by the tls-* findings above.
            async with httpx.AsyncClient(follow_redirects=False,
                                         timeout=timeout) as client:
                resp = await client.get(url, headers={"User-Agent": UA})
    except Exception:  # noqa: BLE001 - no HTTPS response means no HSTS finding to make
        return None
    return "strict-transport-security" in resp.headers


async def audit_tls(host: str, port: int = 443, *,
                    http_client: httpx.AsyncClient | None = None,
                    timeout: float = 6.0) -> tuple[TlsConfig, list[Finding]]:
    """Audit TLS configuration for one ``host:port``.

    Returns the structured :class:`TlsConfig` record and the findings derived
    from it. Finding kinds: ``tls-weak-protocol``, ``tls-expiry``, ``hsts-missing``.
    """
    findings: list[Finding] = []
    target = f"{host}:{port}"
    record = TlsConfig(host=host, port=port)

    for label, version, severity in WEAK_PROTOCOLS:
        if await _version_accepted(host, port, version, timeout):
            record.weak_protocols.append(label)
            findings.append(Finding(severity, "tls-weak-protocol", target,
                                    f"legacy {label} handshake accepted; disable obsolete TLS/SSL protocols"))

    info = await tls_grab(host, port, timeout=timeout)
    record.not_after = info.not_after
    if info.not_after:
        try:
            not_after = datetime.fromisoformat(info.not_after)
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=UTC)
            days = (not_after - datetime.now(UTC)).days
            record.expires_in_days = days
            if days < 0:
                findings.append(Finding("high", "tls-expiry", target,
                                        f"certificate expired {-days} day(s) ago ({info.not_after})"))
            elif days < EXPIRY_WARN_DAYS:
                findings.append(Finding("medium", "tls-expiry", target,
                                        f"certificate expires in {days} day(s) ({info.not_after})"))
        except (ValueError, TypeError):
            pass

    hsts = await _check_hsts(host, port, timeout, http_client)
    record.hsts = hsts
    if hsts is False:
        findings.append(Finding("low", "hsts-missing", target,
                                "HTTPS response has no Strict-Transport-Security header"))
    return record, findings
