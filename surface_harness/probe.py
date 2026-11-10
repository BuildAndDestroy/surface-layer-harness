"""HTTP(S) probing and TLS certificate collection."""

from __future__ import annotations

import asyncio
import html
import re
import ssl

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from .models import HttpService, TlsInfo

UA = "Mozilla/5.0 (compatible; surface-harness/0.1)"
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
GENERATOR_RE = re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", re.I)

TECH_HINTS = [
    # (where, regex, label)
    ("header:x-powered-by", r"(.+)", None),
    ("header:server", r"(.+)", None),
    ("header:x-aspnet-version", r".+", "ASP.NET"),
    ("header:x-drupal-cache", r".+", "Drupal"),
    ("header:x-generator", r"(.+)", None),
    ("header:x-amz-cf-id", r".+", "AWS CloudFront"),
    ("header:cf-ray", r".+", "Cloudflare"),
    ("header:x-vercel-id", r".+", "Vercel"),
    ("header:x-github-request-id", r".+", "GitHub Pages"),
    ("cookie", r"JSESSIONID", "Java"),
    ("cookie", r"PHPSESSID", "PHP"),
    ("cookie", r"ASP\.NET_SessionId", "ASP.NET"),
    ("cookie", r"laravel_session", "Laravel"),
    ("cookie", r"wordpress_|wp-settings", "WordPress"),
    ("body", r"/wp-content/|/wp-includes/", "WordPress"),
    ("body", r"__NEXT_DATA__", "Next.js"),
    ("body", r"ng-version=", "Angular"),
    ("body", r"data-reactroot|react-dom", "React"),
    ("body", r"Jenkins</title>|X-Jenkins", "Jenkins"),
    ("body", r"<title>Grafana</title>", "Grafana"),
    ("body", r"kibana", "Kibana"),
    ("body", r"GitLab", "GitLab"),
    ("body", r"Outlook Web App|/owa/auth", "Outlook Web App"),
    ("body", r"Citrix Gateway|NetScaler", "Citrix Gateway"),
    ("body", r"GlobalProtect", "Palo Alto GlobalProtect"),
    ("body", r"FortiGate|fgt_lang", "Fortinet"),
    ("body", r"Pulse Secure|Ivanti Connect Secure", "Ivanti/Pulse VPN"),
    ("body", r"swagger-ui", "Swagger UI"),
    ("body", r"phpMyAdmin", "phpMyAdmin"),
]


def detect_tech(resp: httpx.Response, body: str) -> list[str]:
    found: list[str] = []
    cookies = "; ".join(resp.headers.get_list("set-cookie"))
    gen = GENERATOR_RE.search(body)
    if gen:
        found.append(gen.group(1).strip())
    for where, pattern, label in TECH_HINTS:
        if where.startswith("header:"):
            val = resp.headers.get(where.split(":", 1)[1])
            if val and (m := re.search(pattern, val)):
                found.append(label or m.group(1).strip())
        elif where == "cookie" and re.search(pattern, cookies, re.I):
            found.append(label)  # type: ignore[arg-type]
        elif where == "body" and re.search(pattern, body[:200_000], re.I):
            found.append(label)  # type: ignore[arg-type]
    return sorted(set(f for f in found if f))[:20]


async def http_probe(client: httpx.AsyncClient, url: str) -> tuple[HttpService, str]:
    svc = HttpService(url=url)
    body = ""
    try:
        resp = await client.get(url, headers={"User-Agent": UA})
        body = resp.text[:500_000]
        svc.status = resp.status_code
        svc.final_url = str(resp.url)
        svc.server = resp.headers.get("server")
        svc.content_length = len(resp.content)
        m = TITLE_RE.search(body)
        if m:
            svc.title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200]
        svc.tech = detect_tech(resp, body)
    except Exception as e:  # noqa: BLE001
        svc.error = f"{type(e).__name__}: {str(e)[:120]}"
    return svc, body


def _name_dict(name: x509.Name) -> dict[str, str]:
    out = {}
    for oid, key in ((NameOID.COMMON_NAME, "CN"), (NameOID.ORGANIZATION_NAME, "O"),
                     (NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"), (NameOID.COUNTRY_NAME, "C")):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            out[key] = str(attrs[0].value)
    return out


async def _handshake(host: str, port: int, verify: bool, timeout: float) -> bytes:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout,
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        return sslobj.getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def tls_grab(host: str, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    info = TlsInfo(port=port, valid=False)
    der: bytes | None = None
    try:
        der = await _handshake(host, port, True, timeout)
        info.valid = True
    except ssl.SSLCertVerificationError as e:
        info.error = e.verify_message or str(e)[:120]
    except Exception as e:  # noqa: BLE001
        info.error = f"{type(e).__name__}: {str(e)[:120]}"
        return info
    if der is None:
        try:
            der = await _handshake(host, port, False, timeout)
        except Exception as e:  # noqa: BLE001
            info.error = f"{info.error}; {type(e).__name__}"
            return info
    try:
        cert = x509.load_der_x509_certificate(der)
        info.subject = _name_dict(cert.subject)
        info.issuer = _name_dict(cert.issuer)
        info.not_after = cert.not_valid_after_utc.isoformat()
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            info.sans = sorted({n.lower() for n in san.value.get_values_for_type(x509.DNSName)})
        except x509.ExtensionNotFound:
            pass
    except Exception as e:  # noqa: BLE001
        info.error = f"cert parse: {e}"
    return info
