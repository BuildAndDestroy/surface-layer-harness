"""Passive subdomain sources. Each returns a set of host names for an apex.

None of these touch the target's infrastructure; they query third-party datasets.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Awaitable, Callable

import httpx

from .config import Config
from .domains import is_subdomain_of, normalize
from .tools import ToolRunner

UA = "surface-harness/0.1 (+attack-surface-discovery)"

SourceFn = Callable[[httpx.AsyncClient, str, Config], Awaitable[set[str]]]


def _filter(names, apex_name: str) -> set[str]:
    out = set()
    for raw in names:
        for part in re.split(r"[\s,]+", str(raw)):
            n = normalize(part)
            if n and is_subdomain_of(n, apex_name):
                out.add(n)
    return out


async def get_json(client: httpx.AsyncClient, url: str, retries: int = 2, **kw):
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            r = await client.get(url, **kw)
            if r.status_code == 429 or r.status_code >= 500:
                raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            return r.json()
        except Exception as e:  # noqa: BLE001
            last = e
            await asyncio.sleep(2 * (attempt + 1))
    raise last  # type: ignore[misc]


# -- individual sources -----------------------------------------------------

_crtsh_cache: dict[str, list[dict]] = {}


async def crtsh_records(client: httpx.AsyncClient, apex_name: str) -> list[dict]:
    """Raw crt.sh rows; cached because related-domain discovery reuses them."""
    if apex_name not in _crtsh_cache:
        data = await get_json(
            client, "https://crt.sh/", params={"q": f"%.{apex_name}", "output": "json"},
            timeout=90, retries=3,
        )
        _crtsh_cache[apex_name] = data if isinstance(data, list) else []
    return _crtsh_cache[apex_name]


async def crtsh(client, apex_name, cfg):
    rows = await crtsh_records(client, apex_name)
    return _filter((r.get("name_value", "") for r in rows), apex_name) | _filter(
        (r.get("common_name", "") for r in rows), apex_name
    )


async def certspotter(client, apex_name, cfg):
    headers = {}
    if "certspotter" in cfg.keys:
        headers["Authorization"] = f"Bearer {cfg.keys['certspotter']}"
    data = await get_json(
        client, "https://api.certspotter.com/v1/issuances",
        params={"domain": apex_name, "include_subdomains": "true", "expand": "dns_names"},
        headers=headers, timeout=60,
    )
    return _filter((n for row in data for n in row.get("dns_names", [])), apex_name)


async def hackertarget(client, apex_name, cfg):
    r = await client.get("https://api.hackertarget.com/hostsearch/", params={"q": apex_name}, timeout=60)
    if "API count exceeded" in r.text or "error" in r.text[:50].lower():
        raise RuntimeError(r.text.strip()[:120])
    return _filter((line.split(",")[0] for line in r.text.splitlines()), apex_name)


async def otx(client, apex_name, cfg):
    headers = {"X-OTX-API-KEY": cfg.keys["otx"]} if "otx" in cfg.keys else {}
    data = await get_json(
        client, f"https://otx.alienvault.com/api/v1/indicators/domain/{apex_name}/passive_dns",
        headers=headers, timeout=60,
    )
    return _filter((p.get("hostname", "") for p in data.get("passive_dns", [])), apex_name)


async def wayback(client, apex_name, cfg):
    r = await client.get(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": f"*.{apex_name}", "output": "json", "fl": "original",
                "collapse": "urlkey", "limit": "50000"},
        timeout=120,
    )
    r.raise_for_status()
    rows = json.loads(r.text or "[]")
    return _filter((row[0] for row in rows[1:]), apex_name)


async def securitytrails(client, apex_name, cfg):
    data = await get_json(
        client, f"https://api.securitytrails.com/v1/domain/{apex_name}/subdomains",
        headers={"APIKEY": cfg.keys["securitytrails"]}, timeout=60,
    )
    return _filter((f"{s}.{apex_name}" for s in data.get("subdomains", [])), apex_name)


async def virustotal(client, apex_name, cfg):
    names: set[str] = set()
    url = f"https://www.virustotal.com/api/v3/domains/{apex_name}/subdomains?limit=40"
    for _ in range(10):  # 10 pages max on free tier
        data = await get_json(client, url, headers={"x-apikey": cfg.keys["virustotal"]}, timeout=60)
        names |= _filter((d.get("id", "") for d in data.get("data", [])), apex_name)
        url = data.get("links", {}).get("next")
        if not url:
            break
    return names


SOURCES: dict[str, tuple[SourceFn, str | None]] = {
    # name: (fn, required api key or None)
    "crtsh": (crtsh, None),
    "certspotter": (certspotter, None),
    "hackertarget": (hackertarget, None),
    "otx": (otx, None),
    "wayback": (wayback, None),
    "securitytrails": (securitytrails, "securitytrails"),
    "virustotal": (virustotal, "virustotal"),
}


async def subfinder(runner: ToolRunner, apex_name: str) -> set[str]:
    res = await runner.run("subfinder", ["-d", apex_name, "-all", "-silent"], timeout=600)
    if not res.ok:
        raise RuntimeError(res.stderr.strip()[-200:])
    return _filter(res.stdout.splitlines(), apex_name)


async def enumerate_passive(
    client: httpx.AsyncClient, runner: ToolRunner, apex_name: str, cfg: Config, log
) -> dict[str, set[str]]:
    """Run every enabled passive source concurrently. Returns {source: hosts}."""
    tasks: dict[str, Awaitable[set[str]]] = {}
    for name, (fn, key) in SOURCES.items():
        if cfg.sources is not None and name not in cfg.sources:
            continue
        if key and key not in cfg.keys:
            continue
        tasks[name] = fn(client, apex_name, cfg)
    if (cfg.sources is None or "subfinder" in cfg.sources) and runner.available("subfinder"):
        tasks["subfinder"] = subfinder(runner, apex_name)

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    out: dict[str, set[str]] = {}
    for name, res in zip(tasks, results):
        if isinstance(res, BaseException):
            log(f"[source:{name}] {apex_name}: {type(res).__name__}: {str(res)[:150]}")
            continue
        out[name] = res
        log(f"[source:{name}] {apex_name}: {len(res)} names")
    return out
