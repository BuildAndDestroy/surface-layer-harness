"""GraphQL API over a merged engagement (engagement.json).

    surface-harness serve engagements/<id>            # http://127.0.0.1:8787/graphql (GraphiQL UI)

The server re-reads engagement.json when it changes, so `merge` while it runs is fine.
It binds to localhost by default: engagement data is client-confidential.

Example query:
    { targets { id name summary findings(minSeverity: "medium") { severity kind target detail } } }
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import strawberry
from strawberry.scalars import JSON

from .graph import open_ports

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Store:
    def __init__(self, path: Path):
        self.path = path
        self._mtime = 0.0
        self._doc: dict = {}
        self._graph: dict = {}

    @property
    def doc(self) -> dict:
        m = os.path.getmtime(self.path)
        if m != self._mtime:
            self._doc = json.loads(self.path.read_text())
            gp = self.path.parent / "graph.json"
            self._graph = json.loads(gp.read_text()) if gp.exists() else {}
            self._mtime = m
        return self._doc

    @property
    def graph(self) -> dict:
        _ = self.doc
        return self._graph


STORE: Store | None = None


def _targets(target_id: str | None = None) -> list[dict]:
    ts = STORE.doc["targets"]  # type: ignore[union-attr]
    return [t for t in ts if target_id in (None, t["id"])]


# -- types -------------------------------------------------------------------------

@strawberry.type
class Evidence:
    signal: str
    detail: str
    weight: float


@strawberry.type
class Domain:
    target_id: str
    name: str
    confidence: float
    seed: bool
    in_scope: bool
    evidence: list[Evidence]
    whois: JSON


@strawberry.type
class HttpService:
    url: str
    status: int | None
    final_url: str | None
    title: str | None
    server: str | None
    tech: list[str]


@strawberry.type
class Host:
    target_id: str
    name: str
    apex: str
    live: bool
    wildcard: bool
    a: list[str]
    aaaa: list[str]
    cnames: list[str]
    open_ports: list[int]
    sources: list[str]
    http: list[HttpService]
    tls: JSON


@strawberry.type
class Ip:
    target_id: str
    ip: str
    asn: str | None
    as_name: str | None
    prefix: str | None
    country: str | None
    ptr: str | None
    hosts: list[str]
    open_ports: list[int]


@strawberry.type
class WebOnPort:
    url: str
    status: int | None
    title: str | None
    server: str | None


@strawberry.type(description="An open port on an IP. `hosts` are the names that resolve to that IP.")
class OpenPort:
    target_id: str
    ip: str
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    cpe: list[str]
    nmap: str | None = strawberry.field(description="nmap's one-line summary, e.g. 'ssl/http nginx 1.29.8'")
    detection: str | None = strawberry.field(
        description="'probed' = nmap fingerprint match, 'table' = guessed from the port number, null = not run")
    hosts: list[str]
    web: list[WebOnPort]


@strawberry.type
class Finding:
    target_id: str
    origin: str  # harness | analyst
    severity: str
    kind: str
    target: str
    detail: str
    status: str


@strawberry.type
class Officer:
    name: str
    role: str


@strawberry.type
class LegalEntity:
    target_id: str
    source: str
    name: str
    match: str
    jurisdiction: str | None
    company_number: str | None
    status: str | None
    entity_type: str | None
    formed: str | None
    registered_address: str | None
    principal_address: str | None
    mailing_address: str | None
    agent_name: str | None
    agent_address: str | None
    agent_commercial: bool
    address_notes: list[str]
    officers: list[Officer]
    parents: list[str]
    subsidiaries: list[str]
    websites: list[str]
    identifiers: JSON
    url: str | None


def _domains(t: dict) -> list[Domain]:
    run = t.get("surface") or {}
    thr = ((run.get("meta") or {}).get("config") or {}).get("threshold", 0.7)
    return [Domain(target_id=t["id"], name=n, confidence=d["confidence"], seed=d.get("seed", False),
                   in_scope=d["confidence"] >= thr, whois=d.get("whois") or {},
                   evidence=[Evidence(**e) for e in d.get("evidence", [])])
            for n, d in (run.get("domains") or {}).items()]


def _hosts(t: dict) -> list[Host]:
    out = []
    for n, h in ((t.get("surface") or {}).get("hosts") or {}).items():
        out.append(Host(
            target_id=t["id"], name=n, apex=h["apex"], live=bool(h.get("resolved")),
            wildcard=bool(h.get("wildcard")), a=h.get("a", []), aaaa=h.get("aaaa", []),
            cnames=h.get("cnames", []), open_ports=h.get("open_ports", []), sources=h.get("sources", []),
            tls=h.get("tls", []),
            http=[HttpService(url=s["url"], status=s.get("status"), final_url=s.get("final_url"),
                              title=s.get("title"), server=s.get("server"), tech=s.get("tech", []))
                  for s in h.get("http", [])]))
    return out


def _findings(t: dict) -> list[Finding]:
    out = [Finding(target_id=t["id"], origin="harness", severity=f["severity"], kind=f["kind"],
                   target=f["target"], detail=f["detail"], status="unverified")
           for f in (t.get("surface") or {}).get("findings", [])]
    out += [Finding(target_id=t["id"], origin="analyst", severity=f.get("severity", "info"),
                    kind=f.get("ref", "analyst").split(":")[0], target=f.get("asset") or f.get("ref") or "",
                    detail=f.get("title", ""), status=f.get("status", ""))
            for f in (t.get("analysis") or {}).get("findings", [])]
    return out


def _entities(t: dict) -> list[LegalEntity]:
    fields = LegalEntity.__annotations__.keys()
    out = []
    for c in (t.get("surface") or {}).get("companies", []):
        d = {k: c.get(k) for k in fields if k not in ("target_id", "officers")}
        d["agent_commercial"] = bool(d.get("agent_commercial"))
        for k in ("address_notes", "parents", "subsidiaries", "websites"):
            d[k] = d.get(k) or []
        d["identifiers"] = d.get("identifiers") or {}
        out.append(LegalEntity(target_id=t["id"], officers=[Officer(**o) for o in c.get("officers", [])], **d))
    return out


def _ports(t: dict) -> list[OpenPort]:
    return [OpenPort(target_id=t["id"], ip=r["ip"], port=r["port"], protocol=r["protocol"], service=r["service"],
                     product=r["product"], version=r["version"], extra_info=(r["nmap"] or {}).get("extra_info"),
                     cpe=(r["nmap"] or {}).get("cpe") or [], nmap=(r["nmap"] or {}).get("summary"),
                     detection=(r["nmap"] or {}).get("method"),
                     hosts=r["hosts"], web=[WebOnPort(**w) for w in r["web"]])
            for r in open_ports(t.get("surface") or {})]


def _ips(t: dict) -> list[Ip]:
    by_ip: dict[str, list[int]] = {}
    for r in open_ports(t.get("surface") or {}):
        by_ip.setdefault(r["ip"], []).append(r["port"])
    return [Ip(target_id=t["id"], ip=ip, asn=i.get("asn"), as_name=i.get("as_name"), prefix=i.get("prefix"),
               country=i.get("country"), ptr=i.get("ptr"), hosts=i.get("hosts", []), open_ports=by_ip.get(ip, []))
            for ip, i in ((t.get("surface") or {}).get("ips") or {}).items()]


def _sev_ok(sev: str, min_severity: str | None) -> bool:
    return min_severity is None or SEV.get(sev, 9) <= SEV.get(min_severity, 9)


@strawberry.type
class Target:
    id: str
    name: str
    status: str
    seeds: list[str]
    org: list[str]
    run_dir: str | None
    meta: JSON
    summary: JSON
    analysis: JSON
    site_identity: JSON

    @strawberry.field
    def domains(self, in_scope_only: bool = False, min_confidence: float = 0.0) -> list[Domain]:
        return [d for d in _domains(_targets(self.id)[0])
                if d.confidence >= min_confidence and (d.in_scope or not in_scope_only)]

    @strawberry.field
    def hosts(self, live: bool | None = None) -> list[Host]:
        return [h for h in _hosts(_targets(self.id)[0]) if live is None or h.live == live]

    @strawberry.field
    def findings(self, min_severity: str | None = None) -> list[Finding]:
        return [f for f in _findings(_targets(self.id)[0]) if _sev_ok(f.severity, min_severity)]

    @strawberry.field
    def entities(self) -> list[LegalEntity]:
        return _entities(_targets(self.id)[0])

    @strawberry.field
    def ips(self) -> list[Ip]:
        return _ips(_targets(self.id)[0])

    @strawberry.field
    def ports(self, port: int | None = None) -> list[OpenPort]:
        return [p for p in _ports(_targets(self.id)[0]) if port in (None, p.port)]


def _target(t: dict) -> Target:
    s = t.get("surface") or {}
    return Target(id=t["id"], name=t["name"], status=t["status"], seeds=t["domains"], org=t.get("org", []),
                  run_dir=t.get("run_dir"), meta=t.get("meta") or {}, summary=t.get("summary") or {},
                  analysis=t.get("analysis"), site_identity=s.get("site_identity") or {})


@strawberry.type
class Engagement:
    id: str
    client: str
    authorization: JSON
    generated_at: str
    schema_version: str
    cross_target: JSON
    summary_md: str | None


@strawberry.type
class Query:
    @strawberry.field
    def engagement(self) -> Engagement:
        d = STORE.doc  # type: ignore[union-attr]
        e = d["engagement"]
        return Engagement(id=e["id"], client=e["client"], authorization=e.get("authorization") or {},
                          generated_at=d["generated_at"], schema_version=d["schema_version"],
                          cross_target=d.get("cross_target") or {}, summary_md=d.get("summary_md"))

    @strawberry.field
    def targets(self) -> list[Target]:
        return [_target(t) for t in _targets()]

    @strawberry.field
    def target(self, id: str) -> Target | None:
        ts = _targets(id)
        return _target(ts[0]) if ts else None

    @strawberry.field(description="Hosts across targets. `tech` and `search` are case-insensitive substrings.")
    def hosts(self, target_id: str | None = None, live: bool | None = None, port: int | None = None,
              tech: str | None = None, search: str | None = None, limit: int = 1000) -> list[Host]:
        out = []
        for t in _targets(target_id):
            for h in _hosts(t):
                if live is not None and h.live != live:
                    continue
                if port is not None and port not in h.open_ports:
                    continue
                if tech and not any(tech.lower() in x.lower() for s in h.http for x in s.tech):
                    continue
                if search and search.lower() not in (h.name + " " + " ".join(s.title or "" for s in h.http)).lower():
                    continue
                out.append(h)
        return out[:limit]

    @strawberry.field
    def domains(self, target_id: str | None = None, in_scope_only: bool = False,
                min_confidence: float = 0.0) -> list[Domain]:
        return [d for t in _targets(target_id) for d in _domains(t)
                if d.confidence >= min_confidence and (d.in_scope or not in_scope_only)]

    @strawberry.field
    def findings(self, target_id: str | None = None, min_severity: str | None = None,
                 origin: str | None = None) -> list[Finding]:
        out = [f for t in _targets(target_id) for f in _findings(t)
               if _sev_ok(f.severity, min_severity) and origin in (None, f.origin)]
        return sorted(out, key=lambda f: (SEV.get(f.severity, 9), f.target_id))

    @strawberry.field
    def entities(self, target_id: str | None = None) -> list[LegalEntity]:
        return [e for t in _targets(target_id) for e in _entities(t)]

    @strawberry.field
    def ips(self, target_id: str | None = None, asn: str | None = None) -> list[Ip]:
        return [i for t in _targets(target_id) for i in _ips(t) if asn in (None, i.asn)]

    @strawberry.field(description="Open ports per IP across targets. `service` matches the service name "
                                  "(ssl/ prefix ignored), `product` is a case-insensitive substring of nmap's product, "
                                  "`host` filters to ports on IPs that host name resolves to.")
    def ports(self, target_id: str | None = None, port: int | None = None, ip: str | None = None,
              service: str | None = None, host: str | None = None,
              product: str | None = None) -> list[OpenPort]:
        return [p for t in _targets(target_id) for p in _ports(t)
                if port in (None, p.port) and ip in (None, p.ip)
                and (service is None or (p.service or "").lower().removeprefix("ssl/") == service.lower()
                     .removeprefix("ssl/"))
                and (product is None or product.lower() in (p.product or "").lower())
                and (host is None or host.lower() in p.hosts)]

    @strawberry.field(description="The node/edge graph (same as graph.json).")
    def graph(self) -> JSON:
        return STORE.graph  # type: ignore[union-attr]


schema = strawberry.Schema(query=Query)


def load(path: str | Path) -> None:
    global STORE
    p = Path(path)
    if p.is_dir():
        p = p / "engagement.json"
    if not p.exists():
        raise FileNotFoundError(f"{p} not found; run `surface-harness merge` first")
    STORE = Store(p)
    _ = STORE.doc


def serve(path: str | Path, host: str = "127.0.0.1", port: int = 8787) -> None:
    import uvicorn
    from strawberry.asgi import GraphQL

    load(path)
    print(f"GraphQL: http://{host}:{port}/graphql  (GraphiQL in the browser)")
    uvicorn.run(GraphQL(schema, graphql_ide="graphiql"), host=host, port=port, log_level="warning")
