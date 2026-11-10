"""Graph view of an engagement: nodes + edges, exported as
  graph.json    generic {nodes, edges}: feed to any tool (D3, Gephi via script, custom UIs)
  graph.cypher  Neo4j import (cypher-shell -f graph.cypher), MERGE-based so re-runs are idempotent
  graph.html    self-contained interactive viewer (Cytoscape.js), open in a browser

Node ids are stable ("ip:1.2.3.4", "domain:acme.com"), so assets shared between targets
collapse into one node and overlaps become visible.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

GRAPH_SCHEMA_VERSION = "1.0"


def _sq(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# Common service names for display; nmap -sV output (when present) wins.
SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
            135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
            587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
            2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt",
            5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis", 6443: "kube-api", 8000: "http-alt",
            8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
            9200: "elasticsearch", 10250: "kubelet", 11211: "memcached", 27017: "mongodb"}


def open_ports(run: dict) -> list[dict]:
    """Open ports per IP, derived from the hosts that resolve to it.

    Scans run per host, so the same IP:port can be reported by several hosts; they are merged
    into one record listing every host name and any HTTP service seen on that port.
    """
    out: dict[tuple[str, int], dict] = {}
    ips = run.get("ips") or {}
    for ip, info in ips.items():  # IP-level scan results (newer runs): include even if no host maps
        for port in info.get("open_ports") or []:
            out.setdefault((ip, int(port)), {"ip": ip, "port": int(port), "protocol": "tcp",
                                             "service": SERVICES.get(int(port)), "hosts": [], "web": []})
    for hname, h in (run.get("hosts") or {}).items():
        for port in h.get("open_ports") or []:
            for ip in (h.get("a") or []) + (h.get("aaaa") or []):
                r = out.setdefault((ip, int(port)), {"ip": ip, "port": int(port), "protocol": "tcp",
                                                     "service": SERVICES.get(int(port)), "hosts": [], "web": []})
                r["hosts"].append(hname)
                for svc in h.get("http") or []:
                    u = urlparse(svc.get("url") or "")
                    if (u.port or {"http": 80, "https": 443}.get(u.scheme)) == int(port) and svc.get("status"):
                        r["web"].append({"url": svc["url"], "status": svc["status"], "title": svc.get("title"),
                                         "server": svc.get("server")})
    for r in out.values():
        r["hosts"] = sorted(set(r["hosts"]))
        nm = next((d for d in (ips.get(r["ip"]) or {}).get("services") or [] if d.get("port") == r["port"]), None)
        r["nmap"] = nm
        if nm:
            r["protocol"] = nm.get("protocol") or r["protocol"]
            if nm.get("service") and nm.get("method") != "table":
                r["service"] = ("ssl/" if nm.get("tunnel") == "ssl" else "") + nm["service"]
            elif nm.get("service") and not r["service"]:
                r["service"] = nm["service"]
        r["product"] = (nm or {}).get("product")
        r["version"] = (nm or {}).get("version")
    return sorted(out.values(), key=lambda r: (r["ip"], r["port"]))


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node(self, nid: str, ntype: str, label: str, **props) -> str:
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "type": ntype, "label": label, "props": {}, "targets": []}
        for k, v in props.items():
            if v not in (None, "", [], {}):
                n["props"][k] = v
        return nid

    def tag(self, nid: str, target_id: str) -> None:
        if target_id not in self.nodes[nid]["targets"]:
            self.nodes[nid]["targets"].append(target_id)

    def edge(self, src: str, dst: str, etype: str, **props) -> None:
        key = (src, dst, etype)
        e = self.edges.setdefault(key, {"source": src, "target": dst, "type": etype, "props": {}})
        e["props"].update({k: v for k, v in props.items() if v not in (None, "")})

    def to_dict(self) -> dict:
        # drop edges whose endpoints were never created (defensive; exporters need both ends)
        self.edges = {k: e for k, e in self.edges.items() if e["source"] in self.nodes and e["target"] in self.nodes}
        return {"schema": "surface-harness/graph", "schema_version": GRAPH_SCHEMA_VERSION,
                "nodes": list(self.nodes.values()), "edges": list(self.edges.values())}


def build_graph(doc: dict) -> Graph:
    g = Graph()
    eng = doc["engagement"]
    eid = g.node(f"engagement:{eng['id']}", "Engagement", eng["client"], id_slug=eng["id"])

    for t in doc["targets"]:
        tid = t["id"]
        tnode = g.node(f"target:{tid}", "Target", t["name"], status=t["status"], seeds=t["domains"])
        g.tag(tnode, tid)
        g.edge(eid, tnode, "INCLUDES")
        run = t.get("surface") or {}
        thr = ((run.get("meta") or {}).get("config") or {}).get("threshold", 0.7)

        # legal entities, agents, officers, parents/subsidiaries
        for c in run.get("companies", []):
            key = c.get("company_number") or c.get("identifiers", {}).get("lei") or c.get("identifiers", {}).get("wikidata") or c["name"]
            en = g.node(f"entity:{c['source']}:{_sq(key)}", "LegalEntity", c["name"], source=c["source"],
                        jurisdiction=c.get("jurisdiction"), number=c.get("company_number"),
                        status=c.get("status"), formed=c.get("formed"),
                        principal_address=c.get("principal_address"),
                        registered_address=c.get("registered_address"), url=c.get("url"))
            g.tag(en, tid)
            g.edge(tnode, en, "HAS_ENTITY", match=c.get("match"))
            if c.get("agent_name"):
                an = g.node(f"agent:{_sq(c['agent_name'])}", "RegisteredAgent", c["agent_name"],
                            commercial=bool(c.get("agent_commercial")), address=c.get("agent_address"))
                g.tag(an, tid)
                g.edge(en, an, "REGISTERED_AGENT")
            for o in c.get("officers", []):
                on = g.node(f"person:{_sq(o['name'])}", "Officer", o["name"])
                g.tag(on, tid)
                g.edge(on, en, "OFFICER_OF", role=o.get("role"))
            for p in c.get("parents", []):
                pn = g.node(f"org:{_sq(p)}", "Organisation", p)
                g.edge(en, pn, "SUBSIDIARY_OF")
            for s in c.get("subsidiaries", [])[:200]:
                sn = g.node(f"org:{_sq(s)}", "Organisation", s)
                g.edge(sn, en, "SUBSIDIARY_OF")

        for ident in (run.get("site_identity") or {}).values():
            for url in ident.get("same_as", []):
                pn = g.node(f"profile:{url.rstrip('/').lower()}", "Profile", url)
                g.tag(pn, tid)
                g.edge(tnode, pn, "HAS_PROFILE")

        # domains
        for name, d in run.get("domains", {}).items():
            conf = d.get("confidence", 0)
            if conf < 0.3:
                continue
            dn = g.node(f"domain:{name}", "Domain", name, seed=d.get("seed"), confidence=conf,
                        registrar=(d.get("whois") or {}).get("registrar"),
                        registrant=(d.get("whois") or {}).get("org"))
            g.tag(dn, tid)
            g.edge(tnode, dn, "OWNS" if conf >= thr else "CANDIDATE", confidence=conf,
                   evidence="; ".join(e["signal"] for e in d.get("evidence", [])))

        # hosts, ips, asns
        ips = run.get("ips", {})
        for hname, h in run.get("hosts", {}).items():
            if not h.get("resolved") and not h.get("cnames"):
                continue
            web = [s for s in h.get("http", []) if s.get("status")]
            hn = g.node(f"host:{hname}", "Host", hname, live=bool(h.get("resolved")), wildcard=h.get("wildcard"),
                        ports=h.get("open_ports"), http_status=[s["status"] for s in web],
                        title=next((s["title"] for s in web if s.get("title")), None),
                        tech=sorted({x for s in web for x in s.get("tech", [])}),
                        sources=h.get("sources"))
            g.tag(hn, tid)
            g.edge(g.node(f"domain:{h['apex']}", "Domain", h["apex"]), hn, "HAS_HOST")
            if h.get("cnames"):
                tgt = h["cnames"][-1]
                cn = g.node(f"host:{tgt}", "Host", tgt, external=True)
                g.edge(hn, cn, "CNAME")
            for ip in h.get("a", []) + h.get("aaaa", []):
                info = ips.get(ip, {})
                ipn = g.node(f"ip:{ip}", "IP", ip, ptr=info.get("ptr"), prefix=info.get("prefix"),
                             country=info.get("country"))
                g.tag(ipn, tid)
                g.edge(hn, ipn, "RESOLVES_TO")
                if info.get("asn"):
                    asn = g.node(f"asn:{info['asn']}", "ASN", f"AS{info['asn']} {info.get('as_name') or ''}".strip(),
                                 name=info.get("as_name"))
                    g.tag(asn, tid)
                    g.edge(ipn, asn, "IN_ASN")

        # open ports hang off the IP they were found on (scans are per host, so merge by IP:port)
        for r in open_ports(run):
            ipn = f"ip:{r['ip']}"
            if ipn not in g.nodes:
                continue
            label = f"{r['port']}/{r['protocol']}" + (f" {r['service']}" if r["service"] else "")
            prodver = " ".join(x for x in (r["product"], r["version"]) if x)
            if prodver:
                label += f" · {prodver}"
            nm = r["nmap"] or {}
            pn = g.node(f"port:{r['ip']}:{r['port']}", "Port", label, ip=r["ip"], port=r["port"],
                        protocol=r["protocol"], service=r["service"], product=r["product"],
                        version=r["version"], extra_info=nm.get("extra_info"), cpe=nm.get("cpe") or None,
                        nmap=nm.get("summary"), nmap_method=nm.get("method"), hosts=r["hosts"],
                        web=[f"{w['status']} {w['url']}" + (f" ({w['title']})" if w.get("title") else "")
                             for w in r["web"]])
            g.tag(pn, tid)
            g.edge(ipn, pn, "HAS_PORT")

        # findings (harness + analyst)
        findings = [dict(f, origin="harness") for f in run.get("findings", [])]
        findings += [{"severity": f.get("severity"), "kind": "analyst", "target": f.get("asset") or "",
                      "detail": f.get("title"), "status": f.get("status"), "origin": "analyst"}
                     for f in (t.get("analysis") or {}).get("findings", [])]
        for i, f in enumerate(findings):
            fn = g.node(f"finding:{tid}:{i}", "Finding", f"{f['severity']}: {f.get('detail', '')[:80]}",
                        severity=f["severity"], kind=f.get("kind"), detail=f.get("detail"),
                        status=f.get("status"), origin=f["origin"])
            g.tag(fn, tid)
            g.edge(fn, _finding_anchor(g, f.get("target", ""), tnode), "AFFECTS")
    return g


def _finding_anchor(g: Graph, target: str, fallback: str) -> str:
    host = urlparse(target).hostname if "://" in target else target.split(":")[0]
    port = target.rsplit(":", 1)[1] if "://" not in target and target.count(":") == 1 else ""
    for nid in (f"port:{target}" if port.isdigit() else "", f"host:{host}", f"ip:{host}", f"ip:{target}",
                f"asn:{target.removeprefix('AS')}"):
        if nid in g.nodes:
            return nid
    return fallback


# ---------------------------------------------------------------------------
# exporters

def _cypher_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_cypher_value(x if isinstance(x, (int, float, bool)) else str(x)) for x in v) + "]"
    return json.dumps(str(v))


def to_cypher(g: Graph) -> str:
    g.to_dict()
    out = ["// Generated by surface-harness. Load with: cypher-shell -f graph.cypher",
           *(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{t}) REQUIRE n.id IS UNIQUE;"
             for t in sorted({n["type"] for n in g.nodes.values()}))]
    for n in g.nodes.values():
        props = {"label": n["label"], "targets": n["targets"], **n["props"]}
        sets = ", ".join(f"n.{re.sub(r'[^A-Za-z0-9_]', '_', k)} = {_cypher_value(v)}" for k, v in props.items())
        out.append(f"MERGE (n:{n['type']} {{id: {json.dumps(n['id'])}}}) SET {sets};")
    for e in g.edges.values():
        st, dt = g.nodes[e["source"]]["type"], g.nodes[e["target"]]["type"]
        props = ", ".join(f"r.{k} = {_cypher_value(v)}" for k, v in e["props"].items())
        out.append(f"MATCH (a:{st} {{id: {json.dumps(e['source'])}}}), (b:{dt} {{id: {json.dumps(e['target'])}}}) "
                   f"MERGE (a)-[r:{e['type']}]->(b)" + (f" SET {props}" if props else "") + ";")
    return "\n".join(out) + "\n"


HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Surface Graph</title>
<script src="https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/webcola@3.4.0/WebCola/cola.min.js"></script>
<script>window.webcola=window.cola;</script>
<script src="https://cdn.jsdelivr.net/npm/cytoscape-cola@2.5.1/cytoscape-cola.js"></script>
<style>
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e2e2dc}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--ink:#ecebe6;--muted:#9a9993;--line:#33332f}}
*{box-sizing:border-box}body{margin:0;font:14px/1.4 system-ui,sans-serif;background:var(--bg);color:var(--ink);display:flex;height:100vh}
aside{width:300px;min-width:240px;border-right:1px solid var(--line);background:var(--panel);padding:14px;overflow:auto}
#cy{flex:1}h1{font-size:16px;margin:0 0 4px}small{color:var(--muted)}
label{display:flex;align-items:center;gap:6px;margin:3px 0;cursor:pointer}.sw{width:12px;height:12px;border-radius:3px;display:inline-block}
input[type=search],select{width:100%;padding:6px 8px;margin:8px 0;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink)}
pre{white-space:pre-wrap;word-break:break-word;font-size:12px;background:var(--bg);padding:8px;border-radius:6px}
.row{display:flex;gap:6px;margin:4px 0 8px}.row button{flex:1;padding:5px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);cursor:pointer}
#modehint{display:block;margin-bottom:6px}
@media (max-width:700px){body{flex-direction:column}aside{width:100%;height:42vh}}
</style></head><body>
<aside><h1>__TITLE__</h1><small>__STATS__</small>
<input type="search" id="q" placeholder="Search label…">
<select id="tgt"><option value="">All targets</option></select>
<select id="mode" title="What moves when you drag a node">
<option value="branch">Drag: branch follows</option><option value="neighbours">Drag: direct neighbours follow</option>
<option value="physics">Drag: live physics (springy)</option><option value="single">Drag: single node</option></select>
<small id="modehint"></small>
<div class="row"><button id="relayout">Re-layout</button><button id="fit" title="Fit to window (F)">Fit</button></div>
<div id="types"></div><h1 style="margin-top:12px">Selection</h1><pre id="info">Click a node or edge.</pre></aside>
<div id="cy"></div>
<script>
const G = __DATA__;
const COLORS={Engagement:"#444",Target:"#2a6fdb",LegalEntity:"#8a4fd8",RegisteredAgent:"#b07d2b",Officer:"#c45c9a",
Organisation:"#7d6bb0",Profile:"#3b9c9c",Domain:"#2f9e44",Host:"#5c7cfa",IP:"#868e96",ASN:"#495057",Port:"#0c8599",Finding:"#e03131"};
const SEV={high:"#e03131",critical:"#c92a2a",medium:"#f08c00",low:"#fab005",info:"#74c0fc"};
const els=[...G.nodes.map(n=>({data:{id:n.id,label:n.label,type:n.type,targets:n.targets,props:n.props,
  color:n.type==="Finding"?(SEV[n.props.severity]||"#e03131"):(COLORS[n.type]||"#999")}})),
  ...G.edges.map((e,i)=>({data:{id:"e"+i,source:e.source,target:e.target,type:e.type,props:e.props}}))];
const cy=cytoscape({container:document.getElementById("cy"),elements:els,wheelSensitivity:0.2,
 style:[{selector:"node",style:{"background-color":"data(color)",label:"data(label)","font-size":8,color:getComputedStyle(document.body).color,"text-valign":"bottom","text-margin-y":3,width:14,height:14,"min-zoomed-font-size":9}},
 {selector:"node[type='Target'],node[type='Engagement']",style:{width:28,height:28,"font-size":12,"font-weight":"bold"}},
 {selector:"node[type='RegisteredAgent']",style:{shape:"diamond"}},{selector:"node[type='Finding']",style:{shape:"triangle"}},
 {selector:"node[type='Port']",style:{shape:"round-rectangle",width:18,height:10}},
 {selector:"edge",style:{width:1,"line-color":"#adb5bd","target-arrow-shape":"triangle","target-arrow-color":"#adb5bd","arrow-scale":0.6,"curve-style":"bezier"}},
 {selector:"edge[type='CANDIDATE']",style:{"line-style":"dashed"}},{selector:".dim",style:{opacity:0.08}},{selector:":selected",style:{"border-width":3,"border-color":"#ffd43b"}}],
 layout:{name:"preset"}});  // real layout runs after filters apply, on the visible nodes only
const COSE={name:"cose",nodeRepulsion:9000,idealEdgeLength:60,numIter:1500,padding:30};
function fitView(animate){const v=cy.elements(":visible");if(!v.length)return;
 animate?cy.animate({fit:{eles:v,padding:30}},{duration:300}):cy.fit(v,30);}
function layoutVisible(animate){const l=cy.elements(":visible").layout({...COSE,animate:!!animate,
 animationDuration:500,fit:false});l.one("layoutstop",()=>fitView(!!animate));l.run();}
const types=[...new Set(G.nodes.map(n=>n.type))].sort(), hidden=new Set();
if(G.nodes.filter(n=>n.type==="IP").length>100){hidden.add("IP");hidden.add("Port");hidden.add("ASN");}  // big CDN ranges drown the picture
document.getElementById("types").innerHTML=types.map(t=>`<label><input type="checkbox" ${hidden.has(t)?"":"checked"} data-t="${t}"><span class="sw" style="background:${COLORS[t]||"#999"}"></span>${t} <small>(${G.nodes.filter(n=>n.type===t).length})</small></label>`).join("");
const tsel=document.getElementById("tgt");[...new Set(G.nodes.flatMap(n=>n.targets))].sort().forEach(t=>tsel.add(new Option(t,t)));
function apply(){const q=document.getElementById("q").value.toLowerCase(),tg=tsel.value;
 cy.nodes().forEach(n=>{const vis=!hidden.has(n.data("type"))&&(!tg||n.data("targets").includes(tg)||n.data("type")==="Engagement");n.style("display",vis?"element":"none");
 n.toggleClass("dim",!!q&&!n.data("label").toLowerCase().includes(q));});}
document.querySelectorAll("#types input").forEach(cb=>cb.onchange=()=>{cb.checked?hidden.delete(cb.dataset.t):hidden.add(cb.dataset.t);apply();});
document.getElementById("q").oninput=apply;tsel.onchange=apply;
apply();
cy.on("tap","node,edge",ev=>{const d=ev.target.data();document.getElementById("info").textContent=JSON.stringify({id:d.id,type:d.type,label:d.label,targets:d.targets,...d.props},null,2);});

// ---- drag behaviour: followers move with the grabbed node -------------------------------
// "branch": everything the node owns (its descendants whose parents are all in the branch),
// plus findings/officers attached to them. Shared nodes (a CDN IP, a common ASN) stay put.
const ATTACH=new Set(["AFFECTS","OFFICER_OF"]);
function branch(root){
 const set=new Set([root.id()]);
 const owned=n=>n.incomers("edge").filter(e=>!ATTACH.has(e.data("type"))).every(e=>set.has(e.source().id()));
 let grew=true;
 while(grew){grew=false;
  cy.nodes().filter(n=>set.has(n.id())).outgoers("edge").forEach(e=>{
   if(ATTACH.has(e.data("type")))return;const t=e.target();
   if(!set.has(t.id())&&t.data("type")!=="Engagement"&&owned(t)){set.add(t.id());grew=true;}});}
 cy.nodes().filter(n=>set.has(n.id())).incomers("edge").forEach(e=>{if(ATTACH.has(e.data("type")))set.add(e.source().id());});
 set.delete(root.id());return cy.nodes().filter(n=>set.has(n.id()));
}
const HINT={branch:"Drag a node: everything it owns comes along (Target → domains → hosts → findings).",
 neighbours:"Drag a node: its directly connected nodes come along.",
 physics:"Nodes are on springs: drag one and connected nodes are pulled after it.",single:"Only the grabbed node moves."};
const modeSel=document.getElementById("mode");
const hasCola=typeof cytoscapeCola!=="undefined"&&typeof cola!=="undefined";
if(hasCola){try{cytoscape.use(cytoscapeCola);}catch(e){}}else modeSel.querySelector("[value=physics]").disabled=true;
let mode="branch",followers=null,last=null,sim=null;
try{const m=localStorage.getItem("surface-graph-mode");if(m&&!(m==="physics"&&!hasCola))mode=m;}catch(e){}
function stopSim(){if(sim){sim.stop();sim=null;}}
let fitTimer=null;
function startSim(){stopSim();clearTimeout(fitTimer);fitTimer=setTimeout(()=>fitView(true),1200);  // fit once it settles
 sim=cy.elements(":visible").layout({name:"cola",infinite:true,fit:false,animate:true,
 nodeSpacing:12,edgeLength:70,randomize:false,avoidOverlap:true,handleDisconnected:true});sim.run();}
function setMode(m){mode=m;modeSel.value=m;document.getElementById("modehint").textContent=HINT[m];
 try{localStorage.setItem("surface-graph-mode",m);}catch(e){}
 m==="physics"?startSim():stopSim();}
modeSel.onchange=()=>setMode(modeSel.value);
cy.on("grab","node",ev=>{const n=ev.target;
 followers=mode==="branch"?branch(n):mode==="neighbours"?n.neighborhood("node"):null;
 if(followers)followers=followers.filter(f=>!f.grabbed()&&!f.selected());last={...n.position()};});
cy.on("drag","node",ev=>{if(!followers||!last)return;const p=ev.target.position();
 const d={x:p.x-last.x,y:p.y-last.y};last={...p};followers.shift(d);});
cy.on("free","node",()=>{followers=null;last=null;});
document.getElementById("relayout").onclick=()=>{
 if(mode==="physics"){cy.nodes().forEach(n=>n.position({x:Math.random()*800,y:Math.random()*600}));startSim();return;}
 layoutVisible(true);};
document.getElementById("fit").onclick=()=>cy.animate({fit:{eles:cy.elements(":visible"),padding:30}},{duration:300});
// filters change the visible set; restart the simulation so hidden nodes don't exert forces
const _apply=apply;apply=function(){_apply();if(mode==="physics")startSim();else fitView(true);};
tsel.onchange=apply;
layoutVisible(false);   // initial view: lay out what is shown, then fit it to the window
setMode(mode);
window.addEventListener("resize",()=>{cy.resize();fitView(false);});
document.addEventListener("keydown",e=>{if(e.key==="f"&&!/INPUT|SELECT|TEXTAREA/.test(e.target.tagName))fitView(true);});
</script></body></html>
"""


def write_graph(doc: dict, out_dir: Path) -> Graph:
    g = build_graph(doc)
    data = g.to_dict()
    (out_dir / "graph.json").write_text(json.dumps(data, indent=1, default=str))
    (out_dir / "graph.cypher").write_text(to_cypher(g))
    stats = f"{len(g.nodes)} nodes · {len(g.edges)} edges · {len(doc['targets'])} targets"
    html = (HTML.replace("__TITLE__", doc["engagement"]["client"].replace("<", "&lt;"))
            .replace("__STATS__", stats)
            .replace("__DATA__", json.dumps(data, default=str).replace("</", "<\\/")))
    (out_dir / "graph.html").write_text(html)
    return g
