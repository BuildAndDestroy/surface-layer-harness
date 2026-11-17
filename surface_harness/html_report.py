"""report.html: the engagement as a work queue, not a document.

One self-contained file (no network, no dependencies) written by `surface-harness merge`.
It turns the merged engagement into things to act on:

  Work queue    analyst-triaged findings, each with what to do, a state (to do / in progress /
                fixed / accepted / not an issue), an owner and a note, plus "copy as ticket"
                and CSV / Markdown export. State lives in the browser (localStorage), is keyed
                by engagement + finding, so it carries over to the next run, and can be
                exported / imported as JSON to share it.
  Decisions     scope questions for the client (copy as an email), and the third-party domains
                the kill-switch refused to touch (copy the scope.yaml line that authorises one).
  Raw findings  every harness finding grouped by kind, with the standard fix for that kind and
                the affected assets ready to copy into a ticket or a script.
  Next steps    recommended tools, what each needs, and the command that enables it.

Everything from the scan (page titles, banners, WHOIS text) is attacker-influenced, so the
data is embedded as JSON and rendered with textContent only; nothing is injected as HTML.
"""

from __future__ import annotations

import json
from typing import Any

# What to do about each kind of raw harness finding (the analyst's recommendation wins when
# a finding has been triaged). Keep these to one imperative sentence.
PLAYBOOK: dict[str, str] = {
    "takeover-candidate": "Remove the DNS record or re-claim the resource it points at today; it can be hijacked by whoever registers it.",
    "dangling-cname": "Delete the CNAME, or restore the target it points at. Confirm with the service owner that the name is unused first.",
    "dangling-ns": "Fix or remove the delegation: a nameserver that no longer exists lets someone else answer for the zone.",
    "dns-axfr": "Restrict zone transfers to the secondary nameservers' addresses.",
    "exposed-service": "Take the service off the internet (firewall / VPN / private endpoint) unless it is meant to be public; if it is, confirm patch level and authentication.",
    "exposed-interface": "Decide whether this login or admin interface needs to be public. If not, restrict it by network; if so, enforce MFA and confirm it is patched.",
    "secret-exposure": "Rotate the exposed credential now, then remove it from the repository history.",
    "breach-exposure": "Force a password reset for the affected accounts and confirm MFA covers them.",
    "tls-weak-protocol": "Disable TLS 1.0/1.1 (and SSL) on the listener; allow TLS 1.2 and 1.3 only.",
    "tls-invalid": "Install a certificate that is valid for this hostname, or retire the hostname.",
    "tls-expiry": "Renew the certificate and put it on automated renewal.",
    "hsts-missing": "Send Strict-Transport-Security (max-age of at least 31536000) on browser-facing HTTPS sites. Ignore for machine-to-machine endpoints.",
    "email-spf": "Publish one SPF record ending in -all (v=spf1 -all for domains that send no mail).",
    "email-dmarc": "Publish DMARC with p=quarantine or p=reject and a rua address (p=reject for domains that send no mail).",
    "email-dkim": "Confirm mail from this domain is DKIM-signed (the check only guesses common selectors); ignore for domains that send no mail.",
    "email-mta-sts": "Optional hardening: publish an MTA-STS policy for domains that receive mail.",
    "email-tls-rpt": "Optional hardening: publish a TLS-RPT record so MTA-STS failures are reported.",
    "dnssec-missing": "Optional hardening: sign the zone with DNSSEC if the DNS provider supports it.",
    "caa-missing": "Publish CAA records naming the certificate authorities that may issue for this domain.",
    "cloud-bucket": "Check the bucket name against your cloud inventory. If it is yours, confirm it is private; if not, make sure nothing references it.",
    "non-production": "Decide whether this non-production environment must be reachable from the internet; restrict by network or SSO if not.",
    "m365-tenant": "Informational: confirm the tenant is yours and review its conditional-access and MFA posture.",
    "m365-federation": "Confirm the federation endpoint is patched, monitored and enforces MFA.",
    "email-format": "Informational: the address format is guessable; make sure MFA and lockout policies assume attackers know valid usernames.",
    "org-asn": "Review this network's prefixes for hosts that DNS-based discovery could not see, and add them to scope if they are yours.",
    "network-cap": "The in-scope network was larger than the expansion cap; raise the cap or split the range to cover all of it.",
    "no-reply": "No action: the probe got no answer.",
}
DEFAULT_ACTION = "Review the affected assets and decide: fix, accept the risk, or mark as not an issue."


def _data(doc: dict) -> dict[str, Any]:
    e = doc["engagement"]
    auth = e.get("authorization") or {}
    targets, actions, raw, scope, blocked = [], [], [], [], []
    for t in doc["targets"]:
        meta = t.get("meta") or {}
        targets.append({
            "id": t["id"], "name": t["name"], "status": t["status"], "started": (meta.get("started_at") or "")[:16],
            "run_dir": t.get("run_dir"), "summary": t.get("summary") or {}, "seeds": t.get("domains") or [],
            "kill": (meta.get("kill_switch") or {}).get("reason"),
            "analysis_summary": (t.get("analysis") or {}).get("summary"),
            "warnings": t.get("analysis_warnings") or [],
        })
        a = t.get("analysis") or {}
        for f in a.get("findings", []):
            actions.append({"target": t["id"], "severity": f.get("severity") or "info",
                            "status": f.get("status") or "", "title": f.get("title") or "",
                            "asset": f.get("asset") or "", "ref": f.get("ref") or "",
                            "evidence": f.get("evidence") or "", "recommendation": f.get("recommendation") or ""})
        for d in a.get("scope_decisions", []):
            scope.append({"target": t["id"], "domain": d.get("domain") or "",
                          "decision": d.get("decision") or "", "rationale": d.get("rationale") or ""})
        surface = t.get("surface") or {}
        for f in surface.get("findings", []):
            raw.append({"target": t["id"], "severity": f.get("severity") or "info", "kind": f.get("kind") or "",
                        "asset": f.get("target") or "", "detail": f.get("detail") or ""})
        for b in (surface.get("meta") or {}).get("third_party_blocked", []):
            blocked.append({"target": t["id"], "domain": b.get("domain"), "score": b.get("evidence_score"),
                            "reason": b.get("reason")})
    tools = [{"name": r.get("name") or r.get("id"), "priority": r.get("priority") or "", "kind": r.get("kind") or "",
              "area": r.get("area") or "", "adds": r.get("adds") or "", "needs": r.get("needs") or "",
              "enable": r.get("enable") or "", "url": r.get("url") or "", "targets": r.get("targets") or [],
              "reasons": r.get("reasons") or []} for r in doc.get("tool_recommendations") or []]
    return {
        "meta": {"client": e.get("client"), "engagement": e.get("id"), "run": doc.get("run"),
                 "generated": doc.get("generated_at"), "authorization": auth.get("reference"),
                 "window": auth.get("window"), "active": bool(auth.get("active_testing"))},
        "targets": targets, "actions": actions, "raw": raw, "scope": scope, "blocked": blocked,
        "tools": tools, "playbook": PLAYBOOK, "default_action": DEFAULT_ACTION,
    }


def render_html(doc: dict) -> str:
    data = json.dumps(_data(doc), default=str, ensure_ascii=False).replace("</", "<\\/")
    title = str(doc["engagement"].get("client") or "Engagement").replace("&", "&amp;").replace("<", "&lt;")
    return TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data)


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · attack surface work queue</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16191d;--mute:#5d6672;--line:#dfe3e8;--accent:#1f5fbf;--accent-ink:#fff;
--crit:#8f1425;--high:#c2291e;--med:#a85d00;--low:#1f5fbf;--info:#5d6672;--ok:#1d7a46;--warn-bg:#fff4e0;--kill-bg:#fde8e6;--code:#f0f2f5}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--ink:#e7eaee;--mute:#9aa4b1;--line:#2c333c;--accent:#6ea8ff;--accent-ink:#0b1220;
--crit:#ff8091;--high:#ff7b6e;--med:#f0b24a;--low:#7fb2ff;--info:#9aa4b1;--ok:#5fd08c;--warn-bg:#3a2c10;--kill-bg:#3d1b18;--code:#232830}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header,main{max-width:1180px;margin:0 auto;padding:0 16px}
header{padding-top:22px}
h1{font-size:22px;margin:0 0 2px}
h2{font-size:17px;margin:26px 0 8px}
.sub{color:var(--mute);font-size:13px}
.banner{border:1px solid var(--line);border-left:5px solid var(--high);background:var(--kill-bg);padding:10px 14px;border-radius:6px;margin:14px 0}
.banner.warn{border-left-color:var(--med);background:var(--warn-bg)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile b{display:block;font-size:24px;line-height:1.2;font-variant-numeric:tabular-nums}
.tile span{color:var(--mute);font-size:12px}
nav{display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-top:8px}
nav button{background:none;border:0;border-bottom:3px solid transparent;color:var(--mute);font:inherit;font-weight:600;padding:9px 12px;cursor:pointer}
nav button[aria-selected=true]{color:var(--ink);border-bottom-color:var(--accent)}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:14px 0}
.bar input[type=search]{flex:1 1 220px;min-width:160px}
input,select,textarea,button{font:inherit;color:inherit}
input[type=search],input[type=text],select,textarea{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:6px 8px}
textarea{width:100%;min-height:56px;resize:vertical}
.btn{display:inline-block;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:6px 10px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
.chip{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:3px 10px;cursor:pointer;font-size:13px}
.chip[aria-pressed=true]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.item{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;overflow:hidden}
.item.done{opacity:.62}
.row{display:grid;grid-template-columns:86px 1fr 150px;gap:10px;align-items:start;padding:10px 12px;cursor:pointer}
.row:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
.sev{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.sev.critical{color:var(--crit)}.sev.high{color:var(--high)}.sev.medium{color:var(--med)}.sev.low{color:var(--low)}.sev.info{color:var(--info)}
.ttl{font-weight:600;overflow-wrap:anywhere}
.asset{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--mute);overflow-wrap:anywhere}
.tag{display:inline-block;font-size:11.5px;border:1px solid var(--line);border-radius:4px;padding:0 6px;margin-right:4px;color:var(--mute)}
.body{border-top:1px solid var(--line);padding:12px;display:grid;grid-template-columns:1fr 280px;gap:16px}
.body h4{margin:0 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute)}
.todo{border-left:4px solid var(--ok);padding:6px 10px;background:color-mix(in srgb,var(--ok) 9%,transparent);border-radius:0 6px 6px 0;overflow-wrap:anywhere}
pre{background:var(--code);border-radius:6px;padding:8px 10px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;max-height:260px;overflow:auto}
.side label{display:block;font-size:12px;color:var(--mute);margin:8px 0 2px}
.side select,.side input{width:100%}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute)}
tr:last-child td{border-bottom:0}
.scroll{overflow-x:auto}
.progress{height:8px;background:var(--line);border-radius:4px;overflow:hidden;flex:1 1 160px;min-width:120px}
.progress i{display:block;height:100%;background:var(--ok)}
.empty{color:var(--mute);padding:18px;text-align:center}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:7px 14px;border-radius:6px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none}
.toast.on{opacity:1}
footer{color:var(--mute);font-size:12.5px;margin:28px 0 40px}
a{color:var(--accent)}
@media (max-width:760px){.row{grid-template-columns:70px 1fr}.row .state{grid-column:1/-1}.body{grid-template-columns:1fr}}
@media print{nav,.bar,.side,button{display:none!important}.item{break-inside:avoid}.body{display:block!important}}
</style>
</head>
<body>
<header>
  <h1 id="h1"></h1>
  <div class="sub" id="sub"></div>
  <div id="banners"></div>
  <div class="tiles" id="tiles"></div>
  <nav role="tablist" id="tabs"></nav>
</header>
<main id="main"></main>
<main><footer>Triage state (status, owner, notes) is stored in this browser only and is keyed to the engagement, so it carries over when you open the report of a later run. Use Export state / Import state to move it. Companion files in this directory: <a href="report.md">report.md</a> (full detail), <a href="graph.html">graph.html</a> (relationships), <a href="engagement.json">engagement.json</a> (data).</footer></main>
<div class="toast" id="toast" role="status"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const SEV = ["critical","high","medium","low","info"];
const STATES = [["todo","To do"],["doing","In progress"],["fixed","Fixed"],["accepted","Risk accepted"],["notissue","Not an issue"]];
const CLOSED = new Set(["fixed","accepted","notissue"]);
const NS = "surface-harness:" + (D.meta.engagement || "engagement") + ":";

// ---- tiny DOM helper: text only, never HTML -------------------------------------------
function el(tag, attrs, ...kids){
  const n = document.createElement(tag);
  for (const [k,v] of Object.entries(attrs || {})){
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()){ if (k != null && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k))); }
  return n;
}
function toast(msg){ const t = document.getElementById("toast"); t.textContent = msg; t.classList.add("on"); setTimeout(() => t.classList.remove("on"), 1600); }
async function copy(text, what){
  try { await navigator.clipboard.writeText(text); }
  catch (e) { const ta = el("textarea"); ta.value = text; document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
  toast((what || "Copied") + " copied");
}
function download(name, text, type){
  const a = el("a", {href: URL.createObjectURL(new Blob([text], {type: type || "text/plain"})), download: name});
  document.body.append(a); a.click(); a.remove();
}
function csv(rows){ return rows.map(r => r.map(c => { let s = String(c == null ? "" : c); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g,'""') + '"'; }).join(",")).join("\r\n"); }

// ---- triage state ---------------------------------------------------------------------
let mem = {};
function load(){ try { mem = JSON.parse(localStorage.getItem(NS + "state") || "{}"); } catch (e) { mem = {}; } }
function save(){ try { localStorage.setItem(NS + "state", JSON.stringify(mem)); } catch (e) { /* private mode: state lasts for this page view */ } }
function keyOf(a){ return a.target + "|" + (a.ref || (a.asset + "|" + a.title)); }
function st(a){
  const s = mem[keyOf(a)] || {};
  return {state: s.state || (a.status === "false-positive" ? "notissue" : "todo"), owner: s.owner || "", note: s.note || ""};
}
function setSt(a, patch){ mem[keyOf(a)] = Object.assign(st(a), patch, {updated: new Date().toISOString().slice(0,10)}); save(); }
const stateLabel = s => (STATES.find(x => x[0] === s) || ["", s])[1];
const action = a => a.recommendation || D.playbook[(a.ref || "").split(":")[0]] || D.default_action;

function ticket(a){
  const s = st(a);
  return [
    "## [" + a.severity.toUpperCase() + "] " + a.title, "",
    "**Asset:** " + (a.asset || "-"), "**Target:** " + a.target, "**Analyst status:** " + (a.status || "-"),
    s.owner ? "**Owner:** " + s.owner : null, "",
    "### What to do", action(a), "",
    a.evidence ? "### Evidence\n```\n" + a.evidence + "\n```" : null,
    s.note ? "\n### Notes\n" + s.note : null, "",
    "_Source: " + D.meta.client + " attack surface assessment" + (D.meta.run ? ", run " + D.meta.run : "") + (a.ref ? ", ref " + a.ref : "") + "_",
  ].filter(x => x != null).join("\n");
}

// ---- header ---------------------------------------------------------------------------
function header(){
  document.getElementById("h1").textContent = (D.meta.client || "Engagement") + ": attack surface work queue";
  document.getElementById("sub").textContent = [
    "Engagement " + D.meta.engagement, D.meta.run ? "run " + D.meta.run : null, "generated " + (D.meta.generated || "").slice(0,16).replace("T"," "),
    "authorization: " + (D.meta.authorization || "none recorded"), D.meta.window ? "window " + D.meta.window : null,
    "active testing " + (D.meta.active ? "permitted" : "not permitted"),
  ].filter(Boolean).join(" · ");
  const b = document.getElementById("banners");
  for (const t of D.targets){
    if (t.kill) b.append(el("div", {class:"banner"}, el("b", {}, "Kill-switch: target " + t.id + " was stopped. "), t.kill + ". Its results are partial."));
    else if (t.status !== "complete") b.append(el("div", {class:"banner warn"}, el("b", {}, "Target " + t.id + ": " + t.status + ". "), t.status === "missing" ? "No harness run was found." : "Results may be partial."));
    for (const w of t.warnings) b.append(el("div", {class:"banner warn"}, "analysis.json for " + t.id + ": " + w));
  }
  if (D.blocked.length) b.append(el("div", {class:"banner warn"}, el("b", {}, D.blocked.length + " third-party domain(s) were not touched. "), "Evidence pointed at them, but nothing shows they are the client's. See Decisions."));
}
function tiles(){
  const open = D.actions.filter(a => !CLOSED.has(st(a).state));
  const n = s => open.filter(a => a.severity === s).length;
  const sum = k => D.targets.reduce((x,t) => x + (t.summary[k] || 0), 0);
  const cells = [
    [open.length, "open items"], [n("critical") + n("high"), "critical / high"], [n("medium"), "medium"], [n("low") + n("info"), "low / info"],
    [D.scope.filter(s => s.decision === "needs-client-confirmation").length, "scope questions"],
    [sum("in_scope_domains"), "in-scope domains"], [sum("live_hosts"), "live hosts"], [D.raw.length, "raw findings"],
  ];
  const t = document.getElementById("tiles"); t.replaceChildren(...cells.map(([v,l]) => el("div", {class:"tile"}, el("b", {}, v), el("span", {}, l))));
}

// ---- tab: work queue ------------------------------------------------------------------
const F = {sev: new Set(), state: "open", q: "", target: ""};
const openRows = new Set();
function queue(root){
  if (!D.actions.length){
    root.append(el("div", {class:"empty"}, "No analyst-triaged findings in this run. The harness findings are under Raw findings, grouped by kind with the standard fix for each."));
    return;
  }
  const list = el("div");
  const prog = el("i"); const progTxt = el("span", {class:"sub"});
  const bar = el("div", {class:"bar"},
    el("input", {type:"search", placeholder:"Filter by asset, title, owner…", "aria-label":"Filter findings", value: F.q, oninput: e => { F.q = e.target.value.toLowerCase(); draw(); }}),
    SEV.filter(s => D.actions.some(a => a.severity === s)).map(s => el("button", {class:"chip", "aria-pressed": String(F.sev.has(s)), onclick: e => { F.sev.has(s) ? F.sev.delete(s) : F.sev.add(s); e.target.setAttribute("aria-pressed", String(F.sev.has(s))); draw(); }}, s)),
    el("select", {"aria-label":"State filter", onchange: e => { F.state = e.target.value; draw(); }},
      [["open","Open items"],["all","Everything"]].concat(STATES).map(([v,l]) => el("option", {value:v, selected: F.state === v}, l))),
    D.targets.length > 1 ? el("select", {"aria-label":"Target filter", onchange: e => { F.target = e.target.value; draw(); }}, el("option", {value:""}, "All targets"), D.targets.map(t => el("option", {value:t.id}, t.id))) : null,
  );
  const tools = el("div", {class:"bar"},
    el("div", {class:"progress", role:"img", "aria-label":"Share of findings handled"}, prog), progTxt,
    el("button", {class:"btn", onclick: () => download("tickets.md", shown().map(ticket).join("\n\n---\n\n"), "text/markdown")}, "Export tickets (Markdown)"),
    el("button", {class:"btn", onclick: () => download("findings.csv", csv([["severity","state","owner","target","asset","title","what_to_do","analyst_status","note","ref"]].concat(shown().map(a => { const s = st(a); return [a.severity, stateLabel(s.state), s.owner, a.target, a.asset, a.title, action(a), a.status, s.note, a.ref]; }))), "text/csv")}, "Export CSV"),
    el("button", {class:"btn", onclick: () => download("triage-state-" + D.meta.engagement + ".json", JSON.stringify(mem, null, 1), "application/json")}, "Export state"),
    el("label", {class:"btn"}, "Import state", el("input", {type:"file", accept:"application/json", hidden:true, onchange: async e => {
      try { const j = JSON.parse(await e.target.files[0].text()); if (j && typeof j === "object" && !Array.isArray(j)) { Object.assign(mem, j); save(); tiles(); draw(); toast("State imported"); } }
      catch (err) { toast("Not a valid state file"); } }})),
  );
  root.append(bar, tools, list);

  function shown(){
    return D.actions.filter(a => {
      const s = st(a);
      if (F.sev.size && !F.sev.has(a.severity)) return false;
      if (F.target && a.target !== F.target) return false;
      if (F.state === "open" ? CLOSED.has(s.state) : (F.state !== "all" && s.state !== F.state)) return false;
      return !F.q || (a.title + " " + a.asset + " " + a.ref + " " + s.owner + " " + s.note).toLowerCase().includes(F.q);
    }).sort((a,b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.asset.localeCompare(b.asset));
  }
  function draw(){
    const done = D.actions.filter(a => CLOSED.has(st(a).state)).length;
    prog.style.width = (D.actions.length ? 100 * done / D.actions.length : 0) + "%";
    progTxt.textContent = done + " of " + D.actions.length + " handled";
    const rows = shown();
    list.replaceChildren(...(rows.length ? rows.map(card) : [el("div", {class:"empty"}, "Nothing matches these filters.")]));
  }
  function card(a){
    const s = st(a), k = keyOf(a);
    const sel = el("select", {class:"state", "aria-label":"State", onclick: e => e.stopPropagation(), onchange: e => { setSt(a, {state: e.target.value}); tiles(); draw(); }},
      STATES.map(([v,l]) => el("option", {value:v, selected: s.state === v}, l)));
    const body = el("div", {class:"body", hidden: !openRows.has(k)},
      el("div", {},
        el("h4", {}, "What to do"), el("div", {class:"todo"}, action(a)),
        a.evidence ? [el("h4", {style:"margin-top:12px"}, "Evidence"), el("pre", {}, a.evidence)] : null,
        el("div", {class:"bar"},
          el("button", {class:"btn primary", onclick: () => copy(ticket(a), "Ticket")}, "Copy as ticket"),
          el("button", {class:"btn", onclick: () => copy(a.asset, "Asset")}, "Copy asset"),
          a.evidence ? el("button", {class:"btn", onclick: () => copy(a.evidence, "Evidence")}, "Copy evidence") : null)),
      el("div", {class:"side"},
        el("label", {}, "Owner"), el("input", {type:"text", value: s.owner, placeholder:"Team or person", onchange: e => setSt(a, {owner: e.target.value})}),
        el("label", {}, "Notes / ticket link"), el("textarea", {onchange: e => setSt(a, {note: e.target.value})}, s.note),
        el("label", {}, "Reference"), el("div", {class:"asset"}, a.ref || "-")));
    const row = el("div", {class:"row", role:"button", tabindex:"0", "aria-expanded": String(openRows.has(k)),
      onclick: () => { openRows.has(k) ? openRows.delete(k) : openRows.add(k); body.hidden = !openRows.has(k); row.setAttribute("aria-expanded", String(openRows.has(k))); },
      onkeydown: e => { if (e.target === row && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); row.click(); } }},
      el("div", {class:"sev " + a.severity}, a.severity),
      el("div", {}, el("div", {class:"ttl"}, a.title), el("div", {class:"asset"}, a.asset),
        el("div", {}, a.status ? el("span", {class:"tag"}, a.status) : null, D.targets.length > 1 ? el("span", {class:"tag"}, a.target) : null, s.owner ? el("span", {class:"tag"}, s.owner) : null)),
      sel);
    return el("div", {class:"item" + (CLOSED.has(s.state) ? " done" : "")}, row, body);
  }
  draw();
}

// ---- tab: decisions -------------------------------------------------------------------
function decisions(root){
  const ask = D.scope.filter(s => s.decision === "needs-client-confirmation");
  root.append(el("h2", {}, "Scope questions for the client (" + ask.length + ")"));
  if (ask.length){
    const mail = "Subject: " + D.meta.client + " attack surface assessment: scope confirmation\n\nPlease confirm whether each of these domains is yours and in scope for testing:\n\n"
      + ask.map((s,i) => (i+1) + ". " + s.domain + "\n   " + s.rationale).join("\n\n") + "\n\nFor each, reply: in scope / out of scope / in scope with limits.";
    root.append(el("div", {class:"bar"}, el("button", {class:"btn primary", onclick: () => copy(mail, "Email")}, "Copy as email to the client"),
      el("button", {class:"btn", onclick: () => copy("    domains: [" + ask.map(s => s.domain).join(", ") + "]", "scope.yaml line")}, "Copy as scope.yaml domains"),
      el("span", {class:"sub"}, "A domain is only tested after you add it to the target's domains in scope.yaml.")));
    root.append(tbl(["Domain","Why it needs a decision"], ask.map(s => [s.domain, s.rationale])));
  } else root.append(el("div", {class:"empty"}, "No open scope questions."));

  root.append(el("h2", {}, "Third-party domains the kill-switch did not touch (" + D.blocked.length + ")"));
  if (D.blocked.length){
    root.append(el("p", {class:"sub"}, "Redirects, certificates or links pointed at these, but nothing shows the client owns them, so nothing was sent to them. If one is the client's, add it to scope.yaml and re-run."));
    root.append(tbl(["Domain","Evidence score","Why it was held back",""], D.blocked.map(b => [b.domain, b.score, b.reason,
      el("button", {class:"btn", onclick: () => copy(b.domain, "Domain")}, "Copy")])));
  } else root.append(el("div", {class:"empty"}, "None in this run."));

  for (const [label, dec] of [["Confirmed in scope","in-scope"],["Ruled out of scope","out-of-scope"]]){
    const rows = D.scope.filter(s => s.decision === dec);
    if (!rows.length) continue;
    const d = el("details", {}, el("summary", {}, el("b", {}, label + " (" + rows.length + ")")), tbl(["Domain","Rationale"], rows.slice(0,500).map(s => [s.domain, s.rationale])),
      rows.length > 500 ? el("p", {class:"sub"}, (rows.length - 500) + " more in engagement.json.") : null);
    root.append(el("div", {style:"margin-top:18px"}, d));
  }
}
function tbl(head, rows){
  return el("div", {class:"scroll"}, el("table", {}, el("thead", {}, el("tr", {}, head.map(h => el("th", {}, h)))),
    el("tbody", {}, rows.map(r => el("tr", {}, r.map(c => el("td", {}, c)))))));
}

// ---- tab: raw findings ----------------------------------------------------------------
function raw(root){
  if (!D.raw.length){ root.append(el("div", {class:"empty"}, "The harness produced no findings in this run.")); return; }
  const groups = new Map();
  for (const f of D.raw){ const k = f.kind + "|" + f.severity; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(f); }
  const sorted = [...groups.values()].sort((a,b) => SEV.indexOf(a[0].severity) - SEV.indexOf(b[0].severity) || b.length - a.length);
  root.append(el("div", {class:"bar"}, el("span", {class:"sub"}, "Unverified harness output, grouped by kind. Triaged versions of the important ones are in the work queue."),
    el("button", {class:"btn", onclick: () => download("raw-findings.csv", csv([["severity","kind","target","asset","detail","standard_fix"]].concat(D.raw.map(f => [f.severity, f.kind, f.target, f.asset, f.detail, D.playbook[f.kind] || D.default_action]))), "text/csv")}, "Export all (CSV)")));
  for (const g of sorted){
    const f0 = g[0];
    const body = el("div", {class:"body", hidden:true, style:"grid-template-columns:1fr"});
    let built = false;
    const row = el("div", {class:"row", role:"button", tabindex:"0", "aria-expanded":"false",
      onclick: () => {
        if (!built){ built = true;
          body.append(el("div", {}, el("h4", {}, "Standard fix"), el("div", {class:"todo"}, D.playbook[f0.kind] || D.default_action),
            el("div", {class:"bar"}, el("button", {class:"btn primary", onclick: () => copy([...new Set(g.map(f => f.asset))].join("\n"), g.length + " assets")}, "Copy affected assets"),
              el("button", {class:"btn", onclick: () => copy("## [" + f0.severity.toUpperCase() + "] " + f0.kind + " on " + g.length + " asset(s)\n\n### What to do\n" + (D.playbook[f0.kind] || D.default_action) + "\n\n### Affected\n" + g.map(f => "- " + f.asset + ": " + f.detail).join("\n"), "Ticket")}, "Copy as one ticket")),
            tbl(["Asset","Detail"], g.slice(0,400).map(f => [el("span", {class:"asset"}, f.asset), f.detail])),
            g.length > 400 ? el("p", {class:"sub"}, (g.length - 400) + " more: use Copy affected assets or the CSV export.") : null)); }
        body.hidden = !body.hidden; row.setAttribute("aria-expanded", String(!body.hidden)); },
      onkeydown: e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); row.click(); } }},
      el("div", {class:"sev " + f0.severity}, f0.severity),
      el("div", {}, el("div", {class:"ttl"}, f0.kind), el("div", {class:"sub"}, D.playbook[f0.kind] || D.default_action)),
      el("div", {class:"sub state"}, g.length + (g.length === 1 ? " asset" : " assets")));
    root.append(el("div", {class:"item"}, row, body));
  }
}

// ---- tab: next steps ------------------------------------------------------------------
function next(root){
  for (const t of D.targets){
    root.append(el("h2", {}, t.name + " (" + t.id + ")"),
      el("p", {class:"sub"}, [t.status, t.started ? "started " + t.started.replace("T"," ") : null, "seeds: " + t.seeds.join(", "), t.run_dir ? "harness output: " + t.run_dir : null].filter(Boolean).join(" · ")),
      t.analysis_summary ? el("p", {}, t.analysis_summary) : null);
  }
  root.append(el("h2", {}, "Recommended tools and coverage gaps (" + D.tools.length + ")"));
  if (!D.tools.length){ root.append(el("div", {class:"empty"}, "No recommendations.")); return; }
  const order = {high:0, medium:1, low:2};
  root.append(tbl(["Priority","Tool","Why","Needs","Enable"], D.tools.slice().sort((a,b) => (order[a.priority] ?? 9) - (order[b.priority] ?? 9)).map(r => [
    r.priority, el("div", {}, el("b", {}, r.name), el("div", {class:"sub"}, r.kind === "coverage-gap" ? "harness coverage gap" : r.area)),
    el("div", {}, r.reasons.length ? r.reasons.map(x => el("div", {}, x)) : r.adds), r.needs,
    r.enable ? el("div", {}, el("div", {class:"asset"}, r.enable), el("button", {class:"btn", style:"margin-top:4px", onclick: () => copy(r.enable, "Command")}, "Copy")) : ""])));
}

// ---- shell ----------------------------------------------------------------------------
const TABS = [["queue","Work queue", queue, () => D.actions.filter(a => !CLOSED.has(st(a).state)).length],
              ["decisions","Decisions", decisions, () => D.scope.filter(s => s.decision === "needs-client-confirmation").length + D.blocked.length],
              ["raw","Raw findings", raw, () => D.raw.length], ["next","Next steps", next, () => D.tools.length]];
function show(id){
  const tab = TABS.find(t => t[0] === id) || TABS[0];
  document.getElementById("tabs").replaceChildren(...TABS.map(t => el("button", {role:"tab", "aria-selected": String(t === tab), onclick: () => show(t[0])}, t[1] + " (" + t[3]() + ")")));
  const m = document.getElementById("main"); m.replaceChildren(); tab[2](m);
  try { history.replaceState(null, "", "#" + tab[0]); } catch (e) { /* file:// in some browsers */ }
}
load(); header(); tiles(); show(location.hash.slice(1) || "queue");
</script>
</body>
</html>
"""
