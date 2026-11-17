"""Tool recommendations: what else is needed for a complete (holistic) external surface picture.

Two kinds of recommendation come out of here:

* **coverage gaps**: things this harness already integrates but that were switched off for a run
  (a missing API key, a missing binary, a mode that wasn't authorised). Enabling them and
  re-running fills the gap.
* **complementary tools**: tools outside the harness that cover parts of the external surface it
  deliberately does not (internet-scan data, screenshots, vulnerability templates, lookalike
  domains, cloud/identity posture with client access, ...). Each one is triggered by what the run
  actually found, so the report only recommends what is relevant to this client.

Nothing here installs or runs a tool. Recommendations are advice for the human running the
engagement, who decides (and, where needed, gets the client's authorization) before using them.

Used by:
  * ``surface-harness doctor``: pre-flight environment check (coverage gaps only).
  * ``report.write_all``: the "Recommended tools" section of each run's report.md.
  * ``engagement.merge``: engagement-wide ``tool_recommendations`` + the report section.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Binaries the pipeline can use. gitleaks/git must be local (they scan a host-side clone).
PIPELINE_TOOLS = ("subfinder", "naabu", "nmap", "gitleaks", "git")


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    area: str  # which part of the holistic picture it covers
    kind: str  # "coverage-gap" (harness integration switched off) | "complementary" (outside the harness)
    adds: str  # what it contributes
    needs: str  # what the human must provide: key, binary, authorization, client access
    enable: str  # how to enable / use it
    url: str = ""


CATALOG: dict[str, Tool] = {t.id: t for t in (
    # -- coverage gaps: harness integrations that need a key/binary/mode -----------------------
    Tool("whoisxml", "WhoisXML Reverse WHOIS", "Domain discovery", "coverage-gap",
         "Finds other domains registered by the same organisation or email: the best source for "
         "unrelated-looking domains (acquisitions, campaigns, regional brands).",
         "API key", "export WHOISXML_API_KEY=...", "https://reverse-whois.whoisxmlapi.com"),
    Tool("securitytrails", "SecurityTrails", "Subdomain discovery", "coverage-gap",
         "Large passive-DNS subdomain corpus, including names never seen in CT logs.",
         "API key", "export SECURITYTRAILS_API_KEY=...", "https://securitytrails.com"),
    Tool("virustotal", "VirusTotal", "Subdomain discovery", "coverage-gap",
         "Subdomains observed by VirusTotal's crawlers and resolvers.",
         "API key", "export VIRUSTOTAL_API_KEY=...", "https://www.virustotal.com"),
    Tool("otx", "AlienVault OTX key", "Subdomain discovery", "coverage-gap",
         "Removes OTX's anonymous rate limit (HTTP 429), so its passive DNS actually returns data.",
         "free API key", "export OTX_API_KEY=...", "https://otx.alienvault.com"),
    Tool("certspotter", "CertSpotter key", "Subdomain discovery", "coverage-gap",
         "Higher CT-log query limits when crt.sh is slow or failing.",
         "API key", "export CERTSPOTTER_API_KEY=...", "https://sslmate.com/certspotter/api/"),
    Tool("opencorporates", "OpenCorporates", "Company / legal entity", "coverage-gap",
         "Registry coverage for all US states (incl. DE/WY) and 140+ jurisdictions: legal entities, "
         "registered agents, officers. Confirmed legal names feed the CT O= search.",
         "API token", "export OPENCORPORATES_API_TOKEN=...", "https://api.opencorporates.com"),
    Tool("contact", "SURFACE_CONTACT (SEC EDGAR + Wikidata)", "Company / legal entity", "coverage-gap",
         "Enables SEC EDGAR (public companies) and Wikidata (parent/subsidiaries with their websites, "
         "which feed domain discovery). Both require contact details in the User-Agent.",
         "contact email or URL", "export SURFACE_CONTACT='security@yourfirm.example'"),
    Tool("hibp", "Have I Been Pwned (domain search)", "Credential exposure", "coverage-gap",
         "Breach-by-domain counts for the client's domains (aggregate only, no credentials).",
         "API key + domains verified on the HIBP subscription", "export HIBP_API_KEY=...",
         "https://haveibeenpwned.com/API/v3"),
    Tool("subfinder", "subfinder", "Subdomain discovery", "coverage-gap",
         "Dozens of extra passive aggregators (more with provider keys in "
         "~/.config/subfinder/provider-config.yaml: Shodan, Censys, Chaos, ...).",
         "binary or Docker image", "make tools-image (or install subfinder on PATH)",
         "https://github.com/projectdiscovery/subfinder"),
    Tool("gitleaks", "gitleaks (local)", "Code / secret exposure", "coverage-gap",
         "Secret-exposure counts in the organisation's known public repositories.",
         "local gitleaks + git binaries", "install gitleaks on PATH (the Docker backend can't scan host clones)",
         "https://github.com/gitleaks/gitleaks"),
    Tool("standard-mode", "Standard mode (HTTP/TLS probing)", "Live services", "coverage-gap",
         "Fingerprints live web services, certificates, TLS config, login pages, buckets and "
         "related-domain evidence from redirects/certs. Passive mode only resolves DNS.",
         "client OK for normal-browsing-level traffic", "--mode standard (scope.yaml defaults.mode)"),
    Tool("active-mode", "Active mode (port scan, nmap -sV, DNS brute force, UDP VPN probes)",
         "Network services", "coverage-gap",
         "Non-web exposure: databases, RDP/SSH, VPN gateways, admin services, with versions/CPEs.",
         "written authorization for active testing (authorization.active_testing: true)",
         "set authorization.active_testing: true, then --mode active"),
    Tool("naabu-nmap", "naabu + nmap", "Network services", "coverage-gap",
         "Faster port discovery and real service/version fingerprints instead of port-number guesses.",
         "binaries or Docker image", "make tools-image (or install naabu and nmap on PATH)",
         "https://github.com/projectdiscovery/naabu"),

    # -- complementary: outside this harness -----------------------------------------------
    Tool("shodan-censys", "Shodan / Censys host data", "Network services", "complementary",
         "Internet-wide scan history for the discovered IPs: open ports, banners, versions and "
         "historic exposure, without sending traffic to the client.",
         "API key (paid tier for bulk lookups)", "query the IPs in ips.txt; also add the keys to "
         "subfinder's provider config", "https://www.shodan.io"),
    Tool("gowitness", "gowitness / EyeWitness screenshots", "Web applications", "complementary",
         "Screenshots of every live web service for fast visual triage (login portals, default "
         "pages, forgotten apps, staging sites).",
         "binary (normal-browsing-level traffic)", "gowitness scan file -f urls.txt",
         "https://github.com/sensepost/gowitness"),
    Tool("nuclei", "nuclei", "Vulnerabilities", "complementary",
         "Template-based detection of known CVEs, misconfigurations and exposed panels on the "
         "live services this harness found (the harness never vulnerability-scans).",
         "written authorization for vulnerability scanning", "nuclei -l urls.txt -severity medium,high,critical",
         "https://github.com/projectdiscovery/nuclei"),
    Tool("testssl", "testssl.sh", "TLS", "complementary",
         "Full cipher-suite, protocol and TLS-vulnerability audit (the harness only checks protocol "
         "versions, expiry and HSTS).",
         "binary (handshake traffic only)", "testssl.sh --file <host:port list>",
         "https://github.com/drwetter/testssl.sh"),
    Tool("katana", "katana (crawler + JS endpoint extraction)", "Web applications", "complementary",
         "API endpoints, hidden paths and third-party hosts referenced from the web apps' "
         "JavaScript: surface that DNS and CT logs never show.",
         "authorization for crawling", "katana -list urls.txt -jc -d 2",
         "https://github.com/projectdiscovery/katana"),
    Tool("dnstwist", "dnstwist", "Brand / phishing", "complementary",
         "Registered lookalike and typosquat domains (phishing infrastructure, brand abuse) that "
         "ownership-based discovery deliberately excludes.",
         "binary (DNS lookups only)", "dnstwist --registered <seed domain>",
         "https://github.com/elceef/dnstwist"),
    Tool("code-search", "GitHub/GitLab org search + trufflehog", "Code / secret exposure", "complementary",
         "Finds the organisation's (and employees') public repositories and leaked secrets. The "
         "harness only scans repositories it already knows from the website.",
         "GitHub token; human review of repo ownership", "trufflehog github --org=<org> --only-verified",
         "https://github.com/trufflesecurity/trufflehog"),
    Tool("cloud-posture", "Prowler / ScoutSuite", "Cloud", "complementary",
         "Configuration review of the client's AWS/Azure/GCP accounts behind the discovered cloud "
         "assets (public buckets, security groups, exposed services).",
         "read-only cloud credentials from the client", "prowler aws|azure|gcp (with client-issued audit role)",
         "https://github.com/prowler-cloud/prowler"),
    Tool("m365-posture", "Maester / CISA ScubaGear", "Identity", "complementary",
         "Microsoft 365 / Entra ID configuration review (MFA, conditional access, legacy auth, "
         "external sharing) for the discovered tenant.",
         "read-only tenant access from the client", "Invoke-Maester / Invoke-SCuBA",
         "https://maester.dev"),
    Tool("web-app-testing", "Burp Suite / OWASP ZAP", "Web applications", "complementary",
         "Manual/authenticated testing of the exposed login portals and applications the harness "
         "only fingerprints.",
         "written authorization for application testing", "proxy the in-scope URLs from urls.txt",
         "https://www.zaproxy.org"),
    Tool("mobile-apps", "App-store search + MobSF", "Mobile", "complementary",
         "The organisation's mobile apps and the API hosts/keys embedded in them, which often "
         "reveal backends not linked from any website.",
         "none for search; MobSF for static analysis", "search the app stores for the legal/brand "
         "names, then mobsf static analysis", "https://github.com/MobSF/Mobile-Security-Framework-MobSF"),
)}

CLOUD_ASN_RE = re.compile(r"AMAZON|AWS|MICROSOFT|AZURE|GOOGLE|ORACLE|DIGITALOCEAN|LINODE|AKAMAI-LINODE|OVH|HETZNER",
                          re.I)


# ---------------------------------------------------------------------------
# Environment probing (pre-flight and run metadata)

def probe_capabilities(keys: dict[str, str], runner, mode: str = "auto") -> dict:
    """What this environment can use: API keys present and how each binary would run."""
    tools: dict[str, str | None] = {}
    for t in PIPELINE_TOOLS:
        tools[t] = runner.backend(t) if mode != "none" else None
    return {"keys": sorted(k for k in keys if k != "contact"), "contact": "contact" in keys or
            "sec_user_agent" in keys, "tools": tools}


@dataclass
class Rec:
    tool: str
    priority: str
    reason: str


def coverage_gaps(caps: dict, mode: str, active_allowed: bool | None = None) -> list[Rec]:
    """Harness integrations that are switched off, given capabilities and the run mode.

    ``active_allowed`` is None when unknown (a standalone scan), True/False from scope.yaml."""
    keys = set(caps.get("keys") or [])
    tools = caps.get("tools") or {}
    out: list[Rec] = []

    def missing_key(k: str, prio: str, why: str) -> None:
        if k not in keys:
            out.append(Rec(k, prio, why))

    missing_key("whoisxml", "high", "No reverse WHOIS: domains registered by the client that share no "
                                    "certificate, DNS or link with the seeds can't be found.")
    missing_key("securitytrails", "medium", "Passive-DNS subdomain coverage is limited to free sources.")
    missing_key("virustotal", "low", "VirusTotal subdomain source skipped.")
    missing_key("otx", "low", "OTX runs anonymously and is usually rate-limited (HTTP 429).")
    missing_key("opencorporates", "medium", "Registry coverage limited to GLEIF and CO/NY/OR open data; "
                                            "DE/WY/other-state entities and agents may be missed.")
    if not caps.get("contact"):
        out.append(Rec("contact", "medium", "SEC EDGAR and Wikidata skipped: subsidiaries' websites "
                                            "are not fed into domain discovery."))
    if mode != "passive":
        missing_key("hibp", "low", "Breach exposure by domain not measured.")
    if tools:  # unknown for runs recorded before capabilities were captured
        if not tools.get("subfinder"):
            out.append(Rec("subfinder", "medium", "subfinder unavailable: dozens of passive aggregators skipped."))
        if mode == "active" and not (tools.get("naabu") and tools.get("nmap")):
            out.append(Rec("naabu-nmap", "medium", "Active scan fell back to the built-in scanner; "
                                                   "service versions are guessed from port numbers."))
        if mode != "passive" and not (tools.get("gitleaks") == "local" and tools.get("git") == "local"):
            out.append(Rec("gitleaks", "low", "Known public repositories are not scanned for secrets."))
    if mode == "passive":
        out.append(Rec("standard-mode", "high", "Passive mode: no HTTP/TLS fingerprinting, login-page, "
                                                "bucket or TLS-config checks were run."))
    if mode != "active":
        why = "Only web ports were examined; non-web services (VPN, RDP, SSH, databases) are unknown."
        if active_allowed is False:
            why += " The engagement does not authorise active testing; ask the client if it should."
        out.append(Rec("active-mode", "medium", why))
    return out


# ---------------------------------------------------------------------------
# Run-level recommendations

def _web_urls(run: dict) -> int:
    return sum(1 for h in run.get("hosts", {}).values() for s in h.get("http", []) if s.get("status"))


def recommend_for_run(run: dict, active_allowed: bool | None = None) -> list[dict]:
    """Recommendations for one run (a ``surface.json`` dict). Sorted by priority."""
    meta = run.get("meta") or {}
    cfg = meta.get("config") or {}
    mode = cfg.get("mode", "standard")
    caps = meta.get("capabilities") or {"keys": cfg.get("api_keys_present") or [],
                                        "contact": True, "tools": {}}  # older runs: don't guess
    recs = coverage_gaps(caps, mode, active_allowed)

    ips = run.get("ips", {})
    kinds = {f.get("kind") for f in run.get("findings", [])}
    web = _web_urls(run)
    scanned = any(i.get("open_ports") for i in ips.values())
    seeds = run.get("seeds") or []

    if ips and not scanned:
        recs.append(Rec("shodan-censys", "high", f"{len(ips)} IPs with no port data from this run: "
                                                 "historic scan data shows non-web exposure passively."))
    elif ips:
        recs.append(Rec("shodan-censys", "low", "Compare with historic exposure on the same IPs."))
    if web:
        recs.append(Rec("gowitness", "medium", f"{web} live web service(s) to triage visually."))
        recs.append(Rec("nuclei", "medium", f"{web} live web service(s) fingerprinted but not checked "
                                            "for known vulnerabilities."))
        recs.append(Rec("katana", "low", "JavaScript-referenced API endpoints and hosts not collected."))
    if run.get("tls_config") or any(h.get("tls") for h in run.get("hosts", {}).values()):
        prio = "medium" if any(t.get("weak_protocols") for t in run.get("tls_config", [])) else "low"
        recs.append(Rec("testssl", prio, "Only protocol versions, expiry and HSTS were checked."))
    if seeds:
        recs.append(Rec("dnstwist", "medium", f"Lookalike/typosquat domains of {', '.join(seeds[:3])} "
                                              "are not part of ownership-based discovery."))
    repos_known = any(re.search(r"github\.com|gitlab\.com|bitbucket\.org", u)
                      for i in (run.get("site_identity") or {}).values() for u in i.get("same_as", []))
    recs.append(Rec("code-search", "medium" if repos_known or "secret-exposure" in kinds else "low",
                    "Public code presence found on the website; search the whole org and employees."
                    if repos_known else "No public repositories were discovered; an org search may find some."))
    cloud_ips = sum(1 for i in ips.values() if CLOUD_ASN_RE.search(i.get("as_name") or ""))
    if run.get("cloud_assets") or cloud_ips:
        why = []
        if run.get("cloud_assets"):
            why.append(f"{len(run['cloud_assets'])} cloud storage asset(s)")
        if cloud_ips:
            why.append(f"{cloud_ips} IPs in cloud-provider ASNs")
        recs.append(Rec("cloud-posture", "medium", ", ".join(why) + ": account configuration is only "
                                                                     "visible with client access."))
    if run.get("m365_tenants"):
        fed = any(m.get("namespace") == "Federated" for m in run["m365_tenants"])
        recs.append(Rec("m365-posture", "medium", "Microsoft 365 tenant found" +
                        (" (federated sign-in)" if fed else "") + "; identity configuration is the "
                        "largest external surface after the web."))
    if "exposed-interface" in kinds or "exposed-service" in kinds:
        recs.append(Rec("web-app-testing", "medium", "Login portals / admin interfaces exposed; only "
                                                     "fingerprinted, never tested."))
    recs.append(Rec("mobile-apps", "low", "Mobile apps are outside DNS/CT discovery."))
    return materialise(recs)


def materialise(recs: list[Rec], target: str | None = None) -> list[dict]:
    best: dict[str, dict] = {}
    for r in recs:
        t = CATALOG.get(r.tool)
        base = asdict(t) if t else {"id": r.tool, "name": r.tool, "area": "Other", "kind": "complementary",
                                    "adds": "", "needs": "", "enable": "", "url": ""}
        cur = best.get(base["id"])
        if cur is None:
            cur = best[base["id"]] = {**base, "priority": r.priority, "reasons": [], "targets": []}
        elif PRIORITY_ORDER.get(r.priority, 9) < PRIORITY_ORDER.get(cur["priority"], 9):
            cur["priority"] = r.priority
        if r.reason and r.reason not in cur["reasons"]:
            cur["reasons"].append(r.reason)
        if target and target not in cur["targets"]:
            cur["targets"].append(target)
    return sort_recs(list(best.values()))


def sort_recs(recs: list[dict]) -> list[dict]:
    return sorted(recs, key=lambda r: (r["kind"] != "coverage-gap", PRIORITY_ORDER.get(r["priority"], 9),
                                       r["area"], r["name"]))


# ---------------------------------------------------------------------------
# Engagement-level aggregation

def _match_catalog(name: str) -> str | None:
    n = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    for t in CATALOG.values():
        if n and (n == re.sub(r"[^a-z0-9]", "", t.id) or n == re.sub(r"[^a-z0-9]", "", t.name.lower())):
            return t.id
    return None


def recommend_for_engagement(targets: list[dict], active_allowed: bool | None) -> list[dict]:
    """Merge per-target recommendations (harness + analyst ``tool_recommendations``)."""
    merged: dict[str, dict] = {}
    why_targets: dict[str, dict[str, list[str]]] = {}  # rec id -> reason -> target ids
    for t in targets:
        recs = list(t.get("recommendations") or [])
        for ar in (t.get("analysis") or {}).get("tool_recommendations") or []:
            if not isinstance(ar, dict) or not ar.get("tool"):
                continue
            tid = _match_catalog(ar["tool"]) or ar["tool"]
            prio = ar.get("priority") if ar.get("priority") in PRIORITY_ORDER else "medium"
            m = materialise([Rec(tid, prio, f"analyst: {ar.get('reason') or ''}".strip())])[0]
            if tid not in CATALOG:
                m.update(area=ar.get("area") or "Other", needs=ar.get("needs") or "",
                         enable=ar.get("enable") or "", adds=ar.get("adds") or "", kind="analyst")
            recs.append(m)
        for r in recs:
            cur = merged.get(r["id"])
            if cur is None:
                cur = merged[r["id"]] = {**r, "reasons": [], "targets": []}
            elif PRIORITY_ORDER.get(r["priority"], 9) < PRIORITY_ORDER.get(cur["priority"], 9):
                cur["priority"] = r["priority"]
            for why in r.get("reasons", []):
                ts = why_targets.setdefault(r["id"], {}).setdefault(why, [])
                if t["id"] not in ts:
                    ts.append(t["id"])
            if t["id"] not in cur["targets"]:
                cur["targets"].append(t["id"])
    for rid, reasons in why_targets.items():  # same reason for several targets is listed once
        merged[rid]["reasons"] = [f"[{', '.join(ts)}] {why}" for why, ts in reasons.items()]
    return sort_recs(list(merged.values()))


# ---------------------------------------------------------------------------
# Markdown

def _esc(s: object) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def render_markdown(recs: list[dict], heading: str = "##", engagement: bool = False) -> str:
    """The "Recommended tools" section. Always the last section of a run report."""
    L = [f"{heading} Recommended tools for a complete picture\n",
         "This harness covers ownership-based domain discovery, DNS, web/TLS fingerprinting and "
         "passive exposure checks. The tools below fill the rest of the external surface. "
         "Nothing here was run: each needs a decision by the engagement lead, and some need the "
         "client's authorization or access.\n"]
    gaps = [r for r in recs if r["kind"] == "coverage-gap"]
    other = [r for r in recs if r["kind"] != "coverage-gap"]
    tcol = " Targets |" if engagement else ""
    tsep = "---|" if engagement else ""
    for title, rows in (("Coverage gaps in this run (enable, then re-run)", gaps),
                        ("Complementary tools (outside the harness)", other)):
        L.append(f"{heading}# {title}\n")
        if not rows:
            L.append("_None._\n")
            continue
        L.append(f"| Priority | Tool | Area |{tcol} Why | Needs | How |")
        L.append(f"|---|---|---|{tsep}---|---|---|")
        for r in rows:
            name = f"[{_esc(r['name'])}]({r['url']})" if r.get("url") else _esc(r["name"])
            why = "<br>".join(_esc(x) for x in r["reasons"][:6]) or _esc(r.get("adds"))
            tc = f" {', '.join(r.get('targets') or [])} |" if engagement else ""
            L.append(f"| {r['priority']} | {name} | {_esc(r['area'])} |{tc} {why} | {_esc(r['needs'])} | "
                     f"{_esc(r.get('enable'))} |")
        L.append("")
    return "\n".join(L)


def render_doctor(gaps: list[dict], caps: dict) -> str:
    lines = ["Tools:"]
    for t, b in caps["tools"].items():
        lines.append(f"  {t:<10} {b or 'unavailable'}")
    lines.append("API keys: " + (", ".join(caps["keys"]) or "none"))
    lines.append(f"SURFACE_CONTACT / SEC_USER_AGENT: {'set' if caps['contact'] else 'not set'}")
    lines.append("")
    if not gaps:
        lines.append("No coverage gaps.")
        return "\n".join(lines)
    lines.append("Coverage gaps (ask the engagement lead before running):")
    for r in gaps:
        lines.append(f"  [{r['priority']:<6}] {r['name']}: {r['reasons'][0] if r['reasons'] else r['adds']}")
        lines.append(f"           needs: {r['needs']}  |  enable: {r['enable']}")
    return "\n".join(lines)

