"""Write run outputs: full JSON, a Markdown report, and flat lists for piping."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Surface


def _md_escape(s: str | None) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _registrant(d) -> str:
    if d.whois.get("org"):
        return _md_escape(d.whois["org"])
    if d.whois.get("registrar"):
        return f"_redacted_ (registrar: {_md_escape(d.whois['registrar'])})"
    return ""


def write_all(s: Surface, out: Path, threshold: float) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "surface.json").write_text(json.dumps(s.to_dict(), indent=2, default=str))

    in_scope = sorted(s.in_scope_apexes(threshold), key=lambda d: (not d.seed, -d.confidence, d.name))
    review = sorted((d for d in s.domains.values() if d.confidence < threshold and d.confidence >= 0.3),
                    key=lambda d: (-d.confidence, d.name))
    live = sorted((h for h in s.hosts.values() if h.resolved), key=lambda h: h.name)
    urls = sorted({svc.final_url or svc.url for h in live for svc in h.http if svc.status})

    (out / "domains.txt").write_text("".join(f"{d.name}\n" for d in in_scope))
    (out / "candidates.tsv").write_text(
        "domain\tconfidence\tevidence\n" + "".join(
            f"{d.name}\t{d.confidence}\t{'; '.join(e.detail for e in d.evidence)}\n" for d in review))
    (out / "hosts.txt").write_text("".join(f"{h.name}\n" for h in live if not h.wildcard))
    (out / "all_hosts.txt").write_text("".join(f"{n}\n" for n in sorted(s.hosts)))
    (out / "urls.txt").write_text("".join(f"{u}\n" for u in urls))
    (out / "ips.txt").write_text("".join(f"{ip}\n" for ip in sorted(s.ips)))
    (out / "findings.tsv").write_text(
        "severity\tkind\ttarget\tdetail\n" +
        "".join(f"{f.severity}\t{f.kind}\t{f.target}\t{f.detail}\n" for f in s.findings))
    (out / "company.json").write_text(json.dumps(
        {"companies": s.to_dict()["companies"], "site_identity": s.to_dict()["site_identity"],
         "org_names": sorted(s.org_names)}, indent=2, default=str))
    (out / "report.md").write_text(render_markdown(s, threshold, in_scope, review, live))


def render_markdown(s, threshold, in_scope, review, live) -> str:
    L: list[str] = []
    w = L.append
    w(f"# Attack surface report: {', '.join(s.seeds)}\n")
    if s.org_names:
        w(f"**Organisation names used:** {', '.join(sorted(s.org_names))}\n")
    sev = {}
    for f in s.findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    w("| In-scope apex domains | Candidates to review | Hosts (total / live) | IPs | Findings |")
    w("|---|---|---|---|---|")
    w(f"| {len(in_scope)} | {len(review)} | {len(s.hosts)} / {len(live)} | {len(s.ips)} | "
      f"{', '.join(f'{k}: {v}' for k, v in sorted(sev.items())) or '0'} |\n")

    render_company(s, w)

    w("## Findings\n")
    if s.findings:
        w("| Severity | Kind | Target | Detail |\n|---|---|---|---|")
        for f in s.findings:
            w(f"| {f.severity} | {f.kind} | `{_md_escape(f.target)}` | {_md_escape(f.detail)} |")
    else:
        w("_None._")
    w("")

    w(f"## In-scope apex domains (confidence ≥ {threshold})\n")
    w("| Domain | Confidence | Registrant | Evidence |\n|---|---|---|---|")
    for d in in_scope:
        ev = "seed" if d.seed else "<br>".join(_md_escape(e.detail) for e in d.evidence)
        w(f"| {d.name} | {d.confidence} | {_registrant(d)} | {ev} |")
    w("")

    w("## Related domains needing review\n")
    w("These have some ownership evidence but not enough to auto-include. "
      "Confirm and re-run with them as seeds if they belong to the target.\n")
    if review:
        w("| Domain | Confidence | Registrant | Evidence |\n|---|---|---|---|")
        for d in review[:200]:
            w(f"| {d.name} | {d.confidence} | {_registrant(d)} | "
              f"{'<br>'.join(_md_escape(e.detail) for e in d.evidence)} |")
    else:
        w("_None._")
    w("")

    w("## Live hosts\n")
    w("| Host | IPs | CNAME | Ports | HTTP | Title | Tech |\n|---|---|---|---|---|---|---|")
    for h in live:
        if h.wildcard:
            continue
        http = ", ".join(f"{svc.status}" for svc in h.http if svc.status) or "-"
        title = next((svc.title for svc in h.http if svc.title), "")
        tech = ", ".join(sorted({t for svc in h.http for t in svc.tech}))[:80]
        w(f"| {h.name} | {', '.join((h.a + h.aaaa)[:3])} | {_md_escape(h.cnames[-1] if h.cnames else '')} | "
          f"{', '.join(map(str, h.open_ports)) or '-'} | {http} | {_md_escape(title)[:60]} | {_md_escape(tech)} |")
    wild = [h.name for h in live if h.wildcard]
    if wild:
        w(f"\n_{len(wild)} hosts only match wildcard DNS and are omitted (see all_hosts.txt)._")
    w("")

    w("## Networks\n")
    asns: dict[str, dict] = {}
    for ip in s.ips.values():
        key = ip.asn or "unknown"
        a = asns.setdefault(key, {"name": ip.as_name, "ips": 0, "prefixes": set()})
        a["ips"] += 1
        if ip.prefix:
            a["prefixes"].add(ip.prefix)
    w("| ASN | Name | IPs | Prefixes |\n|---|---|---|---|")
    for k, a in sorted(asns.items(), key=lambda kv: -kv[1]["ips"]):
        w(f"| {k} | {_md_escape(a['name'])} | {a['ips']} | {', '.join(sorted(a['prefixes'])[:5])} |")
    w("")

    scanned = [ip for ip in s.ips.values() if ip.open_ports]
    if scanned:
        w("## Open ports and services\n")
        w("_Service/version from `nmap -sV --version-light`; \"guessed\" means nmap matched only the port "
          "number, not a fingerprint._\n")
        w("| IP | Port | Service | Product | Version | Extra | Hosts |\n|---|---|---|---|---|---|---|")
        for ip in sorted(scanned, key=lambda i: i.ip):
            svcs = {d["port"]: d for d in ip.services}
            hosts = sorted(ip.hosts)
            hs = ", ".join(hosts[:3]) + (f" +{len(hosts) - 3}" if len(hosts) > 3 else "")
            for p in ip.open_ports:
                d = svcs.get(p, {})
                name = ("ssl/" if d.get("tunnel") == "ssl" else "") + (d.get("service") or "?")
                if d.get("method") == "table":
                    name += " (guessed)"
                w(f"| {ip.ip} | {p}/{d.get('protocol', 'tcp')} | {_md_escape(name)} | "
                  f"{_md_escape(d.get('product') or '')} | {_md_escape(d.get('version') or '')} | "
                  f"{_md_escape(d.get('extra_info') or '')} | {_md_escape(hs)} |")
        w("")
    return "\n".join(L)


def render_company(s, w) -> None:
    w("## Company\n")
    idents = [i for i in s.site_identity.values()
              if i.display_names or i.legal_names or i.emails or i.phones or i.same_as or i.security_txt]
    if not s.companies and not idents:
        w("_No entity information found. Pass `--org \"Legal Name\"`; set OPENCORPORATES_API_TOKEN "
          "for registry coverage beyond GLEIF/Wikidata/CO/NY/OR._\n")
        return

    for c in s.companies:
        title = f"### {_md_escape(c.name)} \u2014 {c.source}"
        if c.jurisdiction:
            title += f" ({_md_escape(c.jurisdiction)})"
        w(title + "\n")
        rows = [
            ("Matched by", c.match),
            ("Registration no.", c.company_number),
            ("Status", c.status),
            ("Type", c.entity_type),
            ("Formed", c.formed),
            ("Industry", c.industry),
            ("Registered address", c.registered_address),
            ("Principal address", c.principal_address),
            ("Mailing address", c.mailing_address),
            ("Registered agent", (f"{c.agent_name}" + (" \u26a0\ufe0f commercial agent service" if c.agent_commercial else ""))
             if c.agent_name else None),
            ("Agent address", c.agent_address),
            ("Officers", "; ".join(f"{o.name} ({o.role})" if o.role else o.name for o in c.officers[:15])),
            ("Other / former names", "; ".join(c.former_names[:10])),
            ("Parent / owner", "; ".join(c.parents)),
            ("Subsidiaries", "; ".join(c.subsidiaries[:30]) + (f" (+{len(c.subsidiaries) - 30} more)"
                                                               if len(c.subsidiaries) > 30 else "")),
            ("Websites", ", ".join(c.websites[:10])),
            ("Identifiers", ", ".join(f"{k}={v}" for k, v in c.identifiers.items()
                                       if v and not k.endswith("_sites"))),
            ("Source", c.url),
        ]
        w("| | |\n|---|---|")
        for k, v in rows:
            if v:
                w(f"| {k} | {_md_escape(str(v))} |")
        for n in c.address_notes:
            w(f"\n> \u26a0\ufe0f {_md_escape(n)}")
        w("")

    for i in idents:
        w(f"### Self-declared on {i.domain}\n")
        w("| | |\n|---|---|")
        for k, v in (("Names", sorted(i.display_names)), ("Legal names", sorted(i.legal_names)),
                     ("Emails", sorted(i.emails)), ("Phones", sorted(i.phones)),
                     ("Addresses", sorted(i.addresses)), ("Profiles (sameAs)", sorted(i.same_as)),
                     ("security.txt", i.security_txt)):
            if v:
                w(f"| {k} | {_md_escape(', '.join(v))} |")
        w("")
