"""Multi-target engagements: run every target in a scope file, then merge the latest
run of each target (plus analyst output) into one report and one versioned JSON document."""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .pipeline import Pipeline
from .report import write_all
from .scope import Scope, Target

ENGAGEMENT_SCHEMA_VERSION = "1.0"
ANALYSIS_SCHEMA = "surface-harness/analysis"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Running

async def _run_target(scope: Scope, t: Target, overrides: dict, sem: asyncio.Semaphore, echo) -> Path:
    async with sem:
        cfg = scope.config_for(t, **overrides)
        cfg.engagement, cfg.target_id = scope.engagement, t.id
        run_dir = Path(cfg.out_dir) / time.strftime("%Y%m%d-%H%M%S")
        prefix = f"[{t.id}]"

        def log(msg: str) -> None:
            if cfg.verbose or "[source:" not in msg:
                echo(f"{prefix} {msg}")

        pipe = Pipeline(cfg, log=log, checkpoint=lambda s: write_all(s, run_dir, cfg.expand_threshold))
        try:
            surface = await pipe.run()
        except Exception as e:  # noqa: BLE001 - one bad target must not sink the engagement
            pipe.s.meta.update(status="failed", error=f"{type(e).__name__}: {e}")
            surface = pipe.s
            echo(f"{prefix} FAILED: {e}")
        write_all(surface, run_dir, cfg.expand_threshold)
        echo(f"{prefix} results: {run_dir}")
        return run_dir


async def run_engagement(scope: Scope, target_ids: list[str] | None, parallel: int, overrides: dict,
                         echo=print) -> list[Path]:
    targets = [scope.target(tid) for tid in target_ids] if target_ids else scope.targets
    sem = asyncio.Semaphore(max(1, parallel))
    return list(await asyncio.gather(*(_run_target(scope, t, overrides, sem, echo) for t in targets)))


# ---------------------------------------------------------------------------
# Merging

def latest_run(target_dir: Path) -> Path | None:
    runs = sorted((p.parent for p in (target_dir / "runs").glob("*/surface.json")), key=lambda p: p.name)
    complete = [r for r in runs if _load(r / "surface.json").get("meta", {}).get("status") == "complete"]
    return (complete or runs or [None])[-1]


def _load(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _validate_analysis(a: dict, tid: str) -> list[str]:
    problems = []
    if a.get("schema") != ANALYSIS_SCHEMA:
        problems.append(f"schema should be '{ANALYSIS_SCHEMA}'")
    if a.get("target_id") not in (None, tid):
        problems.append(f"target_id '{a.get('target_id')}' does not match '{tid}'")
    for i, f in enumerate(a.get("findings", [])):
        for k in ("severity", "status", "title"):
            if k not in f:
                problems.append(f"findings[{i}] missing '{k}'")
    for i, d in enumerate(a.get("scope_decisions", [])):
        if d.get("decision") not in ("in-scope", "out-of-scope", "needs-client-confirmation"):
            problems.append(f"scope_decisions[{i}] has invalid decision '{d.get('decision')}'")
    return problems


def _summary(run: dict) -> dict[str, Any]:
    thr = (run.get("meta", {}).get("config") or {}).get("threshold", 0.7)
    domains = run.get("domains", {})
    hosts = run.get("hosts", {})
    sev: dict[str, int] = defaultdict(int)
    for f in run.get("findings", []):
        sev[f["severity"]] += 1
    return {
        "in_scope_domains": sum(1 for d in domains.values() if d["confidence"] >= thr),
        "candidate_domains": sum(1 for d in domains.values() if 0.3 <= d["confidence"] < thr),
        "hosts": len(hosts),
        "live_hosts": sum(1 for h in hosts.values() if h.get("resolved") and not h.get("wildcard")),
        "web_services": sum(1 for h in hosts.values() for s in h.get("http", []) if s.get("status")),
        "ips": len(run.get("ips", {})),
        "findings": dict(sev),
        "legal_entities": len(run.get("companies", [])),
    }


def merge(scope: Scope) -> dict:
    root = scope.root
    targets_out = []
    ip_targets: dict[str, set[str]] = defaultdict(set)
    asn_targets: dict[str, set[str]] = defaultdict(set)
    asn_names: dict[str, str] = {}
    domain_targets: dict[str, set[str]] = defaultdict(set)

    for t in scope.targets:
        tdir = scope.target_dir(t.id)
        run_dir = latest_run(tdir)
        entry: dict[str, Any] = {"id": t.id, "name": t.name, "domains": t.domains, "org": t.org,
                                 "notes": t.notes, "status": "missing", "run_dir": None,
                                 "meta": None, "summary": None, "analysis": None,
                                 "analysis_warnings": [], "surface": None}
        if run_dir:
            run = _load(run_dir / "surface.json")
            run.pop("log", None)
            meta = run.get("meta", {})
            entry.update(status=meta.get("status", "unknown"), run_dir=str(run_dir.relative_to(root)),
                         meta=meta, summary=_summary(run), surface=run)
            thr = (meta.get("config") or {}).get("threshold", 0.7)
            for ip, info in run.get("ips", {}).items():
                ip_targets[ip].add(t.id)
                if info.get("asn"):
                    asn_targets[info["asn"]].add(t.id)
                    asn_names[info["asn"]] = info.get("as_name") or ""
            for name, d in run.get("domains", {}).items():
                if d["confidence"] >= thr:
                    domain_targets[name].add(t.id)
        a_path = tdir / "analysis.json"
        if a_path.exists():
            a = _load(a_path)
            entry["analysis"] = a or None
            entry["analysis_warnings"] = _validate_analysis(a, t.id) if a else ["analysis.json is not valid JSON"]
        targets_out.append(entry)

    multi = lambda m: {k: sorted(v) for k, v in sorted(m.items()) if len(v) > 1}  # noqa: E731
    doc = {
        "schema": "surface-harness/engagement",
        "schema_version": ENGAGEMENT_SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "engagement": {"id": scope.engagement, "client": scope.client,
                       "authorization": scope.authorization, "defaults": scope.defaults,
                       "exclude": scope.exclude},
        "summary_md": (root / "summary.md").read_text() if (root / "summary.md").exists() else None,
        "targets": targets_out,
        "cross_target": {
            # Overlaps matter when targets are related companies (subsidiaries, shared IT).
            # Shared CDN/cloud IPs are expected; review before drawing conclusions.
            "shared_domains": multi(domain_targets),
            "shared_ips": multi(ip_targets),
            "shared_asns": {k: {"name": asn_names.get(k, ""), "targets": v}
                            for k, v in multi(asn_targets).items()},
        },
    }
    return doc


# ---------------------------------------------------------------------------
# Consolidated report

def _demote(md: str, levels: int = 1) -> str:
    out = []
    in_code = False
    for line in md.splitlines():
        if line.startswith("```"):
            in_code = not in_code
        if not in_code and re.match(r"^#{1,5} ", line):
            line = "#" * levels + line
        out.append(line)
    return "\n".join(out)


def _esc(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def render_report(doc: dict, root: Path) -> str:
    e = doc["engagement"]
    auth = e.get("authorization") or {}
    L: list[str] = []
    w = L.append
    w(f"# Attack surface assessment: {e['client']}\n")
    w("| | |\n|---|---|")
    w(f"| Engagement | `{e['id']}` |")
    w(f"| Authorization | {_esc(auth.get('reference'))} |")
    if auth.get("window"):
        w(f"| Testing window | {_esc(auth.get('window'))} |")
    w(f"| Active testing permitted | {'yes' if auth.get('active_testing') else 'no'} |")
    w(f"| Targets | {len(doc['targets'])} |")
    w(f"| Generated | {doc['generated_at']} |\n")

    if doc.get("summary_md"):
        w("## Executive summary\n")
        w(_demote(doc["summary_md"].replace("# Executive summary", "").strip(), 1))
        w("")

    w("## Targets overview\n")
    w("| Target | Status | Run | In-scope domains | Review | Live hosts | Web | IPs | Findings | Analysis |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    for t in doc["targets"]:
        s = t["summary"] or {}
        f = s.get("findings", {})
        fs = ", ".join(f"{k}: {f[k]}" for k in sorted(f, key=lambda k: SEV_ORDER.get(k, 9))) or "0"
        started = (t["meta"] or {}).get("started_at", "")[:16]
        an = "yes" if t["analysis"] else "-"
        if t["analysis_warnings"]:
            an += f" ({len(t['analysis_warnings'])} warnings)"
        w(f"| **{_esc(t['name'])}** (`{t['id']}`) | {t['status']} | {started} | {s.get('in_scope_domains', '-')} | "
          f"{s.get('candidate_domains', '-')} | {s.get('live_hosts', '-')} | {s.get('web_services', '-')} | "
          f"{s.get('ips', '-')} | {fs} | {an} |")
    w("")

    # Unified findings table: analyst-validated findings first, then raw harness findings.
    rows = []
    for t in doc["targets"]:
        for f in (t["analysis"] or {}).get("findings", []):
            rows.append((SEV_ORDER.get(f.get("severity"), 9), t["id"], f.get("severity"), f.get("status"),
                         f.get("title"), f.get("ref") or f.get("asset") or "", "analyst"))
        for f in (t["surface"] or {}).get("findings", []):
            rows.append((SEV_ORDER.get(f["severity"], 9), t["id"], f["severity"], "unverified",
                         f"{f['kind']}: {f['detail']}", f["target"], "harness"))
    w("## All findings\n")
    if rows:
        w("| Severity | Target | Status | Finding | Asset | Source |\n|---|---|---|---|---|---|")
        for _, tid, sev, status, title, asset, src in sorted(rows, key=lambda r: (r[0], r[1])):
            w(f"| {sev} | `{tid}` | {status} | {_esc(title)} | `{_esc(asset)}` | {src} |")
    else:
        w("_None._")
    w("")

    ct = doc["cross_target"]
    if any(ct.values()):
        w("## Cross-target overlap\n")
        w("Assets shared between targets: expected for subsidiaries or shared IT, but worth confirming. "
          "Shared CDN/cloud ranges are usually meaningless.\n")
        for d, ts in ct["shared_domains"].items():
            w(f"- domain **{d}**: {', '.join(ts)}")
        for asn, v in list(ct["shared_asns"].items())[:30]:
            w(f"- AS{asn} {_esc(v['name'])}: {', '.join(v['targets'])}")
        if ct["shared_ips"]:
            w(f"- {len(ct['shared_ips'])} shared IPs (see engagement.json → cross_target.shared_ips)")
        w("")

    for t in doc["targets"]:
        w(f"---\n\n## Target: {t['name']} (`{t['id']}`)\n")
        w(f"Seeds: {', '.join(t['domains'])}" + (f" · Org: {', '.join(t['org'])}" if t["org"] else ""))
        if t["notes"]:
            w(f"\n> {t['notes']}")
        w("")
        if t["analysis_warnings"]:
            w("> ⚠️ analysis.json problems: " + "; ".join(t["analysis_warnings"]) + "\n")
        a_md = root / "targets" / t["id"] / "analysis.md"
        if a_md.exists():
            w("### Analyst notes\n")
            w(_demote(re.sub(r"^# .*\n", "", a_md.read_text(), count=1), 2))
            w("")
        a = t["analysis"] or {}
        if a.get("scope_decisions"):
            w("### Scope decisions\n")
            w("| Domain | Decision | Rationale |\n|---|---|---|")
            for d in a["scope_decisions"]:
                w(f"| {d.get('domain')} | {d.get('decision')} | {_esc(d.get('rationale'))} |")
            w("")
        if t["run_dir"]:
            run_md = root / t["run_dir"] / "report.md"
            if run_md.exists():
                body = re.sub(r"^# .*\n", "", run_md.read_text(), count=1)
                w(_demote(body, 1))
        else:
            w("_No harness run found for this target._")
        w("")
    return "\n".join(L)


def write_merged(scope: Scope) -> dict:
    from .graph import write_graph

    doc = merge(scope)
    root = scope.root
    (root / "engagement.json").write_text(json.dumps(doc, indent=2, default=str))
    (root / "report.md").write_text(render_report(doc, root))
    write_graph(doc, root)
    return doc


ANALYSIS_TEMPLATE = {
    "schema": ANALYSIS_SCHEMA,
    "schema_version": "1.0",
    "target_id": "<target id>",
    "run_dir": "<targets/<id>/runs/<timestamp>>",
    "summary": "2-4 sentence overview of this company's external attack surface.",
    "scope_decisions": [
        {"domain": "example-cdn.com", "decision": "needs-client-confirmation",
         "rationale": "Shares TLS certs with example.com but registrant is redacted."}
    ],
    "findings": [
        {"ref": "takeover-candidate:old.example.com", "asset": "old.example.com", "severity": "high",
         "status": "confirmed", "title": "Dangling CNAME to unclaimed Azure App Service",
         "evidence": "dig CNAME old.example.com -> example-old.azurewebsites.net (NXDOMAIN)",
         "recommendation": "Remove the DNS record or reclaim the resource."}
    ],
    "notes": ["Anything a human reviewer should know."],
}

