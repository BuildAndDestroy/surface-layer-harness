"""Passive credential-exposure reporting for the client report.

Read-only OSINT only. This module NEVER authenticates, logs in, guesses passwords
or enumerates users. It aggregates publicly available exposure *metadata* so the
report can say "these accounts/domains/repos appear in known breaches or leak
scanners" without ever touching the target's authentication surface.

Three passive signals, each skipped cleanly when its key/tool is absent:

  1. breach-exposure  Have I Been Pwned breach-by-domain: counts of exposed
                      accounts per breach, breach names and dates (HIBP_API_KEY).
  2. email-format     the organisation's likely corporate email format, inferred
                      only from emails the pipeline already collected (seed-site
                      contacts, security.txt). No third-party harvesting.
  3. secret-exposure  gitleaks run over the org's already-known public repos, if
                      a gitleaks binary is available. Counts, rule types and file
                      paths only.

REDACTION INVARIANT: a Finding.detail produced here must NEVER contain a
credential, password, password hash or secret value - only counts, breach/rule
names, dates and file paths. Breach responses carry email aliases and gitleaks
reports carry the literal secret; neither is ever copied into a detail string.
"""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from .sources import UA

if TYPE_CHECKING:
    from collections.abc import Callable

    from .config import Config
    from .models import Finding, Surface

HIBP_BASE = "https://haveibeenpwned.com/api/v3"

# Mailbox local-parts that are role/functional addresses, not people. These tell
# us nothing about the {first}.{last} format and are excluded from inference.
ROLE_LOCALS = frozenset({
    "info", "contact", "hello", "hi", "support", "help", "sales", "admin",
    "administrator", "security", "secure", "abuse", "postmaster", "hostmaster",
    "webmaster", "noreply", "no-reply", "donotreply", "mail", "mailer",
    "marketing", "press", "media", "pr", "legal", "privacy", "dpo", "compliance",
    "hr", "jobs", "careers", "recruiting", "billing", "accounts", "accounting",
    "finance", "invoices", "orders", "office", "team", "all", "everyone",
    "newsletter", "feedback", "enquiries", "inquiries", "general", "service",
    "services", "it", "helpdesk", "sysadmin", "root", "ops", "devops",
})


# ---------------------------------------------------------------------------
# 1. Breach exposure by domain (Have I Been Pwned)

async def hibp_breached_domain(client: httpx.AsyncClient, domain: str, api_key: str) -> dict[str, list[str]]:
    """Raw HIBP breach-by-domain response: {email-alias: [breach name, ...]}.

    Returns {} for a domain with no exposed accounts (or one not verified on the
    account). The aliases are deliberately never surfaced in findings.
    """
    r = await client.get(
        f"{HIBP_BASE}/breacheddomain/{domain}",
        headers={"hibp-api-key": api_key, "User-Agent": UA},
    )
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, dict) else {}


async def hibp_breaches_meta(client: httpx.AsyncClient) -> dict[str, dict]:
    """All-breaches metadata keyed by breach Name (no API key required)."""
    r = await client.get(f"{HIBP_BASE}/breaches", headers={"User-Agent": UA})
    r.raise_for_status()
    rows = r.json()
    return {b["Name"]: b for b in rows if isinstance(b, dict) and b.get("Name")}


def summarize_breached_domain(breached: dict[str, list[str]], meta: dict[str, dict]) -> dict:
    """Aggregate a breach-by-domain response into counts + breach metadata only.

    `breached` maps an email alias -> list of breach names it appears in. We count
    how many accounts each breach touched and total distinct accounts. The alias
    strings themselves are never retained.
    """
    per_breach: Counter[str] = Counter()
    for names in breached.values():
        for name in names:
            per_breach[name] += 1
    breaches = []
    for name, count in per_breach.items():
        info = meta.get(name, {})
        year = (info.get("BreachDate") or "")[:4] or None
        breaches.append({
            "name": info.get("Title") or name,
            "year": year,
            "accounts": count,
        })
    # Most-exposed breaches first, then alphabetical for stability.
    breaches.sort(key=lambda b: (-b["accounts"], b["name"]))
    return {
        "accounts": len(breached),  # distinct exposed accounts on this domain
        "breaches": breaches,
        "breach_count": len(breaches),
    }


def _breach_severity(accounts: int) -> str:
    """Scale severity by magnitude of exposure. Passive reporting caps at medium."""
    if accounts >= 500:
        return "medium"
    if accounts >= 50:
        return "low"
    return "info"


def breach_finding(domain: str, summary: dict) -> Finding | None:
    """Build a `breach-exposure` finding. detail is a redacted, counts-only summary."""
    from .models import Finding

    accounts = summary["accounts"]
    if accounts <= 0:
        return None
    shown = summary["breaches"][:4]
    parts = [f"{b['name']} {b['year']}" if b["year"] else b["name"] for b in shown]
    more = summary["breach_count"] - len(shown)
    if more > 0:
        parts.append(f"+{more} more")
    # detail: counts, breach names and dates only - never aliases or any secret.
    detail = (f"domain {domain}: {accounts:,} exposed account(s) across "
              f"{summary['breach_count']} breach(es) ({', '.join(parts)})")
    return Finding(_breach_severity(accounts), "breach-exposure", domain, detail)


async def breach_exposure_findings(client: httpx.AsyncClient, domains: list[str], api_key: str,
                                   log: Callable[[str], None]) -> list[Finding]:
    if not api_key:
        log("[cred] HIBP_API_KEY not set: skipping breach-exposure lookups")
        return []
    try:
        meta = await hibp_breaches_meta(client)
    except Exception as e:  # noqa: BLE001 - metadata is best-effort; names still work without dates
        log(f"[cred] HIBP breach metadata unavailable: {type(e).__name__}")
        meta = {}
    findings: list[Finding] = []
    for domain in domains:
        try:
            breached = await hibp_breached_domain(client, domain, api_key)
        except Exception as e:  # noqa: BLE001 - one domain failing must not abort the rest
            log(f"[cred:hibp] {domain}: {type(e).__name__}: {str(e)[:120]}")
            continue
        summary = summarize_breached_domain(breached, meta)
        f = breach_finding(domain, summary)
        if f:
            log(f"[cred:hibp] {domain}: {summary['accounts']} account(s), "
                f"{summary['breach_count']} breach(es)")
            findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# 2. Email / username format inference

def _name_tokens(names: list[str]) -> tuple[set[str], set[str]]:
    firsts, lasts = set(), set()
    for n in names or []:
        parts = re.findall(r"[A-Za-z]{2,}", n.lower())
        if len(parts) >= 2:
            firsts.add(parts[0])
            lasts.add(parts[-1])
    return firsts, lasts


def _classify_local(local: str, firsts: set[str], lasts: set[str]) -> str | None:
    """Turn an email local-part into a format template ({first}.{last}, {f}{last}, ...).

    Returns None for role addresses or shapes we can't confidently read.
    """
    local = local.lower()
    if local in ROLE_LOCALS or not re.fullmatch(r"[a-z][a-z0-9._-]*", local):
        return None
    if any(ch.isdigit() for ch in local):
        return None  # jdoe2 / sales07 - noise for format inference

    m = re.search(r"[._-]", local)
    sep = m.group(0) if m else ""
    parts = re.split(r"[._-]", local) if sep else [local]

    def role(p: str) -> str:
        if len(p) == 1:
            return "initial"
        if p in firsts and p not in lasts:
            return "first"
        if p in lasts and p not in firsts:
            return "last"
        return "word"

    if len(parts) == 2:
        a, b = role(parts[0]), role(parts[1])
        mapping = {
            ("first", "last"): ("{first}", "{last}"),
            ("last", "first"): ("{last}", "{first}"),
            ("initial", "last"): ("{f}", "{last}"),
            ("first", "initial"): ("{first}", "{l}"),
            ("last", "initial"): ("{last}", "{l}"),
            ("initial", "first"): ("{f}", "{first}"),
            # Two plain words joined by a separator: the overwhelmingly common
            # corporate convention is first<sep>last.
            ("word", "word"): ("{first}", "{last}"),
        }
        tok = mapping.get((a, b))
        return sep.join(tok) if tok else None

    if len(parts) == 1:
        p = parts[0]
        if p in firsts and p not in lasts:
            return "{first}"
        if p in lasts and p not in firsts:
            return "{last}"
        # initial + last, e.g. "jdoe"
        if len(p) > 2 and p[1:] in lasts:
            return "{f}{last}"
        # first + initial, e.g. "johnd"
        if len(p) > 2 and p[:-1] in firsts:
            return "{first}{l}"
    return None


def infer_email_format(emails: list[str], domain: str, names: list[str] | None = None) -> dict | None:
    """Infer the likely corporate email format for `domain` from already-collected
    addresses. Returns {format, template, samples, domain} or None.

    Only addresses whose host is `domain` are considered. No addresses are stored
    in the result (the template and a count suffice for the report)."""
    firsts, lasts = _name_tokens(names or [])
    templates: Counter[str] = Counter()
    considered = 0
    for e in emails:
        e = e.strip().lower()
        if "@" not in e:
            continue
        local, _, host = e.partition("@")
        if host != domain:
            continue
        considered += 1
        tmpl = _classify_local(local, firsts, lasts)
        if tmpl:
            templates[tmpl] += 1
    if not templates:
        return None
    template, samples = templates.most_common(1)[0]
    return {
        "domain": domain,
        "template": template,
        "format": f"{template}@{domain}",
        "samples": samples,
        "considered": considered,
    }


def email_format_finding(inferred: dict) -> Finding:
    from .models import Finding

    # detail: template + counts only; no raw address is ever included.
    detail = (f"likely corporate email format {inferred['format']} "
              f"(inferred from {inferred['samples']} of {inferred['considered']} "
              f"address(es) seen on {inferred['domain']})")
    return Finding("info", "email-format", inferred["domain"], detail)


# ---------------------------------------------------------------------------
# 3. Public-repo secret exposure (gitleaks, optional / tool-gated)

def known_repos(s: Surface) -> list[str]:
    """Public git repositories already discovered by the pipeline.

    Uses only what was gathered elsewhere (schema.org sameAs links to code hosts).
    This task does NOT discover new repositories.
    """
    repos: list[str] = []
    seen: set[str] = set()
    hosts = ("github.com", "gitlab.com", "bitbucket.org")
    for ident in s.site_identity.values():
        for url in sorted(ident.same_as):
            u = url.rstrip("/")
            host = re.sub(r"^https?://(www\.)?", "", u).split("/", 1)[0].lower()
            if host not in hosts:
                continue
            path = u.split(host, 1)[1].strip("/")
            # org/repo (a concrete repository), not a bare org/user profile page.
            if path.count("/") == 1 and path and u not in seen:
                seen.add(u)
                repos.append(u)
    return repos


def parse_gitleaks_findings(report_json: str, repo: str) -> list[Finding]:
    """Parse a gitleaks JSON report into `secret-exposure` findings.

    Records rule type, file path and line only. The secret value (`Secret`,
    `Match`) present in the report is deliberately NEVER read into a finding.
    """
    from .models import Finding

    try:
        rows = json.loads(report_json)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    by_rule: Counter[str] = Counter()
    files: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        rule = row.get("RuleID") or row.get("Description") or "unknown-rule"
        by_rule[str(rule)] += 1
        f = row.get("File")
        if f:
            files.add(str(f))
    total = sum(by_rule.values())
    if not total:
        return []
    rules = ", ".join(f"{r} x{c}" for r, c in by_rule.most_common())
    shown_files = sorted(files)[:5]
    more = len(files) - len(shown_files)
    file_list = ", ".join(shown_files) + (f" (+{more} more)" if more > 0 else "")
    # detail: counts, rule types and file paths only - never the secret value.
    detail = (f"gitleaks confirmed {total} secret(s) in {repo}: {rules}; "
              f"files: {file_list}")
    return [Finding("high", "secret-exposure", repo, detail)]


async def repo_secret_findings(runner, repos: list[str], log: Callable[[str], None]) -> list[Finding]:
    """Shallow-clone each known public repo and scan it with gitleaks, if available.

    Tool-gated: needs a local gitleaks binary (the Docker backend cannot see a
    host clone path). Skips cleanly otherwise. Never emits a secret value.
    """
    if not repos:
        return []
    if not runner.available("gitleaks"):
        log("[cred:gitleaks] gitleaks not available; skipping public-repo secret scan")
        return []
    if runner.backend("gitleaks") != "local":
        log("[cred:gitleaks] gitleaks needs a local binary to scan cloned repos; skipping")
        return []
    if runner.backend("git") != "local":  # clone step relies on a local git
        log("[cred:gitleaks] git not available to clone repos; skipping")
        return []

    findings: list[Finding] = []
    for repo in repos:
        with tempfile.TemporaryDirectory(prefix="surface-repo-") as tmp:
            dst = Path(tmp) / "repo"
            clone = await asyncio.create_subprocess_exec(
                "git", "clone", "--quiet", "--depth", "1", repo, str(dst),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, err = await clone.communicate()
            if clone.returncode != 0:
                log(f"[cred:gitleaks] clone failed for {repo}: {err.decode(errors='replace')[:120]}")
                continue
            res = await runner.run(
                "gitleaks",
                ["detect", "--source", str(dst), "--report-format", "json",
                 "--report-path", "/dev/stdout", "--no-banner", "--exit-code", "0"],
                timeout=600,
            )
            new = parse_gitleaks_findings(res.stdout, repo)
            if new:
                log(f"[cred:gitleaks] {repo}: {len(new)} secret-exposure finding(s)")
            findings.extend(new)
    return findings


# ---------------------------------------------------------------------------
# Entry point used by the pipeline

async def collect(s: Surface, cfg: Config, client: httpx.AsyncClient, runner,
                  log: Callable[[str], None]) -> list[Finding]:
    """Run all passive credential-exposure checks and return their findings."""
    domains = sorted({d.name for d in s.in_scope_apexes(cfg.expand_threshold)})

    # Names help resolve {first}/{last} ordering in email formats.
    person_names = [o.name for c in s.companies for o in c.officers if o.name]

    findings: list[Finding] = []
    findings += await breach_exposure_findings(client, domains, cfg.keys.get("hibp", ""), log)

    for domain in domains:
        emails: set[str] = set()
        ident = s.site_identity.get(domain)
        if ident:
            emails |= {e.lower() for e in ident.emails}
        inferred = infer_email_format(sorted(emails), domain, person_names)
        if inferred:
            log(f"[cred:email] {domain}: format {inferred['format']}")
            findings.append(email_format_finding(inferred))

    findings += await repo_secret_findings(runner, known_repos(s), log)
    return findings
