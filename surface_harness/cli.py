"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
import warnings
from pathlib import Path

from .config import MODES, Config
from .networks import validate_asns, validate_networks
from .pipeline import Pipeline
from .report import write_all

# Container images set these so the same CLI works inside and outside Docker.
DEFAULT_TOOLS = os.environ.get("SURFACE_TOOLS", "auto")
DEFAULT_OUT = os.environ.get("SURFACE_OUT", "runs")


def parse_args(argv: list[str] | None = None) -> Config:
    p = argparse.ArgumentParser(
        prog="surface-harness",
        description="Discover the external attack surface of an organisation from seed domains.",
    )
    p.add_argument("domains", nargs="*", help="seed domain(s), e.g. acme.com acme.io")
    p.add_argument("-f", "--domains-file", help="file with one seed domain per line")
    p.add_argument("--org", action="append", default=[],
                   help="organisation legal name (repeatable), e.g. 'Acme Corporation'. "
                        "Enables CT search by certificate O= and reverse WHOIS.")
    p.add_argument("--cidr", action="append", default=[],
                   help="in-scope IP range as a CIDR (repeatable), e.g. 203.0.113.0/24. "
                        "Expanded to host IPs for DNS/PTR enrichment (and port scanning in active mode).")
    p.add_argument("--asn", action="append", default=[],
                   help="in-scope ASN (repeatable), e.g. AS64500. Announced prefixes are fetched "
                        "passively via RIPEstat, then expanded like --cidr.")
    p.add_argument("--max-net-hosts", type=int, default=4096,
                   help="cap on host addresses enumerated from --cidr/--asn (default 4096 = one /20)")
    p.add_argument("-m", "--mode", choices=MODES, default="standard",
                   help="passive: third-party data + DNS only; standard: + HTTP/TLS probing (default); "
                        "active: + DNS brute force and port scanning (requires --authorized)")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you have written authorization to actively test these targets")
    p.add_argument("-d", "--depth", type=int, default=1,
                   help="hops from seeds to auto-expand related domains (default 1, 0 = seeds only)")
    p.add_argument("-t", "--threshold", type=float, default=0.7,
                   help="confidence needed to treat a related domain as in-scope (default 0.7)")
    p.add_argument("--max-apexes", type=int, default=25, help="cap on auto-expanded apex domains")
    p.add_argument("-x", "--exclude", action="append", default=[],
                   help="domain/host never to touch (repeatable); subdomains are excluded too")
    p.add_argument("-o", "--out", default=DEFAULT_OUT, help="output directory (default ./runs or $SURFACE_OUT)")
    p.add_argument("-c", "--concurrency", type=int, default=50)
    p.add_argument("--resolvers", help="comma-separated DNS resolvers (default: system)")
    p.add_argument("--ports", help="comma-separated ports for active scanning (default: built-in top list)")
    p.add_argument("-w", "--wordlist", help="subdomain brute-force wordlist (active mode)")
    p.add_argument("--sources", help="comma-separated passive sources to use (default: all available)")
    p.add_argument("--no-company", action="store_true",
                   help="skip company/legal-entity lookups (website identity, GLEIF, registries, Wikidata)")
    p.add_argument("--pivot-subsidiaries", action="store_true",
                   help="also search CT logs for certificates issued to known subsidiaries' names")
    p.add_argument("--tools", choices=("auto", "local", "docker", "none"), default=DEFAULT_TOOLS,
                   help="how to run external tools: local binaries, the Docker tools image, or not at all")
    p.add_argument("--docker-image", default="surface-tools:latest")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)

    seeds = list(a.domains)
    if a.domains_file:
        seeds += [ln.strip() for ln in Path(a.domains_file).read_text().splitlines()
                  if ln.strip() and not ln.startswith("#")]
    if not seeds:
        p.error("provide at least one seed domain")
    if a.mode == "active" and not a.authorized:
        p.error("active mode sends scan traffic to the targets; pass --authorized to confirm "
                "you have permission to test them")
    try:
        networks = validate_networks(a.cidr)
        asns = validate_asns(a.asn)
    except ValueError as e:
        p.error(str(e))

    return Config(
        seeds=seeds, org_names=a.org, mode=a.mode, authorized=a.authorized,
        networks=networks, asns=asns, max_network_hosts=a.max_net_hosts,
        max_depth=a.depth, expand_threshold=a.threshold, max_apexes=a.max_apexes,
        exclude=[x.lower().strip(".") for x in a.exclude], out_dir=a.out,
        concurrency=a.concurrency,
        resolvers=a.resolvers.split(",") if a.resolvers else [],
        ports=[int(x) for x in a.ports.split(",")] if a.ports else [],
        wordlist=a.wordlist, tools=a.tools, docker_image=a.docker_image,
        sources=a.sources.split(",") if a.sources else None, verbose=a.verbose,
        company_intel=not a.no_company, pivot_subsidiaries=a.pivot_subsidiaries,
    )


SUBCOMMANDS = ("scan", "init", "new-run", "engagement", "merge", "serve", "doctor")


def _log_factory(verbose: bool):
    def log(msg: str) -> None:
        if verbose or "[source:" not in msg:
            print(msg, file=sys.stderr, flush=True)
    return log


def cmd_scan(argv: list[str]) -> int:
    cfg = parse_args(argv)
    run_dir = Path(cfg.out_dir) / f"{time.strftime('%Y%m%d-%H%M%S')}_{cfg.seeds[0].replace('/', '_')}"
    try:
        pipe = Pipeline(cfg, log=_log_factory(cfg.verbose),
                        checkpoint=lambda s: write_all(s, run_dir, cfg.expand_threshold))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        surface = asyncio.run(pipe.run())
    except KeyboardInterrupt:
        print("\ninterrupted; writing partial results", file=sys.stderr)
        pipe.s.meta["status"] = "interrupted"
        surface = pipe.s
    write_all(surface, run_dir, cfg.expand_threshold)
    print(f"\nResults: {run_dir}/report.md", file=sys.stderr)
    print(run_dir)
    if surface.meta.get("status") == "killed":
        print(f"KILL-SWITCH: {surface.meta['kill_switch']['reason']}", file=sys.stderr)
        return 3
    return 0


def cmd_new_run(argv: list[str]) -> int:
    from .scope import ScopeError, load_scope

    p = argparse.ArgumentParser(
        prog="surface-harness new-run",
        description="Create a new dated run directory in an engagement and print its path. Pass that "
                    "path to `engagement` and `merge` so every target of one run lands in the same place.")
    p.add_argument("scope", help="engagement directory or scope.yaml")
    a = p.parse_args(argv)
    try:
        scope = load_scope(a.scope)
    except ScopeError as e:
        p.error(str(e))
    scope.run = None
    print(scope.new_run())
    return 0


def cmd_init(argv: list[str]) -> int:
    from .scope import SCOPE_TEMPLATE

    p = argparse.ArgumentParser(prog="surface-harness init", description="Create an engagement directory + scope.yaml")
    p.add_argument("directory", help="e.g. engagements/acme-2026q4 (the last path part becomes the engagement id)")
    p.add_argument("--client", required=True, help="client name for the report")
    a = p.parse_args(argv)
    d = Path(a.directory)
    scope = d / "scope.yaml"
    if scope.exists():
        p.error(f"{scope} already exists")
    d.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9_-]", "-", d.name.lower()).strip("-") or "engagement"
    scope.write_text(SCOPE_TEMPLATE.format(engagement=slug, client=a.client.replace('"', "'")))
    print(f"created {scope} - edit targets and authorization, then: surface-harness engagement {d}")
    return 0


def cmd_engagement(argv: list[str]) -> int:
    from .engagement import run_engagement, write_merged
    from .scope import ScopeError, load_scope

    p = argparse.ArgumentParser(prog="surface-harness engagement",
                                description="Run every target (or selected targets) in a scope file.")
    p.add_argument("scope", help="engagement directory or scope.yaml (starts a new dated run), or an "
                                 "existing run directory from `new-run` (adds to that run)")
    p.add_argument("--target", action="append", default=[], help="only this target id (repeatable)")
    p.add_argument("--parallel", type=int, default=2, help="targets to run at once (default 2)")
    p.add_argument("--mode", choices=MODES, help="override scope mode for this run")
    p.add_argument("--no-merge", action="store_true", help="don't rebuild report.md/engagement.json afterwards")
    p.add_argument("--tools", choices=("auto", "local", "docker", "none"), default=DEFAULT_TOOLS)
    p.add_argument("--docker-image", default="surface-tools:latest")
    p.add_argument("--sources", help="comma-separated passive sources")
    p.add_argument("-c", "--concurrency", type=int, default=50)
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    try:
        scope = load_scope(a.scope)
        overrides = {"tools": a.tools, "docker_image": a.docker_image, "concurrency": a.concurrency,
                     "verbose": a.verbose, "sources": a.sources.split(",") if a.sources else None}
        if a.mode:
            overrides["mode"] = a.mode
        for tid in a.target or [t.id for t in scope.targets]:  # validate before starting anything
            scope.config_for(scope.target(tid), **dict(overrides))
        echo = lambda m: print(m, file=sys.stderr, flush=True)  # noqa: E731
        runs = asyncio.run(run_engagement(scope, a.target or None, a.parallel, overrides, echo))
    except ScopeError as e:
        p.error(str(e))
    for r in runs:
        print(r)
    if not a.no_merge:
        write_merged(scope)
        print(f"\nEngagement report: {scope.out_root / 'report.html'}", file=sys.stderr)
    from .engagement import _load
    killed = [r for r in runs if _load(r / "surface.json").get("meta", {}).get("status") == "killed"]
    return 3 if killed else 0


def cmd_merge(argv: list[str]) -> int:
    from .engagement import write_merged
    from .scope import ScopeError, load_scope

    p = argparse.ArgumentParser(prog="surface-harness merge",
                                description="Merge every target's harness run (+ analysis) of one engagement run "
                                            "into report.html, report.md, engagement.json and graph.*.")
    p.add_argument("scope", help="engagement directory or scope.yaml (merges the latest run), or a run directory")
    a = p.parse_args(argv)
    try:
        scope = load_scope(a.scope, read_only=True)
    except ScopeError as e:
        p.error(str(e))
    doc = write_merged(scope)
    for t in doc["targets"]:
        warn = f"  analysis warnings: {t['analysis_warnings']}" if t["analysis_warnings"] else ""
        print(f"{t['id']:<24} {t['status']:<10} {t['run_dir'] or '-'}{warn}", file=sys.stderr)
    for f in ("report.html", "report.md", "engagement.json", "graph.html", "graph.json", "graph.cypher"):
        print(scope.out_root / f)
    return 0


def cmd_doctor(argv: list[str]) -> int:
    """Pre-flight: which harness integrations are switched off in this environment."""
    import json

    from .recommend import coverage_gaps, materialise, probe_capabilities, render_doctor
    from .scope import ScopeError, load_scope
    from .tools import ToolRunner

    p = argparse.ArgumentParser(prog="surface-harness doctor",
                                description="Check API keys, binaries and mode for coverage gaps before a run. "
                                            "The engagement lead decides which gaps to close.")
    p.add_argument("scope", nargs="?", help="engagement directory or scope.yaml (uses its modes/authorization)")
    p.add_argument("--mode", choices=MODES, help="mode to check for (default: from scope, else standard)")
    p.add_argument("--tools", choices=("auto", "local", "docker", "none"), default=DEFAULT_TOOLS)
    p.add_argument("--docker-image", default="surface-tools:latest")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    a = p.parse_args(argv)

    cfg = Config(seeds=["example.com"])  # only used to read API keys from the environment
    active_allowed = None
    modes = {a.mode or "standard"}
    if a.scope:
        try:
            scope = load_scope(a.scope)
        except ScopeError as e:
            p.error(str(e))
        active_allowed = scope.active_allowed
        if not a.mode:
            modes = {t.mode or scope.defaults.get("mode", "standard") for t in scope.targets}
    caps = probe_capabilities(cfg.keys, ToolRunner(a.tools, a.docker_image, log=lambda _m: None), a.tools)
    recs = [r for m in sorted(modes) for r in coverage_gaps(caps, m, active_allowed)]
    gaps = materialise(recs)
    if a.json:
        print(json.dumps({"modes": sorted(modes), "active_allowed": active_allowed,
                          "capabilities": caps, "coverage_gaps": gaps}, indent=2))
    else:
        print(f"Modes: {', '.join(sorted(modes))}"
              + ("" if active_allowed is None else f" · active testing authorised: {active_allowed}"))
        print(render_doctor(gaps, caps))
    return 0


def cmd_serve(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="surface-harness serve", description="GraphQL API over engagement.json")
    p.add_argument("path", help="engagement directory or engagement.json")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default localhost; data is confidential)")
    p.add_argument("--port", type=int, default=8787)
    a = p.parse_args(argv)
    try:
        from .gql import serve
    except ImportError:
        p.error("GraphQL extras missing: pip install 'surface-harness[graphql]'")
    serve(a.path, a.host, a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in SUBCOMMANDS:
        cmd, argv = argv[0], argv[1:]
    else:
        cmd = "scan"  # backwards compatible: `surface-harness acme.com`
    return {"scan": cmd_scan, "init": cmd_init, "new-run": cmd_new_run, "engagement": cmd_engagement,
            "merge": cmd_merge, "serve": cmd_serve, "doctor": cmd_doctor}[cmd](argv)


if __name__ == "__main__":
    raise SystemExit(main())
