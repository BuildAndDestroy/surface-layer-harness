"""Engagement scope files: one per client contract.

    engagements/<engagement-id>/
      scope.yaml                     <- you write this
      targets/<target-id>/runs/...   <- one directory per harness run
      targets/<target-id>/analysis.{json,md}   <- written by analyst subagents (optional)
      summary.md                     <- boss agent's executive summary (optional)
      engagement.json, report.md, graph.*      <- produced by `surface-harness merge`
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import MODES, Config
from .networks import validate_asns, validate_networks

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class ScopeError(ValueError):
    pass


@dataclass
class Target:
    id: str
    name: str
    domains: list[str]
    org: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)  # CIDRs, e.g. 203.0.113.0/24
    asns: list[str] = field(default_factory=list)  # e.g. AS64500
    exclude: list[str] = field(default_factory=list)
    mode: str | None = None
    depth: int | None = None
    threshold: float | None = None
    notes: str = ""


@dataclass
class Scope:
    path: Path
    engagement: str
    client: str
    authorization: dict
    defaults: dict
    exclude: list[str]
    targets: list[Target]

    @property
    def root(self) -> Path:
        return self.path.parent

    @property
    def active_allowed(self) -> bool:
        return bool(self.authorization.get("active_testing"))

    def target(self, tid: str) -> Target:
        for t in self.targets:
            if t.id == tid:
                return t
        raise ScopeError(f"unknown target id '{tid}' (have: {', '.join(t.id for t in self.targets)})")

    def target_dir(self, tid: str) -> Path:
        return self.root / "targets" / tid

    def config_for(self, t: Target, **overrides) -> Config:
        d = self.defaults
        mode = overrides.pop("mode", None) or t.mode or d.get("mode", "standard")
        if mode not in MODES:
            raise ScopeError(f"{t.id}: invalid mode '{mode}'")
        if mode == "active" and not self.active_allowed:
            raise ScopeError(f"{t.id}: active mode requested but authorization.active_testing is not true "
                             f"in {self.path}")
        return Config(
            seeds=list(t.domains), org_names=list(t.org), mode=mode, authorized=self.active_allowed,
            networks=list(t.networks), asns=list(t.asns),
            max_depth=t.depth if t.depth is not None else d.get("depth", 1),
            expand_threshold=t.threshold if t.threshold is not None else d.get("threshold", 0.7),
            max_apexes=d.get("max_apexes", 25),
            exclude=[x.lower().strip(".") for x in (self.exclude + t.exclude)],
            out_dir=str(self.target_dir(t.id) / "runs"),
            pivot_subsidiaries=d.get("pivot_subsidiaries", False),
            **overrides,
        )


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    if p.is_dir():
        p = p / "scope.yaml"
    try:
        raw = yaml.safe_load(p.read_text()) or {}
    except FileNotFoundError as e:
        raise ScopeError(f"scope file not found: {p}") from e
    for key in ("engagement", "client", "targets"):
        if not raw.get(key):
            raise ScopeError(f"{p}: missing required key '{key}'")
    if not SLUG_RE.match(str(raw["engagement"])):
        raise ScopeError(f"{p}: engagement id must be a lowercase slug (a-z0-9_-)")
    auth = raw.get("authorization") or {}
    if not auth.get("reference"):
        raise ScopeError(f"{p}: authorization.reference is required (SOW / contract / ticket id)")

    targets, seen = [], set()
    for i, t in enumerate(raw["targets"]):
        tid = str(t.get("id", ""))
        if not SLUG_RE.match(tid):
            raise ScopeError(f"{p}: targets[{i}].id must be a lowercase slug")
        if tid in seen:
            raise ScopeError(f"{p}: duplicate target id '{tid}'")
        seen.add(tid)
        if not t.get("domains"):
            raise ScopeError(f"{p}: target '{tid}' has no domains")
        try:
            networks = validate_networks(t.get("networks") or [])
            asns = validate_asns(t.get("asns") or [])
        except ValueError as e:
            raise ScopeError(f"{p}: target '{tid}': {e}") from e
        targets.append(Target(
            id=tid, name=t.get("name") or tid, domains=list(t["domains"]), org=list(t.get("org") or []),
            networks=networks, asns=asns,
            exclude=list(t.get("exclude") or []), mode=t.get("mode"), depth=t.get("depth"),
            threshold=t.get("threshold"), notes=t.get("notes") or "",
        ))
    return Scope(path=p.resolve(), engagement=str(raw["engagement"]), client=str(raw["client"]),
                 authorization=auth, defaults=raw.get("defaults") or {},
                 exclude=list(raw.get("exclude") or []), targets=targets)


SCOPE_TEMPLATE = """\
# Engagement scope. One file per client contract; keep each client in its own directory.
engagement: {engagement}          # lowercase slug, used for directory names
client: "{client}"
authorization:
  reference: "SOW/contract/ticket id"   # required
  contact: "client point of contact"
  window: "YYYY-MM-DD to YYYY-MM-DD"
  active_testing: false                  # true only if the contract allows DNS brute force + port scans
defaults:
  mode: standard        # passive | standard | active
  depth: 1
  threshold: 0.7
  max_apexes: 25
  pivot_subsidiaries: false
exclude: []             # never touched, for every target (e.g. third-party SaaS the client doesn't own)
targets:
  - id: example         # lowercase slug
    name: "Example Corp"
    domains: [example.com]
    org: ["Example Corporation"]
    # networks: [203.0.113.0/24]   # in-scope IP ranges (CIDRs); expanded to host IPs for DNS/PTR
    # asns: [AS64500]              # in-scope ASNs; prefixes fetched via RIPEstat, then expanded
    exclude: []
    notes: ""
"""
