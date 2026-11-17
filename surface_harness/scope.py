"""Engagement scope files: one per client contract.

    engagements/<engagement-id>/
      scope.yaml                       <- you write this
      latest -> <YYYYMMDD-HHMMSS>      <- symlink to the newest run
      <YYYYMMDD-HHMMSS>/               <- one directory per engagement run; never reused
        scope.yaml                     <- the scope as it was for this run
        targets/<target-id>/runs/...   <- harness output for that target
        targets/<target-id>/analysis.{json,md}   <- written by analyst subagents (optional)
        summary.md                     <- boss agent's executive summary (optional)
        engagement.json, report.md, report.html, graph.*   <- produced by `surface-harness merge`

Every run gets its own dated directory, so a new run (or its analysis, summary and merged
reports) can never overwrite an earlier one. Engagements created before this layout keep
targets/ and the merged files directly in the engagement directory; they still merge.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import MODES, Config
from .models import ASSOCIATION_CAP
from .networks import validate_asns, validate_networks

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
RUN_RE = re.compile(r"^\d{8}-\d{6}(-\d+)?$")


def run_names(root: Path) -> list[str]:
    """Dated run directories of an engagement, oldest first."""
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink() and RUN_RE.match(p.name))


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
    run: str | None = None  # dated run directory under root; None = legacy layout (root itself)

    @property
    def root(self) -> Path:
        return self.path.parent

    @property
    def out_root(self) -> Path:
        """Where this run's targets/, summary.md and merged reports live."""
        return self.root / self.run if self.run else self.root

    def new_run(self) -> Path:
        """Create a fresh dated run directory, make it current, and return it."""
        base = name = time.strftime("%Y%m%d-%H%M%S")
        n = 1
        while (self.root / name).exists():
            n += 1
            name = f"{base}-{n}"
        (self.root / name / "targets").mkdir(parents=True)
        self.run = name
        self.snapshot()
        link = self.root / "latest"
        with contextlib.suppress(OSError):  # symlinks may be unavailable; the listing still works
            if link.is_symlink():
                link.unlink()
            if not link.exists():
                link.symlink_to(name, target_is_directory=True)
        return self.out_root

    def snapshot(self) -> None:
        """Record the scope this run actually used next to its results."""
        if self.run:
            shutil.copyfile(self.path, self.out_root / "scope.yaml")

    @property
    def active_allowed(self) -> bool:
        return bool(self.authorization.get("active_testing"))

    def target(self, tid: str) -> Target:
        for t in self.targets:
            if t.id == tid:
                return t
        raise ScopeError(f"unknown target id '{tid}' (have: {', '.join(t.id for t in self.targets)})")

    def target_dir(self, tid: str) -> Path:
        return self.out_root / "targets" / tid

    def config_for(self, t: Target, **overrides) -> Config:
        d = self.defaults
        mode = overrides.pop("mode", None) or t.mode or d.get("mode", "standard")
        if mode not in MODES:
            raise ScopeError(f"{t.id}: invalid mode '{mode}'")
        thr = t.threshold if t.threshold is not None else d.get("threshold", 0.7)
        if thr <= ASSOCIATION_CAP:
            raise ScopeError(f"{t.id}: threshold {thr} must be above {ASSOCIATION_CAP}; at or below it, domains "
                             f"with no ownership evidence (customers, vendors) would be treated as in scope")
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


def load_scope(path: str | Path, *, read_only: bool = False) -> Scope:
    """Load an engagement scope.

    `path` is the engagement directory, its scope.yaml, or one of its dated run directories
    (which selects that run). With `read_only` (merge / reporting) and no run named, the
    latest run is selected, and the scope.yaml stored with the run is the one read, so an
    old run is reported with the scope it actually had.
    """
    p = Path(path)
    run = None
    if p.is_dir() and RUN_RE.match(p.resolve().name) and (p.resolve().parent / "scope.yaml").exists():
        run, p = p.resolve().name, p.resolve().parent
    if p.is_dir():
        p = p / "scope.yaml"
    root = p.parent
    if read_only and run is None:
        run = (run_names(root) or [None])[-1]
    src = p
    if read_only and run and (root / run / "scope.yaml").exists():
        src = root / run / "scope.yaml"
    try:
        raw = yaml.safe_load(src.read_text()) or {}
    except FileNotFoundError as e:
        raise ScopeError(f"scope file not found: {src}") from e
    p = src  # error messages name the file that was read
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
    return Scope(path=(root / "scope.yaml").resolve(), engagement=str(raw["engagement"]),
                 client=str(raw["client"]), authorization=auth, defaults=raw.get("defaults") or {},
                 exclude=list(raw.get("exclude") or []), targets=targets, run=run)


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
