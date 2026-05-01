"""
Cross-domain correlation engine.

Implements the directed-graph model described in design spec §5.

Algorithm (per pattern P):
  1. Find all findings that match P's entry condition
  2. For each entry finding E, resolve its associated AWS resource(s)
  3. For each pivot condition, search the findings store for matches that
     are related to E's resources via the resource_graph adjacency table
  4. If all pivots are satisfied → instantiate an AttackChain

Patterns are loaded from YAML files in the patterns/ directory (auto-
discovered at startup).  New patterns require no code changes.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from ..db import (
    AttackChain, ChainComponent, ChainRole, EffortLevel,
    Finding, FindingsDB, RemediationAction, Severity,
)
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter

log = logging.getLogger(__name__)

# Directory containing the bundled YAML pattern files
_PATTERNS_DIR = Path(__file__).parent.parent.parent / "patterns"

# Severity elevation: when a chain has 3+ components it is raised by one level
_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


# ---------------------------------------------------------------------------
# Pattern schema (loaded from YAML)
# ---------------------------------------------------------------------------

@dataclass
class EntryCondition:
    """Defines the initial vulnerability that triggers a pattern match."""
    type: str                    # app_finding | infra_finding
    category: Optional[str] = None   # e.g. "SSRF", "SQLi", or "XSS"
    wstg: Optional[str] = None       # WSTG code prefix for matching
    check: Optional[str] = None      # cloud-audit/Prowler check ID


@dataclass
class PivotCondition:
    """Defines an infrastructure or application weakness that amplifies the entry."""
    type: str                       # app_finding | infra_finding | any_finding
    check: Optional[str] = None
    wstg: Optional[str] = None
    category: Optional[str] = None
    relationship: Optional[str] = None  # same_compute_resource | same_account | etc.
    severity: Optional[list[str]] = None  # For any_finding type
    # Edge-typed traversal constraint. When set, the relationship is treated
    # as "reachable from entry to pivot via *only* these edge types within
    # via_max_hops". Lets patterns express e.g. "principal escalates to
    # admin role via CAN_ASSUME / CAN_PASS_ROLE only" instead of any-edge.
    via_edges: Optional[list[str]] = None
    via_max_hops: int = 4


@dataclass
class AttackPattern:
    """A single compound attack pattern loaded from a YAML file."""
    name: str
    severity: Severity
    entry: EntryCondition
    pivots: list[PivotCondition]
    impact: str
    remediation_priority: list[dict]   # [{"summary": str, "effort": str, "breaks_chain": bool}]

    @classmethod
    def from_dict(cls, data: dict) -> "AttackPattern":
        """Parse a pattern dict loaded from YAML."""
        entry_data = data["entry"]
        entry = EntryCondition(
            type=entry_data.get("type", "app_finding"),
            category=entry_data.get("category"),
            wstg=entry_data.get("wstg"),
            check=entry_data.get("check"),
        )

        pivots = []
        for p in data.get("pivot", []):
            rel = p.get("relationship")
            via_edges: Optional[list[str]] = None
            via_max_hops = 4
            # Structured relationship: {via_edges: [...], max_hops: N}
            if isinstance(rel, dict):
                via_edges = rel.get("via_edges")
                via_max_hops = int(rel.get("max_hops", via_max_hops))
                # Keep the original relationship string available if the YAML
                # supplied one alongside the structured form (rare).
                rel = rel.get("name")
            pivots.append(PivotCondition(
                type=p.get("type", "infra_finding"),
                check=p.get("check"),
                wstg=p.get("wstg"),
                category=p.get("category"),
                relationship=rel,
                severity=p.get("severity"),
                via_edges=via_edges,
                via_max_hops=via_max_hops,
            ))

        # Normalise remediation_priority to a list of dicts
        raw_prio = data.get("remediation_priority", [])
        remediation_priority = []
        for i, item in enumerate(raw_prio):
            if isinstance(item, str):
                # Simple string form — infer effort from position
                effort = "LOW" if i == 0 else ("MEDIUM" if i <= 2 else "HIGH")
                remediation_priority.append({
                    "summary": item,
                    "effort": effort,
                    "breaks_chain": i == 0,  # First action usually breaks the chain
                })
            elif isinstance(item, dict):
                remediation_priority.append(item)

        return cls(
            name=data["pattern"]["name"] if "pattern" in data else data.get("name", "unknown"),
            severity=Severity(data.get("severity", data.get("pattern", {}).get("severity", "HIGH"))),
            entry=entry,
            pivots=pivots,
            impact=data.get("impact", ""),
            remediation_priority=remediation_priority,
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Loads patterns, builds the finding graph, and instantiates attack chains.

    Call run() to execute all patterns against the current findings store.
    Returns the number of new attack chains created.
    """

    def __init__(
        self,
        db: FindingsDB,
        mcp: MCPRegistry,
        limiter: RateLimiter,
        patterns_dir: Path = _PATTERNS_DIR,
        analyzer: Optional[Any] = None,
    ) -> None:
        self._db = db
        self._mcp = mcp
        self._limiter = limiter
        self._patterns_dir = patterns_dir
        self._patterns: list[AttackPattern] = []
        # Optional AttackSurfaceAnalyzer for multi-hop graph traversal
        self._analyzer = analyzer

    def _load_patterns(self) -> None:
        """Discover and parse all *.yaml files in the patterns directory."""
        if not self._patterns_dir.exists():
            log.warning("Patterns directory not found: %s", self._patterns_dir)
            return

        for yaml_file in sorted(self._patterns_dir.rglob("*.yaml")):
            try:
                with yaml_file.open() as fh:
                    data = yaml.safe_load(fh)
                pattern = AttackPattern.from_dict(data)
                self._patterns.append(pattern)
                log.debug("Loaded pattern: %s", pattern.name)
            except Exception as exc:
                log.warning("Failed to load pattern %s: %s", yaml_file.name, exc)

        log.info("[Correlation] Loaded %d attack patterns", len(self._patterns))

    async def run(self) -> int:
        """Evaluate all patterns and persist any matching attack chains.

        Returns the count of attack chains created.
        """
        self._load_patterns()
        if not self._patterns:
            log.warning("[Correlation] No patterns loaded — nothing to correlate")
            return 0

        # Load all findings once for efficiency
        all_findings = await self._db.get_findings()
        log.info("[Correlation] Evaluating %d patterns against %d findings", len(self._patterns), len(all_findings))

        # Evaluate patterns concurrently (each pattern is independent)
        tasks = [
            self._evaluate_pattern(pattern, all_findings)
            for pattern in self._patterns
        ]
        results = await asyncio.gather(*tasks)
        total = sum(results)
        return total

    async def _evaluate_pattern(
        self, pattern: AttackPattern, all_findings: list[Finding]
    ) -> int:
        """Evaluate one pattern against all findings.  Returns chains created."""
        entry_matches = [f for f in all_findings if self._matches_entry(f, pattern.entry)]
        if not entry_matches:
            return 0

        chains_created = 0
        for entry_finding in entry_matches:
            pivot_sets = await self._find_pivots(entry_finding, pattern.pivots, all_findings)
            if pivot_sets is None:
                continue  # Not all pivots satisfied

            chain = await self._instantiate_chain(pattern, entry_finding, pivot_sets)
            if chain:
                chains_created += 1

        return chains_created

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    def _matches_entry(self, finding: Finding, cond: EntryCondition) -> bool:
        """Return True if *finding* satisfies the entry condition."""
        # Source filter
        if cond.type == "app_finding" and finding.source not in ("autopentest",):
            return False
        if cond.type == "azure_finding" and getattr(finding, "provider", "aws") != "azure":
            return False
        if cond.type == "infra_finding" and finding.source not in ("cloud-audit", "prowler"):
            return False

        # Category / WSTG code match
        if cond.category and cond.category.lower() not in (finding.category or "").lower():
            # Also try matching against the title for category labels like "SSRF"
            if cond.category.lower() not in (finding.title or "").lower():
                return False
        if cond.wstg and not (finding.category or "").startswith(cond.wstg):
            return False
        if cond.check and cond.check not in (finding.category or ""):
            return False

        return True

    async def _find_pivots(
        self,
        entry: Finding,
        pivot_conditions: list[PivotCondition],
        all_findings: list[Finding],
    ) -> Optional[list[list[Finding]]]:
        """For each pivot condition, find matching findings.

        Returns a list of lists (one per pivot) when ALL pivots are
        satisfied, or None if any pivot has zero matches.
        """
        result: list[list[Finding]] = []

        for pivot in pivot_conditions:
            matches = await self._find_pivot_matches(entry, pivot, all_findings)
            if not matches:
                return None  # This pivot is not satisfied
            result.append(matches)

        return result

    async def _find_pivot_matches(
        self,
        entry: Finding,
        pivot: PivotCondition,
        all_findings: list[Finding],
    ) -> list[Finding]:
        """Return findings that satisfy a single pivot condition."""
        candidates: list[Finding] = []

        for f in all_findings:
            if f.id == entry.id:
                continue  # Don't match the entry finding as its own pivot

            # Source type filter
            if pivot.type == "app_finding" and f.source not in ("autopentest",):
                continue
            if pivot.type == "azure_finding" and getattr(f, "provider", "aws") != "azure":
                continue
            if pivot.type == "infra_finding" and f.source not in ("cloud-audit", "prowler"):
                continue
            if pivot.type == "any_finding":
                # Optionally filter by severity list
                if pivot.severity and f.severity.value not in pivot.severity:
                    continue

            # Check ID match
            if pivot.check and pivot.check not in (f.category or ""):
                continue
            if pivot.wstg and not (f.category or "").startswith(pivot.wstg):
                continue
            if pivot.category and pivot.category.lower() not in (f.category or "").lower():
                # Also search title
                if pivot.category.lower() not in (f.title or "").lower():
                    continue

            # Relationship constraint — verify via the knowledge graph.
            needs_relationship_check = (
                pivot.relationship or pivot.via_edges
            ) and entry.resource_id and f.resource_id
            if needs_relationship_check:
                related = await self._are_resources_related(
                    entry.resource_id, f.resource_id, pivot,
                )
                if not related:
                    continue

            candidates.append(f)

        return candidates

    async def _are_resources_related(
        self, src_id: str, dst_id: str, pivot: PivotCondition,
    ) -> bool:
        """Check whether two resources satisfy a pivot's relationship constraint.

        Resolves three forms in order:
          1. Edge-typed multi-hop (``via_edges``) when the YAML supplies one.
          2. Named shortcuts: ``same_account`` / ``same_compute_resource``.
          3. Generic any-edge multi-hop via the knowledge graph; falls back
             to the legacy 1-hop SQLite lookup if no graph is available.
        """
        # 1. Structured edge-typed traversal — the precise form patterns now use.
        if pivot.via_edges:
            if self._analyzer is None:
                # Without a graph we can't honour an edge-typed constraint
                # without false positives — fail the match instead of silently
                # downgrading to any-edge.
                return False
            return self._analyzer.are_related_multi_hop(
                src_id, dst_id,
                max_hops=pivot.via_max_hops,
                edge_types=pivot.via_edges,
            )

        relationship = pivot.relationship
        # Same-account / same-tenant: all findings in the store share a tenant/account
        if relationship in ("same_account", "same_tenant"):
            return True  # If we're here, all findings are from the same assessment

        # Azure subscription / resource group scope shortcuts
        if relationship == "same_subscription":
            return _same_subscription_heuristic(src_id, dst_id)
        if relationship == "same_resource_group":
            return _same_resource_group_heuristic(src_id, dst_id)

        # Same-compute-resource: the resource IDs reference the same EC2/compute
        if relationship == "same_compute_resource":
            return src_id == dst_id or _same_compute_heuristic(src_id, dst_id)

        # Multi-hop graph traversal when knowledge graph is available
        if self._analyzer is not None:
            return self._analyzer.are_related_multi_hop(src_id, dst_id, max_hops=4)

        # Fallback: existing 1-hop SQLite adjacency lookup
        neighbors = await self._db.get_resource_neighbors(src_id)
        if dst_id in neighbors:
            return True
        # Also check reverse direction for symmetric relationships
        reverse_neighbors = await self._db.get_resource_neighbors(dst_id)
        return src_id in reverse_neighbors

    # ------------------------------------------------------------------
    # Chain instantiation
    # ------------------------------------------------------------------

    async def _instantiate_chain(
        self,
        pattern: AttackPattern,
        entry: Finding,
        pivot_sets: list[list[Finding]],
    ) -> Optional[AttackChain]:
        """Create and persist a compound attack chain.

        Returns the AttackChain if successfully created, None on error.
        """
        try:
            # Select the highest-severity pivot finding from each set
            pivot_findings = [
                max(pivots, key=lambda f: _SEVERITY_ORDER.index(f.severity))
                for pivots in pivot_sets
            ]

            all_component_findings = [entry] + pivot_findings
            aggregate_severity = _aggregate_severity(
                [f.severity for f in all_component_findings]
            )

            # Narrative: pattern impact text + brief entry/pivot summary
            narrative = _build_narrative(pattern, entry, pivot_findings)

            chain = AttackChain(
                pattern_name=pattern.name,
                severity=aggregate_severity,
                narrative=narrative,
                entry_finding_id=entry.id,
            )

            # Build chain components
            components = [
                ChainComponent(
                    chain_id=chain.id,
                    finding_id=entry.id,
                    role=ChainRole.ENTRY,
                    sequence_order=0,
                )
            ]
            for i, pivot_finding in enumerate(pivot_findings, start=1):
                role = ChainRole.PIVOT if i < len(pivot_findings) else ChainRole.AMPLIFIER
                components.append(ChainComponent(
                    chain_id=chain.id,
                    finding_id=pivot_finding.id,
                    role=role,
                    sequence_order=i,
                ))

            # Build remediation actions from the pattern's priority list
            actions = []
            for i, prio in enumerate(pattern.remediation_priority):
                actions.append(RemediationAction(
                    chain_id=chain.id,
                    priority_order=i + 1,
                    action_summary=prio.get("summary", ""),
                    effort_level=EffortLevel(prio.get("effort", "MEDIUM").upper()),
                    breaks_chain=bool(prio.get("breaks_chain", False)),
                    cli_command=prio.get("cli_command"),
                    iac_snippet=prio.get("iac_snippet"),
                ))

            await self._db.insert_attack_chain(chain, components, actions)
            log.info(
                "[Correlation] Chain: %s (%s) — entry: %s",
                pattern.name, aggregate_severity.value, entry.title[:60],
            )
            return chain

        except Exception as exc:
            log.warning("[Correlation] Failed to instantiate chain for pattern %s: %s", pattern.name, exc)
            return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _aggregate_severity(severities: list[Severity]) -> Severity:
    """Return the aggregate severity for a set of component findings.

    Takes the maximum individual severity, then elevates by one level if
    there are 3 or more components (per design spec §5.4).
    """
    if not severities:
        return Severity.LOW

    max_sev = max(severities, key=lambda s: _SEVERITY_ORDER.index(s))
    max_idx = _SEVERITY_ORDER.index(max_sev)

    # Elevate by one level for chains with 3+ components
    if len(severities) >= 3 and max_idx < len(_SEVERITY_ORDER) - 1:
        return _SEVERITY_ORDER[max_idx + 1]

    return max_sev


def _build_narrative(
    pattern: AttackPattern,
    entry: Finding,
    pivots: list[Finding],
) -> str:
    """Compose a human-readable attack chain narrative."""
    pivot_titles = "; ".join(f.title for f in pivots)
    return (
        f"**Entry:** {entry.title} ({entry.category})\n"
        f"**Pivots:** {pivot_titles}\n"
        f"**Impact:** {pattern.impact}"
    )


def _same_compute_heuristic(arn1: str, arn2: str) -> bool:
    """Heuristic: two resources are 'same compute' if they share an EC2 instance ID."""
    # EC2 ARNs contain the instance ID: arn:aws:ec2:region:account:instance/i-0abc123
    for part in arn1.split("/"):
        if part.startswith("i-") and part in arn2:
            return True
    return False


def _same_subscription_heuristic(rid1: str, rid2: str) -> bool:
    """True when both Azure resource IDs share the same subscription segment."""
    # /subscriptions/<sub-id>/...
    def _sub(rid: str) -> str:
        parts = rid.lower().split("/subscriptions/")
        if len(parts) < 2:
            return ""
        return parts[1].split("/")[0]

    s1, s2 = _sub(rid1), _sub(rid2)
    return bool(s1) and s1 == s2


def _same_resource_group_heuristic(rid1: str, rid2: str) -> bool:
    """True when both Azure resource IDs share the same subscription AND resource group."""
    # /subscriptions/<sub>/resourceGroups/<rg>/...
    def _rg_key(rid: str) -> str:
        lower = rid.lower()
        try:
            after_sub = lower.split("/subscriptions/")[1]
            sub = after_sub.split("/")[0]
            after_rg = lower.split("/resourcegroups/")[1]
            rg = after_rg.split("/")[0]
            return f"{sub}/{rg}"
        except (IndexError, AttributeError):
            return ""

    k1, k2 = _rg_key(rid1), _rg_key(rid2)
    return bool(k1) and k1 == k2
