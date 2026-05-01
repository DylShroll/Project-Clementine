"""
Novel attack-chain discovery via Claude.

The rule-based correlation engine (:mod:`clementine.correlation.engine`) is
conservative — it only instantiates chains that exactly match a hand-curated
YAML pattern. That's great for precision but it *structurally cannot* find
attack paths nobody has written a pattern for yet. Real-world exploitation
chains mix app-layer bugs, IAM mistakes, and network exposure in ways that
the small pattern library can't enumerate.

This module asks Claude to look at the complete evidence picture — every
finding, every AWS resource-graph edge, and every chain the rule engine
already produced — and propose additional chains the static rules missed.
The LLM output is conservative-by-default (confidence threshold + cap) so
a hallucinating model can't drown the report in speculative chains.

Workflow
--------
1. Collect findings, existing chains, and resource-graph edges from the DB.
2. Ask Claude for ``DiscoveredChain`` objects via structured output.
3. Filter by confidence threshold and chain cap.
4. Map each proposed chain to real ``Finding`` rows (drop chains that
   reference IDs the model made up).
5. Persist with ``chain_source='ai-discovered'`` so downstream reporting
   can distinguish rule-based from AI-proposed chains.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel, Field

from ..config import AIConfig
from ..db import (
    AttackChain, ChainComponent, ChainRole, EffortLevel,
    Finding, FindingsDB, RemediationAction, Severity,
)
from .client import ClaudeClient

if TYPE_CHECKING:
    from ..graph.attack_surface import AttackSurfaceAnalyzer

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured-output schema
# ---------------------------------------------------------------------------

class DiscoveredRemediation(BaseModel):
    """One remediation step for a discovered chain."""
    summary: str = Field(description="One-sentence imperative remediation action.")
    effort: str = Field(
        description="Implementation effort: LOW, MEDIUM, or HIGH.",
        pattern="^(LOW|MEDIUM|HIGH)$",
    )
    breaks_chain: bool = Field(
        description=(
            "True if this action alone would prevent the chain from being "
            "exploitable. Exactly one action should typically be marked True."
        ),
    )


class DiscoveredChain(BaseModel):
    """A novel attack chain proposed by the LLM."""
    name: str = Field(description="Short kebab-case identifier, e.g. 'ssrf-to-imds-exfil'.")
    severity: str = Field(
        description="Aggregate severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO.",
        pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$",
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description=(
            "Probability in [0, 1] that this chain is a genuine, exploitable "
            "attack path — not just a collection of co-occurring findings."
        ),
    )
    entry_finding_id: str = Field(
        description=(
            "The finding that serves as the chain's entry point. Must be a "
            "real finding_id from the input list — never invent IDs."
        ),
    )
    component_finding_ids: list[str] = Field(
        description=(
            "All findings that participate in the chain, in order from entry "
            "to final impact. Must include entry_finding_id as the first item. "
            "Every ID must appear in the input list."
        ),
    )
    narrative: str = Field(
        description=(
            "Two to five sentences explaining how an attacker would traverse "
            "the chain. Reference specific findings, resources, and cloud "
            "services by name. For multi-cloud chains, explicitly name the "
            "cloud-boundary crossing step. No hand-waving."
        ),
    )
    remediation_actions: list[DiscoveredRemediation] = Field(
        description=(
            "Ordered remediation plan — cheapest chain-breaking action first. "
            "Typically 2-4 actions."
        ),
    )


class DiscoveryResult(BaseModel):
    """Container for the LLM response — zero or more chain proposals."""
    chains: list[DiscoveredChain]


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior offensive-security engineer reviewing a completed \
penetration-test run. Your job is to identify *compound attack chains* that \
a rule-based correlator has missed.

You will be given:
* The full list of findings (app-layer, AWS-infrastructure, and Azure-infrastructure), \
  each with a UUID, severity, category, title, provider, and resource context.
* Every edge in the target's resource graph (source → target, relationship). \
  The graph contains both AWS nodes (ARN-style IDs) and Azure nodes (resource \
  IDs starting with /subscriptions/…). Edge types include both AWS IAM \
  traversal edges (CAN_ASSUME, OIDC_TRUSTS, etc.) and Azure equivalents \
  (CAN_ASSUME_MI, HAS_RBAC_ROLE, WORKLOAD_ID_BOUND, PIM_ELIGIBLE_FOR, etc.).
* A summary of every attack chain the static rule engine already produced, \
  so you can avoid duplicating them.

An *attack chain* is not merely a list of findings that happen to exist in \
the same environment. A chain requires a causal path: finding A grants the \
attacker capability that they then use to exploit finding B.

**Multi-cloud chains are highest priority.** Look actively for paths that cross \
cloud boundaries. Valid multi-cloud chain shapes include:

* **GitHub Actions → Azure SP → Azure resources** — a GitHub repository with \
  an overly broad OIDC federated credential can obtain an Azure token and \
  pivot to Key Vaults or subscription-level RBAC.
* **SSRF on AWS-hosted app → Azure IMDS via peering** — an SSRF on an EC2 \
  instance reachable via VPN or VNet peering can reach the Azure IMDS endpoint \
  and exfiltrate a managed identity token.
* **Azure Workload Identity → UAMI → AWS via IRSA or STS federation** — a \
  Kubernetes workload identity bound to a UAMI with federated AWS credentials \
  can request STS tokens and act against AWS resources.
* **SSRF + Azure Function App identity endpoint** — SSRF in an App Service \
  app reaches the internal IDENTITY_ENDPOINT, exfiltrates an MI token, then \
  uses it against Key Vault secrets that include AWS access key IDs.

Multi-cloud chains that are fully evidenced by real findings in the graph \
should be assigned **confidence +0.2 above** a single-provider equivalent \
and labelled with ``provider_lane: multi`` in the narrative.

Single-provider chains (AWS-only or Azure-only):
* **SSRF + IMDSv1** — SSRF → EC2 IMDS → instance role credentials.
* **Weak IAM + exposed bucket** — permissive IAM role → S3 bucket with sensitive data.
* **AKS workload identity overprivilege** — AKS service account bound to UAMI \
  with subscription Owner — any pod in the namespace can own the subscription.
* **App Admin → Global Admin via SP credential reset** — Application Admin resets \
  credentials of a Global Admin service principal.

Non-chains (do NOT propose these):
* Two unrelated findings on different resources with no graph edge or \
  shared identity between them.
* A single finding restated as a "chain of one".
* Speculative chains that require evidence not present in the input.

For every chain you propose:
* **entry_finding_id** must be a real ID from the provided findings list.
* **component_finding_ids** must all be real IDs, in exploit order.
* **narrative** must reference specific findings, providers, and resources by name. \
  For multi-cloud chains, explicitly state the cloud-boundary crossing step.
* **confidence** reflects how firmly the evidence supports the causal path. \
  Cap at 0.55 if any edge is speculative. Add 0.2 for fully-evidenced multi-cloud chains.
* **remediation_actions**: cheapest chain-breaking control first.

Be conservative. Propose zero chains rather than speculative ones. \
The rule engine covered obvious patterns; your value is the non-obvious.
"""


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

async def discover_chains(
    *,
    client: ClaudeClient,
    cfg: AIConfig,
    db: FindingsDB,
    analyzer: Optional["AttackSurfaceAnalyzer"] = None,
) -> list[AttackChain]:
    """Propose novel attack chains, persist the accepted ones, return them.

    Returns only chains that passed the confidence threshold *and* were
    successfully mapped to real findings in the DB.

    When *analyzer* is provided, the resource graph is pruned to nodes within
    a couple of hops of any finding-bearing resource before being serialised
    into the prompt; this is the dominant input-token reduction on real runs.
    """
    all_findings = await db.get_findings()
    if not all_findings:
        log.info("AI discovery: no findings to analyse — skipping")
        return []

    # Pre-filter findings: drop triaged false positives, sub-confidence, and
    # (optionally) INFO-severity. These never participate in real chains and
    # they're the bulk of the token spend on noisy assessments.
    findings = _prefilter_findings(all_findings, cfg.discovery)
    if not findings:
        log.info(
            "AI discovery: all %d findings filtered out — skipping",
            len(all_findings),
        )
        return []

    existing_chains = await db.get_attack_chains()
    graph_edges = await _load_graph_edges(db)

    # Compute the keep-set used for both edge pruning and "this finding's
    # resource is graph-reachable" filtering.
    finding_resource_ids = {
        f.resource_id for f in findings if f.resource_id
    }
    keep_node_ids: Optional[set[str]] = None
    if analyzer is not None and finding_resource_ids:
        keep_node_ids = analyzer.subgraph_around(
            finding_resource_ids, hops=cfg.discovery.subgraph_hops
        )
        # Drop findings whose resource is isolated in the pruned subgraph;
        # they can't form multi-hop chains with anything else.
        if cfg.discovery.drop_unreachable_findings and keep_node_ids:
            before = len(findings)
            findings = [
                f for f in findings
                if not f.resource_id or f.resource_id in keep_node_ids
            ]
            if len(findings) < before:
                log.info(
                    "AI discovery: dropped %d findings with no graph reach",
                    before - len(findings),
                )

    static_user_content, instruction_tail = _render_discovery_prompt(
        findings=findings,
        existing_chains=existing_chains,
        graph_edges=graph_edges,
        keep_node_ids=keep_node_ids,
    )

    system_blocks = [
        {
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]
    # Cache-control breakpoint between the (large, stable) findings + graph
    # block and the (short, instruction-only) tail. On a single-call run
    # this only pays the cache-write cost, but any re-run within the cache
    # TTL replays the whole static block from cache instead of reprocessing.
    user_blocks = [
        {
            "type": "text",
            "text": static_user_content,
            "cache_control": {"type": "ephemeral"},
        },
        {
            "type": "text",
            "text": instruction_tail,
        },
    ]

    log.info(
        "AI discovery: analysing %d findings (of %d), %d existing chains, %d graph edges",
        len(findings), len(all_findings), len(existing_chains), len(graph_edges),
    )

    try:
        result: DiscoveryResult = await client.parse(
            response_model=DiscoveryResult,
            system=system_blocks,
            user_content=user_blocks,
            max_tokens=cfg.discovery.max_tokens,
            model=cfg.critical_model,
            call_site="discovery",
            effort=cfg.discovery.effort,
            max_retries=cfg.discovery.max_retries,
        )
    except Exception as exc:
        log.error("AI discovery request failed: %s", exc)
        return []

    # Build a lookup so we can reject hallucinated finding IDs. Use the
    # *full* finding set so the model can reference findings that were
    # pre-filtered out (the model shouldn't have been told about them, but
    # if it somehow refers to one we still want to accept it).
    finding_by_id = {f.id: f for f in all_findings}

    accepted = _filter_and_validate(
        proposals=result.chains,
        cfg=cfg,
        finding_by_id=finding_by_id,
    )

    persisted = []
    for proposal in accepted:
        chain = await _persist_chain(proposal, finding_by_id, db)
        if chain is not None:
            persisted.append(chain)

    log.info(
        "AI discovery complete — %d proposals, %d accepted, %d persisted",
        len(result.chains), len(accepted), len(persisted),
    )
    return persisted


# ---------------------------------------------------------------------------
# Input rendering
# ---------------------------------------------------------------------------

async def _load_graph_edges(db: FindingsDB) -> list[tuple[str, str, str]]:
    """Fetch every (source_arn, target_arn, relationship) row from the graph.

    Read directly from the connection — the DB class exposes neighbour
    lookups but not a "dump all edges" helper, and this is cheaper than
    walking every ARN we've seen.
    """
    async with db._conn.execute(
        "SELECT source_arn, target_arn, relationship FROM resource_graph"
    ) as cur:
        rows = await cur.fetchall()
    return [(r["source_arn"], r["target_arn"], r["relationship"]) for r in rows]


def _prefilter_findings(
    findings: list[Finding], discovery_cfg
) -> list[Finding]:
    """Drop findings that can't meaningfully participate in a discovered chain.

    Cuts triaged false positives, low-confidence triage verdicts, and
    (by default) INFO-severity noise. Combined with the graph-reachability
    pass in :func:`discover_chains` this is the dominant input-token cut.
    """
    keep: list[Finding] = []
    dropped_fp = dropped_low_conf = dropped_info = 0
    for f in findings:
        if f.triage_is_false_positive is True:
            dropped_fp += 1
            continue
        if (
            f.triage_confidence is not None
            and f.triage_confidence < discovery_cfg.min_finding_confidence
        ):
            dropped_low_conf += 1
            continue
        if (
            not discovery_cfg.include_info
            and f.severity == Severity.INFO
        ):
            dropped_info += 1
            continue
        keep.append(f)
    if dropped_fp or dropped_low_conf or dropped_info:
        log.info(
            "AI discovery prefilter: -%d FP, -%d low-conf, -%d INFO (kept %d/%d)",
            dropped_fp, dropped_low_conf, dropped_info, len(keep), len(findings),
        )
    return keep


def _render_discovery_prompt(
    *,
    findings: list[Finding],
    existing_chains: list[AttackChain],
    graph_edges: list[tuple[str, str, str]],
    keep_node_ids: Optional[set[str]] = None,
) -> tuple[str, str]:
    """Compose the user-content payload for the discovery request.

    Returns a (static_block, instruction_tail) pair so the caller can attach
    a cache-control breakpoint between them. The static block holds the
    findings + chains + graph (the bulk of the tokens, stable across re-runs
    within the cache TTL); the tail is the short "now propose chains" cue.

    Compression:
      * ARNs in the graph block are replaced with short aliases (r1, r2…)
        defined once in a legend. ARNs are ~80 chars each; on a typical
        150-edge graph this is the single biggest character saving.
      * If *keep_node_ids* is provided, edges whose endpoints are both
        outside that set are dropped before rendering.
      * Edges are grouped by relationship so the model sees structured
        compact lists rather than one-line-per-edge noise.
    """
    parts: list[str] = []

    parts.append("## FINDINGS")
    parts.append("One per line: finding_id | provider | severity | category | title | resource")
    for f in findings:
        resource = (
            f"{f.resource_type or '-'}:{f.resource_id or '-'}"
            if (f.resource_type or f.resource_id)
            else "-"
        )
        provider = getattr(f, "provider", "aws") or "aws"
        parts.append(
            f"{f.id} | {provider} | {f.severity.value} | {f.category} | "
            f"{_one_line(f.title)} | {resource}"
        )

    parts.append("")
    parts.append("## EXISTING RULE-BASED CHAINS (do not duplicate)")
    if existing_chains:
        for c in existing_chains:
            parts.append(
                f"- {c.pattern_name} [{c.severity.value}]: {_one_line(c.narrative)}"
            )
    else:
        parts.append("(none)")

    # ---- Graph block: alias ARNs, prune, group ----
    parts.append("")
    parts.append("## RESOURCE GRAPH")
    if not graph_edges:
        parts.append("(no edges recorded)")
    else:
        # 1. Optionally prune to the relevant subgraph.
        if keep_node_ids is not None:
            pruned = [
                (s, d, r) for (s, d, r) in graph_edges
                if s in keep_node_ids or d in keep_node_ids
            ]
        else:
            pruned = list(graph_edges)

        # 2. Build alias table — only for ARNs that actually appear in pruned
        #    edges (legend + edge-list both shrink together).
        endpoints: list[str] = []
        seen_endpoints: set[str] = set()
        for src, dst, _ in pruned:
            for arn in (src, dst):
                if arn not in seen_endpoints:
                    seen_endpoints.add(arn)
                    endpoints.append(arn)
        alias_for: dict[str, str] = {
            arn: f"r{i + 1}" for i, arn in enumerate(endpoints)
        }

        # 3. Render legend.
        parts.append(
            f"Aliases (r<n> = ARN). {len(endpoints)} nodes, "
            f"{len(pruned)} edges (pruned from {len(graph_edges)})."
        )
        for arn, alias in alias_for.items():
            parts.append(f"{alias} = {arn}")

        # 4. Group edges by relationship.
        parts.append("")
        parts.append("Edges (grouped by relationship):")
        by_rel: dict[str, list[tuple[str, str]]] = {}
        for src, dst, rel in pruned:
            by_rel.setdefault(rel, []).append((alias_for[src], alias_for[dst]))
        for rel in sorted(by_rel):
            pairs = ", ".join(f"{s}->{d}" for s, d in by_rel[rel])
            parts.append(f"{rel}: {pairs}")

    static_block = "\n".join(parts)
    instruction_tail = (
        "\n\nPropose novel attack chains that the rule-based correlator missed. "
        "Return an empty list if nothing meets the bar."
    )
    return static_block, instruction_tail


def _one_line(text: str) -> str:
    """Collapse multi-line text to a single line so the prompt stays scannable."""
    return " ".join(text.split())


# ---------------------------------------------------------------------------
# Filtering and persistence
# ---------------------------------------------------------------------------

def _filter_and_validate(
    *,
    proposals: list[DiscoveredChain],
    cfg: AIConfig,
    finding_by_id: dict[str, Finding],
) -> list[DiscoveredChain]:
    """Drop low-confidence, hallucinated, or over-quota proposals."""
    valid: list[DiscoveredChain] = []

    for p in proposals:
        if p.confidence < cfg.discovery.min_confidence:
            log.info(
                "Discovery: dropping '%s' — confidence %.2f below threshold %.2f",
                p.name, p.confidence, cfg.discovery.min_confidence,
            )
            continue

        if p.entry_finding_id not in finding_by_id:
            log.warning(
                "Discovery: dropping '%s' — entry_finding_id %s not in findings",
                p.name, p.entry_finding_id,
            )
            continue

        unknown = [fid for fid in p.component_finding_ids if fid not in finding_by_id]
        if unknown:
            log.warning(
                "Discovery: dropping '%s' — %d hallucinated component IDs",
                p.name, len(unknown),
            )
            continue

        if p.entry_finding_id not in p.component_finding_ids:
            log.warning(
                "Discovery: dropping '%s' — entry not listed in components",
                p.name,
            )
            continue

        valid.append(p)

    # Highest-confidence proposals first, then cap.
    valid.sort(key=lambda c: c.confidence, reverse=True)
    return valid[: cfg.discovery.max_chains]


async def _persist_chain(
    proposal: DiscoveredChain,
    finding_by_id: dict[str, Finding],
    db: FindingsDB,
) -> Optional[AttackChain]:
    """Write a validated proposal into the DB; return the AttackChain or None."""
    try:
        chain = AttackChain(
            pattern_name=proposal.name,
            severity=Severity(proposal.severity),
            narrative=proposal.narrative,
            entry_finding_id=proposal.entry_finding_id,
            chain_source="ai-discovered",
        )

        components: list[ChainComponent] = []
        for idx, fid in enumerate(proposal.component_finding_ids):
            if fid == proposal.entry_finding_id and idx == 0:
                role = ChainRole.ENTRY
            elif idx == len(proposal.component_finding_ids) - 1:
                role = ChainRole.AMPLIFIER
            else:
                role = ChainRole.PIVOT
            components.append(
                ChainComponent(
                    chain_id=chain.id,
                    finding_id=fid,
                    role=role,
                    sequence_order=idx,
                )
            )

        actions: list[RemediationAction] = []
        for i, rem in enumerate(proposal.remediation_actions):
            actions.append(
                RemediationAction(
                    chain_id=chain.id,
                    priority_order=i + 1,
                    action_summary=rem.summary,
                    effort_level=EffortLevel(rem.effort),
                    breaks_chain=rem.breaks_chain,
                )
            )

        await db.insert_attack_chain(chain, components, actions)
        log.info(
            "[AI-Discovery] Chain: %s [%s, conf=%.2f] — %d components",
            proposal.name, proposal.severity, proposal.confidence, len(components),
        )
        return chain

    except Exception as exc:
        log.warning("Failed to persist AI-discovered chain '%s': %s", proposal.name, exc)
        return None
