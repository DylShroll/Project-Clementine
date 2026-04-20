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
from typing import Optional

from pydantic import BaseModel, Field

from ..config import AIConfig
from ..db import (
    AttackChain, ChainComponent, ChainRole, EffortLevel,
    Finding, FindingsDB, RemediationAction, Severity,
)
from .client import ClaudeClient

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
            "the chain. Reference specific findings, resources, and AWS "
            "services by name. No hand-waving."
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
* The full list of findings (app-layer and AWS-infrastructure), each with \
  a UUID, severity, category, title, and resource context.
* Every edge in the target's AWS resource graph (source_arn → target_arn, \
  relationship).
* A summary of every attack chain the static rule engine already produced, \
  so you can avoid duplicating them.

An *attack chain* is not merely a list of findings that happen to exist in \
the same environment. A chain requires a causal path: finding A grants the \
attacker capability that they then use to exploit finding B, escalating to \
the final impact. Examples of valid chain shapes:

* **SSRF + IMDSv1** — an SSRF on an EC2-hosted service reaches the metadata \
  endpoint, steals the instance role credentials, and uses that role to act \
  against other AWS resources.
* **Weak IAM + exposed bucket** — a permissive IAM role attached to a \
  compromised compute resource grants access to an S3 bucket that contains \
  sensitive data.
* **Stored XSS + session cookie without HttpOnly** — an attacker stores XSS \
  on a shared page, then reads admin session cookies via the stolen DOM \
  access.

Non-chains (do NOT propose these):
* Two unrelated findings on different resources with no graph edge or \
  shared identity between them.
* A single finding restated as a "chain of one".
* Speculative chains that require evidence not present in the input \
  (e.g. "there might also be a privilege escalation if the role has *:*").

For every chain you propose:
* **entry_finding_id** must be a real ID from the provided findings list.
* **component_finding_ids** must all be real IDs, must include the entry \
  as the first item, and must be in exploit order (entry → pivots → impact).
* **narrative** must reference specific findings and resources by name. \
  Avoid generic phrases like "the attacker could then pivot".
* **confidence** reflects how firmly the evidence supports the causal path. \
  If the chain requires an edge that only *might* exist, cap at 0.55.
* **remediation_actions** should list the cheapest chain-breaking control \
  first — the thing a defender could change tomorrow.

Be conservative. It is better to propose zero chains than to propose chains \
built on findings that aren't actually linked. The rule engine already \
covered the obvious patterns; your value is finding the non-obvious ones.
"""


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

async def discover_chains(
    *,
    client: ClaudeClient,
    cfg: AIConfig,
    db: FindingsDB,
) -> list[AttackChain]:
    """Propose novel attack chains, persist the accepted ones, return them.

    Returns only chains that passed the confidence threshold *and* were
    successfully mapped to real findings in the DB.
    """
    findings = await db.get_findings()
    if not findings:
        log.info("AI discovery: no findings to analyse — skipping")
        return []

    existing_chains = await db.get_attack_chains()
    graph_edges = await _load_graph_edges(db)

    prompt = _render_discovery_prompt(
        findings=findings,
        existing_chains=existing_chains,
        graph_edges=graph_edges,
    )

    system_blocks = [
        {
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    log.info(
        "AI discovery: analysing %d findings, %d existing chains, %d graph edges",
        len(findings), len(existing_chains), len(graph_edges),
    )

    try:
        result: DiscoveryResult = await client.parse(
            response_model=DiscoveryResult,
            system=system_blocks,
            user_content=prompt,
            max_tokens=16384,
            model=cfg.critical_model,
        )
    except Exception as exc:
        log.error("AI discovery request failed: %s", exc)
        return []

    # Build a lookup so we can reject hallucinated finding IDs.
    finding_by_id = {f.id: f for f in findings}

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


def _render_discovery_prompt(
    *,
    findings: list[Finding],
    existing_chains: list[AttackChain],
    graph_edges: list[tuple[str, str, str]],
) -> str:
    """Compose the user-content payload for the discovery request."""
    parts: list[str] = []

    parts.append("## FINDINGS")
    parts.append("One per line: finding_id | severity | category | title | resource")
    for f in findings:
        resource = (
            f"{f.resource_type or '-'}:{f.resource_id or '-'}"
            if (f.resource_type or f.resource_id)
            else "-"
        )
        parts.append(
            f"{f.id} | {f.severity.value} | {f.category} | "
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

    parts.append("")
    parts.append("## RESOURCE GRAPH EDGES")
    if graph_edges:
        for src, dst, rel in graph_edges:
            parts.append(f"{src} --[{rel}]--> {dst}")
    else:
        parts.append("(no edges recorded)")

    parts.append("")
    parts.append(
        "Propose novel attack chains that the rule-based correlator missed. "
        "Return an empty list if nothing meets the bar."
    )
    return "\n".join(parts)


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
