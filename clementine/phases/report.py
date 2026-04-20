"""
Phase 5 — Unified reporting.

Report sections are generated in parallel; final assembly and file writing
are sequential.  Each enabled format is produced by a dedicated renderer in
the clementine.reporting package.

Knowledge enrichment: before generating the remediation playbook, the AWS
Knowledge MCP server is queried for current best-practice SOPs to augment
the remediation actions stored in the database.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from ..config import ClementineConfig
from ..db import AttackChain, Finding, FindingsDB, Severity
from ..mcp_client import MCPRegistry
from ..reporting.html import HtmlReporter
from ..reporting.sarif import SarifReporter
from ..reporting.security_hub import SecurityHubReporter
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)


async def run_reporting(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 5: generate all configured report formats."""
    output_dir = cfg.reporting.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load findings and chains from the database
    findings = await db.get_findings()
    chains = await db.get_attack_chains()

    log.info(
        "[Phase 5] Generating reports: %d findings, %d attack chains",
        len(findings), len(chains),
    )

    # Enrich remediation actions with current AWS guidance
    await _enrich_remediations(db, mcp, limiter)

    # Generate report sections concurrently where possible
    tasks = []
    formats = cfg.reporting.formats

    if "html" in formats:
        tasks.append(_write_html(cfg, db, findings, chains, output_dir))
    if "json" in formats:
        tasks.append(_write_json(findings, chains, output_dir))
    if "sarif" in formats:
        tasks.append(_write_sarif(findings, output_dir))
    if "markdown" in formats:
        tasks.append(_write_markdown(findings, chains, output_dir))

    await asyncio.gather(*tasks)

    # Security Hub push is sequential (AWS API calls, not file I/O)
    if cfg.reporting.push_to_security_hub:
        await _push_security_hub(cfg, findings)

    log.info("[Phase 5] Reports written to %s", output_dir)


# ---------------------------------------------------------------------------
# Knowledge enrichment
# ---------------------------------------------------------------------------

async def _enrich_remediations(
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
) -> None:
    """Query AWS Knowledge MCP for current SOPs and attach them to chains.

    Only enriches chains that do not already have an aws_sop_ref.
    """
    if not mcp.is_available("aws_knowledge"):
        log.debug("[Phase 5] AWS Knowledge unavailable — skipping enrichment")
        return

    tool_name = mcp.find_tool("aws_knowledge", [
        "retrieve_agent_sops",
        "aws___retrieve_agent_sops",
        "aws___search_documentation",
    ])
    if not tool_name:
        log.debug("[Phase 5] AWS Knowledge has no SOP/doc tool — skipping enrichment")
        return

    chains = await db.get_attack_chains()
    for chain in chains:
        actions = await db.get_remediation_actions(chain_id=chain.id)
        for action in actions:
            if action.aws_sop_ref:
                continue  # Already enriched
            async with limiter:
                sop = await mcp.call_tool(
                    "aws_knowledge",
                    tool_name,
                    {"query": action.action_summary},
                )
            if sop:
                # sop is a list of SOP items; store a reference to the first
                ref = sop[0].get("sop_id") if isinstance(sop, list) and sop else str(sop)
                # Update the action in-place — simplest approach for SQLite
                await db._conn.execute(
                    "UPDATE remediation_actions SET aws_sop_ref = ? WHERE id = ?",
                    (ref, action.id),
                )
        await db._conn.commit()


# ---------------------------------------------------------------------------
# Format writers
# ---------------------------------------------------------------------------

async def _write_html(
    cfg: ClementineConfig,
    db: FindingsDB,
    findings: list[Finding],
    chains: list[AttackChain],
    output_dir: Path,
) -> None:
    reporter = HtmlReporter(cfg, db)
    await reporter.write(findings, chains, output_dir / "report.html")
    log.info("[Phase 5] HTML report written")


async def _write_json(
    findings: list[Finding],
    chains: list[AttackChain],
    output_dir: Path,
) -> None:
    """Write a machine-readable JSON report containing all findings and chains."""
    data = {
        "findings": [_finding_to_dict(f) for f in findings],
        "attack_chains": [_chain_to_dict(c) for c in chains],
    }
    path = output_dir / "report.json"
    path.write_text(json.dumps(data, indent=2, default=str))
    log.info("[Phase 5] JSON report written")


async def _write_sarif(findings: list[Finding], output_dir: Path) -> None:
    reporter = SarifReporter()
    sarif = reporter.build(findings)
    path = output_dir / "report.sarif"
    path.write_text(json.dumps(sarif, indent=2))
    log.info("[Phase 5] SARIF report written")


async def _write_markdown(
    findings: list[Finding],
    chains: list[AttackChain],
    output_dir: Path,
) -> None:
    """Write a Markdown report suitable for Git repository integration."""
    lines = ["# Project Clementine — Security Assessment Report\n"]

    # Summary table
    severity_counts = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity.value] += 1

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {severity_counts.get(sev, 0)} |")

    lines.append(f"\n**Attack Chains Identified:** {len(chains)}\n")

    # Attack chains first
    if chains:
        lines.append("## Attack Chains\n")
        for chain in chains:
            lines.append(f"### {chain.pattern_name} ({chain.severity.value})\n")
            lines.append(chain.narrative)
            lines.append("")

    # Individual findings
    lines.append("## Findings\n")
    for f in findings:
        lines.append(f"### [{f.severity.value}] {f.title}")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Resource:** {f.resource_id or 'N/A'}")
        lines.append(f"\n{f.description}\n")
        if f.remediation_summary:
            lines.append(f"**Remediation:** {f.remediation_summary}\n")

    path = output_dir / "report.md"
    path.write_text("\n".join(lines))
    log.info("[Phase 5] Markdown report written")


async def _push_security_hub(cfg: ClementineConfig, findings: list[Finding]) -> None:
    reporter = SecurityHubReporter(
        region=cfg.reporting.security_hub_region,
        aws_profile=cfg.aws.profile,
        account_id=cfg.aws.account_id or "",
    )
    await reporter.push(findings)
    log.info("[Phase 5] Findings pushed to AWS Security Hub")


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "source": f.source,
        "phase": f.phase,
        "severity": f.severity.value,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "resource_type": f.resource_type,
        "resource_id": f.resource_id,
        "remediation_summary": f.remediation_summary,
        "remediation_cli": f.remediation_cli,
        "compliance_mappings": f.compliance_mappings,
        "confidence": f.confidence,
        "is_validated": f.is_validated,
    }


def _chain_to_dict(c: AttackChain) -> dict:
    return {
        "id": c.id,
        "pattern_name": c.pattern_name,
        "severity": c.severity.value,
        "narrative": c.narrative,
        "breach_cost_low": c.breach_cost_low,
        "breach_cost_high": c.breach_cost_high,
    }
