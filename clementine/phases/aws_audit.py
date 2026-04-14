"""
Phase 2 — AWS configuration and compliance audit.

cloud-audit and Prowler run in parallel (asyncio.gather).  Findings from
both tools are normalised to the shared schema and deduplicated before
storage.  Deduplication key: (aws_resource_arn, category).

The resource_graph adjacency table is populated here as cloud-audit maps
relationships between EC2 instances, IAM roles, security groups, etc.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..config import ClementineConfig
from ..db import (
    Finding, FindingsDB, GraphRelationship, Severity
)
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)


async def run_aws_audit(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 2: parallel cloud-audit + Prowler scan."""
    log.info("[Phase 2] Starting parallel AWS audit (cloud-audit + Prowler)")

    # Run both scanners concurrently; each returns a list of raw finding dicts
    cloud_findings, prowler_findings = await asyncio.gather(
        _run_cloud_audit(cfg, mcp, limiter),
        _run_prowler(cfg, limiter),
    )

    # Deduplicate and store
    all_findings = _deduplicate(cloud_findings + prowler_findings)
    for f in all_findings:
        await db.insert_finding(f)

    # Retrieve and store the health score as assessment state
    if mcp.is_available("cloud_audit"):
        async with limiter:
            health = await mcp.call_tool("cloud_audit", "get_health_score", {})
        if health:
            score = health if isinstance(health, (int, float)) else health.get("score", 0)
            await db.set_state("cloud_audit_health_score", str(score))
            log.info("[Phase 2] cloud-audit health score: %s/100", score)

    # Populate the resource graph from cloud-audit attack chains
    if mcp.is_available("cloud_audit"):
        await _build_resource_graph(db, mcp, limiter)

    log.info(
        "[Phase 2] AWS audit complete — %d findings stored (after dedup)",
        len(all_findings),
    )


# ---------------------------------------------------------------------------
# cloud-audit lane
# ---------------------------------------------------------------------------

async def _run_cloud_audit(
    cfg: ClementineConfig,
    mcp: MCPRegistry,
    limiter: RateLimiter,
) -> list[Finding]:
    """Run cloud-audit and return normalised findings."""
    if not mcp.is_available("cloud_audit"):
        log.warning("[Phase 2] cloud-audit unavailable — skipping")
        return []

    # Initiate scan
    async with limiter:
        scan_result = await mcp.call_tool(
            "cloud_audit",
            "scan_aws",
            {
                "profile": cfg.aws.profile,
                "regions": cfg.aws.regions,
                "account_id": cfg.aws.account_id,
            },
        )
    log.info("[Phase 2] cloud-audit scan initiated: %s", scan_result)

    # Retrieve all findings
    async with limiter:
        raw_findings = await mcp.call_tool("cloud_audit", "get_findings", {})

    return _normalize_cloud_audit(raw_findings or [])


def _normalize_cloud_audit(raw: list[dict]) -> list[Finding]:
    """Map cloud-audit finding dicts to the shared Finding schema."""
    results: list[Finding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        results.append(Finding(
            source="cloud-audit",
            phase=2,
            severity=Severity(item.get("severity", "INFO").upper()),
            category=item.get("check_id", item.get("category", "AWS")),
            title=item.get("title", item.get("check_id", "Unknown")),
            description=item.get("description", ""),
            resource_type=_infer_resource_type(item.get("resource_type", "")),
            resource_id=item.get("resource_arn", item.get("resource_id")),
            aws_account_id=item.get("account_id"),
            aws_region=item.get("region"),
            remediation_summary=item.get("remediation", {}).get("summary"),
            remediation_cli=item.get("remediation", {}).get("cli"),
            remediation_iac=item.get("remediation", {}).get("terraform"),
            compliance_mappings=item.get("compliance_mappings"),
            confidence=1.0,
            is_validated=True,   # cloud-audit findings are confirmed misconfigs
            raw_source_data=item,
        ))
    return results


# ---------------------------------------------------------------------------
# Prowler lane — CLI subprocess
# ---------------------------------------------------------------------------

async def _run_prowler(
    cfg: ClementineConfig,
    limiter: RateLimiter,
) -> list[Finding]:
    """Run the Prowler CLI in a subprocess and parse its JSON output.

    The MCP server is used for knowledge enrichment only; for scan execution
    we call the Prowler CLI directly (per design spec §3.3).
    """
    frameworks = cfg.compliance.frameworks or ["cis_2.0_aws"]
    with tempfile.TemporaryDirectory() as tmp:
        output_file = Path(tmp) / "prowler_output.json"

        cmd = [
            "prowler", "aws",
            "--profile", cfg.aws.profile,
            "--output-formats", "json",
            "--output-directory", tmp,
            "--output-filename", "prowler_output",
        ]
        # Append compliance framework flags
        for framework in frameworks:
            cmd += ["--compliance", framework]

        log.info("[Phase 2] Running Prowler: %s", " ".join(cmd))
        try:
            loop = asyncio.get_event_loop()
            proc_result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,  # Prowler can take up to an hour on large accounts
                ),
            )
            if proc_result.returncode not in (0, 3):
                # Prowler exits 3 when findings are present (non-zero = findings)
                log.warning(
                    "[Phase 2] Prowler exited with code %d: %s",
                    proc_result.returncode, proc_result.stderr[:500],
                )

            if output_file.exists():
                with output_file.open() as fh:
                    raw = json.load(fh)
                return _normalize_prowler(raw)

        except FileNotFoundError:
            log.warning(
                "[Phase 2] Prowler CLI not found — skipping compliance scan. "
                "Install with: pip install prowler"
            )
        except subprocess.TimeoutExpired:
            log.error("[Phase 2] Prowler timed out after 3600s")

    return []


def _normalize_prowler(raw: list[dict] | dict) -> list[Finding]:
    """Map Prowler JSON output to the shared Finding schema."""
    if isinstance(raw, dict):
        raw = raw.get("findings", [])
    results: list[Finding] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        status = item.get("status", "").upper()
        # Only store failed checks (FAIL status in Prowler)
        if status not in ("FAIL", "FAILED"):
            continue
        compliance = {}
        for mapping in item.get("compliance", []):
            framework = mapping.get("Framework", "")
            req = mapping.get("Requirement_Id", "")
            if framework:
                compliance[framework] = req

        results.append(Finding(
            source="prowler",
            phase=2,
            severity=Severity(_prowler_severity(item.get("severity", "LOW"))),
            category=item.get("check_id", "AWS"),
            title=item.get("check_title", item.get("check_id", "Unknown")),
            description=item.get("description", item.get("status_extended", "")),
            resource_type=_infer_resource_type(item.get("service_name", "")),
            resource_id=item.get("resource_arn", item.get("resource_id")),
            aws_account_id=item.get("account_id"),
            aws_region=item.get("region"),
            remediation_summary=item.get("remediation", {}).get("recommendation", {}).get("text"),
            remediation_doc_url=item.get("remediation", {}).get("recommendation", {}).get("url"),
            compliance_mappings=compliance or None,
            confidence=1.0,
            is_validated=True,
            raw_source_data=item,
        ))
    return results


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by (resource_id, category).

    When both cloud-audit and Prowler report the same issue, the richer
    finding is kept: cloud-audit wins for remediation commands; Prowler wins
    for compliance mappings.  Metadata is merged.
    """
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.resource_id or "", f.category)
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        else:
            # Merge: cloud-audit is authoritative for CLI/IaC remediation
            if f.source == "cloud-audit":
                existing.remediation_cli = existing.remediation_cli or f.remediation_cli
                existing.remediation_iac = existing.remediation_iac or f.remediation_iac
            # Prowler is authoritative for compliance mappings
            if f.source == "prowler" and f.compliance_mappings:
                if existing.compliance_mappings:
                    existing.compliance_mappings.update(f.compliance_mappings)
                else:
                    existing.compliance_mappings = f.compliance_mappings
    return list(seen.values())


# ---------------------------------------------------------------------------
# Resource graph population
# ---------------------------------------------------------------------------

async def _build_resource_graph(
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
) -> None:
    """Retrieve cloud-audit attack chains and populate the resource_graph table.

    Attack chains from cloud-audit describe relationships between resources
    (e.g., EC2 instance → IAM role), which the correlation engine uses later.
    """
    async with limiter:
        chains = await mcp.call_tool("cloud_audit", "get_attack_chains", {})

    if not chains:
        return

    for chain in chains:
        if not isinstance(chain, dict):
            continue
        resources = chain.get("resources", [])
        # Treat the chain as a linear sequence: each resource leads_to the next
        for i in range(len(resources) - 1):
            src = resources[i].get("arn", "")
            dst = resources[i + 1].get("arn", "")
            if src and dst:
                await db.add_resource_edge(
                    src, dst, GraphRelationship.ROUTES_TO
                )

    log.debug("[Phase 2] Resource graph populated from cloud-audit chains")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _infer_resource_type(raw: str) -> str:
    """Guess the resource type string from a raw service/resource name."""
    mapping = {
        "ec2": "ec2", "instance": "ec2",
        "s3": "s3", "bucket": "s3",
        "iam": "iam", "role": "iam", "user": "iam", "policy": "iam",
        "rds": "rds", "database": "rds",
        "lambda": "lambda",
        "vpc": "vpc",
        "sg": "sg", "security": "sg",
    }
    raw_lower = raw.lower()
    for keyword, rtype in mapping.items():
        if keyword in raw_lower:
            return rtype
    return "other"


def _prowler_severity(raw: str) -> str:
    """Normalise Prowler severity strings to the shared enum values."""
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "informational": "INFO",
        "info": "INFO",
    }
    return mapping.get(raw.lower(), "INFO")
