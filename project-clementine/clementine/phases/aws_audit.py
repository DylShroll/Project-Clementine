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

    # Populate the resource graph from cloud-audit service map
    if mcp.is_available("cloud_audit"):
        await _build_resource_graph(db, mcp, limiter, cfg)

    log.info(
        "[Phase 2] AWS audit complete — %d findings stored (after dedup)",
        len(all_findings),
    )


# ---------------------------------------------------------------------------
# cloud-audit lane
# ---------------------------------------------------------------------------

_CLOUD_AUDIT_SERVICES = (
    "guardduty",
    "securityhub",
    "inspector",
    "accessanalyzer",
)


async def _run_cloud_audit(
    cfg: ClementineConfig,
    mcp: MCPRegistry,
    limiter: RateLimiter,
) -> list[Finding]:
    """Query the AWS Well-Architected Security MCP server for findings.

    Calls GetSecurityFindings once per supported security service and
    normalises each response to the shared Finding schema.
    """
    if not mcp.is_available("cloud_audit"):
        log.warning("[Phase 2] cloud-audit unavailable — skipping")
        return []

    region = cfg.aws.regions[0] if cfg.aws.regions else "us-east-1"
    all_findings: list[Finding] = []

    for service in _CLOUD_AUDIT_SERVICES:
        async with limiter:
            result = await mcp.call_tool(
                "cloud_audit",
                "GetSecurityFindings",
                {
                    "region": region,
                    "service": service,
                    "max_findings": 100,
                    "aws_profile": cfg.aws.profile,
                    "check_enabled": True,
                },
            )
        if not result:
            continue
        # result may be a list (raw content) or already a dict
        if isinstance(result, list) and result:
            result = result[0]
        if not isinstance(result, dict):
            continue
        if not result.get("enabled", True):
            log.debug("[Phase 2] cloud-audit: %s not enabled — skipping", service)
            continue
        raw = result.get("findings") or []
        parsed = _normalize_cloud_audit(raw, service)
        log.debug("[Phase 2] cloud-audit %s: %d findings", service, len(parsed))
        all_findings.extend(parsed)

    return all_findings


def _normalize_cloud_audit(raw: list[dict], service: str = "aws") -> list[Finding]:
    """Normalise AWS Well-Architected Security MCP findings to the shared schema.

    The server returns raw AWS API objects whose shape varies by service:
      GuardDuty   — Title / Description / Severity (float 1-10) / Resource.*
      Security Hub — Title / Description / Severity.Label / Resources[].Id (ASFF)
      Inspector   — title / description / severity (string) / resources[].id
      AccessAnalyzer — findingType / resource / status (ACTIVE = finding)
    We apply fallback chains to handle all four.
    """
    results: list[Finding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        # ---- severity -------------------------------------------------------
        sev_raw = (
            item.get("Severity", {}).get("Label")          # Security Hub ASFF
            or item.get("severity")                        # Inspector / Access Analyzer
            or item.get("Severity")                        # GuardDuty (may be float)
            or "INFO"
        )
        severity = _severity_from_raw(sev_raw)

        # ---- title / description --------------------------------------------
        title = (
            item.get("Title")
            or item.get("title")
            or item.get("findingType")
            or item.get("type", "Unknown")
        )
        description = (
            item.get("Description")
            or item.get("description")
            or item.get("detail", "")
        )

        # ---- resource -------------------------------------------------------
        resources = item.get("Resources") or item.get("resources") or []
        if resources:
            r = resources[0]
            resource_id = r.get("Id") or r.get("id") or r.get("arn")
            resource_type_raw = r.get("Type") or r.get("type") or service
        else:
            resource_id = item.get("resource") or item.get("Resource")
            resource_type_raw = item.get("resourceType") or service

        # ---- account / region -----------------------------------------------
        account_id = item.get("AccountId") or item.get("account")
        region = item.get("Region") or item.get("region") or ""

        # ---- category -------------------------------------------------------
        category = (
            item.get("Type")                               # GuardDuty finding type
            or item.get("id")
            or service.upper()
        )

        results.append(Finding(
            source="cloud-audit",
            phase=2,
            severity=severity,
            category=str(category)[:200],
            title=str(title)[:500],
            description=str(description),
            resource_type=_infer_resource_type(str(resource_type_raw)),
            resource_id=str(resource_id) if resource_id else None,
            aws_account_id=str(account_id) if account_id else None,
            aws_region=str(region) if region else None,
            confidence=1.0,
            is_validated=True,
            raw_source_data=item,
        ))
    return results


def _severity_from_raw(raw) -> Severity:
    """Normalise a severity value from any AWS service format."""
    if isinstance(raw, (int, float)):
        # GuardDuty uses a 1–10 float scale
        if raw >= 7:
            return Severity.HIGH
        if raw >= 4:
            return Severity.MEDIUM
        return Severity.LOW
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFORMATIONAL": Severity.INFO,
        "INFO": Severity.INFO,
        # Trusted Advisor uses ERROR/WARNING
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
    }
    return mapping.get(str(raw).upper(), Severity.INFO)


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
        # Prowler v4 dropped the old 'json' format; use OCSF JSON instead.
        # Output file: <tmp>/prowler_output.ocsf.json
        cmd = [
            "prowler", "aws",
            "--profile", cfg.aws.profile,
            "--output-formats", "json-ocsf",
            "--output-directory", tmp,
            "--output-filename", "prowler_output",
        ]
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
                    timeout=3600,
                ),
            )
            if proc_result.returncode not in (0, 3):
                # Prowler exits 3 when findings are present — any other non-zero is an error
                log.warning(
                    "[Phase 2] Prowler exited with code %d: %s",
                    proc_result.returncode, proc_result.stderr[:500],
                )

            # Glob for the output file — Prowler v4 names it prowler_output.ocsf.json
            json_files = sorted(Path(tmp).glob("prowler_output*.json"))
            if json_files:
                with json_files[0].open() as fh:
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
    """Map Prowler v4 OCSF JSON output to the shared Finding schema.

    Prowler v4 emits Open Cybersecurity Schema Framework (OCSF) records.
    Key fields:
      status_code          "FAIL" | "PASS"
      severity             "Critical" | "High" | "Medium" | "Low" | "Informational"
      finding_info.title   human-readable title
      finding_info.desc    full description
      metadata.event_code  check_id (e.g. s3_bucket_public_access_block_enabled)
      resources[0].uid     resource ARN
      resources[0].type    resource type string
      cloud.account.uid    AWS account ID
      cloud.region         AWS region
      remediation.desc     remediation guidance
      remediation.references  list of doc URLs
      unmapped.compliance  compliance mapping dict
      unmapped.service_name   AWS service name
    """
    if isinstance(raw, dict):
        raw = raw.get("findings", [])
    results: list[Finding] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue

        status_code = item.get("status_code", item.get("status", "")).upper()
        if status_code not in ("FAIL", "FAILED"):
            continue

        finding_info = item.get("finding_info") or {}
        metadata = item.get("metadata") or {}
        resources = item.get("resources") or []
        resource = resources[0] if resources else {}
        cloud = item.get("cloud") or {}
        remediation = item.get("remediation") or {}
        unmapped = item.get("unmapped") or {}

        check_id = metadata.get("event_code") or finding_info.get("uid", "AWS")
        title = finding_info.get("title") or check_id
        description = (
            finding_info.get("desc")
            or item.get("message")
            or unmapped.get("status_extended", "")
        )
        resource_id = resource.get("uid")
        resource_type_raw = (
            resource.get("type")
            or unmapped.get("service_name", "")
        )
        account_id = cloud.get("account", {}).get("uid")
        region = cloud.get("region") or resource.get("region")

        # Compliance mappings from the unmapped.compliance dict
        compliance: dict = {}
        raw_compliance = unmapped.get("compliance") or {}
        if isinstance(raw_compliance, dict):
            for framework, reqs in raw_compliance.items():
                compliance[framework] = reqs if isinstance(reqs, str) else str(reqs)

        references = remediation.get("references") or []

        results.append(Finding(
            source="prowler",
            phase=2,
            severity=Severity(_prowler_severity(item.get("severity", "LOW"))),
            category=str(check_id)[:200],
            title=str(title)[:500],
            description=str(description),
            resource_type=_infer_resource_type(str(resource_type_raw)),
            resource_id=str(resource_id) if resource_id else None,
            aws_account_id=str(account_id) if account_id else None,
            aws_region=str(region) if region else None,
            remediation_summary=remediation.get("desc"),
            remediation_doc_url=references[0] if references else None,
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
    cfg: ClementineConfig,
) -> None:
    """Use ListServicesInRegion to seed the resource graph with discovered services.

    The well-architected security server returns a service→resource-count map;
    we record each discovered service as a node adjacent to the account root so
    the correlation engine has something to work with even before active scanning.
    """
    region = cfg.aws.regions[0] if cfg.aws.regions else "us-east-1"
    async with limiter:
        result = await mcp.call_tool(
            "cloud_audit",
            "ListServicesInRegion",
            {"region": region, "aws_profile": cfg.aws.profile},
        )

    if not result:
        return
    if isinstance(result, list) and result:
        result = result[0]
    if not isinstance(result, dict):
        return

    services = result.get("services") or []
    account_root = f"arn:aws::::{cfg.aws.account_id or 'unknown'}"
    for svc in services:
        svc_node = f"arn:aws:{svc}:{region}:{cfg.aws.account_id or 'unknown'}:"
        await db.add_resource_edge(account_root, svc_node, GraphRelationship.ROUTES_TO)

    log.debug("[Phase 2] Resource graph seeded with %d services from %s", len(services), region)


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
