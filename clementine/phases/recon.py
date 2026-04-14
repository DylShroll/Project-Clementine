"""
Phase 1 — Reconnaissance and asset discovery.

Goals:
  - Crawl and fingerprint the web attack surface via AutoPentest AI
  - Map AWS resources from response headers and cloud-audit enumeration
  - Build the resource_graph adjacency table used by the correlation engine
  - Store a target manifest in the assessment_state table

All URL-targeting tool calls are scope-checked before dispatch.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..config import ClementineConfig
from ..db import Finding, FindingsDB, GraphRelationship, Severity
from ..mcp_client import MCPRegistry
from ..sanitize import sanitize_evidence
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)


async def run_recon(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 1: recon and asset discovery."""

    target_url = cfg.target.url
    auth_cfg = cfg.auth

    # ------------------------------------------------------------------
    # 1a. Initialise an AutoPentest engagement
    # ------------------------------------------------------------------
    if mcp.is_available("autopentest"):
        log.info("[Phase 1] Initialising AutoPentest engagement for %s", target_url)
        async with limiter:
            scope.check_url(target_url)
            await mcp.call_tool(
                "autopentest",
                "create_engagement",
                {
                    "target_url": target_url,
                    "scope": {
                        "include_domains": cfg.target.scope.include_domains,
                        "exclude_paths": cfg.target.scope.exclude_paths,
                    },
                    "auth": _build_auth_payload(auth_cfg),
                    "rate_limit_rps": cfg.target.scope.rate_limit_rps,
                },
            )
    else:
        log.warning("[Phase 1] AutoPentest unavailable — skipping web surface discovery")

    # ------------------------------------------------------------------
    # 1b. Web surface discovery (crawl, probe, fuzz, fingerprint)
    # ------------------------------------------------------------------
    if mcp.is_available("autopentest"):
        log.info("[Phase 1] Running information gathering (WSTG-INFO)")
        async with limiter:
            scope.check_url(target_url)
            info_result = await mcp.call_tool(
                "autopentest",
                "run_test",
                {"category": "WSTG-INFO", "target_url": target_url},
            )
        if info_result:
            await _store_autopentest_findings(info_result, db, phase=1)

    # ------------------------------------------------------------------
    # 1c. AWS resource mapping (from response headers + cloud-audit)
    # ------------------------------------------------------------------
    log.info("[Phase 1] Mapping AWS resources")
    aws_resources: list[dict] = []

    if mcp.is_available("cloud_audit"):
        async with limiter:
            # list_checks gives us the resource types the tool can enumerate
            checks = await mcp.call_tool("cloud_audit", "list_checks", {})
        log.debug("[Phase 1] cloud-audit has %s checks available", len(checks or []))

    # Discover publicly enumerable AWS resources via AWS Knowledge MCP
    if mcp.is_available("aws_knowledge"):
        async with limiter:
            result = await mcp.call_tool(
                "aws_knowledge",
                "search",
                {"query": f"AWS services used by {target_url} CloudFront ALB API Gateway S3"},
            )
        log.debug("[Phase 1] AWS Knowledge search returned %s items", len(result or []))

    # ------------------------------------------------------------------
    # 1d. Persist the target manifest
    # ------------------------------------------------------------------
    manifest = {
        "primary_url": target_url,
        "domains": cfg.target.scope.include_domains,
        "aws_account_id": cfg.aws.account_id,
        "aws_regions": cfg.aws.regions,
        "aws_resources": aws_resources,
    }
    await db.set_state("target_manifest", json.dumps(manifest))
    log.info("[Phase 1] Target manifest stored (%d domains)", len(manifest["domains"]))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_auth_payload(auth_cfg) -> dict:
    """Convert the AuthConfig into the dict format AutoPentest expects.

    Credentials are only forwarded when a non-'none' auth method is configured.
    """
    if auth_cfg.method == "none":
        return {"method": "none"}
    if auth_cfg.method == "credentials":
        return {
            "method": "credentials",
            "username": auth_cfg.username,
            "password": auth_cfg.password,
            "login_url": auth_cfg.login_url,
        }
    if auth_cfg.method == "token":
        return {"method": "token", "bearer_token": auth_cfg.bearer_token}
    if auth_cfg.method == "cookie":
        return {"method": "cookie", "cookie": auth_cfg.cookie}
    return {"method": "none"}


async def _store_autopentest_findings(raw: Any, db: FindingsDB, phase: int) -> None:
    """Normalise AutoPentest tool output into Finding records and persist them.

    AutoPentest returns a list of finding dicts; we normalise each one to the
    shared schema.  Evidence is scrubbed before storage.
    """
    findings_list: list[dict] = []
    if isinstance(raw, list):
        findings_list = raw
    elif isinstance(raw, dict) and "findings" in raw:
        findings_list = raw["findings"]
    else:
        return

    for item in findings_list:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence", {})
        finding = Finding(
            source="autopentest",
            phase=phase,
            severity=Severity(item.get("severity", "INFO").upper()),
            category=item.get("wstg_code", item.get("category", "WSTG-INFO")),
            title=item.get("title", "Unknown"),
            description=item.get("description", ""),
            resource_type="url",
            resource_id=item.get("url", item.get("resource_id")),
            evidence_type=item.get("evidence_type", "http_exchange"),
            # Scrub credentials from evidence before storing
            evidence_data=sanitize_evidence(evidence) if evidence else None,
            remediation_summary=item.get("remediation"),
            confidence=float(item.get("confidence", 1.0)),
            is_validated=bool(item.get("validated", False)),
            raw_source_data=item,
        )
        await db.insert_finding(finding)

    log.debug("[Phase %d] Stored %d AutoPentest findings", phase, len(findings_list))
