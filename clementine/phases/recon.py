"""
Phase 1 — Reconnaissance and asset discovery.

Goals:
  - Load the AutoPentest engagement and register scope domains
  - Drive Claude Code through WSTG Phase 0 (application discovery) and
    Phase 1 (information gathering) via a subprocess call
  - Map AWS resources from response headers and cloud-audit enumeration
  - Ingest AutoPentest findings into Clementine's database
  - Store a target manifest in the assessment_state table

All URL-targeting tool calls are scope-checked before dispatch.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..config import ClementineConfig
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard
from . import _autopentest

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

    # ------------------------------------------------------------------
    # 1a. Bootstrap the AutoPentest engagement
    # ------------------------------------------------------------------
    eid = None
    if mcp.is_available("autopentest"):
        eid = await _autopentest.get_or_create_engagement_id(cfg, db)
        log.info("[Phase 1] AutoPentest engagement: %s", eid)
        await _autopentest.bootstrap_engagement(cfg, db, mcp, eid)
    else:
        log.warning("[Phase 1] AutoPentest unavailable — skipping engagement bootstrap")

    # ------------------------------------------------------------------
    # 1b. Drive WSTG Phase 0 + Phase 1 via Claude Code subprocess
    # ------------------------------------------------------------------
    if eid:
        scope.check_url(target_url)
        prompt = _build_recon_prompt(cfg, eid)
        log.info("[Phase 1] Running AutoPentest Phase 0/1 via Claude Code")
        output = await _autopentest.run_claude_code(
            prompt,
            timeout=3600,
            model=cfg.ai.primary_model,
            api_key=cfg.ai.api_key or None,
        )
        log.debug("[Phase 1] Claude Code output (last 400 chars): …%s", output[-400:])

        inserted = await _autopentest.ingest_findings(cfg, db, eid, phase=1)
        log.info("[Phase 1] Ingested %d findings from AutoPentest", inserted)

    # ------------------------------------------------------------------
    # 1c. AWS resource mapping (from response headers + cloud-audit)
    # ------------------------------------------------------------------
    log.info("[Phase 1] Mapping AWS resources")
    aws_resources: list[dict] = []

    if mcp.is_available("cloud_audit"):
        region = cfg.aws.regions[0] if cfg.aws.regions else "us-east-1"
        tool = mcp.find_tool("cloud_audit", [
            "ListServicesInRegion",
            "list_services_in_region",
            "list_services",
        ])
        if tool:
            async with limiter:
                svc_map = await mcp.call_tool(
                    "cloud_audit",
                    tool,
                    {"region": region, "aws_profile": cfg.aws.profile},
                )
            if svc_map and isinstance(svc_map, list):
                svc_map = svc_map[0]
            services = (svc_map or {}).get("services") if isinstance(svc_map, dict) else []
            log.debug("[Phase 1] cloud-audit found %s AWS services in %s",
                      len(services or []), region)
        else:
            log.warning("[Phase 1] cloud_audit has no list-services tool — skipping")

    # Discover publicly enumerable AWS resources via AWS Knowledge MCP
    if mcp.is_available("aws_knowledge"):
        tool = mcp.find_tool("aws_knowledge", [
            "aws___search_documentation",
            "search_documentation",
        ])
        if tool:
            async with limiter:
                result = await mcp.call_tool(
                    "aws_knowledge",
                    tool,
                    {
                        "search_phrase": (
                            f"AWS services used by {target_url} "
                            "CloudFront ALB API Gateway S3"
                        ),
                        "topics": ["general"],
                    },
                )
            log.debug("[Phase 1] AWS Knowledge search returned %s items", len(result or []))
        else:
            log.warning("[Phase 1] aws_knowledge has no search tool — skipping")

    # ------------------------------------------------------------------
    # 1d. Persist the target manifest
    # ------------------------------------------------------------------
    manifest = {
        "primary_url": target_url,
        "domains": cfg.target.scope.include_domains,
        "aws_account_id": cfg.aws.account_id,
        "aws_regions": cfg.aws.regions,
        "aws_resources": aws_resources,
        "autopentest_engagement_id": eid,
    }
    await db.set_state("target_manifest", json.dumps(manifest))
    log.info("[Phase 1] Target manifest stored (%d domains)", len(manifest["domains"]))


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_recon_prompt(cfg: ClementineConfig, eid: str) -> str:
    """Prompt Claude Code to execute AutoPentest Phase 0 + Phase 1."""
    auth = cfg.auth
    rate = cfg.target.scope.rate_limit_rps
    include = ", ".join(cfg.target.scope.include_domains) or "(see engagement config)"
    exclude = ", ".join(cfg.target.scope.exclude_paths or []) or "(none)"
    creds_hint = _format_creds_hint(auth)

    return f"""You are driving an AutoPentest engagement on behalf of Project Clementine.

Engagement ID: {eid}
Target URL:    {cfg.target.url}
Scope domains: {include}
Excluded:      {exclude}
Rate limit:    {rate} req/s (respect this across all tools)
Auth:          {creds_hint}

The engagement has already been created in AutoPentest — the YAML config has
been loaded via load_engagement_config() and each in-scope domain has been
registered via register_scope(). Do NOT call those tools again.

Your task is to execute **Phase 0 (Application Discovery)** and **Phase 1
(Information Gathering)** exactly as described in CLAUDE.md:

  1. Call get_engagement_config("{eid}") to confirm scope and credentials.
  2. Execute Phase 0 Steps 0–4: pre-flight, background Tier 1 tools, crawl,
     directory discovery, tool ingestion, build the endpoint map.
  3. Call phase_gate_check("{eid}", 0) — address blockers before Phase 1.
  4. Execute Phase 1 (all MUST WSTG-INFO tests). Track every test with
     track_test() and log any findings with log_finding().
  5. Call phase_gate_check("{eid}", 1).

STOP after Phase 1 completes — Project Clementine will orchestrate the
remaining phases. Do NOT run Phase 2 or later.

Constraints:
  - Honour the rate limit; never exceed {rate} req/s across all tools.
  - Stay inside the registered scope; never touch excluded paths.
  - Use `docker exec autopentest-tools curl` for all HTTP requests.
  - Never call generate_report() — that is Clementine's responsibility.

Proceed now.
"""


def _format_creds_hint(auth: Any) -> str:
    if auth.method == "credentials":
        user = auth.username or "(username in engagement config)"
        return f"form login as {user} at {auth.login_url or '(see config)'}"
    if auth.method == "token":
        return "bearer token (retrieve via get_engagement_config)"
    if auth.method == "cookie":
        return "raw cookie header (retrieve via get_engagement_config)"
    return "none — unauthenticated testing only"
