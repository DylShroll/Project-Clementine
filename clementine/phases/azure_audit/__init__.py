"""
Phase 2b — Azure Cloud Audit.

Runs after Phase 2a (AWS audit); a no-op when ``azure.enabled`` is false.
Follows the 8-step enumeration sequence (each step feeds the next):
  1-3 discovery (tenancy, identity, resources)  -> ._discovery
  4-6 access    (RBAC, federation, directory roles) -> ._access
  7-8 compliance (Prowler, Defender cross-check) -> ._compliance
Shared MCP/scope helpers live in ._shared.
"""
from __future__ import annotations

import logging

from ...config import ClementineConfig, AzureTenantConfig
from ...db import FindingsDB
from ...mcp_client import MCPRegistry
from ...scope import RateLimiter, ScopeGuard
from ._discovery import _step1_tenancy, _step2_identity, _step3_resource_inventory
from ._access import _step4_rbac, _step5_federation, _step6_directory_roles
from ._compliance import _step7_compliance, _step8_defender_crosscheck

log = logging.getLogger(__name__)

__all__ = ["run_azure_audit"]


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

async def run_azure_audit(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute the 8-step Azure audit for every configured tenant."""
    if not cfg.azure.tenants:
        log.warning("azure.enabled=true but no tenants configured — skipping Azure audit")
        await db.set_enrichment_status("azure_audit", "unavailable", "no tenants configured")
        return

    for tenant_cfg in cfg.azure.tenants:
        log.info("=== Azure audit: tenant %s ===", tenant_cfg.tenant_id)
        await _audit_tenant(cfg, db, mcp, limiter, tenant_cfg)


# ---------------------------------------------------------------------------
# Per-tenant audit
# ---------------------------------------------------------------------------

async def _audit_tenant(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tenant: AzureTenantConfig,
) -> None:
    tid = tenant.tenant_id

    # Step 1 — Tenancy bootstrap
    subscription_ids = await _step1_tenancy(cfg, db, mcp, limiter, tenant)
    if not subscription_ids:
        log.warning("[azure] No subscriptions discovered for tenant %s", tid)

    # Step 2 — Identity enumeration
    await _step2_identity(cfg, db, mcp, limiter, tid, subscription_ids)

    # Step 3 — Resource inventory via KQL
    await _step3_resource_inventory(cfg, db, mcp, limiter, tid, subscription_ids)

    # Step 4 — RBAC role assignments
    await _step4_rbac(cfg, db, mcp, limiter, tid, subscription_ids)

    # Step 5 — Federated identity credentials + AKS workload identity binding
    await _step5_federation(cfg, db, mcp, limiter, tid)

    # Step 6 — Entra directory roles + PIM
    await _step6_directory_roles(cfg, db, mcp, limiter, tid)

    # Step 7 — Prowler compliance scan
    await _step7_compliance(cfg, db, mcp, limiter, tid, subscription_ids)

    # Step 8 — Defender for Cloud cross-check
    await _step8_defender_crosscheck(cfg, db, mcp, limiter, tid, subscription_ids)

    await db.set_enrichment_status(
        f"azure_audit_{tid[:8]}", "ok", f"tenant {tid} audit complete"
    )
