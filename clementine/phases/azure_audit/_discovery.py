"""Azure audit steps 1-3 — tenancy bootstrap, identity enumeration, resource inventory."""
from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

from ...config import ClementineConfig, AzureTenantConfig
from ...db import FindingsDB
from ...graph.azure_model import AzureNodeType
from ...mcp_client import MCPRegistry
from ...scope import RateLimiter
from ._shared import _SKIP, _mcp_call

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step 1 — Tenancy bootstrap
# ---------------------------------------------------------------------------

async def _step1_tenancy(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tenant: AzureTenantConfig,
) -> list[str]:
    """Enumerate subscriptions and management group hierarchy.

    Returns the list of subscription IDs to audit (from config or discovered).
    """
    tid = tenant.tenant_id

    # Upsert Tenant node
    await db.upsert_graph_node(
        node_id=f"tenant:{tid}",
        node_type=AzureNodeType.TENANT.value,
        label=f"Tenant {tid[:8]}",
        properties={"tenant_id": tid},
        provider="azure",
        tenant_id=tid,
    )

    # Enumerate subscriptions via azure-mcp
    subscription_ids: list[str] = list(tenant.subscription_ids)
    if not subscription_ids:
        result = await _mcp_call(
            mcp, limiter, "azure_mcp", "azmcp_subscription_list",
            {"tenant_id": tid},
            step="step1_subscriptions",
        )
        if result is not _SKIP and isinstance(result, list):
            for sub in result:
                sub_id = sub.get("subscriptionId") or sub.get("id", "")
                if sub_id:
                    subscription_ids.append(sub_id)

    # Upsert Subscription nodes
    for sub_id in subscription_ids:
        await db.upsert_graph_node(
            node_id=f"subscription:{sub_id}",
            node_type=AzureNodeType.SUBSCRIPTION.value,
            label=f"Subscription {sub_id[:8]}",
            properties={"subscription_id": sub_id, "tenant_id": tid},
            provider="azure",
            tenant_id=tid,
            subscription_id=sub_id,
        )
        await db.add_graph_edge(
            source_id=f"tenant:{tid}",
            target_id=f"subscription:{sub_id}",
            edge_type="CONTAINS",
            provider="azure",
        )

    # Management group hierarchy via cloud-audit (best-effort)
    mg_result = await _mcp_call(
        mcp, limiter, "cloud_audit", "azure_management_group_tree",
        {"tenant_id": tid},
        step="step1_mg_tree",
    )
    if mg_result is not _SKIP and isinstance(mg_result, list):
        for mg in mg_result:
            mg_id = mg.get("id", "")
            if not mg_id:
                continue
            await db.upsert_graph_node(
                node_id=f"mg:{mg_id}",
                node_type=AzureNodeType.MANAGEMENT_GROUP.value,
                label=mg.get("displayName", mg_id),
                properties=mg,
                provider="azure",
                tenant_id=tid,
                management_group_id=mg_id,
            )

    # Resource groups for each subscription
    for sub_id in subscription_ids:
        rg_result = await _mcp_call(
            mcp, limiter, "azure_mcp", "azmcp_group_list",
            {"subscription_id": sub_id},
            step=f"step1_rg_{sub_id[:8]}",
        )
        if rg_result is not _SKIP and isinstance(rg_result, list):
            for rg in rg_result:
                rg_name = rg.get("name", "")
                if not rg_name:
                    continue
                rg_node_id = f"rg:{sub_id}:{rg_name}"
                await db.upsert_graph_node(
                    node_id=rg_node_id,
                    node_type=AzureNodeType.RESOURCE_GROUP.value,
                    label=rg_name,
                    properties=rg,
                    provider="azure",
                    tenant_id=tid,
                    subscription_id=sub_id,
                    resource_group=rg_name,
                )
                await db.add_graph_edge(
                    source_id=f"subscription:{sub_id}",
                    target_id=rg_node_id,
                    edge_type="CONTAINS",
                    provider="azure",
                )

    log.info("[azure] step1: %d subscription(s) for tenant %s", len(subscription_ids), tid[:8])
    return subscription_ids


# ---------------------------------------------------------------------------
# Step 2 — Identity enumeration
# ---------------------------------------------------------------------------

async def _step2_identity(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Enumerate Entra users, groups, SPs, app registrations, and managed identities."""

    identity_calls = [
        ("azure_entra_users", "azure_mcp", "azmcp_entra_user_list", AzureNodeType.ENTRA_USER),
        ("azure_entra_groups", "azure_mcp", "azmcp_group_member_list", AzureNodeType.ENTRA_GROUP),
        ("azure_service_principals", "cloud_audit", "azure_list_service_principals", AzureNodeType.SERVICE_PRINCIPAL),
        ("azure_app_registrations", "cloud_audit", "azure_list_app_registrations", AzureNodeType.APP_REGISTRATION),
    ]

    for step_name, server, tool, node_type in identity_calls:
        result = await _mcp_call(
            mcp, limiter, server, tool, {"tenant_id": tid},
            step=f"step2_{step_name}",
        )
        if result is _SKIP or not isinstance(result, list):
            await db.set_enrichment_status(
                f"azure_{step_name}", "unavailable", f"tool {tool} unavailable"
            )
            continue
        for item in result:
            item_id = item.get("id") or item.get("appId") or str(uuid.uuid4())
            await db.upsert_graph_node(
                node_id=f"{node_type.value}:{item_id}",
                node_type=node_type.value,
                label=item.get("displayName") or item.get("name") or item_id[:12],
                properties=item,
                provider="azure",
                tenant_id=tid,
            )

    # User-assigned managed identities (per subscription)
    for sub_id in subscription_ids:
        uami_result = await _mcp_call(
            mcp, limiter, "cloud_audit", "azure_list_user_assigned_identities",
            {"subscription_id": sub_id},
            step=f"step2_uami_{sub_id[:8]}",
        )
        if uami_result is _SKIP or not isinstance(uami_result, list):
            continue
        for uami in uami_result:
            uami_id = uami.get("id", str(uuid.uuid4()))
            await db.upsert_graph_node(
                node_id=f"az_user_assigned_mi:{uami_id}",
                node_type=AzureNodeType.USER_ASSIGNED_MI.value,
                label=uami.get("name", uami_id[:12]),
                properties=uami,
                provider="azure",
                tenant_id=tid,
                subscription_id=sub_id,
                resource_group=uami.get("resourceGroup"),
                azure_resource_id=uami_id,
            )

    log.info("[azure] step2: identity enumeration complete for tenant %s", tid[:8])


# ---------------------------------------------------------------------------
# Step 3 — Resource inventory via Resource Graph KQL
# ---------------------------------------------------------------------------

async def _step3_resource_inventory(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Run all KQL query files and upsert results as graph nodes."""
    kql_dir = Path(cfg.azure.kql_queries_dir)
    if not kql_dir.exists():
        log.warning("[azure] step3: KQL directory not found: %s", kql_dir)
        await db.set_enrichment_status("azure_resource_inventory", "unavailable", "kql_dir missing")
        return

    kql_files = sorted(kql_dir.glob("*.kql"))
    if not kql_files:
        log.warning("[azure] step3: no .kql files found in %s", kql_dir)
        return

    # Map KQL file stem to Azure node type (best-effort)
    _FILE_NODE_TYPE = {
        "vms_with_mi": AzureNodeType.VIRTUAL_MACHINE,
        "internet_facing_compute": AzureNodeType.VIRTUAL_MACHINE,
        "storage_public_access": AzureNodeType.STORAGE_ACCOUNT,
        "keyvaults_access_model": AzureNodeType.KEY_VAULT,
        "aks_workload_identity": AzureNodeType.AKS_CLUSTER,
        "nsg_inbound_internet_mgmt": AzureNodeType.NSG,
        "federated_identity_credentials": AzureNodeType.FEDERATED_CREDENTIAL,
        "role_assignments_tenant": AzureNodeType.ROLE_ASSIGNMENT,
        "role_definitions_actions": AzureNodeType.ROLE_DEFINITION,
        "defender_compliance_state": AzureNodeType.DEFENDER_PLAN,
    }

    sem = asyncio.Semaphore(4)  # max 4 concurrent KQL queries

    async def _run_kql(kql_file: Path) -> None:
        async with sem:
            kql = kql_file.read_text()
            for sub_id in subscription_ids:
                result = await _mcp_call(
                    mcp, limiter, "cloud_audit", "azure_resource_graph_query",
                    {"kql": kql, "subscription_id": sub_id},
                    step=f"step3_{kql_file.stem}_{sub_id[:8]}",
                )
                if result is _SKIP or not isinstance(result, list):
                    continue
                node_type = _FILE_NODE_TYPE.get(
                    kql_file.stem, AzureNodeType.RESOURCE_GROUP
                )
                for row in result[: cfg.azure.guardrails.max_resources_per_type]:
                    resource_id = (
                        row.get("resourceId") or row.get("id") or str(uuid.uuid4())
                    )
                    await db.upsert_graph_node(
                        node_id=resource_id,
                        node_type=node_type.value,
                        label=row.get("name", resource_id[:24]),
                        properties=row,
                        is_internet_facing=bool(row.get("internet_facing")),
                        provider="azure",
                        tenant_id=tid,
                        subscription_id=sub_id,
                        resource_group=row.get("resourceGroup"),
                        azure_resource_id=resource_id,
                    )

    await asyncio.gather(*[_run_kql(f) for f in kql_files], return_exceptions=True)
    log.info("[azure] step3: resource inventory complete (%d KQL files)", len(kql_files))
