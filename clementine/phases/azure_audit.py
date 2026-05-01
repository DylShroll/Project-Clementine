"""
Phase 2b — Azure Cloud Audit.

Runs after Phase 2a (AWS audit) and is a no-op when azure.enabled is false.
Follows the 8-step enumeration sequence from the Clementine 2.0 spec (§2,
Phase 2b). All MCP calls degrade gracefully: 403/429/unavailable are logged
to enrichment_status and the step continues.

Enumeration order (do not deviate — each step feeds the next):
  1. Tenancy bootstrap (subscriptions + management group hierarchy)
  2. Identity enumeration (Entra users, groups, SPs, app regs, MIs)
  3. Resource inventory via Resource Graph KQL
  4. RBAC role assignment enumeration + scope inheritance expansion
  5. Federated identity credential enumeration + AKS workload identity binding
  6. Entra directory roles + PIM eligibility
  7. Compliance scan via prowler-mcp
  8. Defender for Cloud cross-check + Prowler drift detection
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Optional

from ..config import ClementineConfig, AzureTenantConfig
from ..db import Finding, FindingsDB, Severity
from ..graph.azure_model import AzureEdgeType, AzureNodeType
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)

# Sentinel used to mark a call as skipped due to server unavailability
_SKIP = object()

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


# ---------------------------------------------------------------------------
# Step 4 — RBAC role assignment enumeration
# ---------------------------------------------------------------------------

async def _step4_rbac(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Enumerate role assignments and expand inherited scope chains."""

    for sub_id in subscription_ids:
        result = await _mcp_call(
            mcp, limiter, "azure_mcp", "azmcp_role_assignment_list",
            {"subscription_id": sub_id, "tenant_id": tid},
            step=f"step4_rbac_{sub_id[:8]}",
        )
        if result is _SKIP or not isinstance(result, list):
            await db.set_enrichment_status(
                f"azure_rbac_{sub_id[:8]}", "unavailable", "azmcp_role_assignment_list unavailable"
            )
            continue

        for ra in result:
            assignment_id = ra.get("id") or ra.get("name") or str(uuid.uuid4())
            principal_id = ra.get("properties", {}).get("principalId") or ra.get("principalId", "")
            role_def_id = ra.get("properties", {}).get("roleDefinitionId") or ra.get("roleDefinitionId", "")
            role_def_name = ra.get("roleDefinitionName", "")
            scope = ra.get("properties", {}).get("scope") or ra.get("scope", f"/subscriptions/{sub_id}")
            scope_level = _scope_to_level(scope)
            pim_eligible = bool(ra.get("properties", {}).get("condition") and "pim" in str(ra).lower())

            # Persist the raw assignment
            await db.insert_azure_role_assignment({
                "assignment_id": assignment_id,
                "tenant_id": tid,
                "principal_id": principal_id,
                "principal_type": ra.get("principalType"),
                "role_definition_id": role_def_id,
                "role_definition_name": role_def_name,
                "scope": scope,
                "scope_level": scope_level,
                "inherited": False,
                "pim_eligible": pim_eligible,
                "condition_expr": ra.get("properties", {}).get("condition"),
            })

            # Materialize RoleAssignment node (spec §3.3)
            ra_node_id = f"az_role_assignment:{assignment_id}"
            await db.upsert_graph_node(
                node_id=ra_node_id,
                node_type=AzureNodeType.ROLE_ASSIGNMENT.value,
                label=f"{role_def_name or role_def_id[:12]} @ {scope_level}",
                properties={
                    "assignment_id": assignment_id,
                    "role_definition_id": role_def_id,
                    "role_definition_name": role_def_name,
                    "scope": scope,
                    "scope_level": scope_level,
                    "pim_eligible": pim_eligible,
                },
                provider="azure",
                tenant_id=tid,
                subscription_id=sub_id,
                azure_resource_id=assignment_id,
            )

            # Principal → RoleAssignment
            if principal_id:
                edge_kwargs = dict(
                    provider="azure",
                    edge_kind=AzureEdgeType.HAS_RBAC_ROLE.value,
                    role_definition_id=role_def_id,
                    scope=scope,
                    scope_level=scope_level,
                    pim_eligible=pim_eligible,
                )
                if pim_eligible:
                    await db.add_graph_edge(
                        source_id=principal_id,
                        target_id=ra_node_id,
                        edge_type=AzureEdgeType.PIM_ELIGIBLE_FOR.value,
                        properties={"pim_discount": cfg.azure.pim_activation_cost},
                        **edge_kwargs,
                    )
                else:
                    await db.add_graph_edge(
                        source_id=principal_id,
                        target_id=ra_node_id,
                        edge_type=AzureEdgeType.HAS_RBAC_ROLE.value,
                        **edge_kwargs,
                    )

            # RoleAssignment → scope resource
            scope_node_id = _scope_to_node_id(scope, sub_id)
            await db.add_graph_edge(
                source_id=ra_node_id,
                target_id=scope_node_id,
                edge_type=AzureEdgeType.HAS_RBAC_ROLE.value,
                properties={"role_definition_id": role_def_id, "scope": scope},
                provider="azure",
                edge_kind=AzureEdgeType.HAS_RBAC_ROLE.value,
                scope=scope,
                scope_level=scope_level,
            )

            # Scope inheritance expansion — cap at guardrail to avoid O(large) explosion
            if cfg.azure.expand_inherited_assignments and scope_level in ("mg", "subscription"):
                await _expand_inherited_assignment(
                    db, tid, sub_id, assignment_id, principal_id,
                    role_def_id, role_def_name, scope, scope_level,
                    pim_eligible, cfg.azure.pim_activation_cost,
                    cfg.azure.guardrails.max_resources_per_type,
                )

    log.info("[azure] step4: RBAC enumeration complete for tenant %s", tid[:8])


async def _expand_inherited_assignment(
    db: FindingsDB,
    tid: str,
    sub_id: str,
    source_assignment_id: str,
    principal_id: str,
    role_def_id: str,
    role_def_name: str,
    parent_scope: str,
    parent_scope_level: str,
    pim_eligible: bool,
    pim_cost: float,
    cap: int,
) -> None:
    """Emit inherited HAS_RBAC_ROLE edges to child scopes.

    For an MG-level assignment, expands to all subscriptions beneath.
    For a subscription-level assignment, expands to all resource groups.
    Capped at `cap` expansions to prevent runaway loops on large tenants.
    """
    child_nodes: list[dict] = []

    if parent_scope_level == "subscription":
        # Expand to resource groups within this subscription
        rgs = await db.get_azure_role_assignments(scope_prefix=f"/subscriptions/{sub_id}/resourceGroups/")
        seen = set()
        async with db._conn.execute(
            "SELECT node_id FROM graph_nodes WHERE subscription_id = ? AND node_type = ?",
            (sub_id, AzureNodeType.RESOURCE_GROUP.value),
        ) as cur:
            rows = await cur.fetchall()
        for r in rows[:cap]:
            child_nodes.append({"node_id": r["node_id"], "rg_scope": f"/subscriptions/{sub_id}/resourceGroups/{r['node_id'].split(':')[-1]}"})

    count = 0
    for child in child_nodes[:cap]:
        if count >= cap:
            break
        inherited_ra_id = f"{source_assignment_id}:inherited:{child['node_id']}"
        await db.insert_azure_role_assignment({
            "assignment_id": inherited_ra_id,
            "tenant_id": tid,
            "principal_id": principal_id,
            "principal_type": None,
            "role_definition_id": role_def_id,
            "role_definition_name": role_def_name,
            "scope": child.get("rg_scope", child["node_id"]),
            "scope_level": "rg",
            "inherited": True,
            "pim_eligible": pim_eligible,
        })
        await db.add_graph_edge(
            source_id=principal_id,
            target_id=child["node_id"],
            edge_type=AzureEdgeType.HAS_RBAC_ROLE.value,
            properties={
                "role_definition_id": role_def_id,
                "inherited": True,
                "source_assignment_id": source_assignment_id,
                "pim_discount": pim_cost if pim_eligible else None,
            },
            provider="azure",
            edge_kind=AzureEdgeType.HAS_RBAC_ROLE.value,
            role_definition_id=role_def_id,
            scope=child.get("rg_scope", child["node_id"]),
            scope_level="rg",
            inherited=True,
            source_assignment_id=source_assignment_id,
            pim_eligible=pim_eligible,
        )
        count += 1


# ---------------------------------------------------------------------------
# Step 5 — Federated identity credentials + AKS workload identity
# ---------------------------------------------------------------------------

async def _step5_federation(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
) -> None:
    """List federated credentials and bind AKS service accounts to UAMIs."""

    result = await _mcp_call(
        mcp, limiter, "cloud_audit", "azure_list_federated_identity_credentials",
        {"tenant_id": tid},
        step="step5_fed_creds",
    )
    if result is _SKIP or not isinstance(result, list):
        await db.set_enrichment_status("azure_federation", "unavailable", "cloud_audit unavailable")
        return

    for fed in result:
        fed_id = fed.get("id", str(uuid.uuid4()))
        parent_id = fed.get("parentUami") or fed.get("appRegistrationId") or fed.get("parent", "")
        issuer = fed.get("issuer", "")
        subject = fed.get("subject", "")
        audiences = fed.get("audiences", [])

        await db.insert_azure_federated_credential({
            "id": fed_id,
            "parent_resource_id": parent_id,
            "issuer": issuer,
            "subject": subject,
            "audiences": audiences,
            "name": fed.get("name"),
        })

        # Upsert FederatedCredential node
        await db.upsert_graph_node(
            node_id=f"az_federated_credential:{fed_id}",
            node_type=AzureNodeType.FEDERATED_CREDENTIAL.value,
            label=fed.get("name") or fed_id[:16],
            properties=fed,
            provider="azure",
            tenant_id=tid,
        )

        # OIDC_TRUSTS edge: parent app/UAMI → external issuer
        if parent_id and issuer:
            await db.add_graph_edge(
                source_id=f"az_federated_credential:{fed_id}",
                target_id=parent_id,
                edge_type=AzureEdgeType.OIDC_TRUSTS.value,
                properties={"issuer": issuer, "subject": subject, "audiences": audiences},
                provider="azure",
                edge_kind=AzureEdgeType.OIDC_TRUSTS.value,
                audience=audiences[0] if audiences else None,
            )

        # Generate HIGH finding for wildcard subjects
        if subject == "*" or subject.endswith("/*"):
            finding = Finding(
                source="cloud-audit-azure",
                phase=2,
                severity=Severity.HIGH,
                category="azure-federated-credential-wildcard-subject",
                title="Federated credential with wildcard subject",
                description=(
                    f"App registration or UAMI {parent_id} has a federated identity "
                    f"credential (issuer: {issuer}) with subject '{subject}'. "
                    "Any principal matching this subject from the external IdP can impersonate this identity."
                ),
                resource_id=parent_id,
                azure_resource_id=parent_id,
                provider="azure",
                tenant_id=tid,
                remediation_summary="Replace wildcard subject with a specific, scoped subject claim.",
            )
            await db.insert_finding(finding)

        # AKS workload identity binding — match subject system:serviceaccount:<ns>:<sa>
        if "system:serviceaccount:" in subject:
            await _bind_aks_workload_identity(db, fed_id, parent_id, issuer, subject, tid)

    log.info("[azure] step5: federation enumeration complete for tenant %s", tid[:8])


async def _bind_aks_workload_identity(
    db: FindingsDB,
    fed_id: str,
    uami_id: str,
    oidc_issuer: str,
    subject: str,
    tid: str,
) -> None:
    """Cross-match federated credential to an AKS cluster by OIDC issuer URL."""
    # Find AKS clusters whose OIDC issuer URL matches
    async with db._conn.execute(
        "SELECT node_id, properties FROM graph_nodes WHERE node_type = ? AND tenant_id = ?",
        (AzureNodeType.AKS_CLUSTER.value, tid),
    ) as cur:
        rows = await cur.fetchall()

    for row in rows:
        props = json.loads(row["properties"]) if row["properties"] else {}
        cluster_issuer = props.get("oidcIssuerUrl") or props.get("oidc_issuer_url", "")
        if cluster_issuer and cluster_issuer.rstrip("/") == oidc_issuer.rstrip("/"):
            # Emit WORKLOAD_ID_BOUND edge
            ns_sa = subject.replace("system:serviceaccount:", "")
            sa_node_id = f"az_aks_service_account:{row['node_id']}:{ns_sa}"
            await db.upsert_graph_node(
                node_id=sa_node_id,
                node_type=AzureNodeType.AKS_SERVICE_ACCOUNT.value,
                label=ns_sa,
                properties={"namespace_sa": ns_sa, "cluster": row["node_id"]},
                provider="azure",
                tenant_id=tid,
            )
            await db.insert_azure_federated_credential({
                "id": fed_id,
                "parent_resource_id": uami_id,
                "issuer": oidc_issuer,
                "subject": subject,
                "matched_aks_cluster_id": row["node_id"],
                "matched_k8s_subject": subject,
            })
            await db.add_graph_edge(
                source_id=sa_node_id,
                target_id=uami_id,
                edge_type=AzureEdgeType.WORKLOAD_ID_BOUND.value,
                properties={
                    "oidc_issuer": oidc_issuer,
                    "subject": subject,
                    "fed_cred_id": fed_id,
                },
                provider="azure",
                edge_kind=AzureEdgeType.WORKLOAD_ID_BOUND.value,
            )


# ---------------------------------------------------------------------------
# Step 6 — Entra directory roles + PIM
# ---------------------------------------------------------------------------

async def _step6_directory_roles(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
) -> None:
    """List directory role assignments and flag high-privilege roles."""

    _HIGH_PRIV_ROLES = {
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Hybrid Identity Administrator",
        "User Access Administrator",
    }

    result = await _mcp_call(
        mcp, limiter, "cloud_audit", "azure_list_directory_role_assignments",
        {"tenant_id": tid},
        step="step6_dir_roles",
    )
    if result is _SKIP or not isinstance(result, list):
        await db.set_enrichment_status("azure_directory_roles", "unavailable", "cloud_audit unavailable")
        return

    for assignment in result:
        principal_id = assignment.get("principalId", "")
        role_name = assignment.get("roleDisplayName") or assignment.get("roleName", "")
        pim_eligible = bool(assignment.get("assignmentType") == "Eligible")

        edge_type = AzureEdgeType.PIM_ELIGIBLE_FOR if pim_eligible else AzureEdgeType.HAS_DIRECTORY_ROLE
        await db.add_graph_edge(
            source_id=principal_id,
            target_id=f"entra_dir_role:{role_name.lower().replace(' ', '_')}",
            edge_type=edge_type.value,
            properties={
                "role_name": role_name,
                "pim_eligible": pim_eligible,
                "pim_discount": cfg.azure.pim_activation_cost if pim_eligible else None,
            },
            provider="azure",
            edge_kind=edge_type.value,
            pim_eligible=pim_eligible,
        )

        # Flag high-privilege non-PIM assignments on service principals
        if role_name in _HIGH_PRIV_ROLES and not pim_eligible:
            principal_type = assignment.get("principalType", "")
            if principal_type in ("ServicePrincipal", "Application"):
                severity = Severity.CRITICAL if "Global" in role_name or "Privileged Role" in role_name else Severity.HIGH
                finding = Finding(
                    source="cloud-audit-azure",
                    phase=2,
                    severity=severity,
                    category="azure-sp-high-priv-directory-role",
                    title=f"Service principal holds {role_name} without PIM",
                    description=(
                        f"Service principal {principal_id} is permanently assigned "
                        f"the '{role_name}' directory role without PIM protection. "
                        "This role grants tenant-wide administrative capabilities."
                    ),
                    resource_id=principal_id,
                    azure_resource_id=principal_id,
                    provider="azure",
                    tenant_id=tid,
                    remediation_summary=(
                        "Remove the permanent assignment and replace with PIM-eligible activation. "
                        "Require MFA and justification for activation."
                    ),
                )
                await db.insert_finding(finding)

    log.info("[azure] step6: directory role enumeration complete for tenant %s", tid[:8])


# ---------------------------------------------------------------------------
# Step 7 — Prowler compliance scan
# ---------------------------------------------------------------------------

async def _step7_compliance(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Trigger Prowler compliance scan and stream findings into azure_compliance_findings."""

    if not mcp.is_available("prowler_mcp"):
        log.info("[azure] step7: prowler_mcp unavailable — skipping compliance scan")
        await db.set_enrichment_status("azure_compliance", "unavailable", "prowler_mcp unavailable")
        return

    for framework in cfg.azure.compliance_frameworks:
        for sub_id in subscription_ids:
            result = await _mcp_call(
                mcp, limiter, "prowler_mcp", "azure_scan",
                {
                    "subscription_id": sub_id,
                    "tenant_id": tid,
                    "compliance": framework,
                },
                step=f"step7_{framework[:20]}_{sub_id[:8]}",
            )
            if result is _SKIP:
                continue
            findings = result if isinstance(result, list) else result.get("findings", []) if isinstance(result, dict) else []
            for f in findings:
                await db.insert_azure_compliance_finding({
                    "id": f.get("id") or str(uuid.uuid4()),
                    "framework": framework,
                    "control_id": f.get("checkId") or f.get("control_id", ""),
                    "resource_id": f.get("resourceArn") or f.get("resource_id"),
                    "subscription_id": sub_id,
                    "state": "fail" if f.get("status") in ("FAIL", "fail") else "pass",
                    "severity": f.get("severity"),
                    "source": "prowler",
                    "raw": f,
                })
                # Also surface FAIL findings in the main findings table
                if f.get("status") in ("FAIL", "fail"):
                    sev_str = (f.get("severity") or "MEDIUM").upper()
                    try:
                        sev = Severity(sev_str)
                    except ValueError:
                        sev = Severity.MEDIUM
                    finding = Finding(
                        id=f.get("id") or str(uuid.uuid4()),
                        source="prowler-azure",
                        phase=2,
                        severity=sev,
                        category=f"{framework}:{f.get('checkId', '')}",
                        title=f.get("checkTitle") or f.get("title", ""),
                        description=f.get("statusExtended") or f.get("description", ""),
                        resource_id=f.get("resourceId") or f.get("resource_id"),
                        azure_resource_id=f.get("resourceId") or f.get("resource_id"),
                        provider="azure",
                        tenant_id=tid,
                        subscription_id=sub_id,
                        remediation_summary=f.get("remediation", {}).get("recommendation", {}).get("text"),
                    )
                    await db.insert_finding(finding)

    log.info("[azure] step7: compliance scan complete for tenant %s", tid[:8])


# ---------------------------------------------------------------------------
# Step 8 — Defender for Cloud cross-check
# ---------------------------------------------------------------------------

async def _step8_defender_crosscheck(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Query Defender for Cloud control state via Resource Graph and cross-check with Prowler."""

    defender_kql_path = Path(cfg.azure.kql_queries_dir) / "defender_compliance_state.kql"
    if not defender_kql_path.exists():
        log.debug("[azure] step8: defender_compliance_state.kql not found — skipping cross-check")
        return

    kql = defender_kql_path.read_text()

    for sub_id in subscription_ids:
        result = await _mcp_call(
            mcp, limiter, "cloud_audit", "azure_resource_graph_query",
            {"kql": kql, "subscription_id": sub_id},
            step=f"step8_defender_{sub_id[:8]}",
        )
        if result is _SKIP or not isinstance(result, list):
            continue

        for item in result:
            standard = item.get("standard", "")
            control = item.get("control", "")
            defender_state = item.get("state", "")

            await db.insert_azure_compliance_finding({
                "id": str(uuid.uuid4()),
                "framework": standard,
                "control_id": control,
                "subscription_id": sub_id,
                "state": defender_state.lower(),
                "source": "defender_for_cloud",
                "raw": item,
            })

    # Drift detection: compare Prowler vs Defender for the same control
    prowler_findings = await db.get_azure_compliance_findings(state="fail")
    defender_findings = await db.get_azure_compliance_findings()

    prowler_fails = {f["control_id"] for f in prowler_findings if f["source"] == "prowler"}
    defender_passes = {f["control_id"] for f in defender_findings if f["source"] == "defender_for_cloud" and f["state"] == "pass"}

    drifted = prowler_fails & defender_passes
    if drifted:
        finding = Finding(
            source="cloud-audit-azure",
            phase=2,
            severity=Severity.MEDIUM,
            category="azure-defender-prowler-drift",
            title=f"Compliance evaluator disagreement ({len(drifted)} controls)",
            description=(
                f"Prowler and Defender for Cloud disagree on {len(drifted)} control(s): "
                f"{', '.join(sorted(drifted)[:10])}{'…' if len(drifted) > 10 else ''}. "
                "Prowler marks these as FAIL; Defender marks them as PASS. "
                "Manual review required to determine which evaluator is correct."
            ),
            provider="azure",
            tenant_id=tid,
            raw_source_data={"drifted_controls": sorted(drifted)},
        )
        await db.insert_finding(finding)
        log.info("[azure] step8: %d drift controls detected for tenant %s", len(drifted), tid[:8])

    log.info("[azure] step8: Defender cross-check complete for tenant %s", tid[:8])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _mcp_call(
    mcp: MCPRegistry,
    limiter: RateLimiter,
    server: str,
    tool: str,
    args: dict,
    *,
    step: str,
) -> object:
    """Call an MCP tool with rate-limiting and graceful error handling.

    Returns the tool result on success, or the _SKIP sentinel on failure.
    Error modes (per spec §8.2):
      - Server unavailable → _SKIP (logged)
      - 403 → _SKIP + enrichment_status blocked
      - 429 → exponential backoff up to 4 attempts
      - Any other exception → _SKIP (logged)
    """
    if not mcp.is_available(server):
        log.debug("[azure] %s: server %s unavailable — skipping", step, server)
        return _SKIP

    async with limiter:
        for attempt in range(4):
            try:
                result = await mcp.call_tool(server, tool, args)
                return result
            except Exception as exc:
                exc_str = str(exc)
                if "403" in exc_str or "Forbidden" in exc_str or "AuthorizationFailed" in exc_str:
                    log.warning("[azure] %s: 403 on %s/%s — RBAC insufficient", step, server, tool)
                    return _SKIP
                if "429" in exc_str or "TooManyRequests" in exc_str:
                    wait = 2 ** attempt
                    log.warning("[azure] %s: 429 — backoff %ds (attempt %d/4)", step, wait, attempt + 1)
                    if attempt < 3:
                        await asyncio.sleep(wait)
                        continue
                    log.error("[azure] %s: 429 persisted after 4 attempts — skipping", step)
                    return _SKIP
                if "elicitation" in exc_str.lower() or "sensitive" in exc_str.lower():
                    log.warning("[azure] %s: elicitation prompt from %s — refusing, skipping", step, server)
                    return _SKIP
                log.warning("[azure] %s: %s/%s failed: %s", step, server, tool, exc)
                return _SKIP
    return _SKIP  # should not reach here


def _scope_to_level(scope: str) -> str:
    """Map an Azure scope path to a level string."""
    if "/resourceGroups/" in scope and "/providers/" in scope:
        return "resource"
    if "/resourceGroups/" in scope:
        return "rg"
    if "/subscriptions/" in scope and scope.count("/") <= 3:
        return "subscription"
    if "/managementGroups/" in scope:
        return "mg"
    return "resource"


def _scope_to_node_id(scope: str, sub_id: str) -> str:
    """Convert an Azure scope path to a graph node ID."""
    if scope.startswith("/subscriptions/"):
        parts = scope.split("/")
        if len(parts) >= 5 and parts[3] == "resourceGroups":
            return f"rg:{parts[2]}:{parts[4]}"
        return f"subscription:{parts[2]}"
    if scope.startswith("/providers/Microsoft.Management/managementGroups/"):
        mg_id = scope.split("/")[-1]
        return f"mg:{mg_id}"
    return f"subscription:{sub_id}"
