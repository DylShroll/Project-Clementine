"""Azure audit steps 4-6 — RBAC assignments + scope inheritance, federated
credentials + AKS workload identity, and Entra directory roles / PIM."""
from __future__ import annotations

import json
import logging
import uuid

from ...config import ClementineConfig
from ...db import Finding, FindingsDB, Severity
from ...graph.azure_model import AzureEdgeType, AzureNodeType
from ...mcp_client import MCPRegistry
from ...scope import RateLimiter
from ._shared import _SKIP, _mcp_call, _scope_to_level, _scope_to_node_id

log = logging.getLogger(__name__)


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
                    role_def_id, role_def_name, scope_level,
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
