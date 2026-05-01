"""Azure graph enrichment — 6 sub-passes that build Azure edges from DB data.

Each sub-pass is independently failure-tolerant: an exception in one pass is
logged and skipped, leaving the rest of the graph intact. No live MCP calls
are made here — all data was already written to the DB by Phase 2b (azure_audit).
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from .azure_model import AzureEdgeType, AzureNodeType

if TYPE_CHECKING:
    from ..db import FindingsDB
    from ..mcp_client import MCPRegistry
    from ..scope import RateLimiter
    from .builder import GraphBuilder

log = logging.getLogger(__name__)

# Azure IMDS address — used as the "IMDS" node ID for Azure VMs.
AZURE_IMDS_NODE_ID = "azure://169.254.169.254/metadata"


async def enrich_azure(
    builder: "GraphBuilder",
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
) -> None:
    """Run all 6 Azure graph enrichment sub-passes against already-populated DB data."""
    passes = [
        ("rbac_graph",          _build_rbac_graph),
        ("federation_graph",    _build_federation_graph),
        ("mi_attachment_graph", _build_mi_attachment_graph),
        ("network_topology",    _build_network_topology),
        ("imds_edges",          _derive_imds_edges),
        ("directory_role_graph", _build_directory_role_graph),
    ]
    for name, fn in passes:
        try:
            await fn(builder, db)
            log.debug("[Azure enrichment] Pass '%s' complete", name)
        except Exception as exc:
            log.warning("[Azure enrichment] Pass '%s' failed: %s", name, exc, exc_info=True)


# ---------------------------------------------------------------------------
# Sub-pass 1 — RBAC graph
# ---------------------------------------------------------------------------

async def _build_rbac_graph(builder: "GraphBuilder", db: "FindingsDB") -> None:
    """Read azure_role_assignments → emit HAS_RBAC_ROLE edges.

    Graph shape:  Principal -[HAS_RBAC_ROLE]-> RoleAssignment -[HAS_RBAC_ROLE]-> scope_node
    PIM-eligible assignments additionally get a PIM_ELIGIBLE_FOR edge with a
    0.7 score discount stamped as an edge property.
    """
    assignments = await db.get_azure_role_assignments()
    for ra in assignments:
        principal_id = ra.get("principal_id")
        ra_id = ra.get("assignment_id")
        scope = ra.get("scope", "")
        pim_eligible = bool(ra.get("pim_eligible"))
        inherited = bool(ra.get("inherited"))

        if not principal_id or not ra_id:
            continue

        # Ensure the RoleAssignment node exists
        _ensure_node(
            builder, ra_id,
            AzureNodeType.ROLE_ASSIGNMENT,
            ra.get("role_definition_name") or ra_id[:60],
            {
                "scope": scope,
                "scope_level": ra.get("scope_level"),
                "inherited": inherited,
                "pim_eligible": pim_eligible,
                "role_definition_id": ra.get("role_definition_id"),
                "provider": "azure",
            },
        )

        # Principal → RoleAssignment
        _ensure_edge(builder, principal_id, ra_id, AzureEdgeType.HAS_RBAC_ROLE)

        # RoleAssignment → scope node (subscription / resource group / resource)
        if scope:
            _ensure_node(
                builder, scope,
                _scope_node_type(ra.get("scope_level", "")),
                scope.rsplit("/", 1)[-1] or scope,
                {"provider": "azure"},
            )
            _ensure_edge(builder, ra_id, scope, AzureEdgeType.HAS_RBAC_ROLE)

        # PIM — dotted edge with discount property
        if pim_eligible:
            _ensure_edge(
                builder, principal_id, ra_id, AzureEdgeType.PIM_ELIGIBLE_FOR,
                properties={"pim_discount": 0.7},
            )


def _scope_node_type(scope_level: str) -> AzureNodeType:
    mapping = {
        "mg":           AzureNodeType.MANAGEMENT_GROUP,
        "subscription": AzureNodeType.SUBSCRIPTION,
        "rg":           AzureNodeType.RESOURCE_GROUP,
        "resource":     AzureNodeType.RESOURCE_GROUP,  # best approximation without full resource data
    }
    return mapping.get(scope_level, AzureNodeType.SUBSCRIPTION)


# ---------------------------------------------------------------------------
# Sub-pass 2 — Federation graph
# ---------------------------------------------------------------------------

async def _build_federation_graph(builder: "GraphBuilder", db: "FindingsDB") -> None:
    """Read azure_federated_credentials → emit OIDC_TRUSTS + WORKLOAD_ID_BOUND edges.

    Also cross-matches AKS cluster OIDC issuer URLs to emit WORKLOAD_ID_BOUND
    edges for any credential whose issuer matches a known AKS cluster.
    """
    creds = await db.get_azure_federated_credentials()

    # Build a lookup of AKS cluster OIDC issuer URLs → cluster node IDs so we
    # can cross-match without a second DB round-trip per credential.
    aks_issuer_map: dict[str, str] = {}
    try:
        aks_nodes = [
            (nid, data) for nid, data in builder._graph.nodes(data=True)
            if data.get("node_type") == AzureNodeType.AKS_CLUSTER.value
        ]
        for cluster_id, cluster_data in aks_nodes:
            props = cluster_data.get("properties") or {}
            issuer_url = props.get("oidcIssuerUrl") or props.get("oidc_issuer_url")
            if issuer_url:
                aks_issuer_map[issuer_url.rstrip("/")] = cluster_id
    except Exception as exc:
        log.debug("[Azure enrichment] AKS issuer map build failed: %s", exc)

    for cred in creds:
        cred_id = cred.get("id")
        parent_id = cred.get("parent_resource_id")
        issuer = (cred.get("issuer") or "").rstrip("/")
        subject = cred.get("subject") or ""

        if not cred_id or not parent_id:
            continue

        # Federated credential node
        _ensure_node(
            builder, cred_id,
            AzureNodeType.FEDERATED_CREDENTIAL,
            cred.get("name") or cred_id[:60],
            {
                "issuer": issuer,
                "subject": subject,
                "audiences": cred.get("audiences"),
                "provider": "azure",
            },
        )

        # External issuer node (opaque string node)
        if issuer:
            _ensure_node(
                builder, issuer,
                AzureNodeType.FEDERATED_CREDENTIAL,
                issuer[:80],
                {"provider": "azure", "is_external_issuer": True},
            )
            _ensure_edge(builder, issuer, parent_id, AzureEdgeType.OIDC_TRUSTS)

        # Cross-match: if the issuer is an AKS cluster's OIDC URL, emit
        # WORKLOAD_ID_BOUND edge from service account to the parent UAMI.
        matched_cluster = aks_issuer_map.get(issuer)
        if matched_cluster and subject.startswith("system:serviceaccount:"):
            parts = subject.split(":")  # system:serviceaccount:<ns>:<sa>
            ns = parts[2] if len(parts) > 2 else "unknown"
            sa_name = parts[3] if len(parts) > 3 else subject
            sa_id = f"{matched_cluster}/serviceaccount/{ns}/{sa_name}"
            _ensure_node(
                builder, sa_id,
                AzureNodeType.AKS_SERVICE_ACCOUNT,
                sa_name,
                {"namespace": ns, "cluster": matched_cluster, "provider": "azure"},
            )
            _ensure_edge(builder, sa_id, parent_id, AzureEdgeType.WORKLOAD_ID_BOUND)

        # Wildcard subject — already generates a finding in azure_audit.py,
        # but also emit an extra OIDC_TRUSTS edge from a sentinel wildcard node
        # so the correlation engine can match it.
        if subject == "*":
            wildcard_id = f"az://wildcard-subject/{cred_id}"
            _ensure_node(
                builder, wildcard_id,
                AzureNodeType.FEDERATED_CREDENTIAL,
                "Wildcard OIDC subject (*)",
                {"provider": "azure", "is_wildcard": True},
            )
            _ensure_edge(builder, wildcard_id, parent_id, AzureEdgeType.OIDC_TRUSTS)


# ---------------------------------------------------------------------------
# Sub-pass 3 — MI attachment graph
# ---------------------------------------------------------------------------

async def _build_mi_attachment_graph(
    builder: "GraphBuilder", db: "FindingsDB"
) -> None:
    """Emit MI_ATTACHED_TO (compute→MI) and CAN_ASSUME_MI (MI→its scope) edges.

    Source of truth: graph_nodes with properties.managedIdentity or
    properties.identity from the KQL vms_with_mi.kql output.
    """
    vm_types = {
        AzureNodeType.VIRTUAL_MACHINE.value,
        AzureNodeType.VMSS.value,
        AzureNodeType.APP_SERVICE.value,
        AzureNodeType.FUNCTION_APP.value,
        AzureNodeType.CONTAINER_APP.value,
        AzureNodeType.CONTAINER_INSTANCE.value,
        AzureNodeType.AKS_CLUSTER.value,
    }

    for node_id, data in list(builder._graph.nodes(data=True)):
        if data.get("node_type") not in vm_types:
            continue
        props = data.get("properties") or {}

        # System-assigned MI: the compute resource IS the MI principal.
        identity = props.get("identity") or {}
        if isinstance(identity, str):
            try:
                identity = json.loads(identity)
            except Exception:
                identity = {}

        if isinstance(identity, dict):
            if identity.get("type", "").lower() in ("systemassigned", "systemassigned, userassigned"):
                mi_id = f"{node_id}/system-assigned-identity"
                _ensure_node(
                    builder, mi_id,
                    AzureNodeType.SYSTEM_ASSIGNED_MI,
                    f"SystemMI({data.get('label', node_id[:40])})",
                    {"provider": "azure", "compute_resource": node_id},
                )
                _ensure_edge(builder, node_id, mi_id, AzureEdgeType.MI_ATTACHED_TO)
                # The compute resource can request a token for this MI
                _ensure_edge(builder, node_id, mi_id, AzureEdgeType.CAN_ASSUME_MI)

            # User-assigned MIs
            for uami_id in (identity.get("userAssignedIdentities") or {}).keys():
                _ensure_node(
                    builder, uami_id,
                    AzureNodeType.USER_ASSIGNED_MI,
                    uami_id.rsplit("/", 1)[-1],
                    {"provider": "azure"},
                )
                _ensure_edge(builder, node_id, uami_id, AzureEdgeType.MI_ATTACHED_TO)
                _ensure_edge(builder, node_id, uami_id, AzureEdgeType.CAN_ASSUME_MI)


# ---------------------------------------------------------------------------
# Sub-pass 4 — Network topology
# ---------------------------------------------------------------------------

async def _build_network_topology(
    builder: "GraphBuilder", db: "FindingsDB"
) -> None:
    """Emit PEERED_WITH, PRIVATE_LINK_TO, and INTERNET_FACING edges.

    Data comes from the KQL results already stored as graph node properties.
    """
    for node_id, data in list(builder._graph.nodes(data=True)):
        node_type = data.get("node_type", "")
        props = data.get("properties") or {}
        if isinstance(props, str):
            try:
                props = json.loads(props)
            except Exception:
                props = {}

        # VNet peerings
        if node_type == AzureNodeType.VNET.value:
            peerings = props.get("virtualNetworkPeerings") or props.get("peerings") or []
            for peer in (peerings if isinstance(peerings, list) else []):
                remote_vnet = (
                    peer.get("properties", {}).get("remoteVirtualNetwork", {}).get("id")
                    or peer.get("remoteVirtualNetworkId")
                )
                if remote_vnet:
                    _ensure_node(
                        builder, remote_vnet,
                        AzureNodeType.VNET,
                        remote_vnet.rsplit("/", 1)[-1],
                        {"provider": "azure"},
                    )
                    _ensure_edge(builder, node_id, remote_vnet, AzureEdgeType.PEERED_WITH)

        # Private endpoints — build PRIVATE_LINK_TO between PE and its service
        if node_type == AzureNodeType.PRIVATE_ENDPOINT.value:
            plsc = props.get("privateLinkServiceConnections") or []
            for conn in (plsc if isinstance(plsc, list) else []):
                service_id = (
                    conn.get("properties", {}).get("privateLinkServiceId")
                    or conn.get("privateLinkServiceId")
                )
                if service_id:
                    _ensure_edge(builder, node_id, service_id, AzureEdgeType.PRIVATE_LINK_TO)

        # Public IP → compute node: emit INTERNET_FACING
        if node_type in (
            AzureNodeType.VIRTUAL_MACHINE.value,
            AzureNodeType.APP_SERVICE.value,
            AzureNodeType.FUNCTION_APP.value,
            AzureNodeType.APP_GATEWAY.value,
            AzureNodeType.FRONT_DOOR.value,
        ):
            public_ip = props.get("publicIPAddress") or props.get("publicIp")
            if public_ip and not str(public_ip).lower() in ("none", "null", ""):
                builder._graph.nodes[node_id]["is_internet_facing"] = True
                # Self-loop INTERNET_FACING edge so correlation patterns can match it
                _ensure_edge(builder, node_id, node_id, AzureEdgeType.INTERNET_FACING)


# ---------------------------------------------------------------------------
# Sub-pass 5 — IMDS exposure edges
# ---------------------------------------------------------------------------

async def _derive_imds_edges(
    builder: "GraphBuilder", db: "FindingsDB"
) -> None:
    """Add IMDS_EXPOSED edges for VMs with system-assigned MI and no network restriction.

    A VM is considered IMDS-exposed if it has a system-assigned managed identity
    and no NSG rule blocks access to 169.254.169.254 (no such restriction check
    is performed here — we assume exposure unless properties explicitly indicate
    otherwise, matching the conservative worst-case posture).
    """
    vm_types = {
        AzureNodeType.VIRTUAL_MACHINE.value,
        AzureNodeType.VMSS.value,
    }

    # Ensure the Azure IMDS sentinel node exists
    _ensure_node(
        builder, AZURE_IMDS_NODE_ID,
        AzureNodeType.VIRTUAL_MACHINE,   # closest approximation — it's a metadata endpoint
        "Azure Instance Metadata Service (169.254.169.254)",
        {"provider": "azure", "is_imds": True},
    )

    for node_id, data in list(builder._graph.nodes(data=True)):
        if data.get("node_type") not in vm_types:
            continue
        props = data.get("properties") or {}
        identity = props.get("identity") or {}
        if isinstance(identity, str):
            try:
                identity = json.loads(identity)
            except Exception:
                identity = {}

        has_system_mi = (
            isinstance(identity, dict)
            and "systemassigned" in identity.get("type", "").lower()
        )
        if has_system_mi:
            _ensure_edge(builder, node_id, AZURE_IMDS_NODE_ID, AzureEdgeType.IMDS_EXPOSED)


# ---------------------------------------------------------------------------
# Sub-pass 6 — Directory role graph
# ---------------------------------------------------------------------------

async def _build_directory_role_graph(
    builder: "GraphBuilder", db: "FindingsDB"
) -> None:
    """Emit HAS_DIRECTORY_ROLE edges from graph_nodes that carry directory role properties.

    Phase 2b (azure_audit.py Step 6) writes directory role data as node
    properties on identity nodes. This pass reads those properties and emits
    the corresponding graph edges.
    """
    identity_types = {
        AzureNodeType.ENTRA_USER.value,
        AzureNodeType.SERVICE_PRINCIPAL.value,
        AzureNodeType.APP_REGISTRATION.value,
    }

    for node_id, data in list(builder._graph.nodes(data=True)):
        if data.get("node_type") not in identity_types:
            continue
        props = data.get("properties") or {}
        directory_roles = props.get("directory_roles") or []
        if isinstance(directory_roles, str):
            try:
                directory_roles = json.loads(directory_roles)
            except Exception:
                directory_roles = []

        for role_entry in (directory_roles if isinstance(directory_roles, list) else []):
            role_id = role_entry.get("roleDefinitionId") or role_entry.get("id")
            role_name = role_entry.get("displayName") or role_entry.get("roleDefinitionId", "")
            if not role_id:
                continue
            _ensure_node(
                builder, role_id,
                AzureNodeType.ENTRA_DIRECTORY_ROLE,
                role_name[:80],
                {"provider": "azure", "is_builtin": True},
            )
            _ensure_edge(builder, node_id, role_id, AzureEdgeType.HAS_DIRECTORY_ROLE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_node(
    builder: "GraphBuilder",
    node_id: str,
    node_type: AzureNodeType,
    label: str,
    properties: dict | None = None,
) -> None:
    """Add an Azure node to the builder's in-memory graph if it does not already exist."""
    from .model import GraphNode  # late import to avoid circular dependency

    if not builder._graph.has_node(node_id):
        node = GraphNode(
            node_id=node_id,
            node_type=node_type.value,
            label=label[:80],
            properties=properties or {},
        )
        builder._add_node(node)
    elif properties:
        # Merge extra properties into the existing node
        existing_props = builder._graph.nodes[node_id].get("properties") or {}
        if isinstance(existing_props, dict):
            existing_props.update(properties)


def _ensure_edge(
    builder: "GraphBuilder",
    src: str,
    dst: str,
    edge_type: AzureEdgeType,
    properties: dict | None = None,
) -> None:
    """Add an Azure edge with an optional properties dict stamped onto the NetworkX edge."""
    for nid in (src, dst):
        if not builder._graph.has_node(nid):
            builder._graph.add_node(
                nid, node_type="unknown", label=nid[:80],
                properties={}, is_internet_facing=False,
            )
    if not builder._graph.has_edge(src, dst):
        edge_attrs: dict = {"type": edge_type.value}
        if properties:
            edge_attrs["properties"] = properties
        builder._graph.add_edge(src, dst, **edge_attrs)
    elif properties:
        # Merge additional properties into existing edge
        existing = builder._graph.edges[src, dst].get("properties") or {}
        if isinstance(existing, dict):
            existing.update(properties)
