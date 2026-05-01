"""Attack surface analysis utilities wrapping the AWS knowledge graph."""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Iterable

import networkx as nx

from .azure_model import AZURE_IAM_TRAVERSAL_EDGES, AZURE_PRINCIPAL_NODE_TYPES, AzureEdgeType, AzureNodeType
from .model import AWSEdgeType, AWSNodeType, IAM_TRAVERSAL_EDGES, IMDS_NODE_ID

if TYPE_CHECKING:
    from ..db import Finding

log = logging.getLogger(__name__)

_MAX_PATHS = 20

_SEV_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
}

_NODE_COLORS: dict[str, str] = {
    AWSNodeType.IAM_ROLE.value:                "#7c3aed",
    AWSNodeType.IAM_USER.value:                "#7c3aed",
    AWSNodeType.EKS_SERVICE_ACCOUNT.value:     "#7c3aed",
    AWSNodeType.EC2_INSTANCE.value:            "#2563eb",
    AWSNodeType.EKS_POD.value:                 "#2563eb",
    AWSNodeType.EKS_NODE.value:                "#2563eb",
    AWSNodeType.S3_BUCKET.value:               "#16a34a",
    AWSNodeType.RDS_INSTANCE.value:            "#16a34a",
    AWSNodeType.SECRETS_MANAGER.value:         "#16a34a",
    AWSNodeType.SSM_PARAMETER.value:           "#16a34a",
    AWSNodeType.KMS_KEY.value:                 "#facc15",
    AWSNodeType.LAMBDA_FUNCTION.value:         "#d97706",
    AWSNodeType.LAMBDA_LAYER.value:            "#fbbf24",
    AWSNodeType.SNS_TOPIC.value:               "#a855f7",
    AWSNodeType.SQS_QUEUE.value:               "#a855f7",
    AWSNodeType.VPC.value:                     "#0891b2",
    AWSNodeType.SECURITY_GROUP.value:          "#0891b2",
    AWSNodeType.VPC_ENDPOINT.value:            "#0891b2",
    AWSNodeType.VPC_PEERING.value:             "#0891b2",
    AWSNodeType.TRANSIT_GATEWAY.value:         "#0891b2",
    AWSNodeType.API_GATEWAY_ROUTE.value:       "#f97316",
    AWSNodeType.CLOUDFRONT_DISTRIBUTION.value: "#f97316",
    AWSNodeType.WAF_ACL.value:                 "#475569",
    AWSNodeType.WEB_ENDPOINT.value:            "#dc2626",
    AWSNodeType.IMDS.value:                    "#dc2626",
    AWSNodeType.WILDCARD.value:                "#9ca3af",
}

_AZURE_NODE_COLORS: dict[str, str] = {
    # Scope — slate-blue tones
    AzureNodeType.TENANT.value:              "#1e3a5f",
    AzureNodeType.MANAGEMENT_GROUP.value:    "#1e40af",
    AzureNodeType.SUBSCRIPTION.value:        "#2563eb",
    AzureNodeType.RESOURCE_GROUP.value:      "#3b82f6",
    # Identity — teal tones (distinct from AWS purple)
    AzureNodeType.ENTRA_USER.value:          "#0f766e",
    AzureNodeType.ENTRA_GROUP.value:         "#0d9488",
    AzureNodeType.ENTRA_DIRECTORY_ROLE.value: "#14b8a6",
    AzureNodeType.SERVICE_PRINCIPAL.value:   "#0891b2",
    AzureNodeType.APP_REGISTRATION.value:    "#06b6d4",
    AzureNodeType.SYSTEM_ASSIGNED_MI.value:  "#0e7490",
    AzureNodeType.USER_ASSIGNED_MI.value:    "#155e75",
    # RBAC
    AzureNodeType.ROLE_DEFINITION.value:     "#7dd3fc",
    AzureNodeType.ROLE_ASSIGNMENT.value:     "#38bdf8",
    AzureNodeType.FEDERATED_CREDENTIAL.value: "#0ea5e9",
    # Compute — same blue as AWS EC2 but slightly greener
    AzureNodeType.VIRTUAL_MACHINE.value:     "#1d4ed8",
    AzureNodeType.VMSS.value:                "#1d4ed8",
    AzureNodeType.APP_SERVICE.value:         "#2563eb",
    AzureNodeType.FUNCTION_APP.value:        "#d97706",
    AzureNodeType.CONTAINER_APP.value:       "#1d4ed8",
    AzureNodeType.CONTAINER_INSTANCE.value:  "#1d4ed8",
    AzureNodeType.AKS_CLUSTER.value:         "#1d4ed8",
    AzureNodeType.AKS_NODE_POOL.value:       "#1d4ed8",
    AzureNodeType.AKS_SERVICE_ACCOUNT.value: "#0f766e",
    # Storage — green tones
    AzureNodeType.STORAGE_ACCOUNT.value:     "#15803d",
    AzureNodeType.BLOB_CONTAINER.value:      "#16a34a",
    AzureNodeType.FILE_SHARE.value:          "#22c55e",
    AzureNodeType.QUEUE.value:               "#4ade80",
    AzureNodeType.TABLE.value:               "#86efac",
    # Secrets — amber (matches AWS KMS/Secrets)
    AzureNodeType.KEY_VAULT.value:           "#b45309",
    AzureNodeType.KV_SECRET.value:           "#d97706",
    AzureNodeType.KV_KEY.value:              "#fbbf24",
    AzureNodeType.KV_CERTIFICATE.value:      "#fcd34d",
    # Database
    AzureNodeType.COSMOS_ACCOUNT.value:      "#15803d",
    AzureNodeType.SQL_SERVER.value:          "#16a34a",
    AzureNodeType.SQL_DATABASE.value:        "#22c55e",
    AzureNodeType.MYSQL_SERVER.value:        "#4ade80",
    AzureNodeType.POSTGRESQL_SERVER.value:   "#86efac",
    # Network — cyan tones
    AzureNodeType.VNET.value:               "#0891b2",
    AzureNodeType.SUBNET.value:             "#0e7490",
    AzureNodeType.NSG.value:               "#155e75",
    AzureNodeType.NSG_RULE.value:          "#164e63",
    AzureNodeType.ROUTE_TABLE.value:        "#083344",
    AzureNodeType.PEERING.value:           "#0891b2",
    AzureNodeType.PRIVATE_ENDPOINT.value:   "#0ea5e9",
    AzureNodeType.APP_GATEWAY.value:        "#f97316",
    AzureNodeType.FRONT_DOOR.value:         "#f97316",
    AzureNodeType.AZURE_FIREWALL.value:     "#475569",
    # Messaging
    AzureNodeType.SERVICE_BUS_NS.value:     "#a855f7",
    AzureNodeType.EVENT_HUBS_NS.value:      "#a855f7",
    AzureNodeType.EVENT_GRID_TOPIC.value:   "#a855f7",
    # Governance
    AzureNodeType.LOG_ANALYTICS.value:      "#475569",
    AzureNodeType.DIAGNOSTIC_SETTING.value: "#64748b",
    AzureNodeType.POLICY_ASSIGNMENT.value:  "#6b7280",
    AzureNodeType.DEFENDER_PLAN.value:      "#6b7280",
}

_EDGE_COLORS: dict[str, str] = {
    AWSEdgeType.CAN_ASSUME.value:        "#7c3aed",
    AWSEdgeType.CAN_PASS_ROLE.value:     "#7c3aed",
    AWSEdgeType.HAS_PERMISSION.value:    "#94a3b8",
    AWSEdgeType.SSRF_REACHABLE.value:    "#dc2626",
    AWSEdgeType.IRSA_BOUND.value:        "#7c3aed",
    AWSEdgeType.OIDC_TRUSTS.value:       "#7c3aed",
    AWSEdgeType.ATTACHED_TO.value:       "#2563eb",
    AWSEdgeType.HOSTS_APP.value:         "#94a3b8",
    AWSEdgeType.ROUTES_TO.value:         "#94a3b8",
    AWSEdgeType.INTERNET_FACING.value:   "#dc2626",
    AWSEdgeType.PEERED_WITH.value:       "#0891b2",
    AWSEdgeType.INVOKES.value:           "#f97316",
    AWSEdgeType.ENCRYPTS_WITH.value:     "#facc15",
    AWSEdgeType.KEY_POLICY_GRANTS.value: "#facc15",
    AWSEdgeType.SUBSCRIBES_TO.value:     "#a855f7",
    AWSEdgeType.USES_LAYER.value:        "#fbbf24",
    AWSEdgeType.WAF_PROTECTS.value:      "#475569",
}

_AZURE_EDGE_COLORS: dict[str, str] = {
    AzureEdgeType.CAN_ASSUME_MI.value:          "#0891b2",
    AzureEdgeType.HAS_RBAC_ROLE.value:          "#0ea5e9",
    AzureEdgeType.HAS_DIRECTORY_ROLE.value:     "#14b8a6",
    AzureEdgeType.HAS_API_PERMISSION.value:     "#0d9488",
    AzureEdgeType.OWNS_APP_REGISTRATION.value:  "#06b6d4",
    AzureEdgeType.CONSENT_GRANT.value:          "#a855f7",
    AzureEdgeType.CAN_ATTACH_MI.value:          "#0891b2",
    AzureEdgeType.MI_ATTACHED_TO.value:         "#38bdf8",
    AzureEdgeType.WORKLOAD_ID_BOUND.value:      "#0ea5e9",
    AzureEdgeType.OIDC_TRUSTS.value:            "#0891b2",
    AzureEdgeType.ROUTES_TO.value:              "#94a3b8",
    AzureEdgeType.INTERNET_FACING.value:        "#dc2626",
    AzureEdgeType.PEERED_WITH.value:            "#0891b2",
    AzureEdgeType.PRIVATE_LINK_TO.value:        "#0e7490",
    AzureEdgeType.SSRF_REACHABLE.value:         "#dc2626",
    AzureEdgeType.IMDS_EXPOSED.value:           "#dc2626",
    AzureEdgeType.INVOKES.value:                "#f97316",
    AzureEdgeType.ENCRYPTS_WITH.value:          "#fbbf24",
    AzureEdgeType.STORES_SECRET_FOR.value:      "#d97706",
    AzureEdgeType.POLICY_APPLIES_TO.value:      "#6b7280",
    AzureEdgeType.PIM_ELIGIBLE_FOR.value:       "#7c3aed",
    AzureEdgeType.CAN_RESET_CREDENTIAL_FOR.value: "#dc2626",
    AzureEdgeType.MEMBER_OF.value:              "#94a3b8",
}

_DASHED_EDGES: frozenset[str] = frozenset({
    AWSEdgeType.SSRF_REACHABLE.value,
    AWSEdgeType.INTERNET_FACING.value,
    AWSEdgeType.KEY_POLICY_GRANTS.value,  # logical grant rather than runtime call
    # Azure — dotted = potential / conditional paths
    AzureEdgeType.SSRF_REACHABLE.value,
    AzureEdgeType.IMDS_EXPOSED.value,
    AzureEdgeType.PIM_ELIGIBLE_FOR.value,   # eligible but not yet active
    AzureEdgeType.INTERNET_FACING.value,
})

_SEV_RADIUS: dict[str | None, int] = {
    "CRITICAL": 14,
    "HIGH":     12,
    "MEDIUM":   10,
    "LOW":       9,
    "INFO":      8,
    None:        8,
}

_SEV_COLORS: dict[str | None, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "INFO":     "#2563eb",
    None:       "#94a3b8",
}


class AttackSurfaceAnalyzer:
    """Wraps a NetworkX DiGraph with attack-surface analysis utilities."""

    def __init__(self, graph: nx.DiGraph) -> None:
        self._g = graph

    # ------------------------------------------------------------------
    # Path-finding
    # ------------------------------------------------------------------

    def find_attack_paths(
        self, src: str, dst: str, max_hops: int = 6
    ) -> list[list[str]]:
        """Return simple paths from *src* to *dst*, capped at _MAX_PATHS."""
        if src not in self._g or dst not in self._g:
            return []
        try:
            gen = nx.all_simple_paths(self._g, src, dst, cutoff=max_hops)
            paths: list[list[str]] = []
            for p in gen:
                paths.append(p)
                if len(paths) >= _MAX_PATHS:
                    break
            return paths
        except Exception:
            return []

    def find_paths_from_internet(
        self, target: str, max_hops: int = 8
    ) -> list[list[str]]:
        """Find all paths from internet-facing nodes to *target*."""
        if target not in self._g:
            return []
        sources = [
            n for n, d in self._g.nodes(data=True)
            if d.get("is_internet_facing") and n != target
        ]
        all_paths: list[list[str]] = []
        for src in sources:
            for p in self.find_attack_paths(src, target, max_hops):
                all_paths.append(p)
                if len(all_paths) >= _MAX_PATHS:
                    return all_paths
        return all_paths

    # ------------------------------------------------------------------
    # Blast radius
    # ------------------------------------------------------------------

    def blast_radius(
        self, node_id: str, max_hops: int = 6
    ) -> dict[str, list[str]]:
        """Return nodes reachable from *node_id*, grouped by node type."""
        if node_id not in self._g:
            return {}
        reachable = nx.single_source_shortest_path(
            self._g, node_id, cutoff=max_hops
        )
        grouped: dict[str, list[str]] = {}
        for n in reachable:
            if n == node_id:
                continue
            ntype = self._g.nodes[n].get("node_type", "unknown")
            grouped.setdefault(ntype, []).append(n)
        return grouped

    # ------------------------------------------------------------------
    # Subgraph extraction (for prompt compression)
    # ------------------------------------------------------------------

    def subgraph_around(
        self, node_ids: "set[str] | list[str]", hops: int = 2
    ) -> "set[str]":
        """Return the set of node IDs within *hops* of any node in *node_ids*.

        Treats the graph as undirected for reachability so we don't lose IAM
        chains where the edge direction is opposite the data flow. Used by
        the AI discovery prompt to drop edges that can't possibly be part of
        a chain involving any seed node — typically a 60–75% reduction on
        real assessments where most resources have no findings attached.
        """
        seeds = {nid for nid in node_ids if nid in self._g}
        if not seeds:
            return set()
        # Operating on the undirected view is cheaper than two directed BFSes.
        ug = self._g.to_undirected(as_view=True)
        kept: set[str] = set()
        for seed in seeds:
            # cutoff includes the source at distance 0, so this naturally yields
            # the seed plus everything within `hops` undirected steps.
            reached = nx.single_source_shortest_path_length(ug, seed, cutoff=hops)
            kept.update(reached.keys())
        return kept

    # ------------------------------------------------------------------
    # Queryable graph (B4)
    # ------------------------------------------------------------------

    def paths_between(
        self,
        src: str,
        dst: str,
        edge_types: "Iterable[str] | None" = None,
        max_hops: int = 4,
        max_paths: int = _MAX_PATHS,
    ) -> "list[list[tuple[str, str | None]]]":
        """Return concrete paths from *src* to *dst*, optionally edge-filtered.

        Each path is a list of ``(node_id, incoming_edge_type)`` pairs; the
        first pair has ``edge_type=None`` (the source has no incoming edge).
        When ``edge_types`` is provided, paths that traverse any other edge
        type are excluded — this is what lets correlation patterns express
        "reachable via CAN_ASSUME / CAN_PASS_ROLE only" rather than the old
        any-edge multi-hop check.

        Operates on a directed view of the graph; callers that want
        bidirectional reachability should call this twice (src→dst then
        dst→src) and union the result.
        """
        if src not in self._g or dst not in self._g:
            return []
        allowed: set[str] | None = None
        if edge_types is not None:
            allowed = {str(e) for e in edge_types}
            if not allowed:
                return []  # explicit empty-set means nothing is allowed

        try:
            simple = nx.all_simple_paths(self._g, src, dst, cutoff=max_hops)
        except Exception:
            return []

        results: list[list[tuple[str, str | None]]] = []
        for node_path in simple:
            annotated: list[tuple[str, str | None]] = [(node_path[0], None)]
            ok = True
            for u, v in zip(node_path, node_path[1:]):
                edata = self._g.get_edge_data(u, v) or {}
                etype = edata.get("type")
                if allowed is not None and etype not in allowed:
                    ok = False
                    break
                annotated.append((v, etype))
            if ok:
                results.append(annotated)
                if len(results) >= max_paths:
                    break
        return results

    def principals_reaching(
        self,
        resource_id: str,
        edge_types: "Iterable[str] | None" = None,
        max_hops: int = 4,
    ) -> list[str]:
        """List principals that can reach *resource_id* within *max_hops*.

        A principal is any IAM_USER / IAM_ROLE / EKS_SERVICE_ACCOUNT node.
        ``edge_types`` defaults to :data:`IAM_TRAVERSAL_EDGES` so the answer
        reflects "who has IAM access" rather than "who is graph-adjacent".
        """
        if resource_id not in self._g:
            return []
        # Default traversal set covers both AWS and Azure IAM edges.
        allowed = (
            set(edge_types) if edge_types is not None
            else (set(IAM_TRAVERSAL_EDGES) | AZURE_IAM_TRAVERSAL_EDGES)
        )
        principal_types = {
            # AWS principals
            AWSNodeType.IAM_USER.value,
            AWSNodeType.IAM_ROLE.value,
            AWSNodeType.EKS_SERVICE_ACCOUNT.value,
        } | AZURE_PRINCIPAL_NODE_TYPES
        candidates = [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") in principal_types and n != resource_id
        ]
        reaching: list[str] = []
        for pid in candidates:
            if self.paths_between(
                pid, resource_id, edge_types=allowed,
                max_hops=max_hops, max_paths=1,
            ):
                reaching.append(pid)
        return reaching

    def cycle_detect(
        self, edge_types: "Iterable[str] | None" = None
    ) -> list[list[str]]:
        """Return simple cycles in the (optionally edge-filtered) graph.

        Useful for surfacing IAM trust loops (role A trusts B, B trusts A),
        which are usually misconfigurations rather than intentional. Callers
        typically pass ``edge_types={'CAN_ASSUME'}``.
        """
        if edge_types is None:
            view = self._g
        else:
            allowed = {str(e) for e in edge_types}
            view = nx.DiGraph()
            view.add_nodes_from(self._g.nodes(data=True))
            for u, v, data in self._g.edges(data=True):
                if data.get("type") in allowed:
                    view.add_edge(u, v, **data)
        try:
            return [list(c) for c in nx.simple_cycles(view)]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Correlation helper (kept as a thin wrapper around paths_between)
    # ------------------------------------------------------------------

    def are_related_multi_hop(
        self,
        src_id: str,
        dst_id: str,
        max_hops: int = 4,
        edge_types: "Iterable[str] | None" = None,
    ) -> bool:
        """True if *src* and *dst* are connected within *max_hops* (either direction).

        Now a wrapper over :meth:`paths_between` so the old correlation API
        and the new edge-typed queries share one implementation. ``edge_types``
        is forwarded — the engine uses this to honour the new YAML
        ``via_edges`` constraint.
        """
        if src_id not in self._g or dst_id not in self._g:
            return False
        if self.paths_between(
            src_id, dst_id, edge_types=edge_types,
            max_hops=max_hops, max_paths=1,
        ):
            return True
        if self.paths_between(
            dst_id, src_id, edge_types=edge_types,
            max_hops=max_hops, max_paths=1,
        ):
            return True
        return False

    # ------------------------------------------------------------------
    # Web-app graph bridge
    # ------------------------------------------------------------------

    def bridge_web_app_graph(self, web_graph: dict) -> None:
        """Import SSRF/endpoint nodes from the autopentest-ai knowledge graph.

        Expects the JSON format written by autopentest-ai's knowledge_graph.py:
        {"nodes": {node_id: {type, label, properties, ...}, ...}, "edges": [...]}
        """
        nodes: dict = web_graph.get("nodes", {})

        for node_id, node_data in nodes.items():
            ntype = node_data.get("type", "")
            props = node_data.get("properties", {})
            vuln_class = props.get("vuln_class", "") if isinstance(props, dict) else ""

            is_ssrf = (
                "ssrf" in ntype.lower()
                or "ssrf" in vuln_class.lower()
                or ntype == "finding" and "ssrf" in node_data.get("label", "").lower()
            )
            if not is_ssrf:
                continue

            if not self._g.has_node(node_id):
                self._g.add_node(
                    node_id,
                    node_type=AWSNodeType.WEB_ENDPOINT.value,
                    label=(node_data.get("label") or node_id)[:80],
                    properties={"finding_ids": []},
                    is_internet_facing=True,
                )
            if (
                self._g.has_node(IMDS_NODE_ID)
                and not self._g.has_edge(node_id, IMDS_NODE_ID)
            ):
                self._g.add_edge(
                    node_id, IMDS_NODE_ID,
                    type=AWSEdgeType.SSRF_REACHABLE.value,
                )

    # ------------------------------------------------------------------
    # Cytoscape serialisation
    # ------------------------------------------------------------------

    def to_cytoscape(self, findings_map: "dict[str, Finding]") -> dict:
        """Serialize the graph to Cytoscape.js elements JSON."""
        cy_nodes = []
        cy_edges = []

        for node_id, data in self._g.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            props = data.get("properties") or {}
            finding_ids: list[str] = (
                props.get("finding_ids", []) if isinstance(props, dict) else []
            )

            # Highest severity among linked findings
            severity: str | None = None
            for fid in finding_ids:
                f = findings_map.get(fid)
                if f:
                    fsev = f.severity.value
                    if (
                        severity is None
                        or _SEV_ORDER.get(fsev, 99) < _SEV_ORDER.get(severity, 99)
                    ):
                        severity = fsev

            # Infer provider from node_type prefix (azure types start with "az_")
            provider = "azure" if node_type.startswith("az_") else "aws"
            cy_nodes.append({
                "data": {
                    "id": node_id,
                    "label": (data.get("label") or node_id)[:40],
                    "type": node_type,
                    "provider": provider,
                    "severity": severity,
                    "internet_facing": bool(data.get("is_internet_facing")),
                    "color": _NODE_COLORS.get(node_type) or _AZURE_NODE_COLORS.get(node_type, "#94a3b8"),
                    "border_color": _SEV_COLORS.get(severity, "#94a3b8"),
                    "radius": _SEV_RADIUS.get(severity, 8),
                }
            })

        for i, (src, dst, edge_data) in enumerate(self._g.edges(data=True)):
            etype = edge_data.get("type", "")
            cy_edges.append({
                "data": {
                    "id": f"e{i}",
                    "source": src,
                    "target": dst,
                    "label": etype,
                    "color": _EDGE_COLORS.get(etype) or _AZURE_EDGE_COLORS.get(etype, "#94a3b8"),
                    "dashed": etype in _DASHED_EDGES,
                }
            })

        return {"elements": {"nodes": cy_nodes, "edges": cy_edges}}
