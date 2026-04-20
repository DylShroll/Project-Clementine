"""Graph construction from FindingsDB data and cloud-audit MCP enrichment."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import networkx as nx

from .model import AWSEdgeType, AWSNodeType, GraphNode, IMDS_NODE_ID

if TYPE_CHECKING:
    from ..db import FindingsDB
    from ..mcp_client import MCPRegistry
    from ..scope import RateLimiter

log = logging.getLogger(__name__)

# Map Finding.resource_type to AWSNodeType
_RESOURCE_TYPE_MAP: dict[str, AWSNodeType] = {
    "ec2": AWSNodeType.EC2_INSTANCE,
    "s3": AWSNodeType.S3_BUCKET,
    "iam": AWSNodeType.IAM_ROLE,
    "rds": AWSNodeType.RDS_INSTANCE,
    "lambda": AWSNodeType.LAMBDA_FUNCTION,
    "vpc": AWSNodeType.VPC,
    "sg": AWSNodeType.SECURITY_GROUP,
    "url": AWSNodeType.WEB_ENDPOINT,
}

# Map existing GraphRelationship string values to AWSEdgeType
_RELATIONSHIP_MAP: dict[str, AWSEdgeType] = {
    "hosts": AWSEdgeType.HOSTS_APP,
    "routes_to": AWSEdgeType.ROUTES_TO,
    "attached_to": AWSEdgeType.ATTACHED_TO,
    "has_access_to": AWSEdgeType.HAS_PERMISSION,
    "member_of": AWSEdgeType.ROUTES_TO,
    "CAN_ASSUME": AWSEdgeType.CAN_ASSUME,
    "HAS_PERMISSION": AWSEdgeType.HAS_PERMISSION,
    "CAN_PASS_ROLE": AWSEdgeType.CAN_PASS_ROLE,
    "INTERNET_FACING": AWSEdgeType.INTERNET_FACING,
    "SSRF_REACHABLE": AWSEdgeType.SSRF_REACHABLE,
    "HOSTS_APP": AWSEdgeType.HOSTS_APP,
    "IRSA_BOUND": AWSEdgeType.IRSA_BOUND,
    "OIDC_TRUSTS": AWSEdgeType.OIDC_TRUSTS,
}

# Category substrings that indicate SSRF-type findings
_SSRF_CATEGORIES = ("ssrf", "SSRF", "WSTG-INPV-19", "cmd_injection_imds")


class GraphBuilder:
    """Builds and populates the AWS knowledge graph from DB and optional MCP data."""

    def __init__(self, db: "FindingsDB") -> None:
        self._db = db
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, GraphNode] = {}

    # ------------------------------------------------------------------
    # Node / edge helpers
    # ------------------------------------------------------------------

    def _add_node(self, node: GraphNode) -> None:
        """Add or merge a node into the in-memory graph (idempotent)."""
        if node.node_id in self._nodes:
            existing = self._nodes[node.node_id]
            existing.merge_properties(node.properties)
            if node.is_internet_facing:
                existing.is_internet_facing = True
            # Sync is_internet_facing to networkx attr
            self._graph.nodes[node.node_id]["is_internet_facing"] = existing.is_internet_facing
            return

        self._nodes[node.node_id] = node
        self._graph.add_node(
            node.node_id,
            node_type=node.node_type.value,
            label=node.label,
            properties=node.properties,
            is_internet_facing=node.is_internet_facing,
        )

    def _add_edge(self, src: str, dst: str, edge_type: AWSEdgeType) -> None:
        """Add a directed edge, auto-creating stub nodes for unknown endpoints."""
        for nid in (src, dst):
            if not self._graph.has_node(nid):
                self._graph.add_node(
                    nid, node_type="unknown", label=nid[:80],
                    properties={}, is_internet_facing=False,
                )
        if not self._graph.has_edge(src, dst):
            self._graph.add_edge(src, dst, type=edge_type.value)

    def get_nodes(self) -> list[GraphNode]:
        """Return all tracked GraphNode objects."""
        return list(self._nodes.values())

    # ------------------------------------------------------------------
    # Construction paths
    # ------------------------------------------------------------------

    async def build_from_db(self) -> nx.DiGraph:
        """Reconstruct the graph from persisted graph_nodes + resource_graph rows."""
        # 1. Persisted nodes
        persisted = await self._db.get_graph_nodes()
        for node in persisted:
            self._add_node(node)

        # 2. Resource-graph adjacency edges (read-only, no lock needed)
        async with self._db._conn.execute(
            "SELECT source_arn, target_arn, relationship FROM resource_graph"
        ) as cur:
            rows = await cur.fetchall()

        for row in rows:
            src = row["source_arn"]
            dst = row["target_arn"]
            rel = row["relationship"]
            edge_type = _RELATIONSHIP_MAP.get(rel, AWSEdgeType.ROUTES_TO)
            self._add_edge(src, dst, edge_type)

        log.debug(
            "[Graph] Reconstructed from DB: %d nodes, %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    async def build(
        self,
        mcp: "MCPRegistry",
        limiter: "RateLimiter",
    ) -> nx.DiGraph:
        """Build the full graph from DB + live MCP enrichment.

        Falls back gracefully if cloud_audit is unavailable.
        """
        await self.build_from_db()

        # Ensure IMDS node always exists
        self._add_node(GraphNode(
            node_id=IMDS_NODE_ID,
            node_type=AWSNodeType.IMDS,
            label="EC2 Instance Metadata Service (169.254.169.254)",
            properties={"finding_ids": []},
        ))

        # Derive SSRF exploit edges from findings
        await self._derive_ssrf_edges()

        # Seed AWS resource nodes from all findings
        await self._seed_nodes_from_findings()

        # MCP enrichment (optional)
        if mcp.is_available("cloud_audit"):
            await self._enrich_from_cloud_audit(mcp, limiter)
        else:
            log.debug("[Graph] cloud_audit unavailable — skipping MCP enrichment")

        log.info(
            "[Graph] Built: %d nodes, %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    # ------------------------------------------------------------------
    # Internal enrichment helpers
    # ------------------------------------------------------------------

    async def _derive_ssrf_edges(self) -> None:
        """Add SSRF_REACHABLE edges from SSRF/CMDi findings to IMDS."""
        findings = await self._db.get_findings()
        for f in findings:
            cat = f.category or ""
            is_ssrf = any(kw in cat for kw in _SSRF_CATEGORIES)
            if not is_ssrf:
                continue
            if not f.resource_id:
                continue
            node_type = _RESOURCE_TYPE_MAP.get(f.resource_type or "", AWSNodeType.WEB_ENDPOINT)
            self._add_node(GraphNode(
                node_id=f.resource_id,
                node_type=node_type,
                label=f.title[:80] or f.resource_id[:80],
                properties={"finding_ids": [f.id]},
                is_internet_facing=True,
            ))
            self._add_edge(f.resource_id, IMDS_NODE_ID, AWSEdgeType.SSRF_REACHABLE)

    async def _seed_nodes_from_findings(self) -> None:
        """Create graph nodes for all findings that have a resource_id."""
        findings = await self._db.get_findings()
        for f in findings:
            if not f.resource_id:
                continue
            node_type = _RESOURCE_TYPE_MAP.get(f.resource_type or "", AWSNodeType.EC2_INSTANCE)
            self._add_node(GraphNode(
                node_id=f.resource_id,
                node_type=node_type,
                label=f.title[:80] or f.resource_id[:80],
                properties={"finding_ids": [f.id]},
            ))

    async def _enrich_from_cloud_audit(
        self,
        mcp: "MCPRegistry",
        limiter: "RateLimiter",
    ) -> None:
        """Query cloud_audit for IAM/EC2/Lambda relationships (best-effort)."""
        # We use findings already in the DB as the source of truth — the cloud_audit
        # MCP doesn't expose a structured IAM-graph API, so we derive edges from
        # resource_graph rows that were populated during Phase 2.
        # This method is a hook for future direct IAM enumeration.
        log.debug("[Graph] cloud_audit enrichment: using DB-derived edges (no IAM API calls)")
