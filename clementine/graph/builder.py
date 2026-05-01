"""Graph construction from FindingsDB data and cloud-audit MCP enrichment."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import networkx as nx

from .azure_model import AzureEdgeType
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

# ARN service-prefix → AWSNodeType (used when resource_type is absent)
_ARN_SERVICE_MAP: dict[str, AWSNodeType] = {
    "iam":                  AWSNodeType.IAM_ROLE,
    "s3":                   AWSNodeType.S3_BUCKET,
    "rds":                  AWSNodeType.RDS_INSTANCE,
    "lambda":               AWSNodeType.LAMBDA_FUNCTION,
    "secretsmanager":       AWSNodeType.SECRETS_MANAGER,
    "ssm":                  AWSNodeType.SSM_PARAMETER,
    "eks":                  AWSNodeType.EKS_NODE,
    "vpc":                  AWSNodeType.VPC,
    "elasticloadbalancing": AWSNodeType.VPC_ENDPOINT,
    "apigateway":           AWSNodeType.API_GATEWAY_ROUTE,
    "kms":                  AWSNodeType.KMS_KEY,
    "sns":                  AWSNodeType.SNS_TOPIC,
    "sqs":                  AWSNodeType.SQS_QUEUE,
    "cloudfront":           AWSNodeType.CLOUDFRONT_DISTRIBUTION,
    "wafv2":                AWSNodeType.WAF_ACL,
    "waf":                  AWSNodeType.WAF_ACL,
    "ec2":                  AWSNodeType.EC2_INSTANCE,
}

# ARN resource-type sub-string → AWSNodeType (checked after service prefix)
_ARN_RESOURCE_MAP: dict[str, AWSNodeType] = {
    "security-group":      AWSNodeType.SECURITY_GROUP,
    "security_group":      AWSNodeType.SECURITY_GROUP,
    "vpc-peering":         AWSNodeType.VPC_PEERING,
    "vpc":                 AWSNodeType.VPC,
    "subnet":              AWSNodeType.VPC,
    "network-acl":         AWSNodeType.VPC,
    "transit-gateway":     AWSNodeType.TRANSIT_GATEWAY,
    "volume":              AWSNodeType.EC2_INSTANCE,
    "instance":            AWSNodeType.EC2_INSTANCE,
}

# IAM-only sub-resource override (otherwise everything iam:* maps to IAM_ROLE).
_IAM_RESOURCE_MAP: dict[str, AWSNodeType] = {
    "user/":   AWSNodeType.IAM_USER,
    "role/":   AWSNodeType.IAM_ROLE,
}

# Lambda-only sub-resource override. Keys are matched against parts[5] from
# `arn.split(":", 6)`, which gives e.g. "layer" or "function" (no trailing
# colon — the rest of the ARN is in parts[6]).
_LAMBDA_RESOURCE_MAP: dict[str, AWSNodeType] = {
    "layer":     AWSNodeType.LAMBDA_LAYER,
    "function":  AWSNodeType.LAMBDA_FUNCTION,
}


def _infer_node_type(resource_type: str | None, resource_id: str | None) -> AWSNodeType:
    """Resolve AWSNodeType from resource_type field first, then ARN prefix."""
    # 1. Explicit resource_type mapping (fastest path)
    if resource_type and resource_type in _RESOURCE_TYPE_MAP:
        return _RESOURCE_TYPE_MAP[resource_type]

    # 2. ARN-based inference
    if resource_id and resource_id.startswith("arn:"):
        parts = resource_id.split(":", 6)
        service = parts[2] if len(parts) > 2 else ""
        resource = parts[5] if len(parts) > 5 else ""

        # IAM sub-resource: distinguish role vs user vs other
        if service == "iam":
            for key, ntype in _IAM_RESOURCE_MAP.items():
                if key in resource:
                    return ntype
            return AWSNodeType.IAM_ROLE

        # Lambda sub-resource: distinguish function vs layer.
        # parts[5] is just "layer" or "function" — match it as a token, not
        # a substring (otherwise "layer" would also match "function:layer-x").
        if service == "lambda":
            if resource in _LAMBDA_RESOURCE_MAP:
                return _LAMBDA_RESOURCE_MAP[resource]
            return AWSNodeType.LAMBDA_FUNCTION

        # EC2 sub-resource match (peering, transit-gw, security-group, …)
        if service == "ec2":
            for key, ntype in _ARN_RESOURCE_MAP.items():
                if key in resource:
                    return ntype
            return AWSNodeType.EC2_INSTANCE

        # Service-level match
        if service in _ARN_SERVICE_MAP:
            return _ARN_SERVICE_MAP[service]

    # 3. URL → web endpoint
    if resource_id and (resource_id.startswith("http://") or resource_id.startswith("https://")):
        return AWSNodeType.WEB_ENDPOINT

    # 4. Wildcard placeholder (used by IAM enumeration for `Resource: "*"`)
    if resource_id == "*":
        return AWSNodeType.WILDCARD

    return AWSNodeType.EC2_INSTANCE

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
    "PEERED_WITH": AWSEdgeType.PEERED_WITH,
    "INVOKES": AWSEdgeType.INVOKES,
    "ENCRYPTS_WITH": AWSEdgeType.ENCRYPTS_WITH,
    "KEY_POLICY_GRANTS": AWSEdgeType.KEY_POLICY_GRANTS,
    "SUBSCRIBES_TO": AWSEdgeType.SUBSCRIBES_TO,
    "USES_LAYER": AWSEdgeType.USES_LAYER,
    "WAF_PROTECTS": AWSEdgeType.WAF_PROTECTS,
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
        # node.node_type is now a plain str (either an AWSNodeType value or an
        # AzureNodeType value — both are str enums, so no .value call needed).
        self._graph.add_node(
            node.node_id,
            node_type=node.node_type,
            label=node.label,
            properties=node.properties,
            is_internet_facing=node.is_internet_facing,
        )

    def _add_edge(self, src: str, dst: str, edge_type: "AWSEdgeType | AzureEdgeType | str") -> None:
        """Add a directed edge, auto-creating stub nodes for unknown endpoints."""
        for nid in (src, dst):
            if not self._graph.has_node(nid):
                self._graph.add_node(
                    nid, node_type="unknown", label=nid[:80],
                    properties={}, is_internet_facing=False,
                )
        if not self._graph.has_edge(src, dst):
            # Both AWSEdgeType and AzureEdgeType are str-enums so str() always
            # yields the plain string value without an extra .value call.
            self._graph.add_edge(src, dst, type=str(edge_type))

    def get_nodes(self) -> list[GraphNode]:
        """Return all tracked GraphNode objects."""
        return list(self._nodes.values())

    # ------------------------------------------------------------------
    # Construction paths
    # ------------------------------------------------------------------

    async def build_from_db(self) -> nx.DiGraph:
        """Reconstruct the graph from persisted graph_nodes + edges.

        UNIONs the legacy ``resource_graph`` adjacency table with the richer
        ``graph_edges`` table (which carries finding_ids, is_wildcard, action
        lists, etc.). Edge properties from ``graph_edges`` are stamped onto
        the NetworkX edge so query-time consumers can use them without a
        second DB round-trip.
        """
        # 1. Persisted nodes
        persisted = await self._db.get_graph_nodes()
        for node in persisted:
            self._add_node(node)

        # 2. Legacy adjacency table (read-only, no lock needed)
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

        # 3. Rich edges table — same structure but with provenance properties.
        rich_edges = await self._db.get_graph_edges()
        for e in rich_edges:
            edge_type_str = e["edge_type"]
            # Resolve AWS edge type first, then Azure, then pass raw string.
            try:
                edge_type: AWSEdgeType | AzureEdgeType | str = AWSEdgeType(edge_type_str)
            except ValueError:
                try:
                    edge_type = AzureEdgeType(edge_type_str)
                except ValueError:
                    edge_type = edge_type_str  # unknown but preserve for cross-cloud patterns
            self._add_edge(e["source_id"], e["target_id"], edge_type)
            # Stamp the rich properties onto the in-memory edge so query
            # helpers (paths_between with edge_types filter, etc.) can read
            # them without going back to the DB.
            self._graph.edges[e["source_id"], e["target_id"]].update(
                {"properties": e["properties"]}
            )

        log.debug(
            "[Graph] Reconstructed from DB: %d nodes, %d edges (+%d rich)",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
            len(rich_edges),
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

        # Azure enrichment — runs only when Azure nodes exist in the DB.
        # Importing here avoids a circular import at module load time.
        from .azure_enrichment import enrich_azure
        await enrich_azure(self, db=self._db, mcp=mcp, limiter=limiter)

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
            node_type = _infer_node_type(f.resource_type, f.resource_id)
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
            node_type = _infer_node_type(f.resource_type, f.resource_id)
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
        """Run live IAM enumeration via the cloud_audit MCP server.

        Replaces the previous stub. The IAM pass populates CAN_ASSUME,
        OIDC_TRUSTS, HAS_PERMISSION, and CAN_PASS_ROLE edges directly into
        ``graph_edges`` (with provenance) and into the in-memory NetworkX
        graph. Failures in any sub-pass are recorded in
        ``enrichment_status`` so report consumers can disclose the
        completeness of the topology rather than silently ship a partial
        graph.
        """
        from .iam_enrichment import enrich_iam
        await enrich_iam(self, db=self._db, mcp=mcp, limiter=limiter)
