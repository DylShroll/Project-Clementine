"""Project IaC findings onto the knowledge graph as ``planned`` nodes.

Each Phase 0 finding that names a concrete IaC resource (e.g. tfsec or
checkov flagging ``aws_s3_bucket.demo``) gets a corresponding graph
node tagged ``provenance="iac"``. When a later AWS / Azure phase
upserts a live node sharing the same ``node_id``, the ``ON CONFLICT``
clause in :meth:`FindingsDB.upsert_graph_node` promotes both rows to
``live+iac`` automatically — no separate merge sweep required.

Why finding-driven rather than plan-driven? In M3 we don't have a
parsed Terraform plan available (that lands in M4 with the ``plan``
source path). Walking findings is sufficient for *all chains we
currently care about*: a chain only fires through a resource when at
least one finding flagged it, so resources that scan clean don't need
a graph entry yet.

Edges are deliberately not drawn here — Terraform's ``references``
graph isn't reachable from the scanner-output schema. M4's plan source
will populate edges between planned nodes; M3 ships nodes only.
"""

from __future__ import annotations

import logging

from ...db import Finding, FindingsDB

log = logging.getLogger(__name__)

# Findings whose source matches this prefix originated in Phase 0.
_IAC_SOURCE_PREFIX = "iac-scanner-"

# Resource-type strings we map to the live AWSNodeType / AzureNodeType
# vocabulary. Mapping is intentionally narrow at M3: we cover the
# resource types that the first three IaC patterns reference. Unknown
# resource types are projected with ``node_type`` set to the raw
# scanner string so downstream tools can still surface them, and a
# debug log notes the gap.
_RESOURCE_TYPE_MAP: dict[str, str] = {
    # AWS S3
    "aws_s3_bucket": "S3Bucket",
    "AWS::S3::Bucket": "S3Bucket",
    # AWS Lambda
    "aws_lambda_function": "LambdaFunction",
    "AWS::Lambda::Function": "LambdaFunction",
    # AWS IAM
    "aws_iam_role": "IAMRole",
    "AWS::IAM::Role": "IAMRole",
    "aws_iam_policy": "IAMPolicy",
    "AWS::IAM::Policy": "IAMPolicy",
    # AWS EC2
    "aws_security_group": "SecurityGroup",
    "AWS::EC2::SecurityGroup": "SecurityGroup",
    "aws_instance": "EC2Instance",
    "AWS::EC2::Instance": "EC2Instance",
}


async def project_planned_nodes(db: FindingsDB) -> int:
    """Walk Phase 0 findings and project each resource as a planned node.

    Returns the number of distinct nodes upserted. Calling twice is a
    no-op (SQLite ON CONFLICT keeps the existing row), so this is safe
    to invoke at the end of every Phase 0 run.
    """
    findings = await db.get_findings(phase=0)
    if not findings:
        return 0

    # Dedup by node_id so we only call upsert once per distinct planned
    # resource even if multiple findings target it.
    seen: set[str] = set()
    count = 0
    for f in findings:
        if not _is_iac_finding(f):
            continue
        node_id = _node_id_for(f)
        if node_id is None or node_id in seen:
            continue
        seen.add(node_id)

        node_type = _node_type_for(f)
        label = _label_for(f, node_id)
        await db.upsert_graph_node(
            node_id=node_id,
            node_type=node_type,
            label=label,
            properties={
                "provenance": "iac",
                "iac_source": f"{f.iac_source_path}:{f.iac_source_line}"
                              if f.iac_source_path else None,
                "iac_resource_type": f.resource_type,
                # Hold a reference back to the finding so the report can
                # surface "this planned node has N pre-deployment
                # findings" without a second SQL query.
                "iac_finding_ids": [f.id],
            },
            provenance="iac",
        )
        count += 1
    log.info("[Phase 0] projected %d planned graph node(s) from IaC findings", count)
    return count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_iac_finding(f: Finding) -> bool:
    """Phase-0 findings are tagged with source ``iac-scanner-<name>``."""
    return f.phase == 0 and (f.source or "").startswith(_IAC_SOURCE_PREFIX)


def _node_id_for(f: Finding) -> str | None:
    """Return the graph node id for a planned IaC resource.

    M3 uses the raw ``resource_id`` (e.g. ``aws_s3_bucket.demo``) when
    one is available. Live nodes use ARNs; the two won't collide today
    so the ``ON CONFLICT`` promotion path stays dormant until M4 lands
    deterministic ARN reconstruction.

    Findings that don't name a resource (e.g. a gitleaks hit in a
    standalone ``README.md``) return None and are skipped.
    """
    rid = (f.resource_id or "").strip()
    if not rid:
        return None
    return rid


def _node_type_for(f: Finding) -> str:
    """Map a scanner-native resource type onto the live node-type vocabulary.

    Falls back to the scanner's own string when no mapping exists, so
    correlation patterns can still match on the raw type via wildcards
    even before we extend the map.
    """
    rt = (f.resource_type or "").strip()
    if not rt:
        return "PlannedResource"
    return _RESOURCE_TYPE_MAP.get(rt, rt)


def _label_for(f: Finding, node_id: str) -> str:
    """Produce a short, human-readable node label for the report."""
    if f.resource_type and f.resource_id:
        return f"{f.resource_type} ({f.resource_id})"
    return node_id
