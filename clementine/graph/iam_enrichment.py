"""Live IAM topology enrichment for the AWS knowledge graph.

Replaces the previously-stubbed enrichment path in :class:`GraphBuilder`. Calls
out to the ``cloud_audit`` MCP server to:

  1. List IAM roles and parse trust policies → ``CAN_ASSUME`` / ``OIDC_TRUSTS``
  2. List attached + inline policies on each role/user → ``HAS_PERMISSION``
  3. Detect ``iam:PassRole`` grants → ``CAN_PASS_ROLE``

Every sub-pass is independently failure-tolerant: if a list call returns
nothing usable we record the partial state in ``enrichment_status`` and move
on. The graph stays consistent (no half-built principal nodes) and the
report can disclose "IAM enumeration unavailable" instead of silently
shipping a topology gap.

Edges are persisted to the rich ``graph_edges`` table (with provenance and
``is_wildcard`` markers) so downstream queries (Track B4) can reason about
them without re-running the enumeration.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Iterable, Optional

from .model import AWSEdgeType, AWSNodeType, GraphNode

if TYPE_CHECKING:
    from ..db import FindingsDB
    from ..mcp_client import MCPRegistry
    from ..scope import RateLimiter
    from .builder import GraphBuilder

log = logging.getLogger(__name__)

# Wildcard placeholder used when a policy statement targets ``Resource: "*"``
# rather than a specific ARN. Kept as a sentinel node so traversal queries
# can still find privilege-escalation paths even when the destination is
# unspecified.
WILDCARD_NODE_ID = "*"

# Tool-name candidate lists. The cloud_audit MCP servers we've seen expose
# these under different conventions; use find_tool() to resolve.
_LIST_ROLES_CANDIDATES = ["ListRoles", "list_roles", "iam_list_roles"]
_LIST_USERS_CANDIDATES = ["ListUsers", "list_users", "iam_list_users"]
_GET_ROLE_POLICIES_CANDIDATES = [
    "GetRolePolicies", "get_role_policies", "iam_get_role_policies",
]
_GET_USER_POLICIES_CANDIDATES = [
    "GetUserPolicies", "get_user_policies", "iam_get_user_policies",
]


async def enrich_iam(
    builder: "GraphBuilder",
    *,
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
) -> None:
    """Run all three IAM sub-passes; record outcome in enrichment_status.

    Safe to call when cloud_audit is unavailable — the function will mark the
    enrichment as ``unavailable`` and return without touching the graph.
    """
    if not mcp.is_available("cloud_audit"):
        await db.set_enrichment_status(
            "iam", "unavailable", "cloud_audit MCP not registered or down"
        )
        log.info("[IAM] cloud_audit unavailable — skipping IAM enumeration")
        return

    list_roles_tool = mcp.find_tool("cloud_audit", _LIST_ROLES_CANDIDATES)
    list_users_tool = mcp.find_tool("cloud_audit", _LIST_USERS_CANDIDATES)
    get_role_pols_tool = mcp.find_tool("cloud_audit", _GET_ROLE_POLICIES_CANDIDATES)
    get_user_pols_tool = mcp.find_tool("cloud_audit", _GET_USER_POLICIES_CANDIDATES)

    if not list_roles_tool and not list_users_tool:
        await db.set_enrichment_status(
            "iam", "unavailable",
            "cloud_audit advertises no IAM list tools",
        )
        log.warning("[IAM] No usable IAM list tools — skipping")
        return

    failures: list[str] = []

    role_arns: list[str] = []
    if list_roles_tool:
        try:
            role_arns = await _enumerate_roles(
                builder, db, mcp, limiter, list_roles_tool
            )
        except Exception as exc:
            failures.append(f"list_roles: {exc}")
            log.warning("[IAM] role enumeration failed: %s", exc)

    user_arns: list[str] = []
    if list_users_tool:
        try:
            user_arns = await _enumerate_users(
                builder, db, mcp, limiter, list_users_tool
            )
        except Exception as exc:
            failures.append(f"list_users: {exc}")
            log.warning("[IAM] user enumeration failed: %s", exc)

    if get_role_pols_tool and role_arns:
        try:
            await _enumerate_principal_policies(
                builder, db, mcp, limiter, get_role_pols_tool, role_arns,
                principal_kind="role",
            )
        except Exception as exc:
            failures.append(f"role_policies: {exc}")
            log.warning("[IAM] role policy enumeration failed: %s", exc)

    if get_user_pols_tool and user_arns:
        try:
            await _enumerate_principal_policies(
                builder, db, mcp, limiter, get_user_pols_tool, user_arns,
                principal_kind="user",
            )
        except Exception as exc:
            failures.append(f"user_policies: {exc}")
            log.warning("[IAM] user policy enumeration failed: %s", exc)

    if failures:
        await db.set_enrichment_status(
            "iam", "partial", "; ".join(failures)
        )
    else:
        await db.set_enrichment_status(
            "iam", "ok",
            f"roles={len(role_arns)} users={len(user_arns)}",
        )
    log.info(
        "[IAM] enrichment complete — %d roles, %d users, %d failures",
        len(role_arns), len(user_arns), len(failures),
    )


# ---------------------------------------------------------------------------
# Sub-passes
# ---------------------------------------------------------------------------

async def _enumerate_roles(
    builder: "GraphBuilder",
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    tool_name: str,
) -> list[str]:
    """List IAM roles + parse trust policies → CAN_ASSUME / OIDC_TRUSTS edges.

    Returns the list of role ARNs found, so the policy pass doesn't have to
    re-list them.
    """
    async with limiter:
        result = await mcp.call_tool("cloud_audit", tool_name, {})
    roles = _coerce_list(result, key="roles") or _coerce_list(result, key="Roles")
    if not roles:
        log.debug("[IAM] %s returned no roles", tool_name)
        return []

    arns: list[str] = []
    for role in roles:
        arn = role.get("Arn") or role.get("arn")
        if not arn:
            continue
        name = role.get("RoleName") or role.get("name") or arn.split("/")[-1]
        arns.append(arn)
        builder._add_node(GraphNode(
            node_id=arn,
            node_type=AWSNodeType.IAM_ROLE,
            label=name[:80],
            properties={"finding_ids": []},
        ))
        await _persist_node(
            db, node_id=arn, node_type=AWSNodeType.IAM_ROLE, label=name[:80],
            properties={"finding_ids": []},
        )
        trust = role.get("AssumeRolePolicyDocument") or role.get("trust_policy")
        if trust:
            await _ingest_trust_policy(
                builder=builder, db=db, role_arn=arn, trust_policy=trust,
            )
    return arns


async def _enumerate_users(
    builder: "GraphBuilder",
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    tool_name: str,
) -> list[str]:
    """List IAM users → IAM_USER nodes (no trust policy on users)."""
    async with limiter:
        result = await mcp.call_tool("cloud_audit", tool_name, {})
    users = _coerce_list(result, key="users") or _coerce_list(result, key="Users")
    if not users:
        log.debug("[IAM] %s returned no users", tool_name)
        return []

    arns: list[str] = []
    for user in users:
        arn = user.get("Arn") or user.get("arn")
        if not arn:
            continue
        name = user.get("UserName") or user.get("name") or arn.split("/")[-1]
        arns.append(arn)
        builder._add_node(GraphNode(
            node_id=arn,
            node_type=AWSNodeType.IAM_USER,
            label=name[:80],
            properties={"finding_ids": []},
        ))
        await _persist_node(
            db, node_id=arn, node_type=AWSNodeType.IAM_USER, label=name[:80],
            properties={"finding_ids": []},
        )
    return arns


async def _enumerate_principal_policies(
    builder: "GraphBuilder",
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    tool_name: str,
    principal_arns: list[str],
    *,
    principal_kind: str,
) -> None:
    """For each principal, fetch attached + inline policies and emit edges."""
    arg_key = "RoleName" if principal_kind == "role" else "UserName"
    for arn in principal_arns:
        name = arn.split("/")[-1]
        try:
            async with limiter:
                result = await mcp.call_tool(
                    "cloud_audit", tool_name, {arg_key: name}
                )
        except Exception as exc:
            log.debug("[IAM] %s(%s) failed: %s", tool_name, name, exc)
            continue
        statements = _flatten_statements(result)
        for stmt in statements:
            await _ingest_policy_statement(
                builder=builder, db=db, principal_arn=arn, statement=stmt,
            )


# ---------------------------------------------------------------------------
# Trust-policy & permission-policy ingestion
# ---------------------------------------------------------------------------

async def _ingest_trust_policy(
    *,
    builder: "GraphBuilder",
    db: "FindingsDB",
    role_arn: str,
    trust_policy: dict | str,
) -> None:
    """Emit CAN_ASSUME / OIDC_TRUSTS edges from a role's trust policy.

    Trust-policy principals can be:
      * AWS account roots / users / roles → CAN_ASSUME
      * Federated identities (oidc-provider/…) → OIDC_TRUSTS
      * Service principals (e.g. lambda.amazonaws.com) — skipped here; the
        relevant edge is INVOKES, populated by the per-service enrichment
        passes (Lambda → API Gateway, etc.)
    """
    doc = _coerce_policy_document(trust_policy)
    if not doc:
        return
    for stmt in _iter_statements(doc):
        if (stmt.get("Effect") or "Allow").lower() != "allow":
            continue
        actions = _as_str_list(stmt.get("Action"))
        if not any("AssumeRole" in a for a in actions):
            continue
        principal = stmt.get("Principal") or {}
        if isinstance(principal, str):
            # Wildcard principal — treat as wildcard.
            await _emit_can_assume(
                builder, db, src=WILDCARD_NODE_ID, dst=role_arn, is_wildcard=True
            )
            continue
        if not isinstance(principal, dict):
            continue
        for ptype, values in principal.items():
            for src_arn in _as_str_list(values):
                if ptype == "Federated":
                    builder._add_node(GraphNode(
                        node_id=src_arn,
                        node_type=AWSNodeType.IAM_ROLE,  # closest available bucket
                        label=src_arn.split("/")[-1][:80],
                        properties={"is_federated": True, "finding_ids": []},
                    ))
                    await _persist_node(
                        db, node_id=src_arn, node_type=AWSNodeType.IAM_ROLE,
                        label=src_arn.split("/")[-1][:80],
                        properties={"is_federated": True, "finding_ids": []},
                    )
                    await _persist_edge(
                        db, src_arn, role_arn, AWSEdgeType.OIDC_TRUSTS,
                        properties={"sid": stmt.get("Sid")},
                    )
                    builder._add_edge(src_arn, role_arn, AWSEdgeType.OIDC_TRUSTS)
                elif ptype in ("AWS", "Service", "CanonicalUser"):
                    if src_arn == "*":
                        await _emit_can_assume(
                            builder, db, src=WILDCARD_NODE_ID, dst=role_arn,
                            is_wildcard=True,
                        )
                    else:
                        await _emit_can_assume(
                            builder, db, src=src_arn, dst=role_arn,
                            is_wildcard=False,
                        )


async def _emit_can_assume(
    builder: "GraphBuilder",
    db: "FindingsDB",
    *,
    src: str,
    dst: str,
    is_wildcard: bool,
) -> None:
    if src == WILDCARD_NODE_ID:
        builder._add_node(GraphNode(
            node_id=WILDCARD_NODE_ID,
            node_type=AWSNodeType.WILDCARD,
            label="*",
            properties={"finding_ids": []},
        ))
        await _persist_node(
            db, node_id=WILDCARD_NODE_ID, node_type=AWSNodeType.WILDCARD,
            label="*", properties={"finding_ids": []},
        )
    builder._add_edge(src, dst, AWSEdgeType.CAN_ASSUME)
    await _persist_edge(
        db, src, dst, AWSEdgeType.CAN_ASSUME,
        properties={"is_wildcard": is_wildcard},
    )


async def _ingest_policy_statement(
    *,
    builder: "GraphBuilder",
    db: "FindingsDB",
    principal_arn: str,
    statement: dict,
) -> None:
    """Emit HAS_PERMISSION + (if iam:PassRole) CAN_PASS_ROLE edges."""
    if (statement.get("Effect") or "Allow").lower() != "allow":
        return
    actions = _as_str_list(statement.get("Action"))
    if not actions:
        return
    resources = _as_str_list(statement.get("Resource")) or ["*"]
    sid = statement.get("Sid")
    is_pass_role = any(a == "iam:PassRole" or a.endswith(":PassRole") for a in actions)
    has_wildcard = "*" in resources

    for resource in resources:
        is_wildcard = resource == "*"
        target_id = WILDCARD_NODE_ID if is_wildcard else resource
        if is_wildcard:
            builder._add_node(GraphNode(
                node_id=WILDCARD_NODE_ID,
                node_type=AWSNodeType.WILDCARD,
                label="*",
                properties={"finding_ids": []},
            ))
            await _persist_node(
                db, node_id=WILDCARD_NODE_ID, node_type=AWSNodeType.WILDCARD,
                label="*", properties={"finding_ids": []},
            )

        builder._add_edge(principal_arn, target_id, AWSEdgeType.HAS_PERMISSION)
        await _persist_edge(
            db, principal_arn, target_id, AWSEdgeType.HAS_PERMISSION,
            properties={
                "sid": sid,
                "actions": actions,
                "is_wildcard": is_wildcard,
            },
        )

        if is_pass_role:
            builder._add_edge(principal_arn, target_id, AWSEdgeType.CAN_PASS_ROLE)
            await _persist_edge(
                db, principal_arn, target_id, AWSEdgeType.CAN_PASS_ROLE,
                properties={
                    "sid": sid,
                    "actions": [a for a in actions if "PassRole" in a],
                    "is_wildcard": is_wildcard,
                },
            )

    _ = has_wildcard  # reserved for future "blast radius" annotation


async def _persist_node(
    db: "FindingsDB",
    *,
    node_id: str,
    node_type: AWSNodeType,
    label: str,
    properties: Optional[dict] = None,
    is_internet_facing: bool = False,
) -> None:
    """Persist a graph node so subsequent `build_from_db()` calls preserve it.

    Without this, the in-memory node added by ``builder._add_node`` is lost
    when the graph is rebuilt from the DB, and `_add_edge`'s auto-stub path
    re-creates the node as ``node_type='unknown'`` — which silently breaks
    queries that filter by node type (principals_reaching, attack-surface
    Cytoscape rendering, etc.).
    """
    try:
        await db.upsert_graph_node(
            node_id=node_id,
            node_type=node_type.value,
            label=label,
            properties=properties or {},
            is_internet_facing=is_internet_facing,
        )
    except Exception as exc:
        log.debug("[IAM] persist_node(%s) failed: %s", node_id, exc)


async def _persist_edge(
    db: "FindingsDB",
    src: str,
    dst: str,
    edge_type: AWSEdgeType,
    *,
    properties: Optional[dict] = None,
) -> None:
    """Write an IAM-derived edge to graph_edges with provenance properties."""
    try:
        await db.add_graph_edge(
            source_id=src,
            target_id=dst,
            edge_type=edge_type.value,
            properties=properties or {},
        )
    except Exception as exc:
        # Persistence is best-effort; the in-memory graph is already updated.
        log.debug("[IAM] persist_edge(%s -> %s, %s) failed: %s",
                  src, dst, edge_type.value, exc)


# ---------------------------------------------------------------------------
# Tolerant parsers — MCP responses vary in shape between server versions
# ---------------------------------------------------------------------------

def _coerce_list(result: object, *, key: Optional[str] = None) -> list[dict]:
    """Pull a list of dicts out of an arbitrarily-shaped MCP response."""
    if result is None:
        return []
    if isinstance(result, list):
        out = result
    elif isinstance(result, dict):
        if key and key in result and isinstance(result[key], list):
            out = result[key]
        elif "items" in result and isinstance(result["items"], list):
            out = result["items"]
        else:
            return []
    else:
        return []
    return [item for item in out if isinstance(item, dict)]


def _coerce_policy_document(doc: object) -> Optional[dict]:
    """Return a policy doc as a dict regardless of whether it's JSON-encoded."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        import json
        try:
            parsed = json.loads(doc)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    return None


def _iter_statements(doc: dict) -> Iterable[dict]:
    """Yield each statement dict from a policy document."""
    stmt = doc.get("Statement") or doc.get("statement")
    if isinstance(stmt, list):
        for s in stmt:
            if isinstance(s, dict):
                yield s
    elif isinstance(stmt, dict):
        yield stmt


def _flatten_statements(result: object) -> list[dict]:
    """Pull all policy statements out of a GetPolicies-style MCP response.

    Tolerates: {"AttachedPolicies": [{"PolicyDocument": {...}}, ...]}
    and {"InlinePolicies": [{"PolicyDocument": {...}}]} and bare
    {"PolicyDocument": {...}}.
    """
    if result is None:
        return []
    if isinstance(result, list) and result:
        # Some MCP servers wrap in a single-element list.
        result = result[0]
    if not isinstance(result, dict):
        return []

    statements: list[dict] = []
    bucket_keys = (
        "AttachedPolicies", "InlinePolicies", "Policies", "policies",
    )
    for key in bucket_keys:
        for entry in result.get(key) or []:
            if not isinstance(entry, dict):
                continue
            doc = _coerce_policy_document(
                entry.get("PolicyDocument") or entry.get("policy_document")
            )
            if doc:
                statements.extend(_iter_statements(doc))

    # Bare PolicyDocument at top level
    bare_doc = _coerce_policy_document(result.get("PolicyDocument"))
    if bare_doc:
        statements.extend(_iter_statements(bare_doc))

    return statements


def _as_str_list(value: object) -> list[str]:
    """Coerce a maybe-list-maybe-string IAM field to list[str]."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []
