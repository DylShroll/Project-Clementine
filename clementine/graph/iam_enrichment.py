"""Live IAM topology enrichment for the AWS knowledge graph.

Backed by the official AWS Labs IAM MCP server (``awslabs.iam-mcp-server``)
launched with the ``--readonly`` flag so every mutating tool (create/delete/
attach/detach/update/access-key) is rejected server-side. Clementine itself
only invokes the read tools listed in the candidate tables below.

Sub-passes:

  1. List IAM roles and parse trust policies → ``CAN_ASSUME`` / ``OIDC_TRUSTS``
  2. Inline role + user policies → ``HAS_PERMISSION`` (and ``CAN_PASS_ROLE``
     when an ``iam:PassRole`` statement is found)

The awslabs server has no per-principal "list attached managed policies" tool,
so attached-managed-policy edges are intentionally out of scope for this pass
— inline policies are where custom escalation patterns typically live.

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

from ..mcp_client import unwrap_tool_result
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

# MCP server name. The awslabs server registers itself with snake_case tools;
# we keep PascalCase fallbacks for compatibility with bespoke wrappers users
# may swap in via the same config slot.
_IAM_SERVER = "iam"

_LIST_ROLES_CANDIDATES = ["list_roles", "ListRoles"]
_LIST_USERS_CANDIDATES = ["list_users", "ListUsers"]
_LIST_ROLE_INLINE_POLICIES_CANDIDATES = ["list_role_policies", "ListRolePolicies"]
_GET_ROLE_INLINE_POLICY_CANDIDATES = ["get_role_policy", "GetRolePolicy"]
_LIST_USER_INLINE_POLICIES_CANDIDATES = ["list_user_policies", "ListUserPolicies"]
_GET_USER_INLINE_POLICY_CANDIDATES = ["get_user_policy", "GetUserPolicy"]

# Workaround for an awslabs.iam-mcp-server schema bug: list_users and get_user
# declare `ctx` (FastMCP's Context object) as a *required* tool argument even
# though it should be auto-injected by the framework. Empirically the smallest
# value that passes the pydantic validator is a stub CallToolResult shape; the
# server then ignores it and runs the actual IAM call. Remove this once the
# upstream signature drops `ctx` from the public schema.
_CTX_STUB = {"content": []}


async def enrich_iam(
    builder: "GraphBuilder",
    *,
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
) -> None:
    """Run all three IAM sub-passes; record outcome in enrichment_status.

    Safe to call when the iam server is unavailable — the function will mark
    the enrichment as ``unavailable`` and return without touching the graph.
    """
    if not mcp.is_available(_IAM_SERVER):
        await db.set_enrichment_status(
            "iam", "unavailable", f"{_IAM_SERVER} MCP not registered or down"
        )
        log.info("[IAM] %s unavailable — skipping IAM enumeration", _IAM_SERVER)
        return

    list_roles_tool = mcp.find_tool(_IAM_SERVER, _LIST_ROLES_CANDIDATES)
    list_users_tool = mcp.find_tool(_IAM_SERVER, _LIST_USERS_CANDIDATES)
    list_role_pols_tool = mcp.find_tool(_IAM_SERVER, _LIST_ROLE_INLINE_POLICIES_CANDIDATES)
    get_role_pol_tool = mcp.find_tool(_IAM_SERVER, _GET_ROLE_INLINE_POLICY_CANDIDATES)
    list_user_pols_tool = mcp.find_tool(_IAM_SERVER, _LIST_USER_INLINE_POLICIES_CANDIDATES)
    get_user_pol_tool = mcp.find_tool(_IAM_SERVER, _GET_USER_INLINE_POLICY_CANDIDATES)

    if not list_roles_tool and not list_users_tool:
        await db.set_enrichment_status(
            "iam", "unavailable",
            f"{_IAM_SERVER} advertises no IAM list tools",
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

    if list_role_pols_tool and get_role_pol_tool and role_arns:
        try:
            await _enumerate_role_inline_policies(
                builder, db, mcp, limiter,
                list_tool=list_role_pols_tool,
                get_tool=get_role_pol_tool,
                role_arns=role_arns,
            )
        except Exception as exc:
            failures.append(f"role_policies: {exc}")
            log.warning("[IAM] role policy enumeration failed: %s", exc)

    if list_user_pols_tool and get_user_pol_tool and user_arns:
        try:
            await _enumerate_user_inline_policies(
                builder, db, mcp, limiter,
                list_tool=list_user_pols_tool,
                get_tool=get_user_pol_tool,
                user_arns=user_arns,
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
        result = await mcp.call_tool(_IAM_SERVER, tool_name, {})
    # `None` means MCPRegistry swallowed an MCPServerUnavailable (retries
    # exhausted, likely AccessDenied/ExpiredToken) — raise so enrich_iam
    # records the failure instead of mistaking it for an empty account.
    if result is None:
        raise RuntimeError(
            f"{tool_name} returned no result — server marked unavailable. "
            f"Check enrichment logs for the underlying MCP error (typically "
            f"AccessDenied / ExpiredToken / NoCredentials)."
        )
    result = unwrap_tool_result(result)
    roles = (
        _coerce_list(result, key="Roles")
        or _coerce_list(result, key="roles")
    )
    if not roles:
        log.debug("[IAM] %s returned no roles", tool_name)
        return []

    arns: list[str] = []
    for role in roles:
        arn = role.get("Arn") or role.get("arn")
        if not arn:
            continue
        name = (
            role.get("RoleName")
            or role.get("role_name")
            or role.get("name")
            or arn.split("/")[-1]
        )
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
        trust = (
            role.get("AssumeRolePolicyDocument")
            or role.get("assume_role_policy_document")
            or role.get("trust_policy")
        )
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
        # `ctx` is a workaround — see _CTX_STUB above. list_users won't pass
        # the awslabs server's pydantic validator without it.
        result = await mcp.call_tool(_IAM_SERVER, tool_name, {"ctx": _CTX_STUB})
    if result is None:
        raise RuntimeError(
            f"{tool_name} returned no result — server marked unavailable. "
            f"Check enrichment logs for the underlying MCP error (typically "
            f"AccessDenied / ExpiredToken / NoCredentials)."
        )
    result = unwrap_tool_result(result)
    users = (
        _coerce_list(result, key="users")
        or _coerce_list(result, key="Users")
    )
    if not users:
        log.debug("[IAM] %s returned no users", tool_name)
        return []

    arns: list[str] = []
    for user in users:
        arn = user.get("Arn") or user.get("arn")
        if not arn:
            continue
        name = (
            user.get("UserName")
            or user.get("user_name")
            or user.get("name")
            or arn.split("/")[-1]
        )
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


async def _enumerate_role_inline_policies(
    builder: "GraphBuilder",
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    *,
    list_tool: str,
    get_tool: str,
    role_arns: list[str],
) -> None:
    """For each role: list_role_policies → get_role_policy → HAS_PERMISSION."""
    for arn in role_arns:
        role_name = arn.split("/")[-1]
        names = await _list_inline_policy_names(
            mcp, limiter, tool_name=list_tool,
            args={"role_name": role_name, "RoleName": role_name},
            principal_label=f"role={role_name}",
        )
        for pol_name in names:
            doc = await _fetch_inline_policy_doc(
                mcp, limiter, tool_name=get_tool,
                args={
                    "role_name": role_name, "policy_name": pol_name,
                    "RoleName": role_name, "PolicyName": pol_name,
                },
                principal_label=f"role={role_name}/{pol_name}",
            )
            if not doc:
                continue
            for stmt in _iter_statements(doc):
                await _ingest_policy_statement(
                    builder=builder, db=db, principal_arn=arn, statement=stmt,
                )


async def _enumerate_user_inline_policies(
    builder: "GraphBuilder",
    db: "FindingsDB",
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    *,
    list_tool: str,
    get_tool: str,
    user_arns: list[str],
) -> None:
    """For each user: list_user_policies → get_user_policy → HAS_PERMISSION."""
    for arn in user_arns:
        user_name = arn.split("/")[-1]
        names = await _list_inline_policy_names(
            mcp, limiter, tool_name=list_tool,
            args={"user_name": user_name, "UserName": user_name},
            principal_label=f"user={user_name}",
        )
        for pol_name in names:
            doc = await _fetch_inline_policy_doc(
                mcp, limiter, tool_name=get_tool,
                args={
                    "user_name": user_name, "policy_name": pol_name,
                    "UserName": user_name, "PolicyName": pol_name,
                },
                principal_label=f"user={user_name}/{pol_name}",
            )
            if not doc:
                continue
            for stmt in _iter_statements(doc):
                await _ingest_policy_statement(
                    builder=builder, db=db, principal_arn=arn, statement=stmt,
                )


async def _list_inline_policy_names(
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    *,
    tool_name: str,
    args: dict,
    principal_label: str,
) -> list[str]:
    """Pull inline-policy names from a list_*_policies response."""
    try:
        async with limiter:
            result = await mcp.call_tool(_IAM_SERVER, tool_name, args)
    except Exception as exc:
        log.debug("[IAM] %s(%s) failed: %s", tool_name, principal_label, exc)
        return []
    result = unwrap_tool_result(result)
    if not isinstance(result, dict):
        return []
    raw = (
        result.get("policy_names")
        or result.get("PolicyNames")
        or result.get("policies")
        or []
    )
    return [n for n in raw if isinstance(n, str)]


async def _fetch_inline_policy_doc(
    mcp: "MCPRegistry",
    limiter: "RateLimiter",
    *,
    tool_name: str,
    args: dict,
    principal_label: str,
) -> Optional[dict]:
    """Fetch a single inline policy document, returning it as a dict."""
    try:
        async with limiter:
            result = await mcp.call_tool(_IAM_SERVER, tool_name, args)
    except Exception as exc:
        log.debug("[IAM] %s(%s) failed: %s", tool_name, principal_label, exc)
        return None
    result = unwrap_tool_result(result)
    if not isinstance(result, dict):
        return None
    raw_doc = (
        result.get("policy_document")
        or result.get("PolicyDocument")
    )
    return _coerce_policy_document(raw_doc)


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
    queries that filter by node type (paths_between, attack-surface
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
    """Return a policy doc as a dict regardless of whether it's JSON-encoded.

    Trust-policy documents from IAM list_roles are sometimes returned by the
    upstream MCP server as percent-encoded JSON (the raw shape from the AWS
    API). Try a urllib.unquote pass on json.loads failure before giving up.
    """
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        import json
        try:
            parsed = json.loads(doc)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            pass
        try:
            from urllib.parse import unquote
            parsed = json.loads(unquote(doc))
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


def _as_str_list(value: object) -> list[str]:
    """Coerce a maybe-list-maybe-string IAM field to list[str]."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []
