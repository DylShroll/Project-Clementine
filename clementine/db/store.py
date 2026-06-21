"""Async SQLite persistence for Project Clementine — the FindingsDB handle.

All writes are serialised through an asyncio lock so concurrent phase tasks
never corrupt the database.

Production note: for encrypted storage replace aiosqlite with pysqlcipher3
(SQLCipher) and pass the passphrase via the CLEMENTINE_DB_KEY env var.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Optional

import aiosqlite

from .models import (
    AttackChain,
    ChainComponent,
    ChainRole,
    Finding,
    GraphRelationship,
    RemediationAction,
    Severity,
    _row_to_action,
    _row_to_chain,
    _row_to_finding,
)
from .schema import _SCHEMA_SQL, _apply_migrations

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class FindingsDB:
    """Async wrapper around the SQLite findings store.

    Usage::

        async with FindingsDB.open("sqlite:///findings.db") as db:
            await db.insert_finding(finding)
            chains = await db.get_attack_chains()
    """

    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn
        # Serialises concurrent writes — reads are lock-free
        self._write_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    @asynccontextmanager
    async def open(cls, dsn: str) -> AsyncIterator["FindingsDB"]:
        """Open (or create) the database, apply the schema, yield a handle.

        Only SQLite DSNs (sqlite:///path) are currently supported.  Extend
        this method to support PostgreSQL via asyncpg when needed.
        """
        if dsn.startswith("sqlite:///"):
            db_path = dsn[len("sqlite:///"):]
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        elif dsn.startswith("sqlite://"):
            # In-memory: sqlite://:memory:
            db_path = dsn[len("sqlite://"):]
        else:
            raise ValueError(
                f"Unsupported DB DSN scheme: {dsn!r}. "
                "Only sqlite:/// is currently supported."
            )

        # Open the connection manually so we can shield the close from anyio's
        # cancellation cascade.  aiosqlite uses asyncio Futures for its
        # background thread; if anyio cancels the scope during teardown those
        # futures are cancelled too, raising CancelledError inside close().
        import anyio
        conn_cm = aiosqlite.connect(db_path)
        conn = await conn_cm.__aenter__()
        try:
            conn.row_factory = aiosqlite.Row
            await conn.executescript(_SCHEMA_SQL)
            await conn.commit()
            await _apply_migrations(conn)
            yield cls(conn)
        finally:
            with anyio.CancelScope(shield=True):
                await conn_cm.__aexit__(None, None, None)

    # ------------------------------------------------------------------
    # State machine persistence
    # ------------------------------------------------------------------

    async def set_state(self, key: str, value: str) -> None:
        """Persist an orchestrator state-machine key/value pair."""
        async with self._write_lock:
            await self._conn.execute(
                "INSERT OR REPLACE INTO assessment_state (key, value) VALUES (?, ?)",
                (key, value),
            )
            await self._conn.commit()

    async def get_state(self, key: str, default: str = "") -> str:
        """Read an orchestrator state-machine value."""
        async with self._conn.execute(
            "SELECT value FROM assessment_state WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
        return row["value"] if row else default

    # ------------------------------------------------------------------
    # Findings CRUD
    # ------------------------------------------------------------------

    async def insert_finding(self, finding: Finding) -> None:
        """Insert a normalised finding; silently ignores duplicate IDs."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT OR IGNORE INTO findings (
                    id, source, phase, severity, category, title, description,
                    resource_type, resource_id, aws_account_id, aws_region,
                    evidence_type, evidence_data, remediation_summary,
                    remediation_cli, remediation_iac, remediation_doc_url,
                    compliance_mappings, confidence, is_validated, raw_source_data,
                    provider, tenant_id, subscription_id, management_group_id,
                    resource_group, azure_resource_id, azure_region,
                    iac_source_path, iac_source_line
                ) VALUES (
                    :id, :source, :phase, :severity, :category, :title, :description,
                    :resource_type, :resource_id, :aws_account_id, :aws_region,
                    :evidence_type, :evidence_data, :remediation_summary,
                    :remediation_cli, :remediation_iac, :remediation_doc_url,
                    :compliance_mappings, :confidence, :is_validated, :raw_source_data,
                    :provider, :tenant_id, :subscription_id, :management_group_id,
                    :resource_group, :azure_resource_id, :azure_region,
                    :iac_source_path, :iac_source_line
                )
                """,
                {
                    **finding.__dict__,
                    "evidence_data": json.dumps(finding.evidence_data) if finding.evidence_data else None,
                    "compliance_mappings": json.dumps(finding.compliance_mappings) if finding.compliance_mappings else None,
                    "raw_source_data": json.dumps(finding.raw_source_data) if finding.raw_source_data else None,
                    "is_validated": int(finding.is_validated),
                    "severity": finding.severity.value,
                },
            )
            await self._conn.commit()

    async def get_findings(
        self,
        phase: Optional[int] = None,
        severity: Optional[Severity] = None,
        source: Optional[str] = None,
        category: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> list[Finding]:
        """Query findings with optional filters.  Returns all matching rows."""
        clauses: list[str] = []
        params: list = []

        if phase is not None:
            clauses.append("phase = ?")
            params.append(phase)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity.value)
        if source is not None:
            clauses.append("source = ?")
            params.append(source)
        if category is not None:
            # Support prefix matching (e.g. "WSTG-INPV") for broad category queries
            clauses.append("category LIKE ?")
            params.append(f"{category}%")
        if provider is not None:
            clauses.append("provider = ?")
            params.append(provider)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM findings {where} ORDER BY severity, created_at"

        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()

        return [_row_to_finding(row) for row in rows]

    async def update_finding_triage(
        self,
        finding_id: str,
        confidence: float,
        is_false_positive: bool,
        notes: str,
    ) -> None:
        """Persist the LLM-triage verdict for a finding."""
        async with self._write_lock:
            await self._conn.execute(
                """
                UPDATE findings
                SET triage_confidence = ?,
                    triage_is_false_positive = ?,
                    triage_notes = ?
                WHERE id = ?
                """,
                (confidence, int(is_false_positive), notes, finding_id),
            )
            await self._conn.commit()

    # ------------------------------------------------------------------
    # Attack chains CRUD
    # ------------------------------------------------------------------

    async def insert_attack_chain(
        self,
        chain: AttackChain,
        components: list[ChainComponent],
        actions: list[RemediationAction],
    ) -> None:
        """Insert a complete attack chain with its components and remediations."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT OR IGNORE INTO attack_chains
                    (id, pattern_name, severity, narrative, entry_finding,
                     breach_cost_low, breach_cost_high, chain_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain.id, chain.pattern_name, chain.severity.value,
                    chain.narrative, chain.entry_finding_id,
                    chain.breach_cost_low, chain.breach_cost_high,
                    chain.chain_source,
                ),
            )
            for comp in components:
                await self._conn.execute(
                    """
                    INSERT OR IGNORE INTO chain_components
                        (chain_id, finding_id, role, sequence_order)
                    VALUES (?, ?, ?, ?)
                    """,
                    (comp.chain_id, comp.finding_id, comp.role.value, comp.sequence_order),
                )
            for action in actions:
                await self._conn.execute(
                    """
                    INSERT OR IGNORE INTO remediation_actions
                        (id, chain_id, finding_id, priority_order, action_summary,
                         effort_level, breaks_chain, cli_command, iac_snippet,
                         aws_sop_ref, doc_urls)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action.id, action.chain_id, action.finding_id,
                        action.priority_order, action.action_summary,
                        action.effort_level.value, int(action.breaks_chain),
                        action.cli_command, action.iac_snippet,
                        action.aws_sop_ref,
                        json.dumps(action.doc_urls) if action.doc_urls else None,
                    ),
                )
            await self._conn.commit()

    async def get_attack_chains(self) -> list[AttackChain]:
        """Return all attack chains ordered by severity (critical first)."""
        severity_order = "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"
        async with self._conn.execute(
            f"SELECT * FROM attack_chains ORDER BY {severity_order}"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_chain(row) for row in rows]

    async def get_chain_findings(self, chain_id: str) -> list[tuple[Finding, ChainRole, int]]:
        """Return (Finding, role, sequence_order) tuples for a chain's components."""
        async with self._conn.execute(
            """
            SELECT f.*, cc.role, cc.sequence_order
            FROM chain_components cc
            JOIN findings f ON f.id = cc.finding_id
            WHERE cc.chain_id = ?
            ORDER BY cc.sequence_order
            """,
            (chain_id,),
        ) as cur:
            rows = await cur.fetchall()

        results = []
        for row in rows:
            finding = _row_to_finding(row)
            role = ChainRole(row["role"])
            order = row["sequence_order"]
            results.append((finding, role, order))
        return results

    async def get_remediation_actions(
        self,
        chain_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> list[RemediationAction]:
        """Return remediation actions for a chain or individual finding."""
        if chain_id:
            sql = "SELECT * FROM remediation_actions WHERE chain_id = ? ORDER BY priority_order"
            params = [chain_id]
        elif finding_id:
            sql = "SELECT * FROM remediation_actions WHERE finding_id = ? ORDER BY priority_order"
            params = [finding_id]
        else:
            sql = "SELECT * FROM remediation_actions ORDER BY priority_order"
            params = []

        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [_row_to_action(row) for row in rows]

    # ------------------------------------------------------------------
    # Resource graph
    # ------------------------------------------------------------------

    async def add_resource_edge(
        self, source_arn: str, target_arn: str, relationship: GraphRelationship
    ) -> None:
        """Record a relationship between two AWS resources."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT OR IGNORE INTO resource_graph (source_arn, target_arn, relationship)
                VALUES (?, ?, ?)
                """,
                (source_arn, target_arn, relationship.value),
            )
            await self._conn.commit()

    async def get_resource_neighbors(
        self, arn: str, relationship: Optional[GraphRelationship] = None
    ) -> list[str]:
        """Return ARNs of resources that are reachable from *arn* via *relationship*.

        If *relationship* is None, all outbound edges are returned.
        """
        if relationship:
            sql = "SELECT target_arn FROM resource_graph WHERE source_arn = ? AND relationship = ?"
            params = [arn, relationship.value]
        else:
            sql = "SELECT target_arn FROM resource_graph WHERE source_arn = ?"
            params = [arn]

        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [row["target_arn"] for row in rows]

    # ------------------------------------------------------------------
    # Knowledge graph nodes
    # ------------------------------------------------------------------

    async def upsert_graph_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        properties: dict,
        is_internet_facing: bool = False,
        *,
        provider: str = "aws",
        tenant_id: Optional[str] = None,
        subscription_id: Optional[str] = None,
        management_group_id: Optional[str] = None,
        resource_group: Optional[str] = None,
        azure_resource_id: Optional[str] = None,
        node_kind: Optional[str] = None,
        compressed_alias: Optional[str] = None,
        provenance: str = "live",
    ) -> None:
        """Persist a graph node; merges properties on conflict.

        ``provenance`` distinguishes ``live`` nodes (built from a runtime
        cloud audit) from ``iac`` nodes (projected from an IaC plan) and
        ``live+iac`` (the same logical resource confirmed in both
        sources). Phase 0 / Workstream B writes ``iac`` nodes; the
        identity-merge sweep promotes them to ``live+iac`` when a live
        equivalent is found.
        """
        if provenance not in ("live", "iac", "live+iac"):
            raise ValueError(f"invalid provenance: {provenance!r}")
        props_json = json.dumps(properties)
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT INTO graph_nodes (
                    node_id, node_type, label, properties, internet_facing,
                    provider, tenant_id, subscription_id, management_group_id,
                    resource_group, azure_resource_id, node_kind, compressed_alias,
                    provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    label = excluded.label,
                    node_type = excluded.node_type,
                    properties = excluded.properties,
                    internet_facing = MAX(internet_facing, excluded.internet_facing),
                    provider = excluded.provider,
                    tenant_id = COALESCE(excluded.tenant_id, tenant_id),
                    subscription_id = COALESCE(excluded.subscription_id, subscription_id),
                    management_group_id = COALESCE(excluded.management_group_id, management_group_id),
                    resource_group = COALESCE(excluded.resource_group, resource_group),
                    azure_resource_id = COALESCE(excluded.azure_resource_id, azure_resource_id),
                    node_kind = COALESCE(excluded.node_kind, node_kind),
                    compressed_alias = COALESCE(excluded.compressed_alias, compressed_alias),
                    -- Promote on disagreement: live + iac -> live+iac. Never demote.
                    provenance = CASE
                        WHEN provenance = excluded.provenance THEN provenance
                        ELSE 'live+iac'
                    END
                """,
                (
                    node_id, node_type, label[:500], props_json, int(is_internet_facing),
                    provider, tenant_id, subscription_id, management_group_id,
                    resource_group, azure_resource_id, node_kind, compressed_alias,
                    provenance,
                ),
            )
            await self._conn.commit()

    # ------------------------------------------------------------------
    # Rich graph edges (graph_edges + enrichment_status)
    # ------------------------------------------------------------------

    async def add_graph_edge(
        self,
        *,
        source_id: str,
        target_id: str,
        edge_type: str,
        properties: Optional[dict] = None,
        provider: str = "aws",
        edge_kind: Optional[str] = None,
        role_definition_id: Optional[str] = None,
        scope: Optional[str] = None,
        scope_level: Optional[str] = None,
        inherited: bool = False,
        source_assignment_id: Optional[str] = None,
        condition_expr: Optional[str] = None,
        pim_eligible: bool = False,
        audience: Optional[str] = None,
        provenance: str = "live",
    ) -> None:
        """Insert (or merge) a typed edge with optional properties.

        On UNIQUE conflict (same source/target/type), merges properties:
          * ``finding_ids`` lists are union-merged
          * other keys: existing values win
          * ``provenance`` is promoted to ``live+iac`` whenever an
            insertion's provenance disagrees with the row's existing
            value (e.g. an iac edge being added on top of a live edge
            for the same logical relationship).
        """
        if provenance not in ("live", "iac", "live+iac"):
            raise ValueError(f"invalid provenance: {provenance!r}")
        props = properties or {}
        async with self._write_lock:
            async with self._conn.execute(
                """
                SELECT edge_id, properties, provenance FROM graph_edges
                WHERE source_id = ? AND target_id = ? AND edge_type = ?
                """,
                (source_id, target_id, edge_type),
            ) as cur:
                row = await cur.fetchone()

            if row is None:
                edge_id = str(uuid.uuid4())
                await self._conn.execute(
                    """
                    INSERT INTO graph_edges (
                        edge_id, source_id, target_id, edge_type, properties,
                        provider, edge_kind, role_definition_id, scope, scope_level,
                        inherited, source_assignment_id, condition_expr, pim_eligible, audience,
                        provenance
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        edge_id, source_id, target_id, edge_type, json.dumps(props),
                        provider, edge_kind, role_definition_id, scope, scope_level,
                        int(inherited), source_assignment_id, condition_expr,
                        int(pim_eligible), audience, provenance,
                    ),
                )
            else:
                existing_props = json.loads(row["properties"]) if row["properties"] else {}
                merged = dict(existing_props)
                for k, v in props.items():
                    if k == "finding_ids":
                        existing = merged.get("finding_ids") or []
                        seen = set(existing)
                        for fid in (v or []):
                            if fid not in seen:
                                existing.append(fid)
                                seen.add(fid)
                        merged["finding_ids"] = existing
                    elif k not in merged:
                        merged[k] = v
                # Promote provenance on disagreement (live + iac -> live+iac).
                existing_prov = row["provenance"] or "live"
                new_prov = (
                    existing_prov if existing_prov == provenance else "live+iac"
                )
                await self._conn.execute(
                    """
                    UPDATE graph_edges
                    SET properties = ?, provenance = ?
                    WHERE edge_id = ?
                    """,
                    (json.dumps(merged), new_prov, row["edge_id"]),
                )
            await self._conn.commit()

    async def get_graph_edges(
        self, edge_type: Optional[str] = None
    ) -> list[dict]:
        """Return all rich edges, optionally filtered by edge_type."""
        if edge_type is not None:
            sql = "SELECT source_id, target_id, edge_type, properties FROM graph_edges WHERE edge_type = ?"
            params = [edge_type]
        else:
            sql = "SELECT source_id, target_id, edge_type, properties FROM graph_edges"
            params = []
        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [
            {
                "source_id": r["source_id"],
                "target_id": r["target_id"],
                "edge_type": r["edge_type"],
                "properties": json.loads(r["properties"]) if r["properties"] else {},
            }
            for r in rows
        ]

    async def set_enrichment_status(
        self, pass_name: str, status: str, detail: str = ""
    ) -> None:
        """Record the outcome of an enrichment pass (ok / partial / unavailable)."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT INTO enrichment_status (pass_name, status, detail, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(pass_name) DO UPDATE SET
                    status = excluded.status,
                    detail = excluded.detail,
                    updated_at = excluded.updated_at
                """,
                (pass_name, status, detail),
            )
            await self._conn.commit()

    # ------------------------------------------------------------------
    # Azure-specific tables
    # ------------------------------------------------------------------

    async def insert_azure_role_assignment(self, d: dict) -> None:
        """Upsert a single Azure role assignment row."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT INTO azure_role_assignments (
                    assignment_id, tenant_id, principal_id, principal_type,
                    role_definition_id, role_definition_name, scope, scope_level,
                    inherited, pim_eligible, condition_expr
                ) VALUES (
                    :assignment_id, :tenant_id, :principal_id, :principal_type,
                    :role_definition_id, :role_definition_name, :scope, :scope_level,
                    :inherited, :pim_eligible, :condition_expr
                )
                ON CONFLICT(assignment_id) DO UPDATE SET
                    scope_level = excluded.scope_level,
                    inherited = excluded.inherited,
                    pim_eligible = excluded.pim_eligible
                """,
                {
                    "assignment_id": d.get("assignment_id", str(uuid.uuid4())),
                    "tenant_id": d.get("tenant_id", ""),
                    "principal_id": d.get("principal_id", ""),
                    "principal_type": d.get("principal_type"),
                    "role_definition_id": d.get("role_definition_id", ""),
                    "role_definition_name": d.get("role_definition_name"),
                    "scope": d.get("scope", ""),
                    "scope_level": d.get("scope_level"),
                    "inherited": int(d.get("inherited", False)),
                    "pim_eligible": int(d.get("pim_eligible", False)),
                    "condition_expr": d.get("condition_expr"),
                },
            )
            await self._conn.commit()

    async def get_azure_role_assignments(
        self, scope_prefix: Optional[str] = None
    ) -> list[dict]:
        """Return Azure role assignments, optionally filtered by scope prefix."""
        if scope_prefix:
            sql = "SELECT * FROM azure_role_assignments WHERE scope LIKE ? ORDER BY scope"
            params = [f"{scope_prefix}%"]
        else:
            sql = "SELECT * FROM azure_role_assignments ORDER BY scope"
            params = []
        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def insert_azure_federated_credential(self, d: dict) -> None:
        """Upsert a federated identity credential row."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT INTO azure_federated_credentials (
                    id, parent_resource_id, issuer, subject, audiences, name,
                    matched_aks_cluster_id, matched_k8s_subject
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    matched_aks_cluster_id = COALESCE(excluded.matched_aks_cluster_id, matched_aks_cluster_id),
                    matched_k8s_subject = COALESCE(excluded.matched_k8s_subject, matched_k8s_subject)
                """,
                (
                    d.get("id", str(uuid.uuid4())),
                    d.get("parent_resource_id", ""),
                    d.get("issuer", ""),
                    d.get("subject", ""),
                    json.dumps(d.get("audiences", [])),
                    d.get("name"),
                    d.get("matched_aks_cluster_id"),
                    d.get("matched_k8s_subject"),
                ),
            )
            await self._conn.commit()

    async def get_azure_federated_credentials(
        self, app_id: Optional[str] = None
    ) -> list[dict]:
        """Return federated credentials, optionally for a specific app/UAMI."""
        if app_id:
            sql = "SELECT * FROM azure_federated_credentials WHERE parent_resource_id = ?"
            params = [app_id]
        else:
            sql = "SELECT * FROM azure_federated_credentials"
            params = []
        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def insert_azure_compliance_finding(self, d: dict) -> None:
        """Insert a compliance finding from Prowler or Defender for Cloud."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT OR IGNORE INTO azure_compliance_findings (
                    id, framework, control_id, resource_id, subscription_id,
                    state, severity, source, raw
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    d.get("id", str(uuid.uuid4())),
                    d.get("framework", ""),
                    d.get("control_id", ""),
                    d.get("resource_id"),
                    d.get("subscription_id"),
                    d.get("state", ""),
                    d.get("severity"),
                    d.get("source", ""),
                    json.dumps(d.get("raw")) if d.get("raw") else None,
                ),
            )
            await self._conn.commit()

    async def get_azure_compliance_findings(
        self,
        framework: Optional[str] = None,
        state: Optional[str] = None,
    ) -> list[dict]:
        """Return compliance findings, optionally filtered by framework and state."""
        clauses, params = [], []
        if framework:
            clauses.append("framework = ?")
            params.append(framework)
        if state:
            clauses.append("state = ?")
            params.append(state)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM azure_compliance_findings {where} ORDER BY framework, control_id"
        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # AI usage telemetry
    # ------------------------------------------------------------------

    async def get_or_create_run_id(self) -> str:
        """Return the current run's ID, generating + persisting one if absent.

        Stamped fresh each time a new assessment starts (orchestrator clears
        it on new runs); persists across resumes so token accounting follows
        the logical run rather than the process.
        """
        existing = await self.get_state("current_run_id", "")
        if existing:
            return existing
        new_id = str(uuid.uuid4())
        await self.set_state("current_run_id", new_id)
        return new_id

    async def reset_run_id(self) -> str:
        """Generate a new run_id and persist it; returns the new value."""
        new_id = str(uuid.uuid4())
        await self.set_state("current_run_id", new_id)
        return new_id

    async def record_ai_usage(
        self,
        *,
        run_id: str,
        call_site: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_creation_tokens: int = 0,
        cache_read_tokens: int = 0,
    ) -> None:
        """Insert a row capturing one Claude API call's token usage."""
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT INTO ai_usage (
                    run_id, call_site, model, input_tokens, output_tokens,
                    cache_creation_tokens, cache_read_tokens
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, call_site, model,
                    int(input_tokens), int(output_tokens),
                    int(cache_creation_tokens), int(cache_read_tokens),
                ),
            )
            await self._conn.commit()

    async def get_ai_usage_summary(self, run_id: str) -> list[dict]:
        """Return aggregated token usage rows for a run, grouped by call_site/model.

        Each dict has: call_site, model, calls, input_tokens, output_tokens,
        cache_creation_tokens, cache_read_tokens.
        """
        async with self._conn.execute(
            """
            SELECT
                call_site,
                model,
                COUNT(*)                        AS calls,
                SUM(input_tokens)               AS input_tokens,
                SUM(output_tokens)              AS output_tokens,
                SUM(cache_creation_tokens)      AS cache_creation_tokens,
                SUM(cache_read_tokens)          AS cache_read_tokens
            FROM ai_usage
            WHERE run_id = ?
            GROUP BY call_site, model
            ORDER BY input_tokens DESC
            """,
            (run_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [
            {
                "call_site": r["call_site"],
                "model": r["model"],
                "calls": r["calls"],
                "input_tokens": r["input_tokens"] or 0,
                "output_tokens": r["output_tokens"] or 0,
                "cache_creation_tokens": r["cache_creation_tokens"] or 0,
                "cache_read_tokens": r["cache_read_tokens"] or 0,
            }
            for r in rows
        ]

    async def get_graph_nodes(self) -> list:
        """Return all persisted graph nodes as GraphNode objects."""
        from .graph.model import GraphNode  # local import avoids cycles
        async with self._conn.execute(
            "SELECT node_id, node_type, label, properties, internet_facing FROM graph_nodes"
        ) as cur:
            rows = await cur.fetchall()

        nodes = []
        for row in rows:
            props = json.loads(row["properties"]) if row["properties"] else {}
            nodes.append(GraphNode(
                node_id=row["node_id"],
                node_type=row["node_type"],  # raw string; AWSNodeType and AzureNodeType are both str enums
                label=row["label"],
                properties=props,
                is_internet_facing=bool(row["internet_facing"]),
            ))
        return nodes
