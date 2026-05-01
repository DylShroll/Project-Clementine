"""
Async SQLite database layer for Project Clementine.

Manages the shared findings store used by all assessment phases.  All writes
are serialised through an asyncio lock so concurrent phase tasks never
corrupt the database.

Production note: for encrypted storage replace aiosqlite with pysqlcipher3
(SQLCipher) and pass the passphrase via the CLEMENTINE_DB_KEY env var.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Optional

import aiosqlite

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enumerations that mirror the DB constraints
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvidenceType(str, Enum):
    HTTP_EXCHANGE = "http_exchange"
    CLI_OUTPUT = "cli_output"
    SCREENSHOT = "screenshot"
    CONFIG_DUMP = "config_dump"


class ResourceType(str, Enum):
    URL = "url"
    EC2 = "ec2"
    S3 = "s3"
    IAM = "iam"
    RDS = "rds"
    LAMBDA = "lambda"
    VPC = "vpc"
    SG = "sg"
    OTHER = "other"


class ChainRole(str, Enum):
    ENTRY = "entry"
    PIVOT = "pivot"
    AMPLIFIER = "amplifier"


class EffortLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class GraphRelationship(str, Enum):
    HOSTS = "hosts"
    ROUTES_TO = "routes_to"
    ATTACHED_TO = "attached_to"
    HAS_ACCESS_TO = "has_access_to"
    MEMBER_OF = "member_of"
    # Knowledge graph edge types
    CAN_ASSUME = "CAN_ASSUME"
    HAS_PERMISSION = "HAS_PERMISSION"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"
    INTERNET_FACING = "INTERNET_FACING"
    SSRF_REACHABLE = "SSRF_REACHABLE"
    HOSTS_APP = "HOSTS_APP"
    IRSA_BOUND = "IRSA_BOUND"
    OIDC_TRUSTS = "OIDC_TRUSTS"


# ---------------------------------------------------------------------------
# Dataclasses (lightweight DTO layer — no ORM overhead)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Normalised finding from any MCP source tool."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""              # autopentest | cloud-audit | prowler
    phase: int = 1                # 1-4
    severity: Severity = Severity.INFO
    category: str = ""            # WSTG code or CIS control ID
    title: str = ""
    description: str = ""
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    aws_account_id: Optional[str] = None
    aws_region: Optional[str] = None
    evidence_type: Optional[str] = None
    evidence_data: Optional[dict] = None   # stored as JSON
    remediation_summary: Optional[str] = None
    remediation_cli: Optional[str] = None
    remediation_iac: Optional[str] = None
    remediation_doc_url: Optional[str] = None
    compliance_mappings: Optional[dict] = None   # stored as JSON
    confidence: float = 1.0
    is_validated: bool = False
    raw_source_data: Optional[dict] = None  # original tool JSON
    # AI triage outputs — populated by the ai_triage phase, None until then
    triage_confidence: Optional[float] = None
    triage_is_false_positive: Optional[bool] = None
    triage_notes: Optional[str] = None
    # Azure-specific fields — populated for azure provider findings, None for AWS
    provider: str = "aws"
    tenant_id: Optional[str] = None
    subscription_id: Optional[str] = None
    management_group_id: Optional[str] = None
    resource_group: Optional[str] = None
    azure_resource_id: Optional[str] = None
    azure_region: Optional[str] = None


@dataclass
class AttackChain:
    """A correlated compound attack path produced by the correlation engine."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern_name: str = ""
    severity: Severity = Severity.HIGH
    narrative: str = ""
    entry_finding_id: Optional[str] = None
    breach_cost_low: Optional[float] = None
    breach_cost_high: Optional[float] = None
    # 'pattern' for rule-based matches; 'ai-discovered' for LLM-proposed chains
    chain_source: str = "pattern"


@dataclass
class ChainComponent:
    """Links a Finding to an AttackChain with a role and ordering."""
    chain_id: str = ""
    finding_id: str = ""
    role: ChainRole = ChainRole.ENTRY
    sequence_order: int = 0


@dataclass
class RemediationAction:
    """Prioritised remediation step linked to a chain or individual finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: Optional[str] = None
    finding_id: Optional[str] = None
    priority_order: int = 0
    action_summary: str = ""
    effort_level: EffortLevel = EffortLevel.MEDIUM
    breaks_chain: bool = False
    cli_command: Optional[str] = None
    iac_snippet: Optional[str] = None
    aws_sop_ref: Optional[str] = None
    doc_urls: Optional[list[str]] = None  # stored as JSON


# ---------------------------------------------------------------------------
# DDL — all table creation statements
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS findings (
    id                       TEXT PRIMARY KEY,
    source                   TEXT NOT NULL,
    phase                    INTEGER NOT NULL,
    severity                 TEXT NOT NULL,
    category                 TEXT NOT NULL,
    title                    TEXT NOT NULL,
    description              TEXT NOT NULL,
    resource_type            TEXT,
    resource_id              TEXT,
    aws_account_id           TEXT,
    aws_region               TEXT,
    evidence_type            TEXT,
    evidence_data            TEXT,        -- JSON blob
    remediation_summary      TEXT,
    remediation_cli          TEXT,
    remediation_iac          TEXT,
    remediation_doc_url      TEXT,
    compliance_mappings      TEXT,        -- JSON blob
    confidence               REAL DEFAULT 1.0,
    is_validated             INTEGER DEFAULT 0,
    created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_source_data          TEXT,        -- JSON blob
    -- LLM-triage outputs (NULL until the ai_triage phase has run)
    triage_confidence        REAL,
    triage_is_false_positive INTEGER,
    triage_notes             TEXT
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id               TEXT PRIMARY KEY,
    pattern_name     TEXT NOT NULL,
    severity         TEXT NOT NULL,
    narrative        TEXT NOT NULL,
    entry_finding    TEXT REFERENCES findings(id),
    breach_cost_low  REAL,
    breach_cost_high REAL,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- 'pattern' for rule-matched chains; 'ai-discovered' for LLM-proposed chains
    chain_source     TEXT NOT NULL DEFAULT 'pattern'
);

CREATE TABLE IF NOT EXISTS chain_components (
    chain_id       TEXT REFERENCES attack_chains(id) ON DELETE CASCADE,
    finding_id     TEXT REFERENCES findings(id),
    role           TEXT NOT NULL,
    sequence_order INTEGER NOT NULL,
    PRIMARY KEY (chain_id, finding_id)
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id             TEXT PRIMARY KEY,
    chain_id       TEXT REFERENCES attack_chains(id),
    finding_id     TEXT REFERENCES findings(id),
    priority_order INTEGER NOT NULL,
    action_summary TEXT NOT NULL,
    effort_level   TEXT NOT NULL,
    breaks_chain   INTEGER DEFAULT 0,
    cli_command    TEXT,
    iac_snippet    TEXT,
    aws_sop_ref    TEXT,
    doc_urls       TEXT             -- JSON array
);

-- Lightweight adjacency table for the correlation engine's resource graph
CREATE TABLE IF NOT EXISTS resource_graph (
    source_arn   TEXT NOT NULL,
    target_arn   TEXT NOT NULL,
    relationship TEXT NOT NULL,
    PRIMARY KEY (source_arn, target_arn, relationship)
);

-- Tracks the orchestrator state machine across phases
CREATE TABLE IF NOT EXISTS assessment_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Persistent node registry for the AWS knowledge graph.
-- Rebuilt into an in-memory NetworkX graph at Phase 4 correlation time.
CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id         TEXT PRIMARY KEY,
    node_type       TEXT NOT NULL,
    label           TEXT NOT NULL,
    properties      TEXT,           -- JSON blob (must include finding_ids list)
    internet_facing INTEGER DEFAULT 0
);

-- Richer edge store with provenance — supersedes resource_graph for any
-- edge type that needs properties (statement Sid, action list, finding_ids,
-- is_wildcard, etc.). resource_graph stays read-only for back-compat.
CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id      TEXT PRIMARY KEY,
    source_id    TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    edge_type    TEXT NOT NULL,
    properties   TEXT,           -- JSON blob (finding_ids, is_wildcard, actions, …)
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (source_id, target_id, edge_type)
);

-- Per-enrichment-pass status so partial-failure runs can still produce
-- reports that disclose graph completeness ("IAM enumeration unavailable").
CREATE TABLE IF NOT EXISTS enrichment_status (
    pass_name TEXT PRIMARY KEY,
    status    TEXT NOT NULL,     -- ok | partial | unavailable
    detail    TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Per-call Claude API token accounting. One row per messages.parse() return.
-- Aggregated at end of run for the summary print and as a regression baseline
-- when tuning prompts / models.
CREATE TABLE IF NOT EXISTS ai_usage (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                   TEXT NOT NULL,
    call_site                TEXT NOT NULL,        -- e.g. 'discovery', 'triage_batch'
    model                    TEXT NOT NULL,
    input_tokens             INTEGER NOT NULL DEFAULT 0,
    output_tokens            INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens    INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens        INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Azure-specific normalized tables (all new; backward-compat with AWS-only DBs)
CREATE TABLE IF NOT EXISTS azure_role_assignments (
    assignment_id        TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    principal_id         TEXT NOT NULL,
    principal_type       TEXT,
    role_definition_id   TEXT NOT NULL,
    role_definition_name TEXT,
    scope                TEXT NOT NULL,
    scope_level          TEXT,
    inherited            INTEGER DEFAULT 0,
    pim_eligible         INTEGER DEFAULT 0,
    condition_expr       TEXT,
    discovered_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS azure_federated_credentials (
    id                    TEXT PRIMARY KEY,
    parent_resource_id    TEXT NOT NULL,
    issuer                TEXT NOT NULL,
    subject               TEXT NOT NULL,
    audiences             TEXT,
    name                  TEXT,
    matched_aks_cluster_id TEXT,
    matched_k8s_subject   TEXT
);

CREATE TABLE IF NOT EXISTS azure_compliance_findings (
    id              TEXT PRIMARY KEY,
    framework       TEXT NOT NULL,
    control_id      TEXT NOT NULL,
    resource_id     TEXT,
    subscription_id TEXT,
    state           TEXT NOT NULL,
    severity        TEXT,
    source          TEXT NOT NULL,
    raw             TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_provider
    ON findings(provider);
CREATE INDEX IF NOT EXISTS idx_findings_azure_resource
    ON findings(azure_resource_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_provider
    ON graph_nodes(provider, tenant_id);
CREATE INDEX IF NOT EXISTS idx_azure_ra_principal
    ON azure_role_assignments(principal_id);
CREATE INDEX IF NOT EXISTS idx_azure_ra_scope
    ON azure_role_assignments(scope);
CREATE INDEX IF NOT EXISTS idx_compliance_state
    ON azure_compliance_findings(framework, state);
"""

# Lightweight, idempotent migrations for DBs created before the triage /
# ai-discovery columns existed. SQLite has no "ADD COLUMN IF NOT EXISTS" so
# we introspect the table and only issue ALTERs for missing columns.
_MIGRATIONS: list[tuple[str, str, str]] = [
    # (table, column, full ALTER TABLE clause)
    ("findings",      "triage_confidence",        "ALTER TABLE findings ADD COLUMN triage_confidence REAL"),
    ("findings",      "triage_is_false_positive", "ALTER TABLE findings ADD COLUMN triage_is_false_positive INTEGER"),
    ("findings",      "triage_notes",             "ALTER TABLE findings ADD COLUMN triage_notes TEXT"),
    ("attack_chains", "chain_source",             "ALTER TABLE attack_chains ADD COLUMN chain_source TEXT NOT NULL DEFAULT 'pattern'"),
    # Azure columns on findings (all nullable; existing rows default to 'aws')
    ("findings", "provider",            "ALTER TABLE findings ADD COLUMN provider TEXT DEFAULT 'aws'"),
    ("findings", "tenant_id",           "ALTER TABLE findings ADD COLUMN tenant_id TEXT"),
    ("findings", "subscription_id",     "ALTER TABLE findings ADD COLUMN subscription_id TEXT"),
    ("findings", "management_group_id", "ALTER TABLE findings ADD COLUMN management_group_id TEXT"),
    ("findings", "resource_group",      "ALTER TABLE findings ADD COLUMN resource_group TEXT"),
    ("findings", "azure_resource_id",   "ALTER TABLE findings ADD COLUMN azure_resource_id TEXT"),
    ("findings", "azure_region",        "ALTER TABLE findings ADD COLUMN azure_region TEXT"),
    # Azure columns on graph_nodes
    ("graph_nodes", "provider",            "ALTER TABLE graph_nodes ADD COLUMN provider TEXT DEFAULT 'aws'"),
    ("graph_nodes", "tenant_id",           "ALTER TABLE graph_nodes ADD COLUMN tenant_id TEXT"),
    ("graph_nodes", "subscription_id",     "ALTER TABLE graph_nodes ADD COLUMN subscription_id TEXT"),
    ("graph_nodes", "management_group_id", "ALTER TABLE graph_nodes ADD COLUMN management_group_id TEXT"),
    ("graph_nodes", "resource_group",      "ALTER TABLE graph_nodes ADD COLUMN resource_group TEXT"),
    ("graph_nodes", "azure_resource_id",   "ALTER TABLE graph_nodes ADD COLUMN azure_resource_id TEXT"),
    ("graph_nodes", "node_kind",           "ALTER TABLE graph_nodes ADD COLUMN node_kind TEXT"),
    ("graph_nodes", "compressed_alias",    "ALTER TABLE graph_nodes ADD COLUMN compressed_alias TEXT"),
    # Azure columns on graph_edges
    ("graph_edges", "provider",             "ALTER TABLE graph_edges ADD COLUMN provider TEXT DEFAULT 'aws'"),
    ("graph_edges", "edge_kind",            "ALTER TABLE graph_edges ADD COLUMN edge_kind TEXT"),
    ("graph_edges", "role_definition_id",   "ALTER TABLE graph_edges ADD COLUMN role_definition_id TEXT"),
    ("graph_edges", "scope",                "ALTER TABLE graph_edges ADD COLUMN scope TEXT"),
    ("graph_edges", "scope_level",          "ALTER TABLE graph_edges ADD COLUMN scope_level TEXT"),
    ("graph_edges", "inherited",            "ALTER TABLE graph_edges ADD COLUMN inherited INTEGER DEFAULT 0"),
    ("graph_edges", "source_assignment_id", "ALTER TABLE graph_edges ADD COLUMN source_assignment_id TEXT"),
    ("graph_edges", "condition_expr",       "ALTER TABLE graph_edges ADD COLUMN condition_expr TEXT"),
    ("graph_edges", "pim_eligible",         "ALTER TABLE graph_edges ADD COLUMN pim_eligible INTEGER DEFAULT 0"),
    ("graph_edges", "audience",             "ALTER TABLE graph_edges ADD COLUMN audience TEXT"),
    # Azure columns on enrichment_status
    ("enrichment_status", "provider",  "ALTER TABLE enrichment_status ADD COLUMN provider TEXT DEFAULT 'aws'"),
    ("enrichment_status", "scope_id",  "ALTER TABLE enrichment_status ADD COLUMN scope_id TEXT"),
]


async def _apply_migrations(conn: aiosqlite.Connection) -> None:
    """Add columns introduced after the initial schema for pre-existing DBs."""
    for table, column, ddl in _MIGRATIONS:
        async with conn.execute(f"PRAGMA table_info({table})") as cur:
            existing = {row["name"] for row in await cur.fetchall()}
        if column not in existing:
            await conn.execute(ddl)
    await conn.commit()

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
                    resource_group, azure_resource_id, azure_region
                ) VALUES (
                    :id, :source, :phase, :severity, :category, :title, :description,
                    :resource_type, :resource_id, :aws_account_id, :aws_region,
                    :evidence_type, :evidence_data, :remediation_summary,
                    :remediation_cli, :remediation_iac, :remediation_doc_url,
                    :compliance_mappings, :confidence, :is_validated, :raw_source_data,
                    :provider, :tenant_id, :subscription_id, :management_group_id,
                    :resource_group, :azure_resource_id, :azure_region
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

    async def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        """Fetch a single finding by its UUID."""
        async with self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_finding(row) if row else None

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

    async def get_findings_by_resource(self, resource_id: str) -> list[Finding]:
        """Return all findings whose resource_id matches the given ARN or URL."""
        async with self._conn.execute(
            "SELECT * FROM findings WHERE resource_id = ?", (resource_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_finding(row) for row in rows]

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
    ) -> None:
        """Persist a graph node; merges properties on conflict."""
        props_json = json.dumps(properties)
        async with self._write_lock:
            await self._conn.execute(
                """
                INSERT INTO graph_nodes (
                    node_id, node_type, label, properties, internet_facing,
                    provider, tenant_id, subscription_id, management_group_id,
                    resource_group, azure_resource_id, node_kind, compressed_alias
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    compressed_alias = COALESCE(excluded.compressed_alias, compressed_alias)
                """,
                (
                    node_id, node_type, label[:500], props_json, int(is_internet_facing),
                    provider, tenant_id, subscription_id, management_group_id,
                    resource_group, azure_resource_id, node_kind, compressed_alias,
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
    ) -> None:
        """Insert (or merge) a typed edge with optional properties.

        On UNIQUE conflict (same source/target/type), merges properties:
          * ``finding_ids`` lists are union-merged
          * other keys: existing values win
        """
        props = properties or {}
        async with self._write_lock:
            async with self._conn.execute(
                """
                SELECT edge_id, properties FROM graph_edges
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
                        inherited, source_assignment_id, condition_expr, pim_eligible, audience
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        edge_id, source_id, target_id, edge_type, json.dumps(props),
                        provider, edge_kind, role_definition_id, scope, scope_level,
                        int(inherited), source_assignment_id, condition_expr,
                        int(pim_eligible), audience,
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
                await self._conn.execute(
                    "UPDATE graph_edges SET properties = ? WHERE edge_id = ?",
                    (json.dumps(merged), row["edge_id"]),
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

    async def get_enrichment_status(self) -> list[dict]:
        """Return all enrichment-status rows for report disclosure."""
        async with self._conn.execute(
            "SELECT pass_name, status, detail, updated_at FROM enrichment_status"
        ) as cur:
            rows = await cur.fetchall()
        return [
            {
                "pass_name": r["pass_name"],
                "status": r["status"],
                "detail": r["detail"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

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


# ---------------------------------------------------------------------------
# Row → dataclass helpers
# ---------------------------------------------------------------------------

def _row_to_finding(row: aiosqlite.Row) -> Finding:
    """Convert a raw SQLite row dict into a Finding dataclass."""
    d = dict(row)
    return Finding(
        id=d["id"],
        source=d["source"],
        phase=d["phase"],
        severity=Severity(d["severity"]),
        category=d["category"],
        title=d["title"],
        description=d["description"],
        resource_type=d.get("resource_type"),
        resource_id=d.get("resource_id"),
        aws_account_id=d.get("aws_account_id"),
        aws_region=d.get("aws_region"),
        evidence_type=d.get("evidence_type"),
        evidence_data=json.loads(d["evidence_data"]) if d.get("evidence_data") else None,
        remediation_summary=d.get("remediation_summary"),
        remediation_cli=d.get("remediation_cli"),
        remediation_iac=d.get("remediation_iac"),
        remediation_doc_url=d.get("remediation_doc_url"),
        compliance_mappings=json.loads(d["compliance_mappings"]) if d.get("compliance_mappings") else None,
        confidence=d.get("confidence", 1.0),
        is_validated=bool(d.get("is_validated", 0)),
        raw_source_data=json.loads(d["raw_source_data"]) if d.get("raw_source_data") else None,
        triage_confidence=d.get("triage_confidence"),
        triage_is_false_positive=(
            bool(d["triage_is_false_positive"])
            if d.get("triage_is_false_positive") is not None
            else None
        ),
        triage_notes=d.get("triage_notes"),
        provider=d.get("provider") or "aws",
        tenant_id=d.get("tenant_id"),
        subscription_id=d.get("subscription_id"),
        management_group_id=d.get("management_group_id"),
        resource_group=d.get("resource_group"),
        azure_resource_id=d.get("azure_resource_id"),
        azure_region=d.get("azure_region"),
    )


def _row_to_chain(row: aiosqlite.Row) -> AttackChain:
    d = dict(row)
    return AttackChain(
        id=d["id"],
        pattern_name=d["pattern_name"],
        severity=Severity(d["severity"]),
        narrative=d["narrative"],
        entry_finding_id=d.get("entry_finding"),
        breach_cost_low=d.get("breach_cost_low"),
        breach_cost_high=d.get("breach_cost_high"),
        chain_source=d.get("chain_source") or "pattern",
    )


def _row_to_action(row: aiosqlite.Row) -> RemediationAction:
    d = dict(row)
    return RemediationAction(
        id=d["id"],
        chain_id=d.get("chain_id"),
        finding_id=d.get("finding_id"),
        priority_order=d["priority_order"],
        action_summary=d["action_summary"],
        effort_level=EffortLevel(d["effort_level"]),
        breaks_chain=bool(d.get("breaks_chain", 0)),
        cli_command=d.get("cli_command"),
        iac_snippet=d.get("iac_snippet"),
        aws_sop_ref=d.get("aws_sop_ref"),
        doc_urls=json.loads(d["doc_urls"]) if d.get("doc_urls") else None,
    )
