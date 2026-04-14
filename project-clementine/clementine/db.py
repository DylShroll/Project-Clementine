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
    id                  TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    phase               INTEGER NOT NULL,
    severity            TEXT NOT NULL,
    category            TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    resource_type       TEXT,
    resource_id         TEXT,
    aws_account_id      TEXT,
    aws_region          TEXT,
    evidence_type       TEXT,
    evidence_data       TEXT,        -- JSON blob
    remediation_summary TEXT,
    remediation_cli     TEXT,
    remediation_iac     TEXT,
    remediation_doc_url TEXT,
    compliance_mappings TEXT,        -- JSON blob
    confidence          REAL DEFAULT 1.0,
    is_validated        INTEGER DEFAULT 0,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_source_data     TEXT         -- JSON blob
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id               TEXT PRIMARY KEY,
    pattern_name     TEXT NOT NULL,
    severity         TEXT NOT NULL,
    narrative        TEXT NOT NULL,
    entry_finding    TEXT REFERENCES findings(id),
    breach_cost_low  REAL,
    breach_cost_high REAL,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
"""

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

        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.executescript(_SCHEMA_SQL)
            await conn.commit()
            yield cls(conn)

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
                    compliance_mappings, confidence, is_validated, raw_source_data
                ) VALUES (
                    :id, :source, :phase, :severity, :category, :title, :description,
                    :resource_type, :resource_id, :aws_account_id, :aws_region,
                    :evidence_type, :evidence_data, :remediation_summary,
                    :remediation_cli, :remediation_iac, :remediation_doc_url,
                    :compliance_mappings, :confidence, :is_validated, :raw_source_data
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
                     breach_cost_low, breach_cost_high)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain.id, chain.pattern_name, chain.severity.value,
                    chain.narrative, chain.entry_finding_id,
                    chain.breach_cost_low, chain.breach_cost_high,
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
