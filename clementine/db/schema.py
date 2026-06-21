"""SQLite schema, indexes, and idempotent migrations for the findings store."""
from __future__ import annotations

import aiosqlite


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

-- Indexes that depend on columns added by `_MIGRATIONS` are created
-- by `_apply_migrations` *after* the migrations run. Putting them here
-- would fail on a fresh DB because the columns don't exist yet at
-- schema-script time.
"""

# Indexes that reference migration-added columns. Created after
# `_apply_migrations` has run so the columns are guaranteed to exist.
_POST_MIGRATION_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider)",
    "CREATE INDEX IF NOT EXISTS idx_findings_azure_resource ON findings(azure_resource_id)",
    "CREATE INDEX IF NOT EXISTS idx_graph_nodes_provider ON graph_nodes(provider, tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_azure_ra_principal ON azure_role_assignments(principal_id)",
    "CREATE INDEX IF NOT EXISTS idx_azure_ra_scope ON azure_role_assignments(scope)",
    "CREATE INDEX IF NOT EXISTS idx_compliance_state ON azure_compliance_findings(framework, state)",
]

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
    # IaC columns (Phase 0 / Workstream B). Findings carry a file:line ref
    # back to the IaC source; graph nodes/edges carry a `provenance` flag
    # that distinguishes planned (iac), live (live) and reconciled (live+iac)
    # entities so correlation patterns can constrain on it.
    ("findings",    "iac_source_path", "ALTER TABLE findings    ADD COLUMN iac_source_path TEXT"),
    ("findings",    "iac_source_line", "ALTER TABLE findings    ADD COLUMN iac_source_line INTEGER"),
    ("graph_nodes", "provenance",      "ALTER TABLE graph_nodes ADD COLUMN provenance TEXT DEFAULT 'live'"),
    ("graph_edges", "provenance",      "ALTER TABLE graph_edges ADD COLUMN provenance TEXT DEFAULT 'live'"),
]


async def _apply_migrations(conn: aiosqlite.Connection) -> None:
    """Add columns introduced after the initial schema for pre-existing DBs.

    Also creates indexes whose target columns are added by these
    migrations — putting those indexes in the base schema script would
    fail on a fresh DB because the columns don't exist yet when the
    script runs.
    """
    for table, column, ddl in _MIGRATIONS:
        async with conn.execute(f"PRAGMA table_info({table})") as cur:
            existing = {row["name"] for row in await cur.fetchall()}
        if column not in existing:
            await conn.execute(ddl)
    for index_ddl in _POST_MIGRATION_INDEXES:
        await conn.execute(index_ddl)
    await conn.commit()
