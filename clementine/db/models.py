"""Data models for the Clementine findings store.

Enums, dataclasses, and the row → dataclass mappers shared across the
database layer. Kept free of any connection/IO logic so they can be imported
without touching SQLite.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import aiosqlite


# ---------------------------------------------------------------------------
# Enumerations that mirror the DB constraints
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


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
    # IaC-specific fields (Phase 0 / Workstream B). file:line ref points at
    # the offending IaC source location; used by SARIF physicalLocation and
    # the HTML report's deep-link back to the editor. Both are NULL for
    # findings not produced by an IaC scanner.
    iac_source_path: Optional[str] = None
    iac_source_line: Optional[int] = None


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
        iac_source_path=d.get("iac_source_path"),
        iac_source_line=d.get("iac_source_line"),
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
