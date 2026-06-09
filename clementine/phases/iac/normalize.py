"""Convert scanner-native RawFindings into DB Findings.

Centralising this here means each scanner only has to express its own
output dialect; severity normalisation, sanitisation, source-naming
conventions, and Finding-construction live in exactly one place.
"""

from __future__ import annotations

import logging
from typing import Iterable

from ...db import Finding, Severity
from ...sanitize import sanitize_text
from .scanners.base import RawFinding

log = logging.getLogger(__name__)


# Map every scanner-native severity token we have seen in the wild to
# Clementine's Severity enum. The map is intentionally permissive — any
# unknown token falls back to MEDIUM rather than raising, because a
# scanner update that adds a new label shouldn't crash a scan.
_SEVERITY_MAP: dict[str, Severity] = {
    # tfsec / checkov / gitleaks share these
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
    # cfn-nag emits FAIL / WARN
    "FAIL":     Severity.HIGH,
    "WARN":     Severity.MEDIUM,
    # tfsec sometimes emits UNKNOWN
    "UNKNOWN":  Severity.MEDIUM,
    # checkov "passed" is filtered out before we get here, but be defensive
    "PASSED":   Severity.INFO,
}


def normalize(raw: Iterable[RawFinding]) -> list[Finding]:
    """RawFinding → Finding, with sanitisation and dedup keyed on
    (scanner, rule_id, file_path, line, resource_id).

    Dedup happens here rather than per-scanner so two scanners flagging
    the same line of code (e.g. tfsec + checkov agreeing on an open S3
    bucket) collapse to one finding without losing precision data.
    """
    seen: dict[tuple, Finding] = {}
    for r in raw:
        key = (r.scanner, r.rule_id, r.file_path, r.line, r.resource_id)
        if key in seen:
            continue
        seen[key] = _to_finding(r)
    return list(seen.values())


def _to_finding(r: RawFinding) -> Finding:
    """Single-record mapping — keep this fully synchronous and side-effect-free."""
    severity = _SEVERITY_MAP.get(r.raw_severity, Severity.MEDIUM)

    # Title and description run through the existing redactor so any
    # leaked credential the scanner echoed back (e.g. gitleaks quoting
    # the matched token) never lands in the DB or report.
    title = sanitize_text(r.title)[:500]
    description = sanitize_text(r.description)

    return Finding(
        source=f"iac-scanner-{r.scanner}",
        phase=0,
        severity=severity,
        # Category is the scanner-native rule id; existing
        # cloud-audit/Prowler findings use the check id the same way
        # (e.g. "iam-role-overprivileged"), so correlation patterns can
        # already filter on it via PivotCondition.check.
        category=r.rule_id,
        title=title,
        description=description,
        resource_type=r.resource_type,
        resource_id=r.resource_id,
        evidence_type="config_dump",
        evidence_data={
            "scanner": r.scanner,
            "rule_id": r.rule_id,
            "raw_severity": r.raw_severity,
            "raw": r.raw,
        },
        remediation_summary=r.remediation_summary,
        remediation_doc_url=r.remediation_doc_url,
        # Confidence: scanner findings are deterministic on the source
        # tree, so we treat them as fully confident pre-triage. The AI
        # triage pass can later down-weight likely false positives.
        confidence=1.0,
        provider="iac",
        iac_source_path=r.file_path,
        iac_source_line=r.line,
    )
