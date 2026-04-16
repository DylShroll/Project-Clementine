"""
SARIF (Static Analysis Results Interchange Format) report renderer.

Produces a SARIF v2.1.0 document suitable for:
  - GitHub Code Scanning (upload via github/codeql-action/upload-sarif)
  - VS Code SARIF Viewer extension
  - Any CI/CD tool that consumes SARIF (e.g., Azure DevOps)

Each Project Clementine finding maps to one SARIF result.  The source tool
name is used as the SARIF driver name so findings from AutoPentest, cloud-
audit, and Prowler appear as separate logical tools.
"""

from __future__ import annotations

import logging
from typing import Any

from ..db import Finding, Severity

log = logging.getLogger(__name__)

# SARIF severity level mapping
_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SarifReporter:
    """Builds a SARIF 2.1.0 document from a list of findings."""

    def build(self, findings: list[Finding]) -> dict[str, Any]:
        """Return a SARIF document as a Python dict (caller serialises to JSON)."""
        # Group findings by source tool
        by_source: dict[str, list[Finding]] = {}
        for f in findings:
            by_source.setdefault(f.source, []).append(f)

        runs = []
        for source, source_findings in by_source.items():
            runs.append(self._build_run(source, source_findings))

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }

    def _build_run(self, source: str, findings: list[Finding]) -> dict[str, Any]:
        """Build one SARIF run entry for a single source tool."""
        # Collect unique rules (one rule per finding category)
        rules_by_id: dict[str, dict] = {}
        for f in findings:
            rule_id = self._rule_id(f)
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description[:1000]},
                    "helpUri": f.remediation_doc_url or "",
                    "defaultConfiguration": {
                        "level": _SEVERITY_MAP.get(f.severity, "warning")
                    },
                }

        results = [self._finding_to_result(f) for f in findings]

        return {
            "tool": {
                "driver": {
                    "name": f"clementine/{source}",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/your-org/project-clementine",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
        }

    def _finding_to_result(self, f: Finding) -> dict[str, Any]:
        """Convert a Finding to a SARIF result object."""
        result: dict[str, Any] = {
            "ruleId": self._rule_id(f),
            "level": _SEVERITY_MAP.get(f.severity, "warning"),
            "message": {"text": f.description[:2000]},
        }

        # Location — use URL as artifactLocation if available, otherwise ARN
        location_uri = f.resource_id or ""
        if location_uri:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location_uri},
                    }
                }
            ]

        # Fingerprint for deduplication (hash of category + resource)
        result["fingerprints"] = {
            "clementine/v1": f"{f.category}:{f.resource_id or ''}",
        }

        # Remediation as a fix suggestion
        if f.remediation_summary:
            result["fixes"] = [
                {"description": {"text": f.remediation_summary}}
            ]

        return result

    @staticmethod
    def _rule_id(f: Finding) -> str:
        """Generate a stable SARIF rule ID from the finding category."""
        # Normalise to uppercase, replace spaces/slashes with hyphens
        return f.category.upper().replace(" ", "-").replace("/", "-")
