"""cfn-nag — CloudFormation-specific IaC scanner.

Documentation: https://github.com/stelligent/cfn_nag
Output format: JSON array of per-template results. Each entry has:

    {
      "filename": "...",
      "file_results": {
        "violations": [
          {
            "id":        "W1",
            "type":      "WARN" | "FAIL",
            "message":   "...",
            "line_numbers":         [42],
            "logical_resource_ids": ["LogicalId"]
          }
        ]
      }
    }

We invoke ``cfn_nag_scan --output-format json`` against the source
directory; cfn-nag walks subdirectories itself and only opens files
whose first bytes look like a CloudFormation template.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from .base import RawFinding, SubprocessScanner, applies_to_scanner_import, safe_relpath
from ..sources import ResolvedSource

log = logging.getLogger(__name__)


class CfnNagScanner(SubprocessScanner):
    """Run cfn-nag against a CloudFormation source tree."""

    name = "cfn_nag"
    binary = "cfn_nag_scan"

    def applicable_to(self, source: ResolvedSource) -> bool:
        gate = applies_to_scanner_import(source, self.name)
        if gate is not None:
            return gate
        # cfn-nag exists solely for CFN; running it against pure Terraform
        # would just emit noise.
        return source.source_kind in ("cloudformation", "mixed")

    def build_argv(self, source: ResolvedSource) -> list[str]:
        return [
            "--input-path", ".",         # scan cwd (run() sets cwd to source.path)
            "--output-format", "json",
        ]

    def parse(self, stdout: bytes, source: ResolvedSource) -> list[RawFinding]:
        if not stdout.strip():
            return []
        data = json.loads(stdout)
        if not isinstance(data, list):
            log.warning("[cfn_nag] expected list output, got %s", type(data).__name__)
            return []

        out: list[RawFinding] = []
        root = source.path
        for entry in data:
            filename = entry.get("filename")
            file_results = entry.get("file_results") or {}
            for v in (file_results.get("violations") or []):
                # cfn-nag may report several lines per violation
                # (e.g. when the same rule fires across siblings of a
                # property). We use the first one as the canonical
                # ref and stash the full list in raw for the report.
                lines = v.get("line_numbers") or []
                resources = v.get("logical_resource_ids") or []
                out.append(RawFinding(
                    scanner=self.name,
                    rule_id=str(v.get("id") or "unknown"),
                    title=str(v.get("message") or "cfn-nag violation")[:500],
                    description=str(v.get("message") or ""),
                    # cfn-nag uses FAIL/WARN; the normaliser already maps
                    # those to HIGH/MEDIUM in our Severity vocabulary.
                    raw_severity=str(v.get("type") or "WARN").upper(),
                    file_path=safe_relpath(filename, root) if root and filename else filename,
                    line=_safe_int(lines[0]) if lines else None,
                    resource_type=None,                 # cfn-nag doesn't report a type
                    resource_id=resources[0] if resources else None,
                    remediation_summary=v.get("guideline"),
                    raw=v,
                ))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(value) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
