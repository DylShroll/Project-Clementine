"""tfsec — Terraform-focused IaC security scanner.

Documentation: https://github.com/aquasecurity/tfsec
Output format: JSON with a top-level ``results`` array. Each result
carries ``rule_id``, ``severity`` ({CRITICAL,HIGH,MEDIUM,LOW,INFO,UNKNOWN}),
``description``, ``location.filename``, ``location.start_line``, and
``resource`` (the Terraform resource address).

This wrapper invokes ``tfsec --format json --soft-fail`` so the binary
emits findings via stdout regardless of severity, and an exit code of 0
means "I ran successfully" rather than "I found nothing". We then map
each result into the shared ``RawFinding`` schema.
"""

from __future__ import annotations

import json
from typing import Optional

from .base import RawFinding, SubprocessScanner, applies_to_scanner_import, safe_relpath
from ..sources import ResolvedSource


class TfsecScanner(SubprocessScanner):
    """Run tfsec against a Terraform source tree."""

    name = "tfsec"
    binary = "tfsec"

    # ------------------------------------------------------------------
    # Scanner contract
    # ------------------------------------------------------------------

    def applicable_to(self, source: ResolvedSource) -> bool:
        # scanner_import sources are gated to exactly one scanner.
        gate = applies_to_scanner_import(source, self.name)
        if gate is not None:
            return gate
        # tfsec only meaningfully runs against Terraform sources. The
        # `dir` resolver tags Terraform-shaped directories with
        # source_kind="terraform"; `plan` sources also flow through
        # tfsec via the JSON plan in M2 onwards.
        return source.source_kind in ("terraform", "terraform_plan")

    def build_argv(self, source: ResolvedSource) -> list[str]:
        # `--soft-fail` keeps exit code 0 even when findings exist so a
        # single tfsec invocation doesn't poison `asyncio.gather` with
        # CalledProcessError. `--format json` produces machine-readable
        # output. We always run from `source.path` (set as cwd by the
        # parent run() method), so a literal "." is the scan target.
        return [
            "--format", "json",
            "--soft-fail",
            "--no-colour",
            ".",
        ]

    def parse(self, stdout: bytes, source: ResolvedSource) -> list[RawFinding]:
        if not stdout.strip():
            return []
        data = json.loads(stdout)
        results = data.get("results") or []

        out: list[RawFinding] = []
        for r in results:
            location = r.get("location") or {}
            file_path = location.get("filename")
            line = location.get("start_line")

            out.append(RawFinding(
                scanner=self.name,
                rule_id=str(r.get("rule_id") or r.get("long_id") or "unknown"),
                title=str(r.get("rule_description") or "tfsec finding"),
                description=str(r.get("description") or r.get("rule_description") or ""),
                raw_severity=str(r.get("severity") or "UNKNOWN").upper(),
                file_path=safe_relpath(file_path, source.path) if source.path else file_path,
                line=_safe_int(line),
                resource_type=_split_resource_type(r.get("resource")),
                resource_id=r.get("resource"),
                remediation_summary=r.get("resolution"),
                remediation_doc_url=_first_link(r.get("links")),
                raw=r,
            ))
        return out


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _safe_int(value) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _split_resource_type(resource: Optional[str]) -> Optional[str]:
    """``aws_s3_bucket.public`` → ``aws_s3_bucket`` (None for empty input)."""
    if not resource:
        return None
    return resource.split(".", 1)[0]


def _first_link(links) -> Optional[str]:
    if isinstance(links, list) and links:
        return str(links[0])
    return None
