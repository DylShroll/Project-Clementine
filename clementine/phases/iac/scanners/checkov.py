"""checkov — multi-framework IaC scanner.

Documentation: https://www.checkov.io/
Output format: JSON dict with ``results.failed_checks`` (and a sibling
``results.passed_checks`` we ignore). Each failed check carries
``check_id`` (e.g. ``CKV_AWS_18``), ``severity``, ``file_path``,
``file_line_range`` (a ``[start, end]`` pair), ``resource`` (the IaC
resource address), ``check_name``, and ``guideline``.

We invoke checkov with ``--quiet --soft-fail`` so the scanner doesn't
print noisy progress and a non-zero exit on findings doesn't poison
``asyncio.gather``. ``--framework all`` lets checkov auto-detect TF,
CFN, and dockerfile/k8s without us having to know the source kind.

Why is this scanner applicable to both terraform AND cloudformation?
Checkov is the only scanner in our launch set that understands both
without re-running. We dedupe with tfsec/cfn-nag downstream in
normalize.py — finding the same issue twice is a false-precision risk
we'd rather catch than let through.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from .base import RawFinding, SubprocessScanner, applies_to_scanner_import, safe_relpath
from ..sources import ResolvedSource

log = logging.getLogger(__name__)


class CheckovScanner(SubprocessScanner):
    """Run checkov against a Terraform / CFN / mixed source tree."""

    name = "checkov"
    binary = "checkov"

    def applicable_to(self, source: ResolvedSource) -> bool:
        gate = applies_to_scanner_import(source, self.name)
        if gate is not None:
            return gate
        # Checkov has framework support for terraform, cloudformation,
        # kubernetes, dockerfile, helm, secrets, and more. We restrict to
        # the source kinds the M1 resolver tags so unknown trees are
        # silently skipped rather than producing piles of irrelevant
        # findings.
        return source.source_kind in ("terraform", "terraform_plan", "cloudformation", "mixed")

    def build_argv(self, source: ResolvedSource) -> list[str]:
        return [
            "-d", ".",                  # scan cwd (run() sets cwd to source.path)
            "--output", "json",
            "--quiet",                  # no human-readable progress
            "--soft-fail",              # never exit non-zero on findings
            # Checkov's NVD lookup hits the network; turn it off so Phase
            # 0 stays offline. Vulnerability scanning is Workstream C.
            "--skip-cve-package",
            # Compact JSON; full details are in the per-check entry.
            "--compact",
        ]

    def parse(self, stdout: bytes, source: ResolvedSource) -> list[RawFinding]:
        if not stdout.strip():
            return []
        # Checkov's JSON shape varies: when scanning a single framework
        # it emits a dict; when scanning multiple frameworks at once it
        # emits a list of those dicts. We normalise to a list and walk.
        data = json.loads(stdout)
        records = data if isinstance(data, list) else [data]

        out: list[RawFinding] = []
        root = source.path
        for rec in records:
            failed = (rec.get("results") or {}).get("failed_checks") or []
            for chk in failed:
                file_path = chk.get("file_path") or chk.get("repo_file_path")
                line_range = chk.get("file_line_range") or [None, None]
                start_line = line_range[0] if line_range else None

                out.append(RawFinding(
                    scanner=self.name,
                    rule_id=str(chk.get("check_id") or "unknown"),
                    title=str(chk.get("check_name") or "Checkov finding")[:500],
                    description=str(chk.get("description") or chk.get("check_name") or ""),
                    raw_severity=_normalise_severity(chk.get("severity")),
                    file_path=safe_relpath(file_path, root) if root else file_path,
                    line=_safe_int(start_line),
                    resource_type=_split_resource_type(chk.get("resource")),
                    resource_id=chk.get("resource"),
                    remediation_summary=chk.get("guideline"),
                    remediation_doc_url=chk.get("guideline"),
                    raw=chk,
                ))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_severity(value) -> str:
    """Checkov omits severity for some checks. Default to UNKNOWN so the
    normaliser maps to MEDIUM (its safe-fallback bucket)."""
    if value is None:
        return "UNKNOWN"
    return str(value).upper()


def _safe_int(value) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _split_resource_type(resource: Optional[str]) -> Optional[str]:
    """``aws_s3_bucket.public`` → ``aws_s3_bucket`` (also handles CFN's
    ``AWS::S3::Bucket.LogicalId`` shape — we just split on '.' once)."""
    if not resource:
        return None
    return resource.split(".", 1)[0]
