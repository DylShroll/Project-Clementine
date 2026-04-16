"""
AWS Security Hub reporter.

Pushes findings to Security Hub in ASFF (AWS Security Finding Format).
Uses boto3 — the AWS SDK must be configured with credentials that have
securityhub:BatchImportFindings permission.

Findings are batched in groups of 100 (Security Hub API limit) and pushed
with exponential back-off on throttling errors.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from ..db import Finding, Severity

log = logging.getLogger(__name__)

# Security Hub ASFF severity product score mapping (0-100)
_SEVERITY_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 10,
    Severity.INFO: 0,
}

# ASFF severity labels
_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFORMATIONAL",
}

# Security Hub batch size limit
_BATCH_SIZE = 100


class SecurityHubReporter:
    """Pushes findings to AWS Security Hub in ASFF format."""

    def __init__(self, region: str, aws_profile: str, account_id: str) -> None:
        self._region = region
        self._aws_profile = aws_profile
        self._account_id = account_id

    async def push(self, findings: list[Finding]) -> None:
        """Push all findings to Security Hub in batches."""
        import boto3
        import botocore.exceptions

        # Build the boto3 session using the configured AWS profile
        session = boto3.Session(profile_name=self._aws_profile, region_name=self._region)
        client = session.client("securityhub")

        asff_findings = [
            self._to_asff(f) for f in findings
            # Only push validated findings to avoid flooding Security Hub with noise
            if f.is_validated
        ]

        if not asff_findings:
            log.info("[SecurityHub] No validated findings to push")
            return

        # Batch into groups of _BATCH_SIZE
        for i in range(0, len(asff_findings), _BATCH_SIZE):
            batch = asff_findings[i: i + _BATCH_SIZE]
            await self._push_batch(client, batch)

        log.info("[SecurityHub] Pushed %d findings to Security Hub", len(asff_findings))

    async def _push_batch(self, client: Any, batch: list[dict]) -> None:
        """Push one batch; retries up to 3 times on throttling."""
        import botocore.exceptions

        loop = asyncio.get_event_loop()
        for attempt in range(1, 4):
            try:
                response = await loop.run_in_executor(
                    None,
                    lambda: client.batch_import_findings(Findings=batch),
                )
                failed = response.get("FailedCount", 0)
                if failed:
                    log.warning("[SecurityHub] %d findings failed to import", failed)
                return
            except botocore.exceptions.ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ThrottlingException" and attempt < 3:
                    wait = 2 ** attempt
                    log.warning("[SecurityHub] Throttled — retrying in %ds", wait)
                    await asyncio.sleep(wait)
                else:
                    log.error("[SecurityHub] Batch import error: %s", exc)
                    return

    def _to_asff(self, f: Finding) -> dict[str, Any]:
        """Convert a Finding to an ASFF dict."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        generator_id = f"clementine/{f.source}/{f.category}"

        asff: dict[str, Any] = {
            "SchemaVersion": "2018-10-08",
            "Id": f"clementine/{f.id}",
            "ProductArn": (
                f"arn:aws:securityhub:{self._region}:"
                f"{self._account_id}:product/{self._account_id}/default"
            ),
            "GeneratorId": generator_id,
            "AwsAccountId": self._account_id,
            "Types": [self._finding_type(f)],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {
                "Product": float(_SEVERITY_SCORES[f.severity]),
                "Label": _SEVERITY_LABELS[f.severity],
            },
            "Title": f.title[:256],
            "Description": f.description[:1024],
            "Remediation": {
                "Recommendation": {
                    "Text": (f.remediation_summary or "See full report for remediation steps.")[:512],
                    "Url": f.remediation_doc_url or "",
                }
            },
            "Resources": [self._resource_asff(f)],
            "Confidence": int(f.confidence * 100),
            "VerificationState": "CONFIRMED" if f.is_validated else "UNKNOWN",
            "WorkflowState": "NEW",
        }

        # Attach compliance mappings if present
        if f.compliance_mappings:
            related = [
                {"StandardsId": k, "RelatedRequirements": [v]}
                for k, v in f.compliance_mappings.items()
            ]
            if related:
                asff["Compliance"] = {"RelatedRequirements": [
                    f"{r['StandardsId']}/{r['RelatedRequirements'][0]}"
                    for r in related
                ]}

        return asff

    def _resource_asff(self, f: Finding) -> dict[str, Any]:
        """Build the ASFF Resources entry from a finding's resource fields."""
        resource_type = _map_resource_type(f.resource_type or "other")
        return {
            "Type": resource_type,
            "Id": f.resource_id or "unknown",
            "Region": f.aws_region or self._region,
        }

    @staticmethod
    def _finding_type(f: Finding) -> str:
        """Map a finding to an ASFF finding type taxonomy string."""
        if f.source == "autopentest":
            return "Software and Configuration Checks/Vulnerabilities/CVE"
        if f.source in ("cloud-audit", "prowler"):
            return "Software and Configuration Checks/Industry and Regulatory Standards"
        return "Software and Configuration Checks/Vulnerabilities"


def _map_resource_type(resource_type: str) -> str:
    """Map clementine resource type strings to ASFF AwsResourceType."""
    mapping = {
        "ec2": "AwsEc2Instance",
        "s3": "AwsS3Bucket",
        "iam": "AwsIamRole",
        "rds": "AwsRdsDbInstance",
        "lambda": "AwsLambdaFunction",
        "vpc": "AwsEc2Vpc",
        "sg": "AwsEc2SecurityGroup",
        "url": "Other",
        "other": "Other",
    }
    return mapping.get(resource_type.lower(), "Other")
