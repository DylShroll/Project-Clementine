"""Azure audit steps 7-8 — Prowler compliance scan and Defender-for-Cloud cross-check."""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from ...config import ClementineConfig
from ...db import Finding, FindingsDB, Severity
from ...mcp_client import MCPRegistry
from ...scope import RateLimiter
from ._shared import _SKIP, _mcp_call

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step 7 — Prowler compliance scan
# ---------------------------------------------------------------------------

async def _step7_compliance(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Trigger Prowler compliance scan and stream findings into azure_compliance_findings."""

    if not mcp.is_available("prowler_mcp"):
        log.info("[azure] step7: prowler_mcp unavailable — skipping compliance scan")
        await db.set_enrichment_status("azure_compliance", "unavailable", "prowler_mcp unavailable")
        return

    for framework in cfg.azure.compliance_frameworks:
        for sub_id in subscription_ids:
            result = await _mcp_call(
                mcp, limiter, "prowler_mcp", "azure_scan",
                {
                    "subscription_id": sub_id,
                    "tenant_id": tid,
                    "compliance": framework,
                },
                step=f"step7_{framework[:20]}_{sub_id[:8]}",
            )
            if result is _SKIP:
                continue
            findings = result if isinstance(result, list) else result.get("findings", []) if isinstance(result, dict) else []
            for f in findings:
                await db.insert_azure_compliance_finding({
                    "id": f.get("id") or str(uuid.uuid4()),
                    "framework": framework,
                    "control_id": f.get("checkId") or f.get("control_id", ""),
                    "resource_id": f.get("resourceArn") or f.get("resource_id"),
                    "subscription_id": sub_id,
                    "state": "fail" if f.get("status") in ("FAIL", "fail") else "pass",
                    "severity": f.get("severity"),
                    "source": "prowler",
                    "raw": f,
                })
                # Also surface FAIL findings in the main findings table
                if f.get("status") in ("FAIL", "fail"):
                    sev_str = (f.get("severity") or "MEDIUM").upper()
                    try:
                        sev = Severity(sev_str)
                    except ValueError:
                        sev = Severity.MEDIUM
                    finding = Finding(
                        id=f.get("id") or str(uuid.uuid4()),
                        source="prowler-azure",
                        phase=2,
                        severity=sev,
                        category=f"{framework}:{f.get('checkId', '')}",
                        title=f.get("checkTitle") or f.get("title", ""),
                        description=f.get("statusExtended") or f.get("description", ""),
                        resource_id=f.get("resourceId") or f.get("resource_id"),
                        azure_resource_id=f.get("resourceId") or f.get("resource_id"),
                        provider="azure",
                        tenant_id=tid,
                        subscription_id=sub_id,
                        remediation_summary=f.get("remediation", {}).get("recommendation", {}).get("text"),
                    )
                    await db.insert_finding(finding)

    log.info("[azure] step7: compliance scan complete for tenant %s", tid[:8])


# ---------------------------------------------------------------------------
# Step 8 — Defender for Cloud cross-check
# ---------------------------------------------------------------------------

async def _step8_defender_crosscheck(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    limiter: RateLimiter,
    tid: str,
    subscription_ids: list[str],
) -> None:
    """Query Defender for Cloud control state via Resource Graph and cross-check with Prowler."""

    defender_kql_path = Path(cfg.azure.kql_queries_dir) / "defender_compliance_state.kql"
    if not defender_kql_path.exists():
        log.debug("[azure] step8: defender_compliance_state.kql not found — skipping cross-check")
        return

    kql = defender_kql_path.read_text()

    for sub_id in subscription_ids:
        result = await _mcp_call(
            mcp, limiter, "cloud_audit", "azure_resource_graph_query",
            {"kql": kql, "subscription_id": sub_id},
            step=f"step8_defender_{sub_id[:8]}",
        )
        if result is _SKIP or not isinstance(result, list):
            continue

        for item in result:
            standard = item.get("standard", "")
            control = item.get("control", "")
            defender_state = item.get("state", "")

            await db.insert_azure_compliance_finding({
                "id": str(uuid.uuid4()),
                "framework": standard,
                "control_id": control,
                "subscription_id": sub_id,
                "state": defender_state.lower(),
                "source": "defender_for_cloud",
                "raw": item,
            })

    # Drift detection: compare Prowler vs Defender for the same control
    prowler_findings = await db.get_azure_compliance_findings(state="fail")
    defender_findings = await db.get_azure_compliance_findings()

    prowler_fails = {f["control_id"] for f in prowler_findings if f["source"] == "prowler"}
    defender_passes = {f["control_id"] for f in defender_findings if f["source"] == "defender_for_cloud" and f["state"] == "pass"}

    drifted = prowler_fails & defender_passes
    if drifted:
        finding = Finding(
            source="cloud-audit-azure",
            phase=2,
            severity=Severity.MEDIUM,
            category="azure-defender-prowler-drift",
            title=f"Compliance evaluator disagreement ({len(drifted)} controls)",
            description=(
                f"Prowler and Defender for Cloud disagree on {len(drifted)} control(s): "
                f"{', '.join(sorted(drifted)[:10])}{'…' if len(drifted) > 10 else ''}. "
                "Prowler marks these as FAIL; Defender marks them as PASS. "
                "Manual review required to determine which evaluator is correct."
            ),
            provider="azure",
            tenant_id=tid,
            raw_source_data={"drifted_controls": sorted(drifted)},
        )
        await db.insert_finding(finding)
        log.info("[azure] step8: %d drift controls detected for tenant %s", len(drifted), tid[:8])

    log.info("[azure] step8: Defender cross-check complete for tenant %s", tid[:8])
