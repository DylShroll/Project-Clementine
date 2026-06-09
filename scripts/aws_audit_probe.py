"""Diagnostic harness for Phase 2 (AWS audit).

Runs the Prowler lane and the cloud_audit (GuardDuty / Security Hub /
Inspector / IAM Access Analyzer) lane *independently* against your live AWS
account, prints per-step status, and writes nothing to findings.db.

Usage:
    AWS_AUDIT_PROFILE=default \
    AUTOPENTEST_DIR=/tmp \
    AZURE_TENANT_ID=x AZURE_CLIENT_ID=x AZURE_CLIENT_SECRET=x \
    ./.venv/bin/python scripts/aws_audit_probe.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aws_audit_probe")


async def main() -> int:
    from clementine.aws_creds import resolve_aws_env, verify_aws_credentials
    from clementine.config import HttpServerConfig, load_config
    from clementine.mcp_client import MCPRegistry
    from clementine.phases.aws_audit import _run_cloud_audit, _run_prowler
    from clementine.scope import RateLimiter

    log.info("=== Step 1: load config ===")
    cfg = load_config(REPO_ROOT / "clementine.yaml")
    log.info("AWS profile=%s region=%s account_id=%s",
             cfg.aws.profile, cfg.aws.regions, cfg.aws.account_id)

    log.info("=== Step 2: resolve & verify AWS credentials ===")
    aws_env = resolve_aws_env(cfg.aws.profile)
    if not aws_env:
        log.error("No credentials resolved — refresh your `aws login` / SSO session and retry.")
        return 2
    region = cfg.aws.regions[0] if cfg.aws.regions else "us-east-1"
    account = verify_aws_credentials(aws_env, region=region)
    if account is None:
        log.error("Credentials rejected by sts:GetCallerIdentity — refresh and retry.")
        return 2
    for k, v in aws_env.items():
        os.environ[k] = v
    os.environ.pop("AWS_PROFILE", None)
    log.info("Credentials live for account=%s", account)

    log.info("=== Step 3: register & health-check cloud_audit MCP ===")
    registry = MCPRegistry()
    mcp_cfg = cfg.mcp_servers
    if mcp_cfg.cloud_audit is None:
        log.error("cloud_audit not configured in clementine.yaml")
        return 2
    if isinstance(mcp_cfg.cloud_audit, HttpServerConfig):
        registry.register_http("cloud_audit", mcp_cfg.cloud_audit)
    else:
        registry.register_stdio("cloud_audit", mcp_cfg.cloud_audit)

    async with registry:
        alive = await registry.ping_all()
        for name, ok in alive.items():
            log.info("  MCP %-12s %s", name, "OK" if ok else "DOWN")
            if not ok:
                registry._unavailable.add(name)
        await registry.discover_tools_all()

        limiter = RateLimiter(cfg.target.scope.rate_limit_rps)

        log.info("=== Step 4: cloud_audit lane (GuardDuty/SecHub/Inspector/AccessAnalyzer) ===")
        try:
            ca_findings = await _run_cloud_audit(cfg, registry, limiter)
            log.info("cloud_audit returned %d findings", len(ca_findings))
            _summarize(ca_findings)
        except Exception:
            log.exception("cloud_audit lane raised — surfacing for visibility")

        log.info("=== Step 5: Prowler lane (CLI subprocess) ===")
        try:
            prowler_findings = await _run_prowler(cfg, limiter)
            log.info("prowler returned %d findings", len(prowler_findings))
            _summarize(prowler_findings)
        except Exception:
            log.exception("prowler lane raised — surfacing for visibility")

    log.info("=== done ===")
    return 0


def _summarize(findings: list) -> None:
    if not findings:
        log.info("  (no findings)")
        return
    by_sev: dict[str, int] = {}
    for f in findings:
        s = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        by_sev[s] = by_sev.get(s, 0) + 1
    log.info("  by severity: %s", by_sev)
    for f in findings[:5]:
        log.info(
            "  • [%s] %s (resource=%s)",
            f.severity.value if hasattr(f.severity, "value") else f.severity,
            (f.title or "")[:80],
            (f.resource_id or "-")[:80],
        )
    if len(findings) > 5:
        log.info("  …and %d more", len(findings) - 5)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
