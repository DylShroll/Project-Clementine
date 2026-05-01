"""
Phase 3 — Application-layer penetration testing.

Drives Claude Code through AutoPentest's WSTG Phases 2–5 (configuration,
identity/auth/session, input validation, and client-side + error/crypto/
business-logic + API testing) via a single subprocess invocation.

The subprocess re-uses the engagement registered in Phase 1 (same ID, same
scope, same credentials), so Claude Code picks up where recon left off.
Playwright MCP validation is also requested through the subprocess — running
it separately from Clementine would duplicate the work.

After the subprocess exits, Clementine ingests any newly logged AutoPentest
findings from the engagement's JSON store.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..config import ClementineConfig
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard
from . import _autopentest

if TYPE_CHECKING:
    pass  # forward refs used in probe function signatures

log = logging.getLogger(__name__)


async def run_app_test(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 3: full OWASP WSTG Phases 2–5 via AutoPentest."""
    if not mcp.is_available("autopentest"):
        log.warning("[Phase 3] AutoPentest unavailable — skipping application testing")
        return

    target_url = cfg.target.url
    scope.check_url(target_url)

    eid = await _autopentest.get_or_create_engagement_id(cfg, db)
    log.info("[Phase 3] Continuing AutoPentest engagement %s", eid)

    prompt = _build_app_test_prompt(cfg, eid)
    log.info("[Phase 3] Running AutoPentest Phases 2–5 via Claude Code")
    output = await _autopentest.run_claude_code(
        prompt,
        timeout=7200,
        model=cfg.ai.primary_model,
        aws_region=cfg.ai.aws_region,
    )
    log.debug("[Phase 3] Claude Code output (last 400 chars): …%s", output[-400:])

    inserted = await _autopentest.ingest_findings(cfg, db, eid, phase=3)
    log.info("[Phase 3] Ingested %d new findings from AutoPentest", inserted)

    # ------------------------------------------------------------------
    # Azure-specific probes (opt-in via guardrails)
    # ------------------------------------------------------------------
    if cfg.azure.enabled:
        if cfg.azure.guardrails.allow_imds_probe:
            await _probe_azure_imds(cfg, db)
            await _probe_app_service_identity_endpoint(cfg, db)
        await _probe_wireserver(cfg, db)
        if cfg.azure.guardrails.allow_sas_token_extraction:
            await _probe_sas_token_patterns(cfg, db)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_app_test_prompt(cfg: ClementineConfig, eid: str) -> str:
    """Prompt Claude Code to execute AutoPentest Phases 2–5."""
    rate = cfg.target.scope.rate_limit_rps
    include = ", ".join(cfg.target.scope.include_domains) or "(see engagement config)"
    exclude = ", ".join(cfg.target.scope.exclude_paths or []) or "(none)"

    return f"""You are continuing an AutoPentest engagement on behalf of Project Clementine.

Engagement ID: {eid}
Target URL:    {cfg.target.url}
Scope domains: {include}
Excluded:      {exclude}
Rate limit:    {rate} req/s (respect this across all tools)

Phase 0 and Phase 1 have already been completed. The endpoint map, scope,
credentials, and WSTG-INFO findings are persisted in the engagement. Start
by calling:

  - resume_engagement("{eid}")  — restores the checkpoint state
  - get_engagement_config("{eid}")  — confirms target + credentials
  - get_coverage("{eid}")  — shows already-tracked tests

Your task is to execute Phases 2 through 5 exactly as CLAUDE.md describes:

  Phase 2 — Configuration & Deployment Testing (WSTG-CONF)
    Run all MUST tests. Track each test. Spawn Quality Reviewer. Call
    phase_gate_check("{eid}", 2).

  Phase 3 — Identity, Authentication, Authorization, Session (IDNT/ATHN/
    ATHZ/SESS). Use parallel Analyzer subagents per category. Quality
    Reviewer + phase_gate_check("{eid}", 3).

  Phase 4 — Input Validation (WSTG-INPV): mandatory Analyzer→Exploiter
    pipelines for XSS / Injection / SSRF+SSTI+PathTraversal. Quality
    Reviewer + phase_gate_check("{eid}", 4). Gate 4 is strictly enforced.

  Phase 5 — Error Handling / Cryptography / Business Logic / Client-Side /
    API (WSTG-ERRH, CRYP, BUSL, CLNT, APIT). Quality Reviewer +
    phase_gate_check("{eid}", 5).

STOP after Phase 5 completes — do NOT run Phase 6 (coverage verification)
or Phase 7 (Final Judge). Clementine runs its own correlation and reporting
phases after this subprocess returns.

Constraints:
  - Honour the rate limit; never exceed {rate} req/s.
  - Stay inside the registered scope; never touch excluded paths.
  - Use `docker exec autopentest-tools curl` for HTTP requests.
  - Log every finding with log_finding() immediately when discovered.
  - Do NOT call generate_report() — Clementine handles reporting.

Proceed now.
"""


# ---------------------------------------------------------------------------
# Azure infrastructure probes
# ---------------------------------------------------------------------------

_IMDS_AUDIENCES = [
    "management.azure.com",
    "vault.azure.net",
    "storage.azure.com",
    "graph.microsoft.com",
    "database.windows.net",
]

_IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
_WIRESERVER_ENDPOINT = "http://168.63.129.16/"


async def _probe_azure_imds(cfg: "ClementineConfig", db: "FindingsDB") -> None:
    """Probe Azure IMDS for each target audience; report JWT reachability only.

    Strips the signature before persisting — stores header.payload only.
    Does NOT use the token to call any downstream service.
    """
    import aiohttp
    from ..db import Finding, Severity

    for audience in _IMDS_AUDIENCES:
        url = f"{_IMDS_ENDPOINT}?api-version=2018-02-01&resource=https://{audience}"
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    url,
                    headers={"Metadata": "true"},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        raw_token = body.get("access_token", "")
                        # Strip signature — keep header.payload only
                        parts = raw_token.split(".")
                        safe_token = ".".join(parts[:2]) if len(parts) >= 2 else ""
                        claims = _decode_jwt_payload(parts[1]) if len(parts) >= 2 else {}
                        finding = Finding(
                            title=f"Azure IMDS Token Accessible — audience={audience}",
                            severity=Severity.CRITICAL,
                            category="azure:imds_exposed",
                            source="clementine-azure-probe",
                            provider="azure",
                            description=(
                                f"The Azure Instance Metadata Service is reachable and returned "
                                f"an OAuth2 token for resource {audience}. "
                                f"Token header.payload (signature stripped): {safe_token[:300]}"
                            ),
                            evidence=str(claims),
                        )
                        await db.insert_finding(finding)
                        log.warning(
                            "[Phase 3] Azure IMDS token obtained for %s (CRITICAL)", audience
                        )
        except Exception as exc:
            log.debug("[Phase 3] IMDS probe for %s: %s", audience, exc)


async def _probe_app_service_identity_endpoint(
    cfg: "ClementineConfig", db: "FindingsDB"
) -> None:
    """Probe App Service identity endpoint for each audience.

    The IDENTITY_ENDPOINT env var is only available inside the App Service sandbox
    and is not guessable from outside. This probe is a no-op unless we're running
    inside a target App Service or have SSRF reach to the internal endpoint.
    """
    import os
    import aiohttp
    from ..db import Finding, Severity

    endpoint = os.environ.get("IDENTITY_ENDPOINT")
    header_val = os.environ.get("IDENTITY_HEADER")
    if not endpoint or not header_val:
        log.debug("[Phase 3] IDENTITY_ENDPOINT not set — App Service identity probe skipped")
        return

    for audience in _IMDS_AUDIENCES:
        url = f"{endpoint}?resource=https://{audience}&api-version=2019-08-01"
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    url,
                    headers={"X-IDENTITY-HEADER": header_val},
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        raw_token = body.get("access_token", "")
                        parts = raw_token.split(".")
                        safe_token = ".".join(parts[:2]) if len(parts) >= 2 else ""
                        finding = Finding(
                            title=f"App Service Managed Identity Token — audience={audience}",
                            severity=Severity.CRITICAL,
                            category="azure:app_service_has_system_mi",
                            source="clementine-azure-probe",
                            provider="azure",
                            description=(
                                f"App Service identity endpoint returned OAuth2 token for "
                                f"resource {audience}. Token header.payload: {safe_token[:300]}"
                            ),
                        )
                        await db.insert_finding(finding)
        except Exception as exc:
            log.debug("[Phase 3] App Service identity probe for %s: %s", audience, exc)


async def _probe_wireserver(cfg: "ClementineConfig", db: "FindingsDB") -> None:
    """Probe Azure WireServer (168.63.129.16) — information disclosure only."""
    import aiohttp
    from ..db import Finding, Severity

    try:
        async with aiohttp.ClientSession() as sess:
            async with sess.get(
                _WIRESERVER_ENDPOINT,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status < 500:
                    finding = Finding(
                        title="Azure WireServer Reachable (168.63.129.16) — Azure VM Context Confirmed",
                        severity=Severity.INFO,
                        category="azure:wireserver_reachable",
                        source="clementine-azure-probe",
                        provider="azure",
                        description=(
                            "HTTP GET to 168.63.129.16 succeeded. This confirms the assessment "
                            "is running inside an Azure VM context. The WireServer exposes VM "
                            "extension management endpoints — no token exfiltration attempted."
                        ),
                    )
                    await db.insert_finding(finding)
                    log.info("[Phase 3] Azure WireServer reachable — VM context confirmed")
    except Exception as exc:
        log.debug("[Phase 3] WireServer probe: %s", exc)


async def _probe_sas_token_patterns(cfg: "ClementineConfig", db: "FindingsDB") -> None:
    """Scan accumulated HTTP responses for embedded SAS token patterns.

    Reads findings from the DB that have 'evidence' fields containing SAS token
    signatures and re-classifies them with expiry + scope analysis.
    """
    import re
    from ..db import Finding, Severity

    sas_re = re.compile(
        r"\?(?:.*&)?sv=(?P<sv>[^&\s\"']+).*?sig=(?P<sig>[^&\s\"']{10,}).*?se=(?P<se>[^&\s\"']+)",
        re.IGNORECASE,
    )

    all_findings = await db.get_findings()
    for f in all_findings:
        evidence = f.evidence or ""
        for match in sas_re.finditer(evidence):
            se = match.group("se")  # signed expiry
            sv = match.group("sv")  # signed version
            # Very rough: check if 'srt' or 'sr=account' is in the same token string
            segment = evidence[max(0, match.start() - 50): match.end() + 50]
            is_account_scope = "srt=" in segment or "sr=account" in segment.lower()
            try:
                from datetime import datetime, timezone
                expiry = datetime.fromisoformat(se.rstrip("Z")).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                expiry_days = (expiry - now).days
            except Exception:
                expiry_days = -1

            severity = Severity.HIGH if (expiry_days > 7 or is_account_scope) else Severity.MEDIUM
            sas_finding = Finding(
                title=f"Azure SAS Token Detected in Response (expiry ~{expiry_days}d, account={'yes' if is_account_scope else 'no'})",
                severity=severity,
                category="SAS_TOKEN",
                source="clementine-azure-probe",
                provider="azure",
                resource_id=f.resource_id,
                description=(
                    f"An Azure SAS token was found embedded in HTTP evidence for finding '{f.title}'. "
                    f"Signed version: {sv}. Approximate expiry days: {expiry_days}. "
                    f"Account-scope: {is_account_scope}."
                ),
            )
            await db.insert_finding(sas_finding)
            log.warning("[Phase 3] SAS token found in evidence of finding %s", f.id)


def _decode_jwt_payload(b64: str) -> dict:
    """Base64url-decode a JWT payload; return empty dict on any error."""
    import base64, json as _json
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        return _json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}
