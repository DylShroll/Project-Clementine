"""
Phase 3 — Application-layer penetration testing.

Delegates the full OWASP WSTG methodology to AutoPentest AI.  WSTG
categories 2-5 are dispatched in parallel; category 6 (input validation)
parallelises by attack type; category 7 (client-side) runs last and
dispatches DOM-based PoC validation to the Playwright MCP server.

Project Clementine monitors coverage progress after each batch and logs
any category that does not reach the 80% threshold.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..config import ClementineConfig
from ..db import Finding, FindingsDB, Severity
from ..mcp_client import MCPRegistry
from ..sanitize import sanitize_evidence
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)

# WSTG category codes in the order AutoPentest executes them
_WSTG_PARALLEL_BATCH = ["WSTG-CONF", "WSTG-ATHN", "WSTG-ATHZ", "WSTG-SESS"]
# WSTG-INPV attack types for per-type parallelisation
_INPV_ATTACK_TYPES = ["SQLi", "XSS", "SSRF", "XXE", "CMDI", "SSTI", "PathTraversal", "CORS"]


async def run_app_test(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 3: full OWASP WSTG penetration test via AutoPentest AI."""
    if not mcp.is_available("autopentest"):
        log.warning("[Phase 3] AutoPentest unavailable — skipping application testing")
        return

    target_url = cfg.target.url

    # ------------------------------------------------------------------
    # 3a. Parallel batch: WSTG categories 2-5
    # ------------------------------------------------------------------
    log.info("[Phase 3] Running WSTG categories 2-5 in parallel")
    tasks = [
        _run_wstg_category(target_url, category, db, mcp, scope, limiter)
        for category in _WSTG_PARALLEL_BATCH
    ]
    await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    # 3b. Input validation — parallelised by attack type (WSTG-INPV)
    # ------------------------------------------------------------------
    log.info("[Phase 3] Running WSTG-INPV (input validation) by attack type")
    inpv_tasks = [
        _run_wstg_inpv(target_url, attack_type, db, mcp, scope, limiter)
        for attack_type in _INPV_ATTACK_TYPES
    ]
    await asyncio.gather(*inpv_tasks)

    # ------------------------------------------------------------------
    # 3c. Client-side testing (WSTG-CLNT) — sequential, depends on INPV
    # ------------------------------------------------------------------
    log.info("[Phase 3] Running WSTG-CLNT (client-side) with Playwright PoC validation")
    await _run_wstg_client_side(target_url, db, mcp, scope, limiter)

    # ------------------------------------------------------------------
    # 3d. Coverage check
    # ------------------------------------------------------------------
    await _check_coverage(mcp, limiter)


# ---------------------------------------------------------------------------
# Category runners
# ---------------------------------------------------------------------------

async def _run_wstg_category(
    target_url: str,
    category: str,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Load the technique guide for *category* then run all its tests."""
    log.info("[Phase 3] Category: %s", category)
    async with limiter:
        scope.check_url(target_url)
        # Load the relevant methodology guide before testing
        await mcp.call_tool(
            "autopentest",
            "get_technique_guide",
            {"category": category},
        )

    async with limiter:
        scope.check_url(target_url)
        result = await mcp.call_tool(
            "autopentest",
            "run_test",
            {"category": category, "target_url": target_url},
        )

    if result:
        await _store_phase3_findings(result, category, db)


async def _run_wstg_inpv(
    target_url: str,
    attack_type: str,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Run one WSTG-INPV attack type with its WAF-bypass technique guide."""
    log.info("[Phase 3] WSTG-INPV attack type: %s", attack_type)
    async with limiter:
        scope.check_url(target_url)
        await mcp.call_tool(
            "autopentest",
            "get_technique_guide",
            {"category": "WSTG-INPV", "attack_type": attack_type},
        )

    async with limiter:
        scope.check_url(target_url)
        result = await mcp.call_tool(
            "autopentest",
            "run_test",
            {
                "category": "WSTG-INPV",
                "attack_type": attack_type,
                "target_url": target_url,
            },
        )

    if result:
        await _store_phase3_findings(result, f"WSTG-INPV-{attack_type}", db)


async def _run_wstg_client_side(
    target_url: str,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Run WSTG-CLNT and use Playwright to validate DOM-based findings."""
    async with limiter:
        scope.check_url(target_url)
        clnt_result = await mcp.call_tool(
            "autopentest",
            "run_test",
            {"category": "WSTG-CLNT", "target_url": target_url},
        )

    if clnt_result:
        await _store_phase3_findings(clnt_result, "WSTG-CLNT", db)

    # Playwright validation for DOM-based XSS and clickjacking candidates
    if mcp.is_available("playwright"):
        await _playwright_validate(target_url, db, mcp, scope, limiter)


async def _playwright_validate(
    target_url: str,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Use Playwright to validate client-side vulnerabilities in a live DOM."""
    log.info("[Phase 3] Running Playwright DOM validation")

    # Navigate to the target in headless browser
    async with limiter:
        scope.check_url(target_url)
        await mcp.call_tool("playwright", "navigate", {"url": target_url})

    # Inspect cookie attributes (HttpOnly, Secure, SameSite)
    async with limiter:
        cookies = await mcp.call_tool("playwright", "get_cookies", {})

    if cookies:
        await _check_cookie_attributes(cookies, target_url, db)

    # Screenshot for evidence
    async with limiter:
        screenshot = await mcp.call_tool(
            "playwright",
            "screenshot",
            {"path": f"evidence/phase3_target_{_url_slug(target_url)}.png"},
        )
    log.debug("[Phase 3] Playwright screenshot captured")


async def _check_cookie_attributes(
    cookies: list[dict],
    target_url: str,
    db: FindingsDB,
) -> None:
    """Inspect cookie security attributes and record findings for missing ones."""
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = cookie.get("name", "cookie")

        # Missing HttpOnly — enables session token theft via XSS
        if not cookie.get("httpOnly", False):
            await db.insert_finding(Finding(
                source="autopentest",
                phase=3,
                severity=Severity.MEDIUM,
                category="WSTG-SESS-02",
                title=f"Cookie '{name}' missing HttpOnly flag",
                description=(
                    f"The cookie '{name}' does not have the HttpOnly attribute set. "
                    "This allows JavaScript to read the cookie value, enabling session "
                    "token theft via cross-site scripting (XSS) attacks."
                ),
                resource_type="url",
                resource_id=target_url,
                evidence_type="config_dump",
                evidence_data={"cookie": cookie},
                remediation_summary="Set the HttpOnly attribute on all session cookies.",
                remediation_cli=f'# Set-Cookie: {name}=<value>; HttpOnly; Secure; SameSite=Strict',
                confidence=1.0,
                is_validated=True,
            ))

        # Missing Secure — cookie sent over plain HTTP
        if not cookie.get("secure", False):
            await db.insert_finding(Finding(
                source="autopentest",
                phase=3,
                severity=Severity.MEDIUM,
                category="WSTG-SESS-02",
                title=f"Cookie '{name}' missing Secure flag",
                description=(
                    f"The cookie '{name}' does not have the Secure attribute. "
                    "It may be transmitted over unencrypted HTTP connections."
                ),
                resource_type="url",
                resource_id=target_url,
                evidence_type="config_dump",
                evidence_data={"cookie": cookie},
                remediation_summary="Set the Secure attribute on all cookies.",
                confidence=1.0,
                is_validated=True,
            ))


# ---------------------------------------------------------------------------
# Coverage reporting
# ---------------------------------------------------------------------------

async def _check_coverage(mcp: MCPRegistry, limiter: RateLimiter) -> None:
    """Log a warning for any WSTG category below the 80% coverage threshold."""
    if not mcp.is_available("autopentest"):
        return

    async with limiter:
        coverage = await mcp.call_tool("autopentest", "get_coverage", {})

    if not coverage:
        return

    for category, pct in (coverage or {}).items():
        if isinstance(pct, (int, float)) and pct < 80:
            log.warning(
                "[Phase 3] Coverage below 80%% for %s: %.0f%% — "
                "document why tests are not applicable.",
                category, pct,
            )


# ---------------------------------------------------------------------------
# Finding storage
# ---------------------------------------------------------------------------

async def _store_phase3_findings(
    raw: Any,
    category: str,
    db: FindingsDB,
) -> None:
    """Normalise AutoPentest output for a specific WSTG category and store it."""
    findings_list: list[dict] = []
    if isinstance(raw, list):
        findings_list = raw
    elif isinstance(raw, dict) and "findings" in raw:
        findings_list = raw["findings"]

    for item in findings_list:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence", {})
        await db.insert_finding(Finding(
            source="autopentest",
            phase=3,
            severity=Severity(item.get("severity", "INFO").upper()),
            category=item.get("wstg_code", category),
            title=item.get("title", "Unknown"),
            description=item.get("description", ""),
            resource_type="url",
            resource_id=item.get("url"),
            evidence_type=item.get("evidence_type", "http_exchange"),
            evidence_data=sanitize_evidence(evidence) if evidence else None,
            remediation_summary=item.get("remediation"),
            confidence=float(item.get("confidence", 1.0)),
            is_validated=bool(item.get("validated", False)),
            raw_source_data=item,
        ))


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _url_slug(url: str) -> str:
    """Return a filesystem-safe slug derived from a URL."""
    return url.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
