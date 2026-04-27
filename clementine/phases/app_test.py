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

from ..config import ClementineConfig
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard
from . import _autopentest

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
