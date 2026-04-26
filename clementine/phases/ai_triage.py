"""
Phase 3.5 — LLM triage of raw findings.

Runs after Phase 3 (app-layer testing) and before Phase 4 (correlation) so
that:

* Triage verdicts can be referenced by correlation narratives.
* A future CLI flag can filter out findings the LLM flagged as false
  positives before the correlator builds chains from them.

The phase degrades gracefully: if AI is disabled or no API key is set, it
logs a warning and returns without touching any findings. That keeps the
full assessment runnable on systems that don't have an Anthropic account.
"""

from __future__ import annotations

import logging

from ..ai.client import ClaudeClient
from ..ai.triage import triage_findings
from ..config import ClementineConfig
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)


async def run_ai_triage(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 3.5: LLM triage of every finding in the store."""
    log.info("[Phase 3.5] Starting AI finding triage")

    if not cfg.ai.triage.enabled:
        log.info("[Phase 3.5] Triage disabled in config — skipping")
        return

    client = ClaudeClient.from_config(cfg.ai, db=db)
    if client is None:
        log.info("[Phase 3.5] Claude client unavailable — skipping triage")
        return

    # Triage only findings that don't already have a verdict. Re-running the
    # phase after a resume shouldn't re-triage work that's already been paid for.
    all_findings = await db.get_findings()
    pending = [f for f in all_findings if f.triage_confidence is None]

    if not pending:
        log.info("[Phase 3.5] All %d findings already triaged — nothing to do",
                 len(all_findings))
        return

    log.info("[Phase 3.5] Triaging %d of %d findings", len(pending), len(all_findings))
    await triage_findings(pending, client=client, cfg=cfg.ai, db=db)
    log.info("[Phase 3.5] AI triage complete")
