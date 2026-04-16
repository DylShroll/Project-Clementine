"""
Phase 4 — Cross-domain correlation.

Runs the rule-based correlation engine first (:mod:`clementine.correlation.engine`)
which loads YAML patterns and instantiates attack chains with hand-curated
precision, then — if AI is enabled — invokes
:mod:`clementine.ai.discovery` to propose novel chains the static rules
missed.

The two passes are deliberately additive: AI-discovered chains are tagged
with ``chain_source='ai-discovered'`` in the DB so reports and downstream
consumers can distinguish them from rule-matched chains.
"""

from __future__ import annotations

import logging

from ..ai.client import ClaudeClient
from ..ai.discovery import discover_chains
from ..config import ClementineConfig
from ..correlation.engine import CorrelationEngine
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)


async def run_correlation(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 4: rule-based correlation, then optional AI discovery."""
    log.info("[Phase 4] Starting cross-domain correlation")

    engine = CorrelationEngine(db=db, mcp=mcp, limiter=limiter)
    rule_chains = await engine.run()
    log.info("[Phase 4] Rule-based correlation — %d attack chains identified", rule_chains)

    # AI-assisted discovery is additive and fully optional. If disabled or
    # the client can't be constructed we fall through silently with just the
    # rule-based output, so the phase still succeeds on systems without an
    # Anthropic API key.
    if not cfg.ai.discovery.enabled:
        log.info("[Phase 4] AI chain discovery disabled — skipping")
        return

    client = ClaudeClient.from_config(cfg.ai)
    if client is None:
        log.info("[Phase 4] Claude client unavailable — skipping AI discovery")
        return

    ai_chains = await discover_chains(client=client, cfg=cfg.ai, db=db)
    log.info(
        "[Phase 4] Correlation complete — %d rule-based + %d AI-discovered chains",
        rule_chains, len(ai_chains),
    )
