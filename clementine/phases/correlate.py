"""
Phase 4 — Cross-domain correlation.

Delegates to the correlation engine (clementine.correlation.engine) which
loads YAML patterns, builds the finding graph, and instantiates attack chains.

This phase is intentionally thin — all complex logic lives in the engine.
"""

from __future__ import annotations

import logging

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
    """Execute Phase 4: cross-domain correlation and attack chain generation."""
    log.info("[Phase 4] Starting cross-domain correlation")

    engine = CorrelationEngine(db=db, mcp=mcp, limiter=limiter)
    chains_found = await engine.run()

    log.info("[Phase 4] Correlation complete — %d attack chains identified", chains_found)
