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

import json
import logging
import re
from pathlib import Path

from ..ai.client import ClaudeClient
from ..ai.discovery import discover_chains
from ..config import ClementineConfig
from ..correlation.engine import CorrelationEngine
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)


def _find_web_app_graph(cfg: ClementineConfig) -> Path | None:
    """Locate the autopentest-ai knowledge graph JSON for this engagement."""
    # Derive an engagement ID slug from the target URL (mirrors autopentest-ai logic)
    slug = re.sub(r"[^a-z0-9]+", "-", cfg.target.url.lower()).strip("-")[:40]
    candidates = [
        Path("autopentest-ai/server/data/graphs") / f"{slug}.json",
        Path("autopentest-ai/server/data") / slug / "graph.json",
    ]
    # Also glob for any JSON in the graphs directory
    graphs_dir = Path("autopentest-ai/server/data/graphs")
    if graphs_dir.exists():
        for p in sorted(graphs_dir.glob("*.json")):
            candidates.append(p)

    for p in candidates:
        if p.exists():
            return p
    return None


async def run_correlation(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Execute Phase 4: rule-based correlation, then optional AI discovery."""
    log.info("[Phase 4] Starting cross-domain correlation")

    # Build knowledge graph from persisted nodes and optionally bridge the web-app layer
    analyzer = None
    try:
        from ..graph import GraphBuilder, AttackSurfaceAnalyzer
        builder = GraphBuilder(db)
        nx_graph = await builder.build_from_db()
        analyzer = AttackSurfaceAnalyzer(nx_graph)

        web_graph_path = _find_web_app_graph(cfg)
        if web_graph_path and web_graph_path.exists():
            try:
                web_graph = json.loads(web_graph_path.read_text(encoding="utf-8"))
                analyzer.bridge_web_app_graph(web_graph)
                log.info("[Phase 4] Bridged web-app graph from %s", web_graph_path)
            except Exception as exc:
                log.debug("[Phase 4] Web-app graph bridge failed (non-fatal): %s", exc)

        log.info(
            "[Phase 4] Knowledge graph loaded: %d nodes, %d edges",
            nx_graph.number_of_nodes(), nx_graph.number_of_edges(),
        )
    except Exception as exc:
        log.warning("[Phase 4] Knowledge graph unavailable (falling back to 1-hop): %s", exc)

    engine = CorrelationEngine(db=db, mcp=mcp, limiter=limiter, analyzer=analyzer)
    rule_chains = await engine.run()
    log.info("[Phase 4] Rule-based correlation — %d attack chains identified", rule_chains)

    # AI-assisted discovery is additive and fully optional. If disabled or
    # the client can't be constructed we fall through silently with just the
    # rule-based output, so the phase still succeeds on systems without an
    # Anthropic API key.
    if not cfg.ai.discovery.enabled:
        log.info("[Phase 4] AI chain discovery disabled — skipping")
        return

    client = ClaudeClient.from_config(cfg.ai, db=db)
    if client is None:
        log.info("[Phase 4] Claude client unavailable — skipping AI discovery")
        return

    ai_chains = await discover_chains(
        client=client, cfg=cfg.ai, db=db, analyzer=analyzer
    )
    log.info(
        "[Phase 4] Correlation complete — %d rule-based + %d AI-discovered chains",
        rule_chains, len(ai_chains),
    )
