"""Phase 0 — Infrastructure-as-Code analysis (Workstream B "Pith").

Runs before recon. For every configured IaC source it:

  1. Resolves the source to a local working tree (clones git, extracts
     bundle, etc.). M1 supports `dir` only; later milestones light up
     the remaining types without touching this entry-point.
  2. Runs every applicable enabled scanner in parallel. A single scanner
     crash is isolated via per-scanner ``enrichment_status``; the rest
     of the phase keeps making progress.
  3. Normalises the raw scanner output, dedups, persists.
  4. Records overall phase success/failure summary.

Graph projection (planned IaC nodes onto the live AWS/Azure graph) and
identity merging are M3 work and are deliberately stubbed here behind a
log call so M3 can light them up without touching this file.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from ..config import ClementineConfig
from ..db import FindingsDB
from ..mcp_client import MCPRegistry
from ..scope import RateLimiter, ScopeGuard
from .iac.normalize import normalize
from .iac.projection import project_planned_nodes
from .iac.scanners import build_scanner_list
from .iac.scanners.base import RawFinding
from .iac.sources import ResolvedSource, resolve_sources
from .iac.suppress import filter_suppressed

log = logging.getLogger(__name__)


async def run_iac_scan(
    cfg: ClementineConfig,
    db: FindingsDB,
    mcp: MCPRegistry,
    scope: ScopeGuard,
    limiter: RateLimiter,
) -> None:
    """Phase 0 entry-point.

    Signature matches every other phase
    (cfg, db, mcp, scope, limiter) so the orchestrator can dispatch it
    uniformly. ``mcp``, ``scope`` and ``limiter`` are accepted but
    unused at M1 — Phase 0 deliberately runs no network calls.
    """
    log.info(
        "[Phase 0] Starting IaC scan over %d source(s)",
        len(cfg.iac.sources),
    )

    # 1) Resolve every source to a local tree.
    resolved = await resolve_sources(cfg.iac.sources, cfg.iac.guardrails)
    if not resolved:
        log.warning("[Phase 0] No usable IaC sources resolved — phase exits clean")
        await db.set_enrichment_status(
            "iac_scan", "unavailable", "no usable sources resolved"
        )
        return

    try:
        # 2) Build the scanner list and dispatch in parallel.
        scanners = build_scanner_list(cfg.iac.scanners)
        if not scanners:
            await db.set_enrichment_status(
                "iac_scan", "unavailable", "no enabled scanners"
            )
            log.warning("[Phase 0] No enabled scanners — nothing to do")
            return

        raw_findings = await _run_scanners(
            scanners=scanners,
            sources=resolved,
            db=db,
            timeout=cfg.iac.guardrails.scanner_timeout_seconds,
            fail_open=cfg.iac.guardrails.fail_open,
            max_findings=cfg.iac.guardrails.max_findings_per_scanner,
        )

        # 3) Normalise + dedup, then drop anything carrying a
        #    `# clementine:false-positive` marker on (or directly above)
        #    its source line. Suppression is scanner-agnostic so the
        #    convention is uniform across tfsec / checkov / cfn-nag /
        #    gitleaks / trufflehog.
        findings = normalize(raw_findings)
        findings = filter_suppressed(findings, resolved)

        # 4) Persist. Each finding carries source="iac-scanner-<name>"
        #    and phase=0; downstream phases (correlation, reporting)
        #    pick them up via the standard get_findings() path.
        for f in findings:
            await db.insert_finding(f)

        # 5) Project planned IaC resources onto the knowledge graph as
        #    nodes tagged ``provenance=iac``. When a later AWS/Azure
        #    audit upserts a live node sharing the same node_id, the
        #    upsert's ON CONFLICT clause promotes it to ``live+iac``
        #    automatically — no separate identity-merge sweep needed.
        try:
            projected = await project_planned_nodes(db)
        except Exception as exc:                                   # pragma: no cover - defensive
            log.warning("[Phase 0] graph projection failed (non-fatal): %s", exc)
            projected = 0

        log.info(
            "[Phase 0] IaC scan complete — %d finding(s), %d planned node(s) across %d source(s)",
            len(findings), projected, len(resolved),
        )
        await db.set_enrichment_status(
            "iac_scan",
            "ok",
            f"{len(findings)} findings across {len(resolved)} source(s)",
        )
    finally:
        # Resolved sources may have created temp dirs (git clone, bundle
        # extract, terraform plan render). Always clean them up.
        await _cleanup(resolved)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

async def _run_scanners(
    *,
    scanners: list,
    sources: list[ResolvedSource],
    db: FindingsDB,
    timeout: int,
    fail_open: bool,
    max_findings: int,
) -> list[RawFinding]:
    """Fan out (scanner × applicable source) and aggregate raw findings."""

    async def _run_one(scanner, src: ResolvedSource) -> list[RawFinding]:
        # Pass the configured timeout into each subprocess scanner. We
        # mutate the instance's timeout once per phase rather than
        # threading a kwarg through ``Scanner.run`` because scanners
        # are constructed fresh each phase invocation.
        if hasattr(scanner, "_timeout"):
            scanner._timeout = timeout
        try:
            results = await scanner.run(src)
        except Exception as exc:
            await db.set_enrichment_status(
                f"iac_{scanner.name}",
                "unavailable",
                f"{type(exc).__name__}: {exc}",
            )
            log.warning(
                "[Phase 0] %s crashed on %s: %s",
                scanner.name, src.path, exc,
            )
            if not fail_open:
                raise
            return []

        # Honour the per-scanner finding cap — a misconfigured scanner
        # spraying thousands of low-quality results shouldn't take down
        # the whole DB.
        if len(results) > max_findings:
            log.warning(
                "[Phase 0] %s: capping %d findings -> %d",
                scanner.name, len(results), max_findings,
            )
            await db.set_enrichment_status(
                f"iac_{scanner.name}",
                "partial",
                f"capped at {max_findings} of {len(results)} findings",
            )
            results = results[:max_findings]
        else:
            await db.set_enrichment_status(
                f"iac_{scanner.name}", "ok", f"{len(results)} findings"
            )
        return results

    tasks = [
        _run_one(scanner, src)
        for scanner in scanners
        for src in sources
        if scanner.applicable_to(src)
    ]
    if not tasks:
        log.info("[Phase 0] No scanner-source pairs apply — nothing to scan")
        return []

    # Aggregate. Exceptions from non-fail-open mode propagate so the
    # phase aborts loudly when the user has explicitly asked for it.
    grouped = await asyncio.gather(*tasks)
    return [item for sub in grouped for item in sub]


async def _cleanup(resolved: Iterable[ResolvedSource]) -> None:
    """Best-effort cleanup of temp-dir-backed sources.

    Failures here are debug-logged and never re-raised — temp dir
    leakage at process-exit is preferable to crashing the orchestrator.
    """
    for src in resolved:
        if src.cleanup is None:
            continue
        try:
            result = src.cleanup()
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:                                   # pragma: no cover - best-effort
            log.debug("[Phase 0] cleanup failed for %s: %s", src.path, exc)
