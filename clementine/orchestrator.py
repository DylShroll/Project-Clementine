"""
Orchestration engine — state machine and phase dispatch.

Manages the five-phase assessment lifecycle:
  INITIALIZED → RECON → AWS_AUDIT → APP_TEST → CORRELATION → REPORTING → COMPLETE

The engine coordinates MCP server lifecycle, persists state to the database
so assessments can be resumed, and handles the kill-switch signal (SIGINT /
SIGTERM) gracefully.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from enum import Enum
from pathlib import Path
from typing import Optional

from .config import ClementineConfig
from .db import FindingsDB
from .mcp_client import MCPRegistry
from .scope import RateLimiter, ScopeGuard

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State machine states
# ---------------------------------------------------------------------------

class AssessmentState(str, Enum):
    INITIALIZED = "INITIALIZED"
    RECON_RUNNING = "RECON_RUNNING"
    RECON_COMPLETE = "RECON_COMPLETE"
    AWS_AUDIT_RUNNING = "AWS_AUDIT_RUNNING"
    AWS_AUDIT_COMPLETE = "AWS_AUDIT_COMPLETE"
    APP_TEST_RUNNING = "APP_TEST_RUNNING"
    APP_TEST_COMPLETE = "APP_TEST_COMPLETE"
    # Phase 3.5 — LLM finding triage (optional, skipped when AI disabled)
    AI_TRIAGE_RUNNING = "AI_TRIAGE_RUNNING"
    AI_TRIAGE_COMPLETE = "AI_TRIAGE_COMPLETE"
    CORRELATION_RUNNING = "CORRELATION_RUNNING"
    CORRELATION_COMPLETE = "CORRELATION_COMPLETE"
    REPORTING = "REPORTING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    PAUSED = "PAUSED"


# DB key used to persist current state between runs
_STATE_KEY = "assessment_state"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Drives the full five-phase assessment.

    Instantiate with a loaded ClementineConfig, then call run().  All
    results are persisted to the database; run() returns the path to the
    primary report file.
    """

    def __init__(self, config: ClementineConfig, db: FindingsDB) -> None:
        self._cfg = config
        self._db = db
        self._mcp = MCPRegistry()
        self._scope = ScopeGuard(config.target.scope)
        self._limiter = RateLimiter(config.target.scope.rate_limit_rps)
        self._state = AssessmentState.INITIALIZED
        self._kill_requested = False

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    async def run(self) -> Path:
        """Execute the full assessment and return the output directory path.

        Resumes from the last persisted state so a failed run can be
        restarted without repeating completed phases.
        """
        self._register_kill_switch()

        try:
            async with self._mcp:
                await self._setup_mcp_servers()
                await self._run_phases()
        except Exception as exc:
            await self._set_state(AssessmentState.FAILED)
            log.exception("Assessment failed: %s", exc)
            raise
        finally:
            self._deregister_kill_switch()

        return self._cfg.reporting.output_dir

    # ------------------------------------------------------------------
    # Phase dispatch
    # ------------------------------------------------------------------

    async def _run_phases(self) -> None:
        """Restore state and run outstanding phases in order."""
        # Restore persisted state (allows resuming after a crash)
        persisted = await self._db.get_state(_STATE_KEY)
        if persisted:
            try:
                restored = AssessmentState(persisted)
            except ValueError:
                restored = AssessmentState.INITIALIZED
            # COMPLETE / FAILED mean a prior run already finished — start fresh
            # rather than immediately skipping everything or repeating a failure.
            if restored in (AssessmentState.COMPLETE, AssessmentState.FAILED):
                self._state = AssessmentState.INITIALIZED
                log.info("Previous run ended with %s — starting fresh assessment", restored)
            else:
                self._state = restored
                log.info("Resuming from state: %s", self._state)

        # Import phases lazily so each module is only loaded when needed
        from .phases.recon import run_recon
        from .phases.aws_audit import run_aws_audit
        from .phases.app_test import run_app_test
        from .phases.ai_triage import run_ai_triage
        from .phases.correlate import run_correlation
        from .phases.report import run_reporting

        phases = [
            (AssessmentState.RECON_RUNNING, AssessmentState.RECON_COMPLETE, run_recon),
            (AssessmentState.AWS_AUDIT_RUNNING, AssessmentState.AWS_AUDIT_COMPLETE, run_aws_audit),
            (AssessmentState.APP_TEST_RUNNING, AssessmentState.APP_TEST_COMPLETE, run_app_test),
            (AssessmentState.AI_TRIAGE_RUNNING, AssessmentState.AI_TRIAGE_COMPLETE, run_ai_triage),
            (AssessmentState.CORRELATION_RUNNING, AssessmentState.CORRELATION_COMPLETE, run_correlation),
            (AssessmentState.REPORTING, AssessmentState.COMPLETE, run_reporting),
        ]

        for start_state, end_state, phase_fn in phases:
            if self._kill_requested:
                log.warning("Kill switch triggered — stopping assessment")
                return

            # Skip phases that were already completed in a prior run
            if self._is_state_past(start_state):
                log.info("Skipping already-complete phase: %s", start_state)
                continue

            await self._maybe_pause(start_state)

            await self._set_state(start_state)
            log.info("=== Starting phase: %s ===", start_state)

            await phase_fn(
                cfg=self._cfg,
                db=self._db,
                mcp=self._mcp,
                scope=self._scope,
                limiter=self._limiter,
            )

            await self._set_state(end_state)
            log.info("=== Phase complete: %s ===", end_state)

    # ------------------------------------------------------------------
    # MCP server setup
    # ------------------------------------------------------------------

    async def _setup_mcp_servers(self) -> None:
        """Register all configured MCP servers and run an initial health check."""
        from .config import HttpServerConfig

        mcp_cfg = self._cfg.mcp_servers
        servers = [
            ("autopentest",  mcp_cfg.autopentest),
            ("cloud_audit",  mcp_cfg.cloud_audit),
            ("prowler",      mcp_cfg.prowler),
            ("aws_knowledge", mcp_cfg.aws_knowledge),
            ("aws_docs",     mcp_cfg.aws_docs),
            ("playwright",   mcp_cfg.playwright),
        ]
        for name, cfg in servers:
            if cfg is None:
                continue
            if isinstance(cfg, HttpServerConfig):
                self._mcp.register_http(name, cfg)
            else:
                self._mcp.register_stdio(name, cfg)

        health = await self._mcp.ping_all()
        for name, alive in health.items():
            status = "OK" if alive else "UNAVAILABLE"
            log.info("  MCP server %-20s %s", name, status)
            if not alive:
                # Mark as unavailable so phases skip tool calls on dead servers
                self._mcp._unavailable.add(name)

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    _STATE_ORDER = [
        AssessmentState.INITIALIZED,
        AssessmentState.RECON_RUNNING,
        AssessmentState.RECON_COMPLETE,
        AssessmentState.AWS_AUDIT_RUNNING,
        AssessmentState.AWS_AUDIT_COMPLETE,
        AssessmentState.APP_TEST_RUNNING,
        AssessmentState.APP_TEST_COMPLETE,
        AssessmentState.AI_TRIAGE_RUNNING,
        AssessmentState.AI_TRIAGE_COMPLETE,
        AssessmentState.CORRELATION_RUNNING,
        AssessmentState.CORRELATION_COMPLETE,
        AssessmentState.REPORTING,
        AssessmentState.COMPLETE,
    ]

    def _is_state_past(self, state: AssessmentState) -> bool:
        """Return True if the given state has already been completed."""
        try:
            current_idx = self._STATE_ORDER.index(self._state)
            target_idx = self._STATE_ORDER.index(state)
        except ValueError:
            return False
        return current_idx > target_idx

    async def _set_state(self, state: AssessmentState) -> None:
        self._state = state
        await self._db.set_state(_STATE_KEY, state.value)

    async def _maybe_pause(self, upcoming: AssessmentState) -> None:
        """If pause_between_phases is configured, block until user confirms."""
        if not self._cfg.orchestrator.pause_between_phases:
            return
        print(f"\n[Clementine] Ready to start {upcoming.value}. Press ENTER to continue…")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, input)

    # ------------------------------------------------------------------
    # Kill switch (SIGINT / SIGTERM)
    # ------------------------------------------------------------------

    def _register_kill_switch(self) -> None:
        """Install signal handlers to set the kill flag on SIGINT / SIGTERM."""
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._trigger_kill)

    def _deregister_kill_switch(self) -> None:
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)

    def _trigger_kill(self) -> None:
        log.warning("Kill switch triggered (signal received)")
        self._kill_requested = True
