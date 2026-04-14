"""
Command-line interface for Project Clementine.

Usage:
  clementine run    --config clementine.yaml [--format sarif] [--output ./reports]
  clementine check  --config clementine.yaml [--max-severity HIGH]
  clementine report --config clementine.yaml [--format html]

The `run` command executes a full assessment.
The `check` command exits non-zero if findings at or above --max-severity exist
(suitable for CI/CD pipeline gating).
The `report` command regenerates reports from an existing findings database
without re-running the assessment.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click

from . import __version__
from .config import load_config
from .db import FindingsDB, Severity


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(level: str) -> None:
    """Configure root logger — INFO by default, DEBUG when --debug is passed."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Silence noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, "--version", "-V")
def main() -> None:
    """Project Clementine — automated web-app penetration-testing orchestrator."""


# ---------------------------------------------------------------------------
# `run` command
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to clementine.yaml configuration file.",
)
@click.option(
    "--format", "-f",
    "formats",
    multiple=True,
    type=click.Choice(["html", "json", "sarif", "markdown"], case_sensitive=False),
    help="Override report formats (repeatable; overrides config file).",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Override output directory for reports.",
)
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def run(config: Path, formats: tuple[str, ...], output: Path | None, debug: bool) -> None:
    """Run a full five-phase security assessment."""
    cfg = load_config(config)
    _configure_logging("DEBUG" if debug else cfg.orchestrator.log_level)

    # Apply CLI overrides
    if formats:
        cfg.reporting.formats = list(formats)  # type: ignore[assignment]
    if output:
        cfg.reporting.output_dir = output

    log = logging.getLogger(__name__)
    log.info("Project Clementine v%s starting assessment of %s", __version__, cfg.target.url)

    async def _run() -> None:
        from .orchestrator import Orchestrator
        async with FindingsDB.open(cfg.orchestrator.finding_db) as db:
            orch = Orchestrator(cfg, db)
            report_dir = await orch.run()
        click.echo(f"\nAssessment complete. Reports written to: {report_dir}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# `check` command — CI/CD severity gate
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to clementine.yaml configuration file.",
)
@click.option(
    "--max-severity",
    default="HIGH",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Fail (exit 1) if any finding at this severity or above exists.",
    show_default=True,
)
def check(config: Path, max_severity: str) -> None:
    """Exit non-zero if findings at or above MAX_SEVERITY exist.

    Use this as a CI/CD gate to block deployments when critical or high
    findings are present.
    """
    cfg = load_config(config)
    _configure_logging(cfg.orchestrator.log_level)

    # Severity threshold: findings at this level OR ABOVE cause a non-zero exit
    _severity_rank = {s.value: i for i, s in enumerate(
        [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    )}
    threshold_rank = _severity_rank[max_severity.upper()]

    async def _check() -> int:
        async with FindingsDB.open(cfg.orchestrator.finding_db) as db:
            findings = await db.get_findings()
        failing = [
            f for f in findings
            if _severity_rank.get(f.severity.value, 0) >= threshold_rank
        ]
        if failing:
            click.echo(
                f"FAIL: {len(failing)} finding(s) at {max_severity} or above.",
                err=True,
            )
            for f in failing[:10]:  # Show the top 10
                click.echo(f"  [{f.severity.value}] {f.title}", err=True)
            if len(failing) > 10:
                click.echo(f"  ... and {len(failing) - 10} more.", err=True)
            return 1
        click.echo(f"PASS: No findings at {max_severity} or above.")
        return 0

    exit_code = asyncio.run(_check())
    sys.exit(exit_code)


# ---------------------------------------------------------------------------
# `report` command — regenerate reports from existing DB
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to clementine.yaml configuration file.",
)
@click.option(
    "--format", "-f",
    "formats",
    multiple=True,
    type=click.Choice(["html", "json", "sarif", "markdown"], case_sensitive=False),
    help="Report formats to generate (repeatable; defaults to config file values).",
)
def report(config: Path, formats: tuple[str, ...]) -> None:
    """Re-generate reports from an existing findings database.

    Useful when you want to change the report format without re-running the
    full assessment.
    """
    cfg = load_config(config)
    _configure_logging(cfg.orchestrator.log_level)
    if formats:
        cfg.reporting.formats = list(formats)  # type: ignore[assignment]

    async def _report() -> None:
        from .phases.report import run_reporting
        from .mcp_client import MCPRegistry
        from .scope import RateLimiter, ScopeGuard

        async with FindingsDB.open(cfg.orchestrator.finding_db) as db:
            async with MCPRegistry() as mcp:
                # Only AWS Knowledge MCP is needed for enrichment during re-reporting
                if cfg.mcp_servers.aws_knowledge:
                    mcp.register_http("aws_knowledge", cfg.mcp_servers.aws_knowledge)

                await run_reporting(
                    cfg=cfg,
                    db=db,
                    mcp=mcp,
                    scope=ScopeGuard(cfg.target.scope),
                    limiter=RateLimiter(cfg.target.scope.rate_limit_rps),
                )

        click.echo(f"Reports written to: {cfg.reporting.output_dir}")

    asyncio.run(_report())
