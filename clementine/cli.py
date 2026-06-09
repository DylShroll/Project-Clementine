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

import logging
import sys
from pathlib import Path
import asyncio
import anyio

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

    anyio.run(_run)


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
@click.option(
    "--phase",
    "phase_filter",
    default=None,
    type=int,
    help=(
        "Only consider findings from this phase "
        "(0=IaC, 1=recon, 2=cloud-audit, 3=app-test). "
        "Use --phase 0 to gate CI/CD purely on IaC findings."
    ),
)
def check(config: Path, max_severity: str, phase_filter: int | None) -> None:
    """Exit non-zero if findings at or above MAX_SEVERITY exist.

    Use this as a CI/CD gate to block deployments when critical or high
    findings are present. Combine with --phase 0 to gate only on IaC
    (Phase 0) findings — useful for a fast pre-deploy guard that doesn't
    need a full assessment to have run.
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
            findings = await db.get_findings(phase=phase_filter)
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

    exit_code = anyio.run(_check)
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


# ---------------------------------------------------------------------------
# `iac` command — standalone Phase 0 run (Workstream B)
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to clementine.yaml configuration file.",
)
@click.option(
    "--source", "-s", "sources",
    multiple=True,
    help=(
        "Override iac.sources at the CLI (repeatable). Forms:\n"
        "  dir:./infra\n"
        "  plan:./tfplan.json\n"
        "  bundle:./iac-bundle.tar.gz\n"
        "  git:https://github.com/owner/repo[#ref]\n"
        "  scanner_import:checkov:./checkov.json"
    ),
)
@click.option(
    "--format", "-f", "formats",
    multiple=True,
    type=click.Choice(["html", "json", "sarif", "markdown"], case_sensitive=False),
    help="Report formats to generate (repeatable; overrides config file).",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the output directory for reports.",
)
@click.option(
    "--max-severity",
    default=None,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help=(
        "Exit non-zero when any IaC finding is at or above this level. "
        "Use this to gate a CI/CD pipeline on the IaC scan alone."
    ),
)
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Override iac.guardrails.include_state_files (off by default — .tfstate often holds plaintext secrets).",
)
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def iac(
    config: Path,
    sources: tuple[str, ...],
    formats: tuple[str, ...],
    output: Path | None,
    max_severity: str | None,
    include_state: bool,
    debug: bool,
) -> None:
    """Run only Phase 0 (IaC scanning) and emit reports.

    Skips network reconnaissance, cloud audit, app-test, AI triage, and
    correlation — useful as a fast pre-deploy gate in CI/CD where you
    only care about IaC posture, not runtime behaviour.
    """
    cfg = load_config(config)
    _configure_logging("DEBUG" if debug else cfg.orchestrator.log_level)

    # Apply CLI overrides on top of the config file. The config file
    # remains the source of truth; the CLI lets a CI job point at a
    # different infra dir without committing a config change.
    if sources:
        from .config import IacSourceConfig
        cfg.iac.sources = [_parse_iac_source_flag(s) for s in sources]
    cfg.iac.enabled = True                                       # mandatory for this command
    if include_state:
        cfg.iac.guardrails.include_state_files = True
    if formats:
        cfg.reporting.formats = list(formats)                    # type: ignore[assignment]
    if output:
        cfg.reporting.output_dir = output

    if not cfg.iac.sources:
        click.echo(
            "ERROR: no IaC sources configured. Provide --source or set iac.sources in YAML.",
            err=True,
        )
        sys.exit(2)

    log = logging.getLogger(__name__)
    log.info("Project Clementine v%s starting IaC-only scan", __version__)

    async def _run() -> int:
        from .mcp_client import MCPRegistry
        from .phases.iac_scan import run_iac_scan
        from .phases.report import run_reporting
        from .scope import RateLimiter, ScopeGuard

        async with FindingsDB.open(cfg.orchestrator.finding_db) as db:
            # Phase 0 doesn't need any MCP server. The reporter can use
            # AWS Knowledge MCP for enrichment when configured, but it's
            # optional — IaC-only runs work fine without it.
            async with MCPRegistry() as mcp:
                if cfg.mcp_servers.aws_knowledge:
                    mcp.register_http("aws_knowledge", cfg.mcp_servers.aws_knowledge)

                phase_kwargs = dict(
                    cfg=cfg,
                    db=db,
                    mcp=mcp,
                    scope=ScopeGuard(cfg.target.scope),
                    limiter=RateLimiter(cfg.target.scope.rate_limit_rps),
                )
                await run_iac_scan(**phase_kwargs)
                await run_reporting(**phase_kwargs)

            click.echo(f"Reports written to: {cfg.reporting.output_dir}")

            if max_severity is None:
                return 0
            return await _gate_phase0_severity(db, max_severity)

    exit_code = anyio.run(_run)
    sys.exit(exit_code)


def _parse_iac_source_flag(spec: str):
    """Parse `type:value` shorthand from --source into an IacSourceConfig.

    Recognised forms:
      dir:<path>
      plan:<path>
      bundle:<path>
      git:<url>           or git:<url>#<ref>
      scanner_import:<scanner>:<path>

    Anything else raises a click error so the CLI fails fast and loud.
    """
    from .config import IacSourceConfig

    if ":" not in spec:
        raise click.BadParameter(
            f"--source value {spec!r} is not in 'type:value' form"
        )
    kind, _, rest = spec.partition(":")
    kind = kind.strip()

    if kind == "dir":
        return IacSourceConfig(type="dir", path=Path(rest))
    if kind == "plan":
        return IacSourceConfig(type="plan", path=Path(rest))
    if kind == "bundle":
        return IacSourceConfig(type="bundle", bundle_path=Path(rest))
    if kind == "git":
        url, _, ref = rest.partition("#")
        return IacSourceConfig(type="git", url=url, ref=ref or None)
    if kind == "scanner_import":
        scanner_name, _, path = rest.partition(":")
        if not scanner_name or not path:
            raise click.BadParameter(
                "scanner_import requires 'scanner_import:<scanner>:<path>'"
            )
        return IacSourceConfig(type="scanner_import", scanner=scanner_name, path=Path(path))
    raise click.BadParameter(f"unknown --source type: {kind!r}")


async def _gate_phase0_severity(db: FindingsDB, max_severity: str) -> int:
    """Return non-zero when any Phase 0 finding meets or exceeds threshold."""
    rank = {s.value: i for i, s in enumerate(
        [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    )}
    threshold = rank[max_severity.upper()]
    findings = await db.get_findings(phase=0)
    failing = [f for f in findings if rank.get(f.severity.value, 0) >= threshold]
    if failing:
        click.echo(
            f"FAIL: {len(failing)} IaC finding(s) at {max_severity.upper()} or above.",
            err=True,
        )
        for f in failing[:10]:
            loc = f"{f.iac_source_path}:{f.iac_source_line}" if f.iac_source_path else "?"
            click.echo(f"  [{f.severity.value}] {f.title} ({loc})", err=True)
        if len(failing) > 10:
            click.echo(f"  ... and {len(failing) - 10} more.", err=True)
        return 1
    click.echo(f"PASS: No IaC findings at {max_severity.upper()} or above.")
    return 0
