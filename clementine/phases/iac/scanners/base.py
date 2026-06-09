"""Scanner protocol and shared subprocess plumbing.

Every scanner implementation conforms to the ``Scanner`` protocol:

    name:              str  — short, kebab-case identifier (also used in
                              the Finding.source field as
                              ``iac-scanner-<name>``)
    applicable_to(src) -> bool — does this scanner support that source?
    run(src)           -> list[RawFinding] — execute and return native results

The common pattern (subprocess-emit-JSON) is captured by
``SubprocessScanner`` so each concrete scanner only has to declare its
argv and write a JSON->RawFinding mapping function.

Why a thin RawFinding step instead of mapping straight to the DB Finding
dataclass? Two reasons:
  * Scanner output uses scanner-specific severity strings ("CRITICAL",
    "HIGH"; or numbers; or pass/fail) that we want to normalise once,
    centrally, in normalize.py — not duplicate inside every scanner.
  * The DB Finding dataclass requires UUIDs and other plumbing we'd
    rather generate at insertion time, not inside scanner code.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol

from ..sources import ResolvedSource

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RawFinding:
    """A scanner result before normalisation into the DB Finding schema.

    Field types and naming are deliberately close to the DB Finding so
    the normaliser is a near-direct field copy. ``raw_severity`` is the
    scanner-native severity token (e.g. "HIGH" for tfsec, "ERROR" for
    cfn-nag); the normaliser maps it to db.Severity.
    """
    scanner: str                                    # e.g. "tfsec"
    rule_id: str                                    # native rule id (e.g. "AVD-AWS-0017")
    title: str
    description: str
    raw_severity: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    resource_type: Optional[str] = None             # e.g. "aws_s3_bucket"
    resource_id: Optional[str] = None               # logical name from IaC
    remediation_summary: Optional[str] = None
    remediation_doc_url: Optional[str] = None
    raw: dict = field(default_factory=dict)         # full original record


# ---------------------------------------------------------------------------
# Scanner protocol
# ---------------------------------------------------------------------------

class Scanner(Protocol):
    """All scanners conform to this small surface."""

    name: str

    def applicable_to(self, source: ResolvedSource) -> bool:
        """Return True when this scanner can usefully run against the source.

        For example, ``tfsec`` returns True for Terraform sources only;
        ``cfn_nag`` for CloudFormation sources only. ``gitleaks`` runs
        against any source tree.
        """
        ...

    async def run(self, source: ResolvedSource) -> list[RawFinding]:
        """Execute the scanner against the resolved source.

        Implementations should never raise on findings — only on infra
        problems (missing binary, malformed JSON, timeout). The phase
        wrapper translates exceptions into ``enrichment_status`` rows.
        """
        ...


# ---------------------------------------------------------------------------
# SubprocessScanner — convenience base for the common case
# ---------------------------------------------------------------------------

class SubprocessScanner:
    """Most scanners are "shell out, parse JSON, map to RawFinding".

    Subclass and override:
      * ``name`` (class attribute)
      * ``binary`` — the executable to spawn (must be on PATH)
      * ``build_argv(source)`` — argv list (excluding the binary itself)
      * ``parse(stdout, source)`` — bytes -> list[RawFinding]
      * ``applicable_to(source)`` — whether this scanner supports the source

    Subprocess hardening (applies uniformly to every scanner):
      * argv list, never shell=True (no shell injection)
      * empty env by default — subclasses may opt in to specific vars
      * timeout is enforced via wait_for; on timeout the process is
        killed and an empty list is returned with a warning
      * stderr is captured and logged at DEBUG so a scanner failure is
        diagnosable without flooding the orchestrator log
    """

    name: str = "<override>"
    binary: str = "<override>"

    def __init__(
        self,
        *,
        extra_args: Optional[list[str]] = None,
        timeout_seconds: int = 600,
    ) -> None:
        self._extra_args = list(extra_args or [])
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------
    # Hooks for subclasses
    # ------------------------------------------------------------------

    def applicable_to(self, source: ResolvedSource) -> bool:        # noqa: D401
        raise NotImplementedError

    def build_argv(self, source: ResolvedSource) -> list[str]:      # noqa: D401
        raise NotImplementedError

    def parse(self, stdout: bytes, source: ResolvedSource) -> list[RawFinding]:  # noqa: D401
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Default run() implementation
    # ------------------------------------------------------------------

    async def run(self, source: ResolvedSource) -> list[RawFinding]:
        # scanner_import short-circuit: when the user supplied
        # pre-recorded JSON output for *this* scanner, skip the
        # subprocess entirely and feed the bytes straight into parse().
        # applicable_to() already gated the source to this scanner only.
        if source.precomputed_scanner == self.name and source.precomputed_output is not None:
            log.info("[Phase 0] %s: replaying pre-recorded output (%d bytes)",
                     self.name, len(source.precomputed_output))
            try:
                return self.parse(source.precomputed_output, source)
            except (json.JSONDecodeError, ValueError) as exc:
                log.warning("[Phase 0] %s: pre-recorded output unparseable: %s",
                            self.name, exc)
                return []

        argv = [self.binary, *self.build_argv(source), *self._extra_args]
        log.info("[Phase 0] %s: scanning %s", self.name, source.path)
        log.debug("[Phase 0] %s argv: %s", self.name, argv)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Empty env by default — defence in depth against scanner
                # plugins that read host AWS_*/GITHUB_TOKEN credentials.
                # Subclasses can override _build_env() if they need PATH.
                env=self._build_env(),
                cwd=str(source.path) if source.path else None,
            )
        except FileNotFoundError as exc:
            log.warning("[Phase 0] %s binary not found: %s", self.name, exc)
            return []

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout
            )
        except asyncio.TimeoutError:
            log.warning("[Phase 0] %s timed out after %ds — killing", self.name, self._timeout)
            proc.kill()
            await proc.wait()
            return []

        # Many scanners (tfsec, checkov, gitleaks, cfn-nag) document a
        # non-zero exit as "findings present". Treat exit codes as
        # advisory: parse stdout regardless, and only log stderr on a
        # fatal-looking failure (no JSON produced).
        if stderr:
            log.debug("[Phase 0] %s stderr: %s", self.name, stderr.decode("utf-8", errors="replace")[:2000])

        try:
            return self.parse(stdout, source)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning(
                "[Phase 0] %s produced unparseable output (rc=%s): %s",
                self.name, proc.returncode, exc,
            )
            return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_env(self) -> dict[str, str]:
        """Minimal environment for the scanner subprocess.

        Default: only ``PATH`` so the scanner can find sub-binaries
        (e.g. ``terraform`` for tfsec deep-resolve mode). Override for
        scanners that genuinely need credentials (e.g. checkov's
        soft-fail-on-secrets-API-lookup).
        """
        import os

        path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        return {"PATH": path}


# ---------------------------------------------------------------------------
# Helper used by parsers
# ---------------------------------------------------------------------------

def applies_to_scanner_import(source: ResolvedSource, scanner_name: str) -> Optional[bool]:
    """Resolve scanner_import gating before checking source-kind rules.

    Returns:
      * ``True``  — this is a scanner_import source for this scanner
      * ``False`` — this is a scanner_import source for a *different* scanner
      * ``None``  — not a scanner_import source; caller should fall
                    through to its normal source-kind checks.
    """
    if source.source_kind != "scanner_import":
        return None
    return source.precomputed_scanner == scanner_name


def safe_relpath(file_path: Optional[str], source_root: Path) -> Optional[str]:
    """Return ``file_path`` relative to ``source_root`` when possible.

    Many scanners report absolute paths into a temp dir; for SARIF + UI
    purposes we want the path the user supplied. Falls back to the
    absolute path when the file lives outside the source root.
    """
    if file_path is None:
        return None
    try:
        return str(Path(file_path).resolve().relative_to(source_root.resolve()))
    except (ValueError, OSError):
        return file_path
