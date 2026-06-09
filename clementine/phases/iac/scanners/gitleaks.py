"""gitleaks — hardcoded-secret detection for any source tree.

Documentation: https://github.com/gitleaks/gitleaks
Output format: JSON array (one object per finding) when invoked with
``--report-format=json --report-path=<path>``. Each entry carries
``RuleID``, ``Description``, ``StartLine``, ``File``, ``Match`` (a
short window around the secret), ``Secret`` (the raw secret), and
several other context fields.

**Critical security note.** Gitleaks's default output includes the
*raw* secret. We pass ``--redact`` so the binary emits ``REDACTED`` in
``Match`` / ``Secret`` fields before we ever see it. As defence in
depth we also drop the ``Match``/``Secret`` keys from ``raw`` before
storing, in case a future flag changes the redaction default.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from .base import RawFinding, SubprocessScanner, applies_to_scanner_import, safe_relpath
from ..sources import ResolvedSource

log = logging.getLogger(__name__)

# Severity isn't a first-class concept in gitleaks. Every secret is
# treated as HIGH for normalisation purposes — exposing a credential is
# always serious, and the rule_id distinguishes the kind (AWS key vs
# generic API token vs JWT) for downstream filtering.
_DEFAULT_SEVERITY = "HIGH"

# Keys we strip from the raw record before persistence. Even with
# --redact, defence-in-depth drops the field outright.
_SENSITIVE_KEYS = ("Match", "Secret")


class GitleaksScanner(SubprocessScanner):
    """Run gitleaks against any source tree."""

    name = "gitleaks"
    binary = "gitleaks"

    async def run(self, source: ResolvedSource) -> list[RawFinding]:
        # Gitleaks writes its JSON report to a file when given
        # ``--report-path``. We use ``/dev/stdout`` so the base class's
        # subprocess-and-parse plumbing keeps working uniformly across
        # scanners — no separate temp-file dance, no special teardown.
        # Linux + macOS both expose /dev/stdout; Phase 0 only runs in
        # the bundled Docker image (Linux) so portability is fine.
        return await super().run(source)

    def applicable_to(self, source: ResolvedSource) -> bool:
        gate = applies_to_scanner_import(source, self.name)
        if gate is not None:
            return gate
        # Gitleaks runs against any directory tree; scanner_import
        # gating above prevents it from also running on a payload meant
        # for a different scanner.
        return source.source_kind != "scanner_import"

    def build_argv(self, source: ResolvedSource) -> list[str]:
        return [
            "detect",
            "--source", ".",                       # cwd is source.path
            "--report-format", "json",
            "--report-path", "/dev/stdout",        # JSON report on stdout
            "--redact",                            # never echo raw secrets
            "--no-banner",                         # suppress decorative output
            "--no-git",                            # treat dir as flat tree, not git repo
            "--exit-code", "0",                    # findings != error
        ]

    def parse(self, stdout: bytes, source: ResolvedSource) -> list[RawFinding]:
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            log.debug("[gitleaks] could not parse report — likely empty")
            return []
        if not isinstance(data, list):
            return []

        out: list[RawFinding] = []
        root = source.path
        for entry in data:
            file_path = entry.get("File")
            line = entry.get("StartLine")
            rule = entry.get("RuleID") or "unknown"

            # Strip raw secret values from the persisted record so they
            # never reach the DB even if --redact is bypassed in some
            # future gitleaks release.
            sanitised_raw = {k: v for k, v in entry.items() if k not in _SENSITIVE_KEYS}

            out.append(RawFinding(
                scanner=self.name,
                rule_id=str(rule),
                title=f"Hardcoded secret ({rule})",
                description=str(entry.get("Description") or "Hardcoded credential detected"),
                raw_severity=_DEFAULT_SEVERITY,
                file_path=safe_relpath(file_path, root) if root and file_path else file_path,
                line=_safe_int(line),
                resource_type=None,
                resource_id=None,
                remediation_summary=(
                    "Move the secret to a managed secret store "
                    "(AWS Secrets Manager / Azure Key Vault / GCP Secret Manager) "
                    "and reference it at runtime."
                ),
                raw=sanitised_raw,
            ))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(value) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
