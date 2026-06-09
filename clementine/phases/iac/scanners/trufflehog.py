"""trufflehog — second-opinion hardcoded-secret scanner.

Documentation: https://github.com/trufflesecurity/trufflehog
Output format: JSONL (one JSON object per line) when invoked with
``--json``. Each line carries ``DetectorName`` (e.g. "AWS"),
``SourceMetadata.Data.Filesystem.file`` and ``.line``, ``Raw`` (the
raw secret), and ``Verified`` (true if the credential was confirmed
live by hitting the provider's API).

**Critical security note.** Trufflehog will, by default, *call the
target API* to verify each detected credential ("verification"). For
Phase 0 this is unacceptable: it would leak information about secrets
to third parties and turn the scanner into an active credential-test
machine. We pass ``--no-verification`` so it stays purely passive.

We also drop the ``Raw`` field from every record before persistence
to mirror the gitleaks defence — even with ``--no-verification`` we
never want a literal secret in the DB.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from .base import RawFinding, SubprocessScanner, applies_to_scanner_import, safe_relpath
from ..sources import ResolvedSource

log = logging.getLogger(__name__)

_DEFAULT_SEVERITY = "HIGH"
_SENSITIVE_KEYS = ("Raw", "RawV2", "Redacted")


class TrufflehogScanner(SubprocessScanner):
    """Run trufflehog against any source tree."""

    name = "trufflehog"
    binary = "trufflehog"

    def applicable_to(self, source: ResolvedSource) -> bool:
        gate = applies_to_scanner_import(source, self.name)
        if gate is not None:
            return gate
        return source.source_kind != "scanner_import"

    def build_argv(self, source: ResolvedSource) -> list[str]:
        return [
            "filesystem",
            ".",                                   # cwd is source.path
            "--json",
            "--no-verification",                   # never call provider APIs
            "--no-update",                         # no version-check phone-home
            "--fail",                              # noop here; explicit
        ]

    def parse(self, stdout: bytes, source: ResolvedSource) -> list[RawFinding]:
        if not stdout.strip():
            return []
        # JSONL: parse line-by-line; skip blanks and lines that aren't
        # JSON objects (trufflehog interleaves the occasional log line
        # to stdout).
        out: list[RawFinding] = []
        root = source.path
        for raw_line in stdout.splitlines():
            line_text = raw_line.strip()
            if not line_text or not line_text.startswith(b"{"):
                continue
            try:
                rec = json.loads(line_text)
            except json.JSONDecodeError:
                continue

            file_path, line_num = _extract_filesystem_loc(rec)
            detector = rec.get("DetectorName") or "unknown"

            sanitised_raw = {k: v for k, v in rec.items() if k not in _SENSITIVE_KEYS}
            # Drop nested raw secret in SourceMetadata.Data.Filesystem too —
            # trufflehog stashes a substring there in some versions.
            _scrub_nested_raw(sanitised_raw)

            out.append(RawFinding(
                scanner=self.name,
                rule_id=str(detector),
                title=f"Hardcoded secret ({detector})",
                description=str(rec.get("Description") or "Hardcoded credential detected"),
                raw_severity=_DEFAULT_SEVERITY,
                file_path=safe_relpath(file_path, root) if root and file_path else file_path,
                line=_safe_int(line_num),
                resource_type=None,
                resource_id=None,
                remediation_summary=(
                    "Rotate the secret and move it to a managed secret store; "
                    "remove it from version control."
                ),
                raw=sanitised_raw,
            ))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_filesystem_loc(rec: dict) -> tuple[Optional[str], Optional[int]]:
    """Pull ``(file, line)`` out of trufflehog's nested SourceMetadata."""
    fs = (
        rec.get("SourceMetadata", {})
        .get("Data", {})
        .get("Filesystem", {})
    )
    return fs.get("file"), fs.get("line")


def _scrub_nested_raw(rec: dict) -> None:
    """Best-effort recursive scrub of fields named like raw secrets.

    We only scrub keys that historically held raw secret values; we
    don't traverse arbitrarily deep (no nested data structures past the
    SourceMetadata wrapper carry secrets in trufflehog's schema).
    """
    fs = (
        rec.get("SourceMetadata", {})
        .get("Data", {})
        .get("Filesystem", {})
    )
    for k in list(fs.keys()):
        if k.lower() in {"raw", "rawcontents"}:
            fs.pop(k, None)


def _safe_int(value) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
