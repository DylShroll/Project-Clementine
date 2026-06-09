"""Source-comment suppression for IaC findings.

Developers may legitimately need to silence a Phase 0 finding — a
deliberate-permissive demo policy, a fixture that has to embed a
fake credential to exercise a code path, an issue an upstream module
emits but downstream callers can't fix. We honour the same convention
across all scanners:

    resource "aws_s3_bucket" "demo" {
      acl    = "public-read"  # clementine:false-positive: deliberate demo bucket
      bucket = "..."
    }

Format:

    # clementine:false-positive[: <free-form reason>]

The marker may sit on the same line as the offending statement, on
the line above (in which case it suppresses the next non-empty line),
or as a leading line of the file (suppresses the whole file).

Why post-filter rather than emit per-scanner suppression markers?
Each scanner has its own suppression syntax (``# checkov:skip=...``,
``# tfsec:ignore:...``); building five separate translators is
maintenance churn for no extra precision. A post-filter is one
function, scanner-agnostic, and trivially auditable in a report.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

from ...db import Finding
from .sources import ResolvedSource

log = logging.getLogger(__name__)

# Recognise the marker anywhere on a line. The optional ``: <reason>``
# is captured but not currently surfaced; M5 will plumb it into the
# report so reviewers can see *why* a finding was suppressed.
_MARKER_RE = re.compile(
    r"#\s*clementine:false-positive(?::\s*(?P<reason>.+?))?\s*$",
    flags=re.IGNORECASE,
)

# A line is a *file-level* marker when it contains only the marker (and
# optional whitespace before the ``#``), no preceding code. Mixed lines
# like ``acl = "public" # clementine:false-positive: ...`` always
# suppress only that line, never the whole file. Without this we would
# accidentally silence every finding in a file just because one same-
# line marker happens to live in the first few lines.
_LINE_ONLY_MARKER_RE = re.compile(
    r"^\s*#\s*clementine:false-positive(?::\s*(?P<reason>.+?))?\s*$",
    flags=re.IGNORECASE,
)

# How many leading lines we inspect for a file-level marker. Five is
# generous enough to allow license headers / shebangs / blank lines
# above the marker without admitting deeper "marker accidentally near
# the top" matches.
_FILE_LEADER_LINES = 5


def filter_suppressed(
    findings: Iterable[Finding],
    sources: Iterable[ResolvedSource],
) -> list[Finding]:
    """Drop findings whose IaC source location carries the marker.

    Findings without ``iac_source_path`` are passed through unchanged
    (so non-IaC findings the phase might one day produce — e.g. a
    config-only finding — are never affected).
    """
    # Build a set of suppressed (relative_path, line) pairs and a set
    # of fully-suppressed paths from each resolved source.
    file_level: set[tuple[str, str]] = set()      # (root_str, rel_path)
    line_level: set[tuple[str, str, int]] = set() # (root_str, rel_path, line)

    for src in sources:
        try:
            _index_source(src, file_level, line_level)
        except OSError as exc:                                       # pragma: no cover - defensive
            log.debug("[suppress] could not index %s: %s", src.path, exc)

    out: list[Finding] = []
    suppressed = 0
    for f in findings:
        if not f.iac_source_path or not f.iac_source_line:
            out.append(f)
            continue
        if _is_suppressed(f, file_level, line_level, sources):
            suppressed += 1
            continue
        out.append(f)

    if suppressed:
        log.info("[Phase 0] suppressed %d finding(s) via inline marker", suppressed)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _index_source(
    src: ResolvedSource,
    file_level: set,
    line_level: set,
) -> None:
    """Walk source files once and remember every marker location.

    Doing this up front means each finding's suppression check is two
    dict lookups rather than re-reading the file. ``max_files_scanned``
    on guardrails caps walk size at the resolver step; here we trust
    that bound.
    """
    root = src.path
    if not root or not root.is_dir():
        return
    root_str = str(root.resolve())
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip obviously-binary files. We only care about IaC sources
        # that scanners pinned a finding on; reading 5MB of node_modules
        # JSON would be wasteful.
        if p.suffix.lower() not in {".tf", ".tfvars", ".yaml", ".yml", ".json", ".sh"}:
            continue
        try:
            text = p.read_text("utf-8", errors="replace")
        except OSError:
            continue

        rel = p.relative_to(root)
        rel_str = str(rel)
        lines = text.splitlines()

        # Whole-file suppression: a line in the leader window that
        # consists ONLY of the marker (no preceding code). Mixed lines
        # never trigger file-level suppression — see _LINE_ONLY_MARKER_RE.
        for line in lines[:_FILE_LEADER_LINES]:
            if _LINE_ONLY_MARKER_RE.match(line):
                file_level.add((root_str, rel_str))
                break

        # Per-line suppression: marker on this line OR the previous one.
        for i, line in enumerate(lines, start=1):
            if _MARKER_RE.search(line):
                # Suppress the line itself (covers same-line markers)
                # and the next non-empty line (covers leader-line
                # markers above the offending statement).
                line_level.add((root_str, rel_str, i))
                next_idx = _next_non_blank(lines, i)
                if next_idx is not None:
                    line_level.add((root_str, rel_str, next_idx))


def _next_non_blank(lines: list[str], one_based_idx: int) -> int | None:
    """Return the 1-based index of the next non-blank, non-comment-only line."""
    for i in range(one_based_idx, len(lines)):
        s = lines[i].strip()
        if s and not s.startswith("#"):
            return i + 1
    return None


def _is_suppressed(
    finding: Finding,
    file_level: set,
    line_level: set,
    sources: Iterable[ResolvedSource],
) -> bool:
    """Match a finding against the suppression sets.

    We try every source root because a finding's ``iac_source_path`` is
    relative to whichever resolved source produced it; the indexer
    keyed on absolute roots so the lookup is unambiguous.
    """
    rel = finding.iac_source_path
    line = finding.iac_source_line
    if not rel or not line:
        return False

    for src in sources:
        if not src.path:
            continue
        root_str = str(Path(src.path).resolve())
        if (root_str, rel) in file_level:
            return True
        if (root_str, rel, line) in line_level:
            return True
    return False
