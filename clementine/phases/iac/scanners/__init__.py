"""Concrete IaC scanner implementations.

Adding a new scanner is purely additive:

    1. Create a new file ``<name>.py`` in this package that exports a
       ``Scanner`` instance (typically a subclass of ``base.SubprocessScanner``).
    2. Register the instance in ``build_scanner_list()`` below.
    3. Add a default entry in ``IacConfig.scanners`` (config.py).

No orchestrator code change is required — this matches the
"configuration-driven, never code-driven" guiding principle from the
roadmap.
"""

from __future__ import annotations

from typing import Iterable

from .base import Scanner
from .checkov import CheckovScanner
from .cfn_nag import CfnNagScanner
from .gitleaks import GitleaksScanner
from .tfsec import TfsecScanner
from .trufflehog import TrufflehogScanner


def build_scanner_list(toggles: dict) -> list[Scanner]:
    """Materialise the list of scanner instances enabled by config.

    `toggles` is the raw ``IacConfig.scanners`` dict (scanner name ->
    IacScannerConfig). Disabled scanners are silently skipped; unknown
    keys log a warning but do not abort, so a typo in the YAML doesn't
    crash an entire scan.
    """
    import logging

    log = logging.getLogger(__name__)
    registry: dict[str, type[Scanner]] = {
        "tfsec":      TfsecScanner,
        "checkov":    CheckovScanner,
        "cfn_nag":    CfnNagScanner,
        "gitleaks":   GitleaksScanner,
        "trufflehog": TrufflehogScanner,
    }

    scanners: list[Scanner] = []
    for name, cfg in toggles.items():
        if not cfg.enabled:
            continue
        cls = registry.get(name)
        if cls is None:
            # B.M2 will land checkov / cfn_nag / gitleaks / trufflehog.
            # Until then, an enabled-but-unimplemented scanner is a
            # quiet skip rather than a hard failure.
            log.debug("Scanner %s enabled in config but not yet implemented", name)
            continue
        scanners.append(cls(extra_args=list(cfg.extra_args)))
    return scanners


__all__: Iterable[str] = (
    "Scanner",
    "build_scanner_list",
    "TfsecScanner",
    "CheckovScanner",
    "CfnNagScanner",
    "GitleaksScanner",
    "TrufflehogScanner",
)
