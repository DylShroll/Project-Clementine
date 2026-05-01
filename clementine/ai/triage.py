"""
LLM-powered triage of raw findings.

Security-tool output is noisy — scanners fire on heuristics that can't tell
apart "reflected param in an error page" from "real reflected XSS", and every
medium-ish CIS control check looks identical to a human reviewer. The triage
pass asks Claude to review each finding along with its evidence and return:

* a confidence score in [0, 1] that the finding is a real exploitable issue
* a boolean flag for "almost certainly a false positive"
* a one-to-three sentence justification that can later surface in the report

The pass runs *after* app-layer testing and *before* correlation so that the
correlator can optionally filter out triaged false positives, and so chain
narratives can cite the LLM's reasoning.

Design notes
------------
* Findings are batched (default 10 per request) so each request amortises
  the prompt-cache cost of the system prompt + the schema, while keeping
  per-request context small enough that the model can actually reason about
  each item instead of drowning in a megabatch.
* Evidence is already scrubbed of credentials by ``clementine.sanitize``
  before it hits the DB, so we can pass it to the LLM unchanged.
* All batches run through the shared semaphore in :class:`ClaudeClient`
  so we respect the tenant's configured parallelism cap.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from pydantic import BaseModel, Field

from pathlib import Path

from ..config import AIConfig
from ..db import Finding, FindingsDB
from .client import ClaudeClient, build_azure_alias_map, apply_azure_aliases

_AZURE_PROMPT_PATH = Path(__file__).parent.parent.parent / "prompts" / "azure" / "phase4.md"

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structured-output schema
# ---------------------------------------------------------------------------

class TriageVerdict(BaseModel):
    """A single finding's triage verdict."""
    finding_id: str = Field(description="The finding's UUID, copied verbatim from the input.")
    confidence: float = Field(
        ge=0.0, le=1.0,
        description=(
            "Probability in [0, 1] that this is a real, exploitable security "
            "issue. 0.0 means certainly noise; 1.0 means certainly exploitable."
        ),
    )
    is_false_positive: bool = Field(
        description=(
            "True if the evidence clearly indicates a scanner false positive "
            "(e.g. a reflection that isn't actually executed, a CIS check that "
            "flagged a compensating control, a header warning on a non-sensitive "
            "endpoint). Should be True roughly when confidence is below 0.35."
        ),
    )
    rationale: str = Field(
        description=(
            "One to three sentences explaining the verdict. Must reference "
            "specific evidence from the input. No generic 'this looks suspicious' "
            "boilerplate."
        ),
    )


class TriageBatchResult(BaseModel):
    """Container for the per-batch response — one verdict per input finding."""
    verdicts: list[TriageVerdict]


# ---------------------------------------------------------------------------
# System prompt — long and stable so the prompt cache actually hits
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior application- and cloud-security engineer triaging the raw \
output of automated scanning tools. Your job is to decide, for each finding \
you are given, how likely it represents a real, exploitable security issue \
versus scanner noise.

You receive findings produced by three classes of tools:

1. **AutoPentest AI** — web-application scanner driven by the OWASP WSTG \
   methodology. Common false-positive shapes include reflected params that \
   aren't actually executed, "missing security header" flags on endpoints \
   that don't need them, CSRF warnings on idempotent GET endpoints, and \
   verbose error pages mistaken for information disclosure.

2. **AWS Well-Architected Security Assessment** — cloud configuration scanner. \
   Common false-positive shapes include S3 buckets flagged as public that are \
   intentional static-asset hosts behind CloudFront, "overly permissive" IAM \
   roles that are actually constrained by session policies or SCPs, and open \
   security groups protecting endpoints that are additionally gated by IAM.

3. **Prowler** — compliance scanner (CIS, PCI, SOC2). Common false-positive \
   shapes include controls that fail because of a compensating control the \
   scanner can't see, account-wide checks flagged on accounts where the \
   resource type is unused, and region checks for regions the tenant has \
   explicitly opted out of.

For every finding, examine:
* The category, severity, and title assigned by the tool.
* The description and remediation summary.
* The attached evidence (HTTP exchange, CLI output, or config dump).
* The resource context (AWS service/region, URL, etc.) if present.

Then assign:
* **confidence**: the probability in [0, 1] that this is a genuine, \
  exploitable issue. Be honest about uncertainty — don't anchor on 0.5.
* **is_false_positive**: True if you are confident this is scanner noise. \
  Prefer this over "low confidence but real" when the evidence contradicts \
  the finding's claim.
* **rationale**: one to three crisp sentences that cite the evidence. Avoid \
  filler like "this looks suspicious" or "further investigation needed". \
  State what you saw and why it changes (or confirms) the severity.

Calibration guidance:
* A finding with strong, specific evidence of impact (e.g. an HTTP exchange \
  clearly showing an unauthenticated admin endpoint responding with data) \
  should land at 0.85–1.0.
* A finding where the evidence is *consistent* with an issue but not proof \
  (e.g. a missing HttpOnly flag on a non-session cookie) belongs around \
  0.4–0.7 with a rationale stating what's missing.
* A finding where the evidence *contradicts* the finding (e.g. an S3 public \
  flag on a bucket whose policy requires SigV4 + VPC endpoint) should be \
  marked is_false_positive=True with confidence <= 0.25.

Output a verdict for every finding you are given, in the same order. Do not \
drop findings and do not invent finding IDs that weren't provided.
"""


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

async def triage_findings(
    findings: list[Finding],
    *,
    client: ClaudeClient,
    cfg: AIConfig,
    db: Optional[FindingsDB] = None,
) -> list[TriageVerdict]:
    """Run the LLM triage pass over *findings* and persist verdicts if *db* given.

    Returns the full list of verdicts (across all batches). The caller is
    responsible for deciding what to do with low-confidence findings — this
    function only writes the verdict back to the DB, it does *not* delete
    or downgrade findings.
    """
    if not findings:
        return []

    batches = _chunk(findings, cfg.triage.batch_size)
    log.info(
        "AI triage: %d findings split into %d batch(es) of up to %d",
        len(findings), len(batches), cfg.triage.batch_size,
    )

    # Run batches concurrently — the ClaudeClient semaphore caps actual
    # in-flight requests, so we can launch them all without worrying.
    tasks = [_triage_batch(batch, client=client) for batch in batches]
    batch_results = await asyncio.gather(*tasks, return_exceptions=True)

    verdicts: list[TriageVerdict] = []
    for idx, result in enumerate(batch_results):
        if isinstance(result, Exception):
            # One bad batch shouldn't abort the whole phase — log and continue
            # so the remaining batches' verdicts still get persisted.
            log.error("Triage batch %d failed: %s", idx, result)
            continue
        verdicts.extend(result.verdicts)

    if db is not None:
        await _persist_verdicts(verdicts, db)

    log.info(
        "AI triage complete — %d verdicts; %d flagged as false-positive",
        len(verdicts),
        sum(1 for v in verdicts if v.is_false_positive),
    )
    return verdicts


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _chunk(items: list[Finding], size: int) -> list[list[Finding]]:
    """Split *items* into chunks of at most *size*."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def _load_azure_triage_prompt() -> str:
    """Load the Azure-specific triage guidance section (phase4.md), or empty string."""
    try:
        return _AZURE_PROMPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


async def _triage_batch(
    batch: list[Finding],
    *,
    client: ClaudeClient,
) -> TriageBatchResult:
    """Send one batch of findings to Claude and parse the verdicts.

    When the batch contains Azure findings (provider='azure'), the Azure-specific
    triage guidance from prompts/azure/phase4.md is appended to the system prompt
    and resource IDs are compressed using the Azure alias map. Both blocks share
    the same cache_control breakpoint so cache hits still occur on identical batches.
    """
    has_azure = any(getattr(f, "provider", "aws") == "azure" for f in batch)

    system_blocks: list[dict] = [
        {
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    if has_azure:
        azure_section = _load_azure_triage_prompt()
        if azure_section:
            system_blocks.append({
                "type": "text",
                "text": azure_section,
                "cache_control": {"type": "ephemeral"},
            })

    # Build alias map for any Azure resource IDs in this batch
    alias_map: dict[str, str] = {}
    if has_azure:
        azure_rids = [
            f.resource_id or getattr(f, "azure_resource_id", None) or ""
            for f in batch
            if getattr(f, "provider", "aws") == "azure"
        ]
        alias_map = build_azure_alias_map([r for r in azure_rids if r])

    user_text = _render_batch_prompt(batch, alias_map=alias_map)

    return await client.parse(
        response_model=TriageBatchResult,
        system=system_blocks,
        user_content=user_text,
        max_tokens=8192,
        call_site="triage_batch",
    )


def _render_batch_prompt(
    batch: list[Finding],
    alias_map: dict[str, str] | None = None,
) -> str:
    """Render a batch of findings into a compact prompt block.

    When *alias_map* is provided (Azure batches), Azure resource IDs embedded
    in description/evidence are compressed to short aliases before serialisation.
    An alias legend is appended at the end of the block behind a cache breakpoint.
    """
    alias_map = alias_map or {}

    def _alias(text: str) -> str:
        return apply_azure_aliases(text, alias_map) if alias_map else text

    lines = [
        f"Triage the following {len(batch)} finding(s). Return one verdict per "
        f"finding, referencing its ID verbatim.",
        "",
    ]
    for idx, f in enumerate(batch, start=1):
        lines.append(f"--- Finding {idx} of {len(batch)} ---")
        lines.append(f"finding_id: {f.id}")
        lines.append(f"source: {f.source}")
        lines.append(f"provider: {getattr(f, 'provider', 'aws')}")
        lines.append(f"severity: {f.severity.value}")
        lines.append(f"category: {f.category}")
        lines.append(f"title: {_alias(f.title or '')}")
        lines.append(f"description: {_alias(f.description or '')}")
        if f.resource_type or f.resource_id:
            lines.append(
                f"resource: {f.resource_type or '?'} / {_alias(f.resource_id or '?')}"
            )
        if f.aws_account_id or f.aws_region:
            lines.append(
                f"aws: account={f.aws_account_id or '-'} region={f.aws_region or '-'}"
            )
        # Azure-specific context fields
        az_sub = getattr(f, "subscription_id", None)
        az_rg = getattr(f, "resource_group", None)
        if az_sub or az_rg:
            lines.append(f"azure: subscription={az_sub or '-'} rg={az_rg or '-'}")
        if f.evidence_type:
            lines.append(f"evidence_type: {f.evidence_type}")
        if f.evidence_data:
            lines.append("evidence_data:")
            lines.append(_truncate(_alias(str(f.evidence_data)), limit=4000))
        if f.remediation_summary:
            lines.append(f"remediation_summary: {f.remediation_summary}")
        lines.append("")

    # Alias legend so the model can decode compressed IDs in its rationale
    if alias_map:
        lines.append("--- Azure Resource ID Alias Map ---")
        for rid, alias in alias_map.items():
            lines.append(f"  {alias} = {rid}")

    return "\n".join(lines)


def _truncate(text: str, *, limit: int) -> str:
    """Truncate overlong evidence so a single finding can't blow past context."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated {len(text) - limit} chars]"


async def _persist_verdicts(
    verdicts: list[TriageVerdict], db: FindingsDB
) -> None:
    """Write each verdict back to the corresponding finding row."""
    for v in verdicts:
        try:
            await db.update_finding_triage(
                finding_id=v.finding_id,
                confidence=v.confidence,
                is_false_positive=v.is_false_positive,
                notes=v.rationale,
            )
        except Exception as exc:
            # A bad finding_id (e.g. hallucinated) shouldn't sink the whole batch
            log.warning("Failed to persist triage for %s: %s", v.finding_id, exc)
