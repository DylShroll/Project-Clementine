"""
Thin async wrapper around the Anthropic Bedrock SDK.

Centralises four concerns so the rest of the AI subsystem does not have to
care about them:

1. **Graceful degradation** — if the ``ai`` config section is disabled,
   :meth:`ClaudeClient.from_config` returns ``None`` so callers can skip AI
   work without raising.
2. **Parallelism control** — a semaphore caps concurrent requests at
   ``max_parallel_requests`` so a single large assessment can't exhaust the
   Bedrock account's throughput quota.
3. **Retry logic** — transient errors (throttling, network, 5xx) are retried
   with exponential backoff; permanent errors (bad request, auth) bubble up
   immediately. Per-call retry override lets the discovery path opt out of
   multi-retry token amplification.
4. **Token telemetry** — every parsed response's ``usage`` is captured and
   persisted to the ``ai_usage`` table so per-run cost is queryable without
   external tooling.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Type, TypeVar

from pydantic import BaseModel

from ..config import AIConfig

if TYPE_CHECKING:
    from ..db import FindingsDB

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


@dataclass
class TokenUsage:
    """Running tally of token consumption for one ClaudeClient instance."""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    calls: int = 0
    by_call_site: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(
        self,
        *,
        call_site: str,
        input_tokens: int,
        output_tokens: int,
        cache_creation_tokens: int,
        cache_read_tokens: int,
    ) -> None:
        self.calls += 1
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.cache_creation_tokens += cache_creation_tokens
        self.cache_read_tokens += cache_read_tokens
        site = self.by_call_site.setdefault(
            call_site,
            {"calls": 0, "input": 0, "output": 0, "cache_create": 0, "cache_read": 0},
        )
        site["calls"] += 1
        site["input"] += input_tokens
        site["output"] += output_tokens
        site["cache_create"] += cache_creation_tokens
        site["cache_read"] += cache_read_tokens


class ClaudeUnavailable(RuntimeError):
    """Raised when AI features are requested but the client is not configured."""


# Maps effort level names to Bedrock extended-thinking budget_tokens values.
_EFFORT_BUDGET: dict[str, int] = {
    "low": 1024,
    "medium": 4096,
    "high": 10000,
    "xhigh": 16000,
    "max": 32000,
}


class ClaudeClient:
    """Async wrapper around :class:`anthropic.AsyncAnthropicBedrock`.

    Authentication is handled by boto3's standard credential chain — no API key
    is required. Use :meth:`from_config` to construct; it returns ``None`` when
    AI is disabled, which is the signal that callers should skip AI work.
    """

    def __init__(self, cfg: AIConfig, db: Optional["FindingsDB"] = None) -> None:
        # Lazy import so the orchestrator doesn't require the SDK unless AI
        # is actually enabled in the config.
        from anthropic import AsyncAnthropicBedrock

        self._cfg = cfg
        self._client = AsyncAnthropicBedrock(aws_region=cfg.aws_region)
        self._semaphore = asyncio.Semaphore(cfg.max_parallel_requests)
        self._db = db
        self.usage = TokenUsage()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls, cfg: AIConfig, db: Optional["FindingsDB"] = None
    ) -> Optional["ClaudeClient"]:
        """Build a client or return None if AI should be skipped.

        AI is skipped when ``ai.enabled`` is False. AWS credentials are
        resolved at first call via boto3's standard chain (env vars,
        ~/.aws/credentials, instance profile, ECS task role); a missing or
        invalid credential will raise on the first Bedrock request rather than
        here so the config-load path stays fast.

        Pass ``db`` to enable per-call token-usage persistence to the
        ``ai_usage`` table.
        """
        if not cfg.enabled:
            log.info("AI subsystem disabled via config — skipping triage and discovery")
            return None
        return cls(cfg, db=db)

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    async def parse(
        self,
        *,
        response_model: Type[T],
        system: list[dict] | str,
        user_content: list[dict] | str,
        max_tokens: int = 8192,
        model: Optional[str] = None,
        call_site: str = "unknown",
        effort: Optional[str] = None,
        max_retries: Optional[int] = None,
    ) -> T:
        """Send a structured-output request and return the parsed Pydantic model.

        Uses ``messages.parse`` so the SDK enforces the schema and raises on
        malformed output rather than silently handing us free-form text.

        The system prompt is sent as a list of content blocks so callers can
        mark stable prefixes with ``cache_control`` for prompt-cache hits.

        Pass ``model`` to override the default primary model (used by
        discovery for the Opus critical path). Pass ``effort`` to override the
        configured Opus thinking effort for this call only — discovery uses
        this to drop from "high" to "medium" without affecting triage. Pass
        ``max_retries`` to cap retry amplification for token-heavy calls.

        ``call_site`` is the tag used in ai_usage rows + log lines.
        """
        chosen_model = model or self._cfg.primary_model
        chosen_effort = effort or self._cfg.effort
        params: dict = {
            "model": chosen_model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user_content}],
            "output_format": response_model,
        }
        # Extended thinking is an Opus 4.x feature on Bedrock; Sonnet ignores it.
        # budget_tokens must be strictly less than max_tokens, so clamp upward
        # if the caller-supplied max_tokens is too tight for the chosen effort.
        if "opus" in chosen_model.lower():
            budget = _EFFORT_BUDGET.get(chosen_effort, 10000)
            if params["max_tokens"] <= budget:
                params["max_tokens"] = budget + 1024
            params["thinking"] = {"type": "enabled", "budget_tokens": budget}

        async with self._semaphore:
            result = await self._with_retries(
                lambda: self._client.messages.parse(**params),
                max_retries=max_retries,
            )

        await self._record_usage(result, call_site=call_site, model=chosen_model)

        # messages.parse() returns a ParsedMessage; parsed_output holds the
        # validated Pydantic instance (or None if the model refused / failed
        # to conform to the schema).
        parsed = getattr(result, "parsed_output", None)
        if parsed is None:
            raise RuntimeError(
                f"Claude returned no parsed output for {response_model.__name__}"
            )
        return parsed

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------

    async def _record_usage(self, result: object, *, call_site: str, model: str) -> None:
        """Capture .usage from a ParsedMessage and persist + tally it."""
        usage = getattr(result, "usage", None)
        if usage is None:
            return
        # The SDK exposes these as attributes on the Usage object.
        in_tok = int(getattr(usage, "input_tokens", 0) or 0)
        out_tok = int(getattr(usage, "output_tokens", 0) or 0)
        cache_create = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)

        self.usage.add(
            call_site=call_site,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cache_creation_tokens=cache_create,
            cache_read_tokens=cache_read,
        )
        log.info(
            "AI[%s|%s] in=%d out=%d cache_create=%d cache_read=%d",
            call_site, model, in_tok, out_tok, cache_create, cache_read,
        )

        if self._db is None:
            return
        try:
            run_id = await self._db.get_or_create_run_id()
            await self._db.record_ai_usage(
                run_id=run_id,
                call_site=call_site,
                model=model,
                input_tokens=in_tok,
                output_tokens=out_tok,
                cache_creation_tokens=cache_create,
                cache_read_tokens=cache_read,
            )
        except Exception as exc:
            # Telemetry must never break the call path.
            log.debug("Failed to persist ai_usage row: %s", exc)

    # ------------------------------------------------------------------
    # Retry loop
    # ------------------------------------------------------------------

    async def _with_retries(self, call, *, max_retries: Optional[int] = None):
        """Retry *call* on transient Anthropic errors with exponential backoff.

        Pass ``max_retries`` to override the per-client default — discovery
        sets this to 1 so a 16K-token call doesn't silently triple the bill.
        """
        # The anthropic SDK wraps Bedrock-level errors in the same exception
        # hierarchy as the direct API, so these imports work for both transports.
        from anthropic import (
            APIConnectionError,
            APITimeoutError,
            InternalServerError,
            RateLimitError,
        )

        budget = max_retries if max_retries is not None else self._cfg.max_retries
        transient = (RateLimitError, APIConnectionError, APITimeoutError, InternalServerError)
        attempt = 0
        while True:
            try:
                return await call()
            except transient as exc:
                attempt += 1
                if attempt > budget:
                    log.error(
                        "Bedrock request failed after %d retries: %s", attempt - 1, exc
                    )
                    raise
                # Exponential backoff with jitter: 1s, 2s, 4s, … capped at 30s
                delay = min(30.0, (2 ** (attempt - 1)) + random.random())
                log.warning(
                    "Bedrock transient error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt, budget, exc, delay,
                )
                await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Azure resource ID aliasing (token budget reducer for Bedrock prompts)
# ---------------------------------------------------------------------------

def build_azure_alias_map(resource_ids: list[str]) -> dict[str, str]:
    """Compress Azure resource IDs to short readable aliases.

    Azure resource IDs are long (/subscriptions/…/resourceGroups/…/providers/…)
    and consume significant tokens when serialised into prompts. This function
    maps each unique resource ID to a 6–10 char alias like ``kv:dxz`` or
    ``vm:ab7``, using the resource type as the prefix and a 3-char hash suffix
    for uniqueness.

    Returns a dict mapping original resource ID → alias. Call
    ``apply_azure_aliases(text, alias_map)`` to perform substitution.
    """
    import hashlib

    # Extract the resource type leaf (last provider segment, e.g. "vaults" → "kv")
    _TYPE_SHORT: dict[str, str] = {
        "vaults":               "kv",
        "virtualMachines":      "vm",
        "storageAccounts":      "sa",
        "managedClusters":      "aks",
        "sites":                "app",
        "functionApps":         "fn",
        "roleAssignments":      "ra",
        "roleDefinitions":      "rd",
        "userAssignedIdentities": "uami",
        "sqlServers":           "sql",
        "databaseAccounts":     "cos",
        "namespaces":           "sb",
        "networkSecurityGroups": "nsg",
        "virtualNetworks":      "vnet",
        "containerGroups":      "aci",
        "registries":           "acr",
        "subscriptions":        "sub",
        "resourceGroups":       "rg",
    }

    alias_map: dict[str, str] = {}
    seen_aliases: set[str] = set()

    for rid in resource_ids:
        if not rid or rid in alias_map:
            continue
        # Find the last "providers/…/<type>/<name>" segment
        parts = rid.split("/")
        type_hint = "res"
        for i, part in enumerate(parts):
            if part.lower() == "providers" and i + 2 < len(parts):
                leaf = parts[i + 2]
                type_hint = _TYPE_SHORT.get(leaf, leaf[:4].lower())
                break

        # 3-char hash suffix for uniqueness within this type prefix
        suffix = hashlib.sha1(rid.encode()).hexdigest()[:3]
        alias = f"{type_hint}:{suffix}"
        # Resolve collisions (rare) by appending an extra char
        while alias in seen_aliases:
            suffix = hashlib.sha1((rid + alias).encode()).hexdigest()[:4]
            alias = f"{type_hint}:{suffix}"

        alias_map[rid] = alias
        seen_aliases.add(alias)

    return alias_map


def apply_azure_aliases(text: str, alias_map: dict[str, str]) -> str:
    """Replace all Azure resource IDs in *text* with their short aliases."""
    for rid, alias in alias_map.items():
        text = text.replace(rid, alias)
    return text
