"""
Thin async wrapper around the Anthropic SDK.

Centralises three concerns so the rest of the AI subsystem does not have to
care about them:

1. **Graceful degradation** — if the API key is missing or the ``ai`` config
   section is disabled, :meth:`ClaudeClient.from_config` returns ``None`` so
   callers can skip AI work without raising.
2. **Parallelism control** — a semaphore caps concurrent requests at
   ``max_parallel_requests`` so a single large assessment can't exhaust the
   tenant's Anthropic rate budget.
3. **Retry logic** — transient errors (rate limit, network, 5xx) are retried
   with exponential backoff; permanent errors (bad request, auth) bubble up
   immediately so they aren't silently masked.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional, Type, TypeVar

from pydantic import BaseModel

from ..config import AIConfig

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class ClaudeUnavailable(RuntimeError):
    """Raised when AI features are requested but the client is not configured."""


class ClaudeClient:
    """Async wrapper around :class:`anthropic.AsyncAnthropic`.

    Use :meth:`from_config` to construct; it returns ``None`` when AI is
    disabled, which is the signal that callers should skip AI work.
    """

    def __init__(self, cfg: AIConfig) -> None:
        # Lazy import so the orchestrator doesn't require the SDK unless AI
        # is actually enabled in the config.
        from anthropic import AsyncAnthropic

        self._cfg = cfg
        self._client = AsyncAnthropic(api_key=cfg.api_key)
        self._semaphore = asyncio.Semaphore(cfg.max_parallel_requests)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, cfg: AIConfig) -> Optional["ClaudeClient"]:
        """Build a client or return None if AI should be skipped.

        AI is skipped when:
          * ``ai.enabled`` is False, or
          * ``ai.api_key`` is missing / empty (e.g. ``ANTHROPIC_API_KEY`` unset).
        """
        if not cfg.enabled:
            log.info("AI subsystem disabled via config — skipping triage and discovery")
            return None
        if not cfg.api_key:
            log.warning(
                "AI subsystem enabled but no API key resolved — skipping triage and "
                "discovery. Set ANTHROPIC_API_KEY to enable."
            )
            return None
        return cls(cfg)

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
    ) -> T:
        """Send a structured-output request and return the parsed Pydantic model.

        Uses ``messages.parse`` so the SDK enforces the schema and raises on
        malformed output rather than silently handing us free-form text.

        The system prompt is sent as a list of content blocks so callers can
        mark stable prefixes with ``cache_control`` for prompt-cache hits.

        Pass ``model`` to override the default primary model (used by
        discovery for the Opus critical path).
        """
        chosen_model = model or self._cfg.primary_model
        params: dict = {
            "model": chosen_model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user_content}],
            "output_format": response_model,
        }
        # Adaptive thinking + effort are Opus 4.x features; Sonnet rejects them.
        if "opus" in chosen_model.lower():
            params["thinking"] = {"type": "adaptive"}
            params["output_config"] = {"effort": self._cfg.effort}

        async with self._semaphore:
            result = await self._with_retries(
                lambda: self._client.messages.parse(**params)
            )
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
    # Retry loop
    # ------------------------------------------------------------------

    async def _with_retries(self, call):
        """Retry *call* on transient Anthropic errors with exponential backoff."""
        from anthropic import (
            APIConnectionError,
            APITimeoutError,
            InternalServerError,
            RateLimitError,
        )

        transient = (RateLimitError, APIConnectionError, APITimeoutError, InternalServerError)
        attempt = 0
        while True:
            try:
                return await call()
            except transient as exc:
                attempt += 1
                if attempt > self._cfg.max_retries:
                    log.error(
                        "Anthropic request failed after %d retries: %s", attempt - 1, exc
                    )
                    raise
                # Exponential backoff with jitter: 1s, 2s, 4s, … capped at 30s
                delay = min(30.0, (2 ** (attempt - 1)) + random.random())
                log.warning(
                    "Anthropic transient error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt, self._cfg.max_retries, exc, delay,
                )
                await asyncio.sleep(delay)
