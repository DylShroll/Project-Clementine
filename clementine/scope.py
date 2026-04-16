"""
Scope enforcement and rate limiting.

The orchestrator calls check_url() before every MCP tool call that targets a
URL or domain.  This ensures no requests are ever sent outside the defined
assessment scope, regardless of which MCP server initiates them.

Rate limiting is handled by a simple token-bucket implementation that the
orchestrator enforces at the top level rather than delegating to individual
tools (per design spec §8.4).
"""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

from .config import ScopeConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scope checker
# ---------------------------------------------------------------------------

class ScopeError(Exception):
    """Raised when a tool call would target an out-of-scope resource."""


class ScopeGuard:
    """Validates that URLs and domains are within the defined assessment scope.

    The guard checks in order:
    1. The domain must be in *include_domains* (exact match or subdomain).
    2. The path must NOT start with any *exclude_paths* prefix.

    Usage::

        guard = ScopeGuard(config.target.scope)
        guard.check_url("https://app.example.com/login")    # OK
        guard.check_url("https://other.example.com/")       # raises ScopeError
    """

    def __init__(self, scope: ScopeConfig) -> None:
        self._include_domains = [d.lower() for d in scope.include_domains]
        self._exclude_paths = scope.exclude_paths

    def _is_domain_in_scope(self, hostname: str) -> bool:
        """Return True if *hostname* is an allowed domain or a subdomain of one."""
        hostname = hostname.lower()
        for allowed in self._include_domains:
            if hostname == allowed or hostname.endswith(f".{allowed}"):
                return True
        return False

    def check_url(self, url: str) -> None:
        """Raise ScopeError if *url* is outside the assessment scope.

        Does nothing (returns None) when the URL is in scope.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if not self._is_domain_in_scope(hostname):
            raise ScopeError(
                f"URL is out of scope: {url!r} — "
                f"allowed domains: {self._include_domains}"
            )

        path = parsed.path or "/"
        for excluded in self._exclude_paths:
            if path.startswith(excluded):
                raise ScopeError(
                    f"URL path is excluded from scope: {url!r} "
                    f"(matched exclusion prefix {excluded!r})"
                )

    def check_domain(self, domain: str) -> None:
        """Raise ScopeError if *domain* is not in scope."""
        if not self._is_domain_in_scope(domain.lower()):
            raise ScopeError(
                f"Domain is out of scope: {domain!r} — "
                f"allowed: {self._include_domains}"
            )


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Async token-bucket rate limiter.

    Enforces a maximum of *rps* requests per second across all concurrent
    calls.  Each acquire() call consumes one token; callers that arrive when
    the bucket is empty wait until a token is available.

    Usage::

        limiter = RateLimiter(rps=10)
        async with limiter:
            # guaranteed ≤10 requests/second
            await mcp.call_tool(...)
    """

    def __init__(self, rps: int) -> None:
        self._rps = max(1, rps)
        # Interval between token refills
        self._interval = 1.0 / self._rps
        self._tokens: float = float(self._rps)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        new_tokens = elapsed * self._rps
        self._tokens = min(float(self._rps), self._tokens + new_tokens)
        self._last_refill = now

    async def acquire(self) -> None:
        """Block until one token is available, then consume it."""
        async with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            # Not enough tokens — calculate wait and sleep outside the lock
            # so other tasks can check without blocking on the sleep itself.
            wait = self._interval * (1.0 - self._tokens)

        await asyncio.sleep(wait)
        # Re-acquire to consume the token after waking
        async with self._lock:
            self._refill()
            self._tokens = max(0.0, self._tokens - 1.0)

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *_) -> None:
        pass  # Nothing to release; tokens replenish over time
