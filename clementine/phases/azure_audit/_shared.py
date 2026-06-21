"""Shared helpers for the Azure audit steps.

The ``_SKIP`` sentinel marks an MCP call that was skipped because the
server was unavailable (403/429/unavailable); ``_mcp_call`` returns it and
every step checks ``is _SKIP`` to degrade gracefully.
"""
from __future__ import annotations

import asyncio
import logging

from ...mcp_client import MCPRegistry
from ...scope import RateLimiter

log = logging.getLogger(__name__)

# Sentinel used to mark a call as skipped due to server unavailability
_SKIP = object()


async def _mcp_call(
    mcp: MCPRegistry,
    limiter: RateLimiter,
    server: str,
    tool: str,
    args: dict,
    *,
    step: str,
) -> object:
    """Call an MCP tool with rate-limiting and graceful error handling.

    Returns the tool result on success, or the _SKIP sentinel on failure.
    Error modes (per spec §8.2):
      - Server unavailable → _SKIP (logged)
      - 403 → _SKIP + enrichment_status blocked
      - 429 → exponential backoff up to 4 attempts
      - Any other exception → _SKIP (logged)
    """
    if not mcp.is_available(server):
        log.debug("[azure] %s: server %s unavailable — skipping", step, server)
        return _SKIP

    async with limiter:
        for attempt in range(4):
            try:
                result = await mcp.call_tool(server, tool, args)
                return result
            except Exception as exc:
                exc_str = str(exc)
                if "403" in exc_str or "Forbidden" in exc_str or "AuthorizationFailed" in exc_str:
                    log.warning("[azure] %s: 403 on %s/%s — RBAC insufficient", step, server, tool)
                    return _SKIP
                if "429" in exc_str or "TooManyRequests" in exc_str:
                    wait = 2 ** attempt
                    log.warning("[azure] %s: 429 — backoff %ds (attempt %d/4)", step, wait, attempt + 1)
                    if attempt < 3:
                        await asyncio.sleep(wait)
                        continue
                    log.error("[azure] %s: 429 persisted after 4 attempts — skipping", step)
                    return _SKIP
                if "elicitation" in exc_str.lower() or "sensitive" in exc_str.lower():
                    log.warning("[azure] %s: elicitation prompt from %s — refusing, skipping", step, server)
                    return _SKIP
                log.warning("[azure] %s: %s/%s failed: %s", step, server, tool, exc)
                return _SKIP
    return _SKIP  # should not reach here


def _scope_to_level(scope: str) -> str:
    """Map an Azure scope path to a level string."""
    if "/resourceGroups/" in scope and "/providers/" in scope:
        return "resource"
    if "/resourceGroups/" in scope:
        return "rg"
    if "/subscriptions/" in scope and scope.count("/") <= 3:
        return "subscription"
    if "/managementGroups/" in scope:
        return "mg"
    return "resource"


def _scope_to_node_id(scope: str, sub_id: str) -> str:
    """Convert an Azure scope path to a graph node ID."""
    if scope.startswith("/subscriptions/"):
        parts = scope.split("/")
        if len(parts) >= 5 and parts[3] == "resourceGroups":
            return f"rg:{parts[2]}:{parts[4]}"
        return f"subscription:{parts[2]}"
    if scope.startswith("/providers/Microsoft.Management/managementGroups/"):
        mg_id = scope.split("/")[-1]
        return f"mg:{mg_id}"
    return f"subscription:{sub_id}"
