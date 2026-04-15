"""
MCP server client — stdio and HTTP transport abstraction.

Provides a single MCPClient class that wraps the mcp Python SDK and exposes
a call_tool() method regardless of transport type.  The orchestrator and
phase modules use this class exclusively; they never touch raw transport
primitives.

Retry policy: 3 attempts with exponential backoff (1s, 4s, 16s) as specified
in the design.  If a server fails all retries it is marked unavailable and
the calling phase receives MCPServerUnavailable rather than an unhandled
exception.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from enum import Enum
from typing import Any, AsyncIterator

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import HttpServerConfig, StdioServerConfig

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MCPServerUnavailable(Exception):
    """Raised when a server cannot be reached after all retry attempts."""


class MCPToolError(Exception):
    """Raised when the server returns an error response for a tool call."""


# ---------------------------------------------------------------------------
# Retry helpers
# ---------------------------------------------------------------------------

_RETRY_DELAYS = (1, 4, 16)  # seconds; exponential backoff as per design spec


async def _with_retries(coro_factory, server_name: str) -> Any:
    """Call *coro_factory()* up to len(_RETRY_DELAYS)+1 times with backoff.

    *coro_factory* is a callable that returns a fresh coroutine each attempt
    so that connection-level errors trigger a full reconnect rather than
    re-awaiting an already-failed coroutine.
    """
    last_exc: Exception | None = None
    for attempt, delay in enumerate((*_RETRY_DELAYS, None), start=1):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            if delay is None:
                break  # final attempt exhausted
            log.warning(
                "[%s] tool call failed (attempt %d/%d): %s — retrying in %ds",
                server_name, attempt, len(_RETRY_DELAYS) + 1, exc, delay,
            )
            await asyncio.sleep(delay)

    raise MCPServerUnavailable(
        f"MCP server '{server_name}' unavailable after {len(_RETRY_DELAYS) + 1} attempts"
    ) from last_exc


# ---------------------------------------------------------------------------
# Transport: stdio
# ---------------------------------------------------------------------------

class StdioMCPClient:
    """MCP client backed by a local child process over stdio transport.

    The child process is started lazily on the first call_tool() invocation
    and kept alive for the lifetime of the client object.  Call close() when
    done (or use as an async context manager).
    """

    def __init__(self, name: str, cfg: StdioServerConfig) -> None:
        self.name = name
        self._cfg = cfg
        self._session: ClientSession | None = None
        self._stdio_ctx = None

    async def _ensure_session(self) -> ClientSession:
        """Lazily start the child process and initialise the MCP session."""
        if self._session is not None:
            return self._session

        # Build the environment for the child process.
        # Start from a clean copy of the current env so the child inherits
        # PATH and other essentials, then apply server-specific overrides.
        env = dict(os.environ)
        env.update(self._cfg.env)

        params = StdioServerParameters(
            command=self._cfg.command,
            args=self._cfg.args,
            env=env,
        )
        # Only store _stdio_ctx after __aenter__ succeeds.  If __aenter__
        # raises (e.g. the child process exits immediately), leaving
        # _stdio_ctx pointing at a half-initialised async generator causes
        # anyio cancel-scope errors in close() later.
        ctx = stdio_client(params)
        read, write = await ctx.__aenter__()
        self._stdio_ctx = ctx

        session = ClientSession(read, write)
        await session.__aenter__()
        await session.initialize()

        self._session = session
        log.info("[%s] MCP stdio session initialised", self.name)
        return self._session

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Call a named MCP tool and return the result content.

        Raises MCPServerUnavailable if the server cannot be reached.
        Raises MCPToolError if the server returns an error response.
        """
        async def _attempt():
            session = await self._ensure_session()
            result = await session.call_tool(tool, arguments)
            # The MCP SDK returns a CallToolResult; surface errors explicitly
            if result.isError:
                raise MCPToolError(
                    f"[{self.name}] tool '{tool}' returned error: {result.content}"
                )
            return result.content

        return await _with_retries(_attempt, self.name)

    async def ping(self) -> bool:
        """Light health check — returns True if the session is alive."""
        try:
            session = await self._ensure_session()
            # The MCP SDK ping is a lightweight protocol message
            await session.send_ping()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        """Terminate the child process and close the session cleanly."""
        if self._session:
            try:
                await self._session.__aexit__(None, None, None)
            except Exception:
                pass
            self._session = None
        if self._stdio_ctx:
            try:
                await self._stdio_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._stdio_ctx = None

    async def __aenter__(self) -> "StdioMCPClient":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Transport: HTTP (Streamable HTTP — AWS Knowledge MCP Server)
# ---------------------------------------------------------------------------

class HttpMCPClient:
    """MCP client for remote servers that speak Streamable HTTP transport.

    AWS's managed MCP servers expose a stateless JSON-over-HTTP interface
    where each tool call is an independent POST request.  This client does
    NOT use the mcp SDK's SSE client because AWS uses the newer Streamable
    HTTP transport introduced in MCP spec v0.7.

    The request/response format follows the MCP JSON-RPC schema:
      POST {base_url}/
      Content-Type: application/json
      Body: {"jsonrpc":"2.0","method":"tools/call","params":{...},"id":1}
    """

    def __init__(self, name: str, cfg: HttpServerConfig) -> None:
        self.name = name
        self._base_url = cfg.url.rstrip("/")
        # Share one httpx session across all calls for connection pooling.
        # cfg.headers are forwarded with every request (e.g. Bearer auth).
        self._http = httpx.AsyncClient(timeout=30.0, headers=cfg.headers)
        self._call_id = 0

    def _next_id(self) -> int:
        self._call_id += 1
        return self._call_id

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Call a named MCP tool via HTTP and return the result.

        Raises MCPServerUnavailable on network errors.
        Raises MCPToolError if the server returns a JSON-RPC error.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
            "id": self._next_id(),
        }

        async def _attempt():
            response = await self._http.post(
                self._base_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            body = response.json()

            if "error" in body:
                raise MCPToolError(
                    f"[{self.name}] tool '{tool}' error: {body['error']}"
                )
            return body.get("result", {}).get("content")

        return await _with_retries(_attempt, self.name)

    async def ping(self) -> bool:
        """Health check — HEAD request to the base URL."""
        try:
            resp = await self._http.head(self._base_url, timeout=5.0)
            return resp.status_code < 500
        except Exception:
            return False

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "HttpMCPClient":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Public type alias
# ---------------------------------------------------------------------------

MCPClient = StdioMCPClient | HttpMCPClient


# ---------------------------------------------------------------------------
# Server registry — builds and holds all configured clients
# ---------------------------------------------------------------------------

class MCPRegistry:
    """Holds all MCP client instances and provides a call_tool() proxy.

    The orchestrator accesses MCP servers exclusively through this class so
    that health monitoring and graceful degradation logic is centralised.
    """

    def __init__(self) -> None:
        # Maps server name → client instance
        self._clients: dict[str, MCPClient] = {}
        # Names of servers confirmed to be unavailable this run
        self._unavailable: set[str] = set()

    def register_stdio(self, name: str, cfg: StdioServerConfig) -> None:
        """Register a stdio-transport MCP server."""
        self._clients[name] = StdioMCPClient(name, cfg)

    def register_http(self, name: str, cfg: HttpServerConfig) -> None:
        """Register an HTTP-transport MCP server."""
        self._clients[name] = HttpMCPClient(name, cfg)

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Call a tool on the named server.

        Returns None (rather than raising) if the server is currently marked
        unavailable — the calling phase should treat None as 'skip this step'.
        """
        if server in self._unavailable:
            log.debug("[%s] skipped (server marked unavailable)", server)
            return None

        client = self._clients.get(server)
        if client is None:
            log.warning("call_tool: unknown server '%s'", server)
            return None

        try:
            return await client.call_tool(tool, arguments)
        except MCPServerUnavailable:
            log.error("[%s] marking server unavailable after repeated failures", server)
            self._unavailable.add(server)
            return None

    async def ping_all(self) -> dict[str, bool]:
        """Health-check all registered servers; returns {name: is_alive}."""
        results: dict[str, bool] = {}
        for name, client in self._clients.items():
            alive = await client.ping()
            results[name] = alive
            if not alive:
                log.warning("[%s] health check failed", name)
        return results

    def is_available(self, server: str) -> bool:
        """Return True if the server is registered and not marked unavailable."""
        return server in self._clients and server not in self._unavailable

    async def close_all(self) -> None:
        """Shut down every registered client."""
        for client in self._clients.values():
            await client.close()
        self._clients.clear()

    async def __aenter__(self) -> "MCPRegistry":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close_all()
