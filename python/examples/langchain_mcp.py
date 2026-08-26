"""Standalone LangChain MCP adapter with an explicitly persistent session.

This is the NATIVE-MCP form: the framework's own MCP client owns the child.
`langchain_tools.py` beside it is the tool-shaped form and is the recommended one --
`memory.as_*_tools()` builds the same two tools from live discovery and keeps
the bounded stderr and the typed entitlement error this form gives up.
Kept because it demonstrates the handover honestly, not because it is worse.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from kaleidoscope_memory.descriptor import (
    EXPECTED_TOOLS,
    LaunchDescriptor,
    safe_bootstrap_environment,
)
from kaleidoscope_memory.entitlement import entitlement_preflight


async def run_with_langchain_tools(
    descriptor: LaunchDescriptor,
    provider: Callable[[Sequence[Any]], Awaitable[Any]],
) -> Any:
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools

    # Third-party MCP client: the allowlist change reaches it for free, the
    # typed entitlement error does not. Preflight, then let the engine decide.
    entitlement_preflight(descriptor.command)

    client = MultiServerMCPClient(
        {
            "kaleidoscope": {
                "transport": "stdio",
                "command": descriptor.command,
                "args": list(descriptor.args),
                "env": safe_bootstrap_environment(),
            }
        }
    )
    # get_tools() is stateless and would reopen stdio for calls. Holding this
    # session around the provider run keeps exactly one application process.
    async with client.session("kaleidoscope") as session:
        tools = await load_mcp_tools(session)
        if {tool.name for tool in tools} != set(EXPECTED_TOOLS):
            raise RuntimeError("Kaleidoscope must expose exactly search and remember")
        return await provider(tools)
