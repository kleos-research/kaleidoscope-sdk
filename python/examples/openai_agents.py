"""OpenAI Agents SDK with one context-managed MCP server per agent run.

This is the NATIVE-MCP form: the framework's own MCP client owns the child.
`openai_agents_tools.py` beside it is the tool-shaped form and is the recommended one --
`memory.as_*_tools()` builds the same two tools from live discovery and keeps
the bounded stderr and the typed entitlement error this form gives up.
Kept because it demonstrates the handover honestly, not because it is worse.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from typing import Any

from kaleidoscope_memory.descriptor import (
    EXPECTED_TOOLS,
    LaunchDescriptor,
    safe_bootstrap_environment,
)
from kaleidoscope_memory.entitlement import entitlement_preflight


async def run_agent_turns(
    descriptor: LaunchDescriptor,
    model: Any,
    prompts: Sequence[str],
) -> list[Any]:
    from agents.mcp import create_static_tool_filter

    # Third-party MCP client: the allowlist change reaches it for free, the
    # typed entitlement error does not. Preflight, then let the engine decide.
    entitlement_preflight(descriptor.command)

    # This example set no errlog, so the MCP SDK default applied and the child's
    # stderr INHERITED to the parent -- the opposite of session.py's policy, and
    # a path by which engine output could reach model-visible output.
    #
    # `MCPServerStdioParams` has no errlog field and `create_streams` calls
    # `stdio_client(self.params)` with no errlog argument, so an "errlog" key in
    # params is dropped by pydantic and the redirect silently does not happen.
    # Overriding `create_streams` is the only wiring that actually fires; see
    # tests/test_openai_agents.py::test_openai_agents_bounds_child_stderr.
    with tempfile.TemporaryFile(mode="w+b") as errlog:
        server = _BoundedStderrServer(
            errlog=errlog,
            name="kaleidoscope",
            params={
                "command": descriptor.command,
                "args": list(descriptor.args),
                "env": safe_bootstrap_environment(),
            },
            cache_tools_list=True,
            client_session_timeout_seconds=30,
            tool_filter=create_static_tool_filter(allowed_tool_names=list(EXPECTED_TOOLS)),
            use_structured_content=False,
            max_retry_attempts=0,
        )
        return await _run(server, model, prompts)


def _bounded_stderr_server_class() -> Any:
    from agents.mcp import MCPServerStdio

    class _Bounded(MCPServerStdio):
        def __init__(self, *args: Any, errlog: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._errlog = errlog

        def create_streams(self) -> Any:
            from mcp.client.stdio import stdio_client

            return stdio_client(self.params, errlog=self._errlog)

    return _Bounded


class _BoundedStderrServer:
    """Lazy facade so importing this module never requires `agents`."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        return _bounded_stderr_server_class()(*args, **kwargs)


async def _run(server: Any, model: Any, prompts: Sequence[str]) -> list[Any]:
    from agents import Agent, Runner

    async with server:
        names = [tool.name for tool in await server.list_tools()]
        if len(names) != 2 or set(names) != set(EXPECTED_TOOLS):
            raise RuntimeError(f"Kaleidoscope published an incompatible tool set: {names!r}")
        agent = Agent(
            name="Memory-aware assistant",
            instructions="Use Kaleidoscope as the only durable memory owner.",
            model=model,
            mcp_servers=[server],
        )
        return [await Runner.run(agent, prompt) for prompt in prompts]
