"""Claude Agent SDK: keep one client (and MCP child) for the whole conversation."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from kaleidoscope_memory.descriptor import LaunchDescriptor, safe_bootstrap_environment
from kaleidoscope_memory.entitlement import entitlement_preflight


async def run_conversation(
    descriptor: LaunchDescriptor, prompts: Sequence[str]
) -> AsyncIterator[object]:
    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

    # This adapter bypasses PersistentKaleidoscopeSession, so the typed
    # entitlement error does not reach it for free. Fails open on any engine
    # whose gate status cannot be read; the engine remains the authority.
    entitlement_preflight(descriptor.command)

    options = ClaudeAgentOptions(
        mcp_servers={
            "kaleidoscope": {
                "type": "stdio",
                "command": descriptor.command,
                "args": list(descriptor.args),
                "env": safe_bootstrap_environment(),
            }
        },
        allowed_tools=[
            "mcp__kaleidoscope__search",
            "mcp__kaleidoscope__remember",
        ],
        strict_mcp_config=True,
    )
    async with ClaudeSDKClient(options=options) as client:
        for prompt in prompts:
            await client.query(prompt)
            async for message in client.receive_response():
                yield message
