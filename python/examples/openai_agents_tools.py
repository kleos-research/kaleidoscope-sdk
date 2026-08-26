"""OpenAI Agents SDK: hand Kaleidoscope over as `tools=[...]`.

This is the shape mem0's own Agents SDK page uses -- `tools=[search_memory,
save_memory]`, not `mcp_servers=[...]` -- except that the two tools are built
for you from live MCP discovery instead of hand-written as `@function_tool`
wrappers.

`openai_agents.py` beside this file is the native-MCP alternative, kept because
it demonstrates the one stderr wiring that actually fires. Use this one.
"""

from __future__ import annotations

import asyncio

from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default", api_key="ksk_alpha....") as memory:
        from agents import Agent, Runner

        agent = Agent(
            name="Memory-aware assistant",
            instructions=(
                "Use Kaleidoscope as the only durable memory owner. Search at the "
                "start of a nontrivial task; remember verified durable deltas."
            ),
            model="gpt-5-mini",
            tools=memory.as_openai_tools(),
        )
        result = await Runner.run(agent, "What did we decide about the retry policy?")
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
