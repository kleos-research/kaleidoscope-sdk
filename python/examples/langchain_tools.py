"""LangChain: hand Kaleidoscope over as `tools=[...]`.

No `api_key=` here, on purpose: omitted, the key comes from
KALEIDOSCOPE_API_KEY in the caller's environment, or from the engine's key file.
Both routes work and neither needs a code change.
"""

from __future__ import annotations

import asyncio

from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:
        from langchain.agents import create_agent

        agent = create_agent(
            model="openai:gpt-5-mini",
            tools=memory.as_langchain_tools(),
            system_prompt="Use Kaleidoscope as the only durable memory owner.",
        )
        state = await agent.ainvoke(
            {"messages": [{"role": "user", "content": "What did we decide about retries?"}]}
        )
        print(state["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
