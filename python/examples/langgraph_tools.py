"""LangGraph: `as_langgraph_tools()` into `ToolNode` and `bind_tools`.

`as_langgraph_tools` is a literal alias of `as_langchain_tools`. There is no
LangGraph tool type -- `ToolNode` and `bind_tools()` consume LangChain tools
unchanged -- and the alias exists only because people look for it by name.
"""

from __future__ import annotations

import asyncio
from typing import Any

from kaleidoscope_memory import KaleidoscopeMemory


def _needs_tools(state: Any) -> str:
    return "tools" if getattr(state["messages"][-1], "tool_calls", None) else "end"


async def main() -> None:
    from langchain.chat_models import init_chat_model
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    async with KaleidoscopeMemory(profile="default") as memory:
        tools = memory.as_langgraph_tools()
        model = init_chat_model("openai:gpt-5-mini").bind_tools(tools)

        async def call_model(state: MessagesState) -> dict:
            return {"messages": [await model.ainvoke(state["messages"])]}

        builder = StateGraph(MessagesState)
        builder.add_node("model", call_model)
        builder.add_node("tools", ToolNode(tools))
        builder.add_edge(START, "model")
        builder.add_conditional_edges("model", _needs_tools, {"tools": "tools", "end": END})
        builder.add_edge("tools", "model")
        graph = builder.compile()

        # The graph is built and run INSIDE the context. `get_tools()`-style
        # stateless clients respawn stdio per call; the context is the lifecycle
        # boundary that keeps exactly one engine process alive across turns.
        state = await graph.ainvoke(
            {"messages": [{"role": "user", "content": "What did we decide about retries?"}]}
        )
        print(state["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
