"""LangChain/LangGraph: retain the explicit MCP session around every graph turn.

This is the NATIVE-MCP form: the framework's own MCP client owns the child.
`langgraph_tools.py` beside it is the tool-shaped form and is the recommended one --
`memory.as_*_tools()` builds the same two tools from live discovery and keeps
the bounded stderr and the typed entitlement error this form gives up.
Kept because it demonstrates the handover honestly, not because it is worse.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from kaleidoscope_memory.descriptor import (
    EXPECTED_TOOLS,
    LaunchDescriptor,
    safe_bootstrap_environment,
)


async def run_tool_node_calls(
    descriptor: LaunchDescriptor,
    calls: Sequence[tuple[str, Mapping[str, Any]]],
) -> list[Any]:
    from langchain_core.messages import AIMessage
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

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
    outputs: list[Any] = []
    # MultiServerMCPClient.get_tools() is stateless. The explicit session is the
    # lifecycle boundary that keeps Kaleidoscope's process alive across turns.
    async with client.session("kaleidoscope") as session:
        tools = await load_mcp_tools(session)
        if {tool.name for tool in tools} != set(EXPECTED_TOOLS):
            raise RuntimeError("Kaleidoscope must expose exactly search and remember")
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode(tools))
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile()
        for index, (name, arguments) in enumerate(calls):
            result = await graph.ainvoke(
                {
                    "messages": [
                        AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "name": name,
                                    "args": dict(arguments),
                                    "id": f"call-{index}",
                                    "type": "tool_call",
                                }
                            ],
                        )
                    ]
                }
            )
            outputs.append(result["messages"][-1].content)
    return outputs
