from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

import pytest

pytest.importorskip("langchain_mcp_adapters")
pytest.importorskip("langgraph")

from examples.langchain_mcp import run_with_langchain_tools
from examples.langgraph_mcp import run_tool_node_calls
from kaleidoscope_memory.descriptor import load_launch_descriptor


def tool_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(
        isinstance(block, dict) and block.get("type") == "text" for block in value
    ):
        return "\n".join(block["text"] for block in value)
    raise AssertionError(f"unexpected LangChain tool content: {value!r}")


class FakeLangChainProvider:
    """Deterministic provider double that calls only the supplied MCP tools."""

    async def __call__(self, tools: Sequence[Any]) -> tuple[dict, dict]:
        by_name = {tool.name: tool for tool in tools}
        remembered = json.loads(
            tool_text(
                await by_name["remember"].ainvoke(
                {
                    "mode": "create",
                    "content_md": "# LangChain fixture\n\nOne adapter session owns the process.",
                    "semantic_delta": {
                        "memory_type": "architecture",
                        "title": "LangChain fixture",
                        "facts": [
                            {
                                "subject": "LangChain fixture",
                                "predicate": "uses",
                                "object": "Kaleidoscope MCP",
                            }
                        ],
                    },
                }
                )
            )
        )
        searched = json.loads(
            tool_text(await by_name["search"].ainvoke({"query": "LangChain fixture"}))
        )
        return remembered, searched


@pytest.mark.asyncio
async def test_standalone_langchain_keeps_one_adapter_session(fake_binary: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "langchain")
    remembered, searched = await run_with_langchain_tools(descriptor, FakeLangChainProvider())
    assert remembered["pid"] == searched["pid"]
    assert searched["records"] == [
        "# LangChain fixture\n\nOne adapter session owns the process."
    ]


@pytest.mark.asyncio
async def test_langgraph_tool_node_reuses_the_same_adapter_session(fake_binary: Path) -> None:
    descriptor = load_launch_descriptor(fake_binary, "langgraph")
    outputs = await run_tool_node_calls(
        descriptor,
        [
            (
                "remember",
                {
                    "mode": "create",
                    "content_md": "# LangGraph fixture\n\nToolNode uses the MCP adapter.",
                    "semantic_delta": {
                        "memory_type": "architecture",
                        "title": "LangGraph fixture",
                        "facts": [
                            {
                                "subject": "LangGraph fixture",
                                "predicate": "uses",
                                "object": "Kaleidoscope MCP",
                            }
                        ],
                    },
                },
            ),
            ("search", {"query": "LangGraph fixture"}),
        ],
    )
    remembered, searched = (json.loads(tool_text(output)) for output in outputs)
    assert remembered["pid"] == searched["pid"]
    assert searched["records"] == ["# LangGraph fixture\n\nToolNode uses the MCP adapter."]
