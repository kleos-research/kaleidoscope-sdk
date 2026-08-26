from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("crewai_tools")

from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters
from kaleidoscope_memory.descriptor import safe_bootstrap_environment


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(
        isinstance(block, dict) and block.get("type") == "text" for block in value
    ):
        return "\n".join(block["text"] for block in value)
    raise AssertionError(f"unexpected CrewAI MCP content: {value!r}")


def test_crewai_adapter_reuses_one_stdio_process(fake_binary: Path) -> None:
    parameters = StdioServerParameters(
        command=str(fake_binary),
        args=["mcp", "--profile", "crewai"],
        env=safe_bootstrap_environment(),
    )
    with MCPServerAdapter(parameters) as tools:
        assert {tool.name for tool in tools} == {"search", "remember"}
        by_name = {tool.name: tool for tool in tools}
        remembered = json.loads(
            _text(
                by_name["remember"].run(
                    mode="create",
                    content_md="# CrewAI fixture\n\nOne adapter owns the process.",
                    semantic_delta={
                        "memory_type": "architecture",
                        "title": "CrewAI fixture",
                        "facts": [
                            {
                                "subject": "CrewAI fixture",
                                "predicate": "uses",
                                "object": "Kaleidoscope MCP",
                            }
                        ],
                    },
                )
            )
        )
        searched = json.loads(_text(by_name["search"].run(query="CrewAI fixture")))
    assert remembered["pid"] == searched["pid"]
    assert searched["records"] == ["# CrewAI fixture\n\nOne adapter owns the process."]
