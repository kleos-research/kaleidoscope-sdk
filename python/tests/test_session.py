from __future__ import annotations

import json
from pathlib import Path

import pytest

from kaleidoscope_memory.descriptor import load_launch_descriptor
from kaleidoscope_memory.errors import ProtocolError, ToolRefusalError
from kaleidoscope_memory.session import PersistentKaleidoscopeSession


class FakeProvider:
    """Deterministic provider double; it owns no memory and calls only MCP tools."""

    async def run(self, memory: PersistentKaleidoscopeSession) -> tuple[dict, dict, dict]:
        remembered = json.loads(
            await memory.remember_raw(
                {
                "mode": "create",
                "content_md": "# Fixture fact\n\nThe persistent process retained this fixture record.",
                "semantic_delta": {
                    "memory_type": "architecture",
                    "title": "Fixture fact",
                    "facts": [
                        {
                            "subject": "DX-07 fixture",
                            "predicate": "uses",
                            "object": "one persistent MCP process",
                            "basis": "stated",
                            "mode": "fact",
                        }
                    ],
                },
                }
            )
        )
        first = json.loads(await memory.search_raw({"query": "fixture"}))
        second = json.loads(await memory.search_raw({"query": "fixture again"}))
        return remembered, first, second


@pytest.mark.asyncio
async def test_fake_provider_reuses_one_process_and_session(fake_binary: Path) -> None:
    launch = load_launch_descriptor(fake_binary, "test")
    async with PersistentKaleidoscopeSession(launch) as memory:
        remembered, first, second = await FakeProvider().run(memory)
    assert remembered["pid"] == first["pid"] == second["pid"]
    assert first["records"] == second["records"]
    assert first["records"] == [
        "# Fixture fact\n\nThe persistent process retained this fixture record."
    ]


@pytest.mark.asyncio
async def test_stdio_child_does_not_receive_ambient_secret(
    fake_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KALEIDOSCOPE_TEST_SECRET", "must-not-reach-child")
    launch = load_launch_descriptor(fake_binary, "test")
    async with PersistentKaleidoscopeSession(launch) as memory:
        result = json.loads(await memory.search_raw({"query": "__environment__"}))
    assert result["secret"] == "absent"


@pytest.mark.asyncio
async def test_refuses_operator_tool_before_wire(fake_binary: Path) -> None:
    launch = load_launch_descriptor(fake_binary, "test")
    async with PersistentKaleidoscopeSession(launch) as memory:
        with pytest.raises(ProtocolError, match="non-agent"):
            await memory.call_text("feedback", {})


@pytest.mark.asyncio
async def test_rejects_extra_discovered_tool(fake_binary: Path) -> None:
    launch = load_launch_descriptor(fake_binary, "extra")
    with pytest.raises(ProtocolError, match="exactly"):
        async with PersistentKaleidoscopeSession(launch):
            pass


@pytest.mark.asyncio
async def test_rejects_structured_content(fake_binary: Path) -> None:
    launch = load_launch_descriptor(fake_binary, "structured")
    async with PersistentKaleidoscopeSession(launch) as memory:
        with pytest.raises(ProtocolError, match="structuredContent"):
            await memory.remember_raw({"mode": "create", "content_md": "# test"})


@pytest.mark.asyncio
async def test_preserves_tool_refusal_category(fake_binary: Path) -> None:
    launch = load_launch_descriptor(fake_binary, "refuse")
    async with PersistentKaleidoscopeSession(launch) as memory:
        with pytest.raises(ToolRefusalError) as refusal:
            await memory.remember_raw({"mode": "create", "content_md": "# test"})
    assert "invalid_schema" in refusal.value.text
